// Copyright 2026 reFuzz project author -------youngkk.
//
// ir_defuse.cpp — .ll-as-PROGRAM static analysis (replaces the regex .ll-as-text pass).
//
// Uses the real LLVM IR API on a parsed module: SSA def-use, typed-GEP abstract locations
// (DataLayout::accumulateConstantOffset, GEP::getSourceElementType), SwitchInst case values,
// and the VALUE dimension the regex pass lacked:
//   WRITE      <func> <loc> <value>        store/atomicrmw/inline-asm-bitop: location + value/mask
//   BRANCHUSE  <func> <loc> <reqvals>      a load that flows (real SSA slice) into a br/switch cond
//   SWITCH     <func> <condloc> <case> <block>   dispatch case value (value-specific narrowing)
//   CALL       <func> <callee|INDIRECT>    bitcode call graph (indirect calls preserved)
// loc = "<rootStructType>+<byteOffset>"  (canonical; matches def<->use across functions by field,
//        not by raw string offset). value lets us express "case X writes F=V; B branches on F==V".
//
// Build: clang++-20 ir_defuse.cpp -o ir_defuse $(llvm-config-20 --cxxflags --ldflags --libs core irreader support)
// Usage: ir_defuse <module.ll/.bc> [func ...]      (no funcs = all defined functions)

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"   // gep_type_iterator: array-of-struct field offsets
#include "llvm/IR/DebugInfoMetadata.h"            // DWARF: recover opaque-ptr byte-GEP base struct type
#include "llvm/IR/DebugInfo.h"                    // DebugInfoFinder (struct member map for load-chain)
#include "llvm/IR/DebugProgramInstruction.h"      // DbgVariableRecord for LLVM-20 debug records
#include "llvm/BinaryFormat/Dwarf.h"              // DW_TAG_member
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/SmallString.h"
#include <cstdlib>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

static std::string apStr(const APInt &a, bool sgn) {
  SmallString<40> s;
  a.toString(s, 10, sgn);
  return std::string(s.str());
}

static const DataLayout *g_DL = nullptr;             // for sizing anon structs in tyName
static std::vector<StructType *> g_named;            // module's identified (named) structs
static std::map<StructType *, std::string> g_canon;  // type -> canonical name (cache)
static std::map<std::pair<unsigned, uint64_t>, std::string> g_shape2name;  // {fieldNum,size}->name

// struct.file_operations.45 -> struct.file_operations (keep up to the 2nd dot, like SyzDescribe).
static std::string stripSuffix(const std::string &n) {
  size_t d1 = n.find('.');
  if (d1 == std::string::npos)
    return n;
  size_t d2 = n.find('.', d1 + 1);
  return (d2 == std::string::npos) ? n : n.substr(0, d2);
}

// Canonical type name (KallGraph-style): a struct's identity is {fieldNum, sizeInByte}. clang may
// emit an ops-table global as an ANONYMOUS literal while the dispatch GEPs the NAMED type; matching
// on {fieldNum,size} unifies them robustly — immune to the padding-element representation diffs that
// defeat isLayoutIdentical, and to .NN suffixes.
static std::string tyName(Type *T) {
  auto *st = dyn_cast<StructType>(T);
  if (!st) {
    std::string s;
    raw_string_ostream os(s);
    T->print(os);
    return os.str();
  }
  if (st->hasName())
    return stripSuffix(st->getName().str());
  auto it = g_canon.find(st);
  if (it != g_canon.end())
    return it->second;
  std::string r;
  if (g_DL && st->isSized()) {
    auto key = std::make_pair(st->getNumElements(), (uint64_t)g_DL->getTypeAllocSize(st));
    auto f = g_shape2name.find(key);
    r = (f != g_shape2name.end())
            ? f->second
            : "anon#" + std::to_string(key.first) + "#" + std::to_string(key.second);
  }
  if (r.empty()) {
    raw_string_ostream os(r);
    st->print(os);
  }
  g_canon[st] = r;
  return r;
}

// peel GEPs to a canonical (root struct type, constant byte offset) — opaque-ptr safe.
// DWARF base-type recovery for opaque-pointer byte GEPs: clang-KASAN lowers `obj->field` to
// `gep i8, ptr %base, N`, erasing the struct type ("i8+N"). When %base is a function ARGUMENT, the
// DISubprogram's parameter DIType names the source struct ("inode"), so the field key becomes
// struct.inode+N (matching the typed/gate side). "" when unrecoverable (alloc/load chains, anon) ->
// honest "i8+N". 96% of writes are byte GEPs; handler args are the high-coverage recoverable base.
// strip a DIType (pointer/const/volatile/typedef wrappers) down to its DICompositeType struct name.
static std::string diStructName(DIType *t) {
  for (int guard = 0; t && guard < 8; ++guard) {
    if (auto *c = dyn_cast<DICompositeType>(t))
      return c->getName().str();
    if (auto *d = dyn_cast<DIDerivedType>(t)) {
      t = d->getBaseType();
      continue;
    }
    break;
  }
  return "";
}

// the DWARF parameter/return types of f as a DISubroutineType type array ([0]=return, [1..]=params).
static DITypeRefArray subroutineTypes(const Function *f) {
  if (DISubprogram *sp = f ? f->getSubprogram() : nullptr)
    if (auto *st = dyn_cast_or_null<DISubroutineType>(sp->getType()))
      return st->getTypeArray();
  return DITypeRefArray();
}

static std::string absLoc(Value *ptr, const DataLayout &DL, int depth = 0);  // fwd (load-chain recursion)

// struct name -> (byte offset -> the struct named by the member there). Built once from DWARF; used by
// the load-chain recovery: `%obj = load (P+M)` -> %obj is the pointee struct of P's member at offset M.
struct MemberInfo {
  std::string name;
  uint64_t size = 0;
  bool pointer = false;
};
static std::map<std::string, std::map<int64_t, MemberInfo>> g_dwMember;
static std::map<std::string, std::map<std::string, int64_t>> g_dwFieldOffset;
// Deep field map: byte offset -> field name, RECURSING anonymous unions/structs (so a field nested in an
// anonymous union, e.g. genl_split_ops' doit/dumpit inside its do/dump union, is resolvable).  Kept separate
// from g_dwFieldOffset so FIELD_ICALL's dwFieldNameAt (op-alignment gate) is byte-for-byte unaffected; only
// the GENLCMD endpoint filter reads this.
static std::map<std::string, std::multimap<int64_t, std::string>> g_dwFieldDeep;

static std::string bareStructName(std::string n) {
  if (n.rfind("struct.", 0) == 0)
    n = n.substr(7);
  return stripSuffix(n);
}

static DICompositeType *diComposite(DIType *t) {
  for (int guard = 0; t && guard < 8; ++guard) {
    if (auto *c = dyn_cast<DICompositeType>(t))
      return c;
    if (auto *d = dyn_cast<DIDerivedType>(t)) {
      t = d->getBaseType();
      continue;
    }
    break;
  }
  return nullptr;
}

static bool diIsPointerToStruct(DIType *t) {
  auto *d = dyn_cast_or_null<DIDerivedType>(t);
  if (!d || d->getTag() != dwarf::DW_TAG_pointer_type)
    return false;
  return diComposite(d->getBaseType()) != nullptr;
}

static std::string dbgValueStruct(Value *v) {
  if (!v)
    return "";
  SmallVector<DbgValueInst *, 4> dbgValues;
  SmallVector<DbgVariableRecord *, 4> dbgRecords;
  findDbgValues(dbgValues, v, &dbgRecords);
  for (auto *dvi : dbgValues)
    if (auto *var = dvi ? dvi->getVariable() : nullptr)
      if (auto *c = diComposite(var->getType()))
        if (!c->getName().empty())
          return c->getName().str();
  for (auto *dvr : dbgRecords)
    if (dvr && dvr->isValueOfVariable())
      if (auto *var = dvr->getVariable())
        if (auto *c = diComposite(var->getType()))
          if (!c->getName().empty())
            return c->getName().str();
  return "";
}

// Flatten every member of composite `c` (recursing anonymous union/struct members only -- never through a
// pointer) into g_dwFieldDeep[top] at its byte offset.  Lets the GENLCMD filter name a field nested inside an
// anonymous do/dump union.  Depth-guarded against self-referential DWARF.
static void recordDeepMembers(const std::string &top, const DICompositeType *c, int64_t base, int depth) {
  if (!c || depth > 6)
    return;
  for (DINode *e : c->getElements()) {
    auto *m = dyn_cast_or_null<DIDerivedType>(e);
    if (!m || m->getTag() != dwarf::DW_TAG_member)
      continue;
    int64_t off = base + (int64_t)(m->getOffsetInBits() / 8);
    if (!m->getName().empty())
      g_dwFieldDeep[top].emplace(off, m->getName().str());
    else if (auto *bt = dyn_cast_or_null<DICompositeType>(m->getBaseType()))
      if (bt->getTag() == dwarf::DW_TAG_union_type || bt->getTag() == dwarf::DW_TAG_structure_type)
        recordDeepMembers(top, bt, off, depth + 1);   // anonymous union/struct member
  }
}

static std::string dwFieldNameAtDeep(const std::string &structName, int64_t off) {
  auto it = g_dwFieldDeep.find(bareStructName(structName));
  if (it != g_dwFieldDeep.end()) {
    auto r = it->second.equal_range(off);
    if (r.first != r.second)
      return r.first->second;   // any field at this offset (a union slot may name >1; caller only tests membership)
  }
  return "";
}

static void buildDwarfMembers(Module &M) {
  DebugInfoFinder finder;
  finder.processModule(M);
  std::vector<const DICompositeType *> comps;
  for (const DIType *t : finder.types())
    if (auto *c = dyn_cast<DICompositeType>(t))
      comps.push_back(c);
  // Also harvest struct layouts reachable ONLY through a global variable's DWARF type.  DebugInfoFinder
  // traverses CU retained types + subprogram signatures, but a struct used only as the type of a global
  // (e.g. usb_class_driver, referenced solely by @hiddev_class in the usbhid TU, with no function taking
  // it by value) is not in finder.types() -- so its member offsets would be missing and readConstField
  // (.fops/.name for usb_register_dev etc.) would fail.  Add each global's composite type as an entry.
  // (Verified: these global-only layouts are consumed by reg's readConstField; they do not change cmd or
  // fields output -- the structs they add are never GEP field-access targets there.)
  for (GlobalVariable &GV : M.globals()) {
    SmallVector<DIGlobalVariableExpression *, 2> gves;
    GV.getDebugInfo(gves);
    for (auto *gve : gves)
      if (auto *var = gve ? gve->getVariable() : nullptr)
        if (auto *c = diComposite(var->getType()))
          comps.push_back(c);
  }
  std::set<const DICompositeType *> seen;
  for (const DICompositeType *c : comps) {
    if (!c || c->getName().empty() || !seen.insert(c).second)
      continue;
    std::string sname = c->getName().str();
    for (DINode *e : c->getElements()) {
      auto *m = dyn_cast_or_null<DIDerivedType>(e);
      if (!m || m->getTag() != dwarf::DW_TAG_member)
        continue;
      if (!m->getName().empty())
        g_dwFieldOffset[sname].emplace(m->getName().str(), (int64_t)(m->getOffsetInBits() / 8));
      auto *mc = diComposite(m->getBaseType());
      if (mc && !mc->getName().empty()) {
        MemberInfo mi;
        mi.name = mc->getName().str();
        mi.size = mc->getSizeInBits() / 8;
        mi.pointer = diIsPointerToStruct(m->getBaseType());
        g_dwMember[sname].emplace((int64_t)(m->getOffsetInBits() / 8), mi);
      }
    }
    recordDeepMembers(sname, c, 0, 0);   // GENLCMD endpoint identity: flatten anon do/dump unions
  }
}

static std::string canonicalStructByteLoc(const std::string &structName, int64_t off) {
  std::string cur = bareStructName(structName);
  int64_t curOff = off;
  // For opaque i8 GEPs into embedded structs, recover the deepest named member.
  // Do not project through pointer members: `obj->ops` is the pointer field, while
  // a load from that field is what changes the base type to the pointee struct.
  for (int guard = 0; guard < 4; ++guard) {
    auto it = g_dwMember.find(cur);
    if (it == g_dwMember.end())
      break;
    const MemberInfo *best = nullptr;
    int64_t bestOff = 0;
    for (auto &kv : it->second) {
      int64_t mo = kv.first;
      const MemberInfo &mi = kv.second;
      if (mi.pointer || mi.size == 0 || mo > curOff)
        continue;
      if (curOff < mo + (int64_t)mi.size && (!best || mo >= bestOff)) {
        best = &mi;
        bestOff = mo;
      }
    }
    if (!best || bareStructName(best->name) == cur)
      break;
    cur = bareStructName(best->name);
    curOff -= bestOff;
  }
  return "struct." + cur + "+" + std::to_string(curOff);
}

static std::string dwarfBaseStruct(Value *base, const DataLayout &DL, int depth) {
  base = base->stripPointerCasts();
  std::string dbg = dbgValueStruct(base);
  if (!dbg.empty())
    return dbg;
  // ARG: the parameter's source struct type (handler entry objects).
  if (auto *a = dyn_cast<Argument>(base)) {
    auto arr = subroutineTypes(a->getParent());
    unsigned i = a->getArgNo() + 1;   // [0] = return type
    if (arr && i < arr.size())
      return diStructName(arr[i]);
    return "";
  }
  // CALL: the callee's DWARF RETURN struct type (typed getters like X_to_inode(...); kmalloc returns
  // void* -> "" honest). [classify: i8 base=call = 33% of unrecovered]
  if (auto *ci = dyn_cast<CallInst>(base)) {
    if (!ci->isInlineAsm())
      if (Function *f = ci->getCalledFunction()) {
        auto arr = subroutineTypes(f);
        if (arr && arr.size() > 0)
          return diStructName(arr[0]);
      }
    return "";
  }
  // LOAD: %obj = load (struct.P + M) -> %obj is the struct named by P's DWARF member at byte offset M.
  // [classify: i8 base=load = 31% of unrecovered]. Bounded recursion (absLoc on the source pointer).
  if (auto *L = dyn_cast<LoadInst>(base)) {
    if (depth >= 3)
      return "";
    std::string src = absLoc(L->getPointerOperand(), DL, depth + 1);  // "struct.P+M" / "struct.P+M?"
    if (src.rfind("struct.", 0) == 0) {
      size_t plus = src.rfind('+');
      if (plus != std::string::npos) {
        std::string P = src.substr(7, plus - 7);
        std::string moff = src.substr(plus + 1);
        if (!moff.empty() && moff.back() == '?')
          moff.pop_back();
        char *end = nullptr;
        long long Mv = std::strtoll(moff.c_str(), &end, 10);
        if (end && *end == '\0') {
          auto it = g_dwMember.find(P);
          if (it != g_dwMember.end()) {
            auto j = it->second.find((int64_t)Mv);
            if (j != it->second.end())
              return j->second.name;
          }
        }
      }
    }
    return "";
  }
  return "";
}

static std::string absLoc(Value *ptr, const DataLayout &DL, int depth) {
  // Canonical (root struct type, field byte-offset within it). gep_type_iterator walks indices with
  // their aggregate types so we get the FIELD offset even when an array index in the same GEP is
  // nonconst (accumulateConstantOffset returns nothing then — the old bug that left array-of-struct
  // accesses as "[N x %struct.X]+0?"). At an ARRAY index (instance selection) we RESET root to the
  // element struct + offset to 0 (the field is within the element; WHICH element is the S/instance,
  // marked by the "?"). A struct index accumulates its field offset. A subsequent GEP's zero
  // pointer-deref is a no-op (keeps outer.inner.field consistent whether split across GEPs or not).
  std::vector<GEPOperator *> chain;
  Value *cur = ptr;
  while (auto *g = dyn_cast<GEPOperator>(cur)) {
    chain.push_back(g);
    cur = g->getPointerOperand();
  }
  if (chain.empty())
    return "?+0";
  Type *rootTy = nullptr;
  int64_t off = 0;
  bool nonconst = false;
  for (auto it = chain.rbegin(); it != chain.rend(); ++it) {   // outermost (base) first
    bool firstIdx = true;
    for (auto GTI = gep_type_begin(*it), GTE = gep_type_end(*it); GTI != GTE; ++GTI) {
      ConstantInt *ci = dyn_cast<ConstantInt>(GTI.getOperand());
      bool zero = ci && ci->isZero();
      if (firstIdx) {                          // pointer-deref index of this GEP
        firstIdx = false;
        Type *elem = GTI.getIndexedType();
        if (!rootTy) {                         // chain start: base object pointee = root
          rootTy = elem;
          if (ci) off += ci->getSExtValue() * (int64_t)DL.getTypeAllocSize(elem);  // byte/elem offset
          else nonconst = true;                // nonconst base index
        } else if (ci) {                       // continuing same object: add const offset, keep root
          off += ci->getSExtValue() * (int64_t)DL.getTypeAllocSize(elem);
        } else {                               // nonconst ptr arith on a later GEP = instance
          nonconst = true; off = 0; rootTy = elem;
        }
        continue;
      }
      if (StructType *st = GTI.getStructTypeOrNull()) {        // struct field -> accumulate offset
        off += DL.getStructLayout(st)->getElementOffset(ci ? ci->getZExtValue() : 0);
      } else {                                                // array index = instance -> reset to element
        if (!zero) nonconst = true;
        off = 0;
        rootTy = GTI.getIndexedType();
      }
    }
  }
  if (!rootTy)
    return "?+0";
  while (auto *at = dyn_cast<ArrayType>(rootTy))   // trailing array root -> its (struct) element
    rootTy = at->getElementType();
  if (!isa<StructType>(rootTy)) {                  // byte-GEP erased the struct type -> recover via DWARF
    std::string t = dwarfBaseStruct(cur, DL, depth);
    if (!t.empty())
      return canonicalStructByteLoc(t, off) + (nonconst ? "?" : "");
  }
  std::string s = tyName(rootTy) + "+" + std::to_string(off);
  if (nonconst)
    s += "?";
  return s;
}

// global-identity location (E9): peel GEPs; if the base is a GlobalVariable, key by the global's NAME
// (a singleton/global's state is distinct from any heap struct.X instance). Returns "" if not a global.
// ADDITIVE — emitted alongside the struct.X loc, so existing (struct-keyed) facts are unchanged.
static std::string globalLoc(Value *ptr, const DataLayout &DL) {
  int64_t total = 0;
  Value *cur = ptr;
  while (auto *g = dyn_cast<GEPOperator>(cur)) {
    APInt off(DL.getIndexTypeSizeInBits(g->getType()), 0);
    if (g->accumulateConstantOffset(DL, off))
      total += off.getSExtValue();
    cur = g->getPointerOperand();
  }
  if (auto *gv = dyn_cast<GlobalVariable>(cur))
    return "@" + gv->getName().str() + "+" + std::to_string(total);
  return "";
}

// container-field identity: the (owning struct, byte offset) of an idr/xarray field, WITHOUT drilling into
// the collection's nested layout.  canonicalStructByteLoc (used by absLoc) would collapse &drm_file->object_idr
// all the way into the idr's inner xa_lock -> "struct.spinlock+0", merging every unrelated container into one
// anchor.  A container's identity IS its field slot on its owner (drm_file+136), computed locally at the call
// and caller-independent -- the terminal-anchor key that lets a producer's INS and a consumer's LKP match with
// zero cross-function arg threading.
static std::string containerLoc(Value *ptr, const DataLayout &DL) {
  int64_t total = 0;
  Value *cur = ptr;
  while (auto *g = dyn_cast<GEPOperator>(cur)) {
    APInt off(DL.getIndexTypeSizeInBits(g->getType()), 0);
    if (g->accumulateConstantOffset(DL, off))
      total += off.getSExtValue();
    cur = g->getPointerOperand();
  }
  cur = cur->stripPointerCasts();
  if (auto *gv = dyn_cast<GlobalVariable>(cur))
    return "@" + gv->getName().str() + "+" + std::to_string(total);
  std::string t = dwarfBaseStruct(cur, DL, 0);
  if (!t.empty())
    return "struct." + bareStructName(t) + "+" + std::to_string(total);
  return "";
}

// S (object identity): trace the field pointer's GEP base to its PROVENANCE — what identifies WHICH
// object the field belongs to, not just its struct type. A WRITE and a GATE form a real coupling only
// when they share (field, S) = the same field on the SAME object. Classes:
//   arg:<n>   handler parameter (resource-resolved offline: same resource type => same object)
//   @<global> singleton / module state
//   call:<f>  allocator or container lookup (idr_find / kmalloc / xa_load)
//   load:<F>  object reached via ANOTHER object's field (recursive identity)
//   ?         unrecoverable -> low S confidence, honest handoff (do NOT force the edge)
static std::string provenanceRoot(Value *ptr, const DataLayout &DL) {
  Value *cur = ptr;
  while (auto *g = dyn_cast<GEPOperator>(cur))
    cur = g->getPointerOperand();
  cur = cur->stripPointerCasts();
  if (auto *a = dyn_cast<Argument>(cur))
    return "arg:" + std::to_string(a->getArgNo());
  if (auto *gv = dyn_cast<GlobalVariable>(cur))
    return "@" + gv->getName().str();
  if (auto *ci = dyn_cast<CallInst>(cur)) {
    if (!ci->isInlineAsm())
      if (Function *c = ci->getCalledFunction())
        return "call:" + stripSuffix(c->getName().str());
    return "icall";
  }
  if (auto *L = dyn_cast<LoadInst>(cur))
    return "load:" + absLoc(L->getPointerOperand(), DL);  // reached via another object's field
  return "?";
}

// container-collection APIs: arg0 is the idr/xarray. Emitting its (struct,off) lets insert⋈lookup on
// the SAME collection field couple create->use across syscalls (the dominant kernel cross-syscall
// pattern: object inserted into a table, looked up by a later call). Only idr/xarray have real call
// pairs on BOTH sides — list/rbtree/hash LOOKUPS are inline macros (no call), so they can't pair here.
static const char *containerOp(const std::string &n) {
  static const std::set<std::string> INS = {
      "idr_alloc", "idr_alloc_cyclic", "idr_alloc_u32", "__xa_alloc", "__xa_alloc_cyclic",
      "xa_alloc", "xa_alloc_cyclic", "xa_store", "__xa_store", "xa_insert", "__xa_insert"};
  static const std::set<std::string> LKP = {
      "idr_find", "idr_get_next", "idr_get_next_ul", "xa_load", "xa_find", "xa_find_after"};
  if (INS.count(n)) return "INS";
  if (LKP.count(n)) return "LKP";
  return nullptr;
}

// Sub-classify a COMPUTED stored value (beyond const/flag/arg/load/call) by its data-flow ROOT + whether
// arithmetic transforms it = the sub-taxonomy of the value-precision wall (WHY a coupling is weak):
//   arg-expr / arg-cast = value traces to a syscall ARG -> a fuzzer CAN reach B's check on F (Redqueen/
//                         taint-recoverable: arg-cast is direct, arg-expr needs to invert the expression)
//   field-expr/field-cast = traces to another LOAD -> data-flow from another object's field
//   call-expr           = derived from a call return
//   addr                = an address/GEP computation (pointer value)
//   cond                = select/phi of internal values
//   internal            = pure kernel-internal arithmetic (a fuzzer can't set F directly; only the dynamics)
static std::string classifyComputed(Value *v) {
  bool expr = false, arg = false, fld = false, call = false, addr = false, cond = false;
  std::set<Value *> seen;
  std::vector<Value *> wl{v};
  int guard = 0;
  while (!wl.empty() && guard++ < 128) {
    Value *x = wl.back()->stripPointerCasts();
    wl.pop_back();
    if (!seen.insert(x).second)
      continue;
    if (isa<Argument>(x)) { arg = true; continue; }
    if (isa<LoadInst>(x)) { fld = true; continue; }          // value comes from memory -> stop here
    if (isa<CallInst>(x)) { call = true; continue; }
    if (isa<GetElementPtrInst>(x)) { addr = true; continue; }
    if (isa<ConstantInt>(x) || isa<ConstantPointerNull>(x) || isa<ConstantExpr>(x))
      continue;
    if (isa<BinaryOperator>(x))
      expr = true;
    else if (isa<SelectInst>(x) || isa<PHINode>(x))
      cond = true;
    if (auto *I = dyn_cast<Instruction>(x))            // recurse through casts/exprs/selects/phis
      for (auto &o : I->operands())
        wl.push_back(o.get());
  }
  if (arg)  return expr ? "arg-expr" : "arg-cast";    // arg wins (fuzzer-controllable) over a field/internal mix
  if (fld)  return expr ? "field-expr" : "field-cast";
  if (call) return "call-expr";
  if (addr) return "addr";
  if (cond) return "cond";
  return "internal";
}

// For a field-DERIVED store value (F = f(G), or a direct copy F = G), return the SOURCE field G — the field
// whose load feeds the stored value — so the transitive flow F<-G can be built (B's gate on F really depends
// on G, set by some producer A). "" if the value doesn't trace to a field load. First field source wins.
static std::string sourceField(Value *v, const DataLayout &DL) {
  std::set<Value *> seen;
  std::vector<Value *> wl{v};
  int guard = 0;
  while (!wl.empty() && guard++ < 128) {
    Value *s = wl.back()->stripPointerCasts();
    wl.pop_back();
    if (!seen.insert(s).second)
      continue;
    if (auto *L = dyn_cast<LoadInst>(s)) {
      std::string g = absLoc(L->getPointerOperand(), DL);
      if (g.rfind("struct.", 0) == 0 || (!g.empty() && g[0] == '@'))
        return g;                                    // F derives from this field
      continue;
    }
    if (isa<Argument>(s) || isa<CallInst>(s) || isa<Constant>(s))
      continue;                                      // not a field source
    if (auto *I = dyn_cast<Instruction>(s))
      for (auto &o : I->operands())
        wl.push_back(o.get());
  }
  return "";
}

// value written by a store: constant, bitfield mask (or/and), arg-derived, or a sub-classified computed value.
static std::string storeVal(Value *v) {
  if (auto *ci = dyn_cast<ConstantInt>(v))
    return apStr(ci->getValue(), true);
  if (auto *bo = dyn_cast<BinaryOperator>(v)) {
    auto op = bo->getOpcode();
    if (op == Instruction::Or || op == Instruction::And || op == Instruction::Xor)
      for (auto &o : bo->operands())
        if (auto *ci = dyn_cast<ConstantInt>(o))
          return std::string(op == Instruction::And ? "mask&0x" : "bit|0x") +
                 apStr(ci->getValue().zext(64), false);
  }
  if (isa<ConstantPointerNull>(v))
    return "0";                       // null store = clear (existence teardown), bucket with const 0
  if (isa<Argument>(v))
    return "arg";
  Value *sv = v->stripPointerCasts();
  if (auto *ci = dyn_cast<CallInst>(sv))     // noalias return = FRESH object (real existence) vs getter
    return ci->returnDoesNotAlias() ? "alloc" : "call";
  if (isa<LoadInst>(sv))
    return "load";                    // copied from another location (linkage)
  return classifyComputed(v);         // computed: sub-classify by data-flow root (arg/field/internal/...)
}

// backward SSA slice from a branch/switch condition: collect loaded locations + constant operands.
static void sliceCond(Value *c, const DataLayout &DL, std::set<std::string> &locs,
                      std::set<std::string> &vals) {
  std::set<Value *> seen;
  std::vector<Value *> wl{c};
  while (!wl.empty()) {
    Value *v = wl.back();
    wl.pop_back();
    if (!seen.insert(v).second)
      continue;
    if (auto *L = dyn_cast<LoadInst>(v)) {
      locs.insert(absLoc(L->getPointerOperand(), DL));
      std::string gl = globalLoc(L->getPointerOperand(), DL);   // E9: additive global-state branch
      if (!gl.empty())
        locs.insert(gl);
      continue;
    }
    if (auto *ci = dyn_cast<ConstantInt>(v)) {
      vals.insert(apStr(ci->getValue(), true));
      continue;
    }
    if (auto *I = dyn_cast<Instruction>(v))
      for (auto &o : I->operands())
        wl.push_back(o.get());
  }
}

static std::string join(const std::set<std::string> &s) {
  std::string r;
  for (auto &x : s) {
    if (!r.empty())
      r += ",";
    r += x;
  }
  return r.empty() ? "-" : r;
}

static bool skipRuntimeFunction(StringRef n) {
  return n.starts_with("llvm.") || n.starts_with("__asan") || n.starts_with("asan.") ||
         n.starts_with("kasan") || n.starts_with("__sanitizer") || n.starts_with("__kasan");
}

// scan a constant aggregate initializer: record function-pointer fields as (struct+offset)->func.
// Recovers the kernel's STATIC ops-tables (struct file_operations x = {.unlocked_ioctl=foo}, a
// global constant — not a runtime store). Opaque-pointer safe: uses struct layout, not pointee type.
static void scanConst(Constant *C, const DataLayout &DL,
                      std::map<std::string, std::set<std::string>> &m) {
  if (auto *cs = dyn_cast<ConstantStruct>(C)) {
    StructType *st = cs->getType();
    const StructLayout *sl = DL.getStructLayout(st);
    std::string tn = tyName(st);
    for (unsigned i = 0; i < cs->getNumOperands(); i++) {
      Constant *e = cs->getOperand(i);
      if (auto *F = dyn_cast<Function>(e->stripPointerCasts())) {
        if (!F->isDeclaration() && !skipRuntimeFunction(F->getName()))
          m[tn + "+" + std::to_string(sl->getElementOffset(i))].insert(F->getName().str());
      } else {
        scanConst(e, DL, m);
      }
    }
  } else if (auto *ca = dyn_cast<ConstantArray>(C)) {
    for (unsigned i = 0; i < ca->getNumOperands(); i++)
      scanConst(ca->getOperand(i), DL, m);
  }
}

// backward: does this value derive from a function Argument? (cmd-dispatch detection)
static void argsBehind(Value *v, std::set<Argument *> &out, std::set<Value *> &seen) {
  if (!seen.insert(v).second)
    return;
  if (auto *a = dyn_cast<Argument>(v)) {
    out.insert(a);
    return;
  }
  if (auto *I = dyn_cast<Instruction>(v))
    for (auto &o : I->operands())
      argsBehind(o.get(), out, seen);
}

// dominator subtree rooted at bb (the blocks "owned" by a cmd case) — SyzDescribe get_dom_bb.
static void domSubtree(DominatorTree &DT, BasicBlock *bb, std::set<BasicBlock *> &out) {
  auto *n = DT.getNode(bb);
  if (!n)
    return;
  for (auto *c : n->children()) {
    if (out.insert(c->getBlock()).second)
      domSubtree(DT, c->getBlock(), out);
  }
}

// functions called in the owned blocks (direct + field-devirt-resolved) = the cmd's region roots.
static std::set<std::string> calledFuncs(std::set<BasicBlock *> &owned, const DataLayout &DL,
                                         std::map<std::string, std::set<std::string>> &ft) {
  std::set<std::string> r;
  for (auto *bb : owned)
    for (Instruction &I : *bb)
      if (auto *CI = dyn_cast<CallInst>(&I)) {
        if (CI->isInlineAsm())
          continue;
        if (Function *c = CI->getCalledFunction()) {
          if (!c->isIntrinsic() && !c->getName().starts_with("llvm.") &&
              !c->getName().starts_with("__asan") && !c->getName().starts_with("kasan") &&
              !c->getName().starts_with("__sanitizer") && !c->getName().starts_with("__kasan"))
            r.insert(c->getName().str());
        } else if (auto *L = dyn_cast<LoadInst>(CI->getCalledOperand())) {
          auto it = ft.find(absLoc(L->getPointerOperand(), DL));
          if (it != ft.end())
            for (auto &t : it->second)
              r.insert(t);
        }
      }
  return r;
}

// caller-count per function name (module-wide): how many DISTINCT functions call it. Few callers =>
// VALUE-SPECIFIC (the function is (nearly) exclusively reached through this dispatch path, safe to pull
// its whole body into the region); many callers => shared helper (stop, expanding into it un-narrows
// the region to all-to-all). Populated once in main before --cmd.
static std::map<std::string, int> g_callerCount;
static const int REGION_EXPAND_MAX = 3;

// Broad fallback for the cmd's transitive function region. Direct callees of the owned BBs are always
// included; deeper functions are included only when caller-count <= REGION_EXPAND_MAX. regionFuncs below
// preserves that boundary but carries exact integer call arguments through callee CFGs before falling back
// here if its bounded context walk cannot complete.
static std::set<std::string> regionFuncsBroad(std::set<BasicBlock *> &owned, const DataLayout &DL,
                                              std::map<std::string, std::set<std::string>> &ft,
                                              Module &M) {
  auto skip = [](StringRef n) {
    return n.starts_with("llvm.") || n.starts_with("__asan") || n.starts_with("kasan") ||
           n.starts_with("__sanitizer") || n.starts_with("__kasan");
  };
  auto calleesOf = [&](BasicBlock *bb, std::vector<std::string> &out) {
    for (Instruction &I : *bb)
      if (auto *CI = dyn_cast<CallInst>(&I)) {
        if (CI->isInlineAsm())
          continue;
        if (Function *c = CI->getCalledFunction()) {
          if (!c->isIntrinsic() && !skip(c->getName()))
            out.push_back(c->getName().str());
        } else if (auto *L = dyn_cast<LoadInst>(CI->getCalledOperand())) {
          auto it = ft.find(absLoc(L->getPointerOperand(), DL));
          if (it != ft.end())
            for (auto &t : it->second)
              out.push_back(t);
        }
      }
  };
  std::set<std::string> result, expanded;
  std::vector<Function *> work;
  auto consider = [&](const std::string &nm, bool direct) {
    auto cc = g_callerCount.find(nm);
    bool vs = cc != g_callerCount.end() && cc->second <= REGION_EXPAND_MAX;
    if (!direct && !vs)
      return;  // deep shared helper: expanding here un-narrows the region — exclude it
    if (!result.insert(nm).second)
      return;
    if (vs)
      if (Function *f = M.getFunction(nm))
        if (!f->isDeclaration() && expanded.insert(nm).second)
          work.push_back(f);
  };
  std::vector<std::string> direct;
  for (auto *bb : owned)
    calleesOf(bb, direct);
  for (auto &nm : direct)
    consider(nm, true);
  while (!work.empty()) {
    Function *f = work.back();
    work.pop_back();
    std::vector<std::string> cs;
    for (BasicBlock &bb : *f)
      calleesOf(&bb, cs);
    for (auto &nm : cs)
      consider(nm, false);
  }
  return result;
}

// Context-sensitive variant of regionFuncsBroad.  The cmd case already narrows the caller's BBs; when a
// call in those BBs passes an integer constant, carry it into the callee and prune only CFG edges whose
// condition can be evaluated exactly.  Unknown conditions keep every successor.  This prevents a callee's
// impossible constant-controlled arm from becoming a handler candidate while preserving the old broad set
// whenever the bounded context walk cannot be completed.
static std::set<std::string> regionFuncs(std::set<BasicBlock *> &owned, const DataLayout &DL,
                                         std::map<std::string, std::set<std::string>> &ft, Module &M) {
  using ConstEnv = std::map<unsigned, APInt>;
  struct WorkItem {
    Function *fn;
    ConstEnv env;
    unsigned depth;
  };

  auto skip = [](StringRef n) {
    return n.starts_with("llvm.") || n.starts_with("__asan") || n.starts_with("kasan") ||
           n.starts_with("__sanitizer") || n.starts_with("__kasan");
  };

  std::function<bool(Value *, const ConstEnv &, APInt &, std::set<Value *> &)> evalInt;
  evalInt = [&](Value *v, const ConstEnv &env, APInt &out, std::set<Value *> &active) -> bool {
    if (!v || !v->getType()->isIntegerTy() || !active.insert(v).second)
      return false;
    bool known = false;
    if (auto *ci = dyn_cast<ConstantInt>(v)) {
      out = ci->getValue();
      known = true;
    } else if (auto *arg = dyn_cast<Argument>(v)) {
      auto it = env.find(arg->getArgNo());
      if (it != env.end()) {
        out = it->second;
        known = true;
      }
    } else if (auto *cast = dyn_cast<CastInst>(v)) {
      APInt src(1, 0);
      if (evalInt(cast->getOperand(0), env, src, active)) {
        unsigned width = cast->getType()->getIntegerBitWidth();
        switch (cast->getOpcode()) {
        case Instruction::Trunc:
          if (width <= src.getBitWidth()) {
            out = src.trunc(width);
            known = true;
          }
          break;
        case Instruction::ZExt:
          if (width >= src.getBitWidth()) {
            out = src.zext(width);
            known = true;
          }
          break;
        case Instruction::SExt:
          if (width >= src.getBitWidth()) {
            out = src.sext(width);
            known = true;
          }
          break;
        case Instruction::BitCast:
          if (width == src.getBitWidth()) {
            out = src;
            known = true;
          }
          break;
        default:
          break;
        }
      }
    } else if (auto *bo = dyn_cast<BinaryOperator>(v)) {
      APInt lhs(1, 0), rhs(1, 0);
      if (evalInt(bo->getOperand(0), env, lhs, active) &&
          evalInt(bo->getOperand(1), env, rhs, active) && lhs.getBitWidth() == rhs.getBitWidth()) {
        switch (bo->getOpcode()) {
        case Instruction::Add:  out = lhs + rhs; known = true; break;
        case Instruction::Sub:  out = lhs - rhs; known = true; break;
        case Instruction::Mul:  out = lhs * rhs; known = true; break;
        case Instruction::And:  out = lhs & rhs; known = true; break;
        case Instruction::Or:   out = lhs | rhs; known = true; break;
        case Instruction::Xor:  out = lhs ^ rhs; known = true; break;
        case Instruction::UDiv:
          if (!rhs.isZero()) { out = lhs.udiv(rhs); known = true; }
          break;
        case Instruction::SDiv:
          if (!rhs.isZero()) { out = lhs.sdiv(rhs); known = true; }
          break;
        case Instruction::URem:
          if (!rhs.isZero()) { out = lhs.urem(rhs); known = true; }
          break;
        case Instruction::SRem:
          if (!rhs.isZero()) { out = lhs.srem(rhs); known = true; }
          break;
        case Instruction::Shl:
        case Instruction::LShr:
        case Instruction::AShr: {
          uint64_t amount = rhs.getLimitedValue();
          if (amount < lhs.getBitWidth()) {
            out = bo->getOpcode() == Instruction::Shl ? lhs.shl(amount) :
                  bo->getOpcode() == Instruction::LShr ? lhs.lshr(amount) : lhs.ashr(amount);
            known = true;
          }
          break;
        }
        default:
          break;
        }
      }
    } else if (auto *icmp = dyn_cast<ICmpInst>(v)) {
      APInt lhs(1, 0), rhs(1, 0);
      if (evalInt(icmp->getOperand(0), env, lhs, active) &&
          evalInt(icmp->getOperand(1), env, rhs, active) && lhs.getBitWidth() == rhs.getBitWidth()) {
        bool result = false;
        switch (icmp->getPredicate()) {
        case ICmpInst::ICMP_EQ:  result = lhs == rhs; break;
        case ICmpInst::ICMP_NE:  result = lhs != rhs; break;
        case ICmpInst::ICMP_UGT: result = lhs.ugt(rhs); break;
        case ICmpInst::ICMP_UGE: result = lhs.uge(rhs); break;
        case ICmpInst::ICMP_ULT: result = lhs.ult(rhs); break;
        case ICmpInst::ICMP_ULE: result = lhs.ule(rhs); break;
        case ICmpInst::ICMP_SGT: result = lhs.sgt(rhs); break;
        case ICmpInst::ICMP_SGE: result = lhs.sge(rhs); break;
        case ICmpInst::ICMP_SLT: result = lhs.slt(rhs); break;
        case ICmpInst::ICMP_SLE: result = lhs.sle(rhs); break;
        default: break;
        }
        out = APInt(1, result);
        known = true;
      }
    } else if (auto *sel = dyn_cast<SelectInst>(v)) {
      APInt cond(1, 0);
      if (evalInt(sel->getCondition(), env, cond, active))
        known = evalInt(sel->getOperand(cond.isZero() ? 2 : 1), env, out, active);
    } else if (auto *freeze = dyn_cast<FreezeInst>(v)) {
      known = evalInt(freeze->getOperand(0), env, out, active);
    }
    active.erase(v);
    return known;
  };

  auto knownInt = [&](Value *v, const ConstEnv &env, APInt &out) {
    std::set<Value *> active;
    return evalInt(v, env, out, active);
  };

  auto reachableBlocks = [&](Function *fn, const ConstEnv &env) {
    std::set<BasicBlock *> reachable;
    std::vector<BasicBlock *> work{&fn->getEntryBlock()};
    while (!work.empty()) {
      BasicBlock *bb = work.back();
      work.pop_back();
      if (!reachable.insert(bb).second)
        continue;
      Instruction *term = bb->getTerminator();
      if (auto *br = dyn_cast<BranchInst>(term)) {
        APInt cond(1, 0);
        if (br->isConditional() && knownInt(br->getCondition(), env, cond)) {
          work.push_back(br->getSuccessor(cond.isZero() ? 1 : 0));
          continue;
        }
      } else if (auto *sw = dyn_cast<SwitchInst>(term)) {
        APInt cond(1, 0);
        if (knownInt(sw->getCondition(), env, cond)) {
          BasicBlock *dest = sw->getDefaultDest();
          for (auto c : sw->cases())
            if (c.getCaseValue()->getValue() == cond) {
              dest = c.getCaseSuccessor();
              break;
            }
          work.push_back(dest);
          continue;
        }
      }
      for (BasicBlock *succ : successors(bb))
        work.push_back(succ);
    }
    return reachable;
  };

  auto contextKey = [](Function *fn, const ConstEnv &env) {
    std::string key = fn->getName().str();
    for (const auto &kv : env)
      key += "|" + std::to_string(kv.first) + ":" + std::to_string(kv.second.getBitWidth()) + ":" +
             apStr(kv.second, false);
    return key;
  };

  std::set<std::string> result, expandedContexts;
  std::vector<WorkItem> work;
  bool aborted = false;
  static const unsigned REGION_CONTEXT_MAX = 4096;
  static const unsigned REGION_CONTEXT_DEPTH = 12;

  std::function<void(const std::string &, Function *, bool, const ConstEnv &, unsigned)> consider;
  consider = [&](const std::string &name, Function *target, bool direct, const ConstEnv &env,
                 unsigned depth) {
    auto cc = g_callerCount.find(name);
    bool valueSpecific = cc != g_callerCount.end() && cc->second <= REGION_EXPAND_MAX;
    if (!direct && !valueSpecific)
      return;
    result.insert(name);
    if (!valueSpecific || !target || target->isDeclaration())
      return;
    if (depth > REGION_CONTEXT_DEPTH || expandedContexts.size() >= REGION_CONTEXT_MAX) {
      aborted = true;
      return;
    }
    std::string key = contextKey(target, env);
    if (expandedContexts.insert(key).second)
      work.push_back({target, env, depth});
  };

  auto visitCall = [&](CallInst *call, const ConstEnv &env, bool direct, unsigned depth) {
    std::vector<Function *> targets;
    if (Function *callee = call->getCalledFunction()) {
      if (!callee->isIntrinsic() && !skip(callee->getName()))
        targets.push_back(callee);
    } else if (auto *load = dyn_cast<LoadInst>(call->getCalledOperand()->stripPointerCasts())) {
      auto it = ft.find(absLoc(load->getPointerOperand(), DL));
      if (it != ft.end())
        for (const std::string &name : it->second)
          if (Function *callee = M.getFunction(name))
            targets.push_back(callee);
    }
    for (Function *callee : targets) {
      ConstEnv calleeEnv;
      unsigned n = std::min<unsigned>(call->arg_size(), callee->arg_size());
      for (unsigned i = 0; i < n; ++i) {
        APInt value(1, 0);
        if (call->getArgOperand(i)->getType()->isIntegerTy() && knownInt(call->getArgOperand(i), env, value))
          calleeEnv.emplace(i, value);
      }
      consider(callee->getName().str(), callee, direct, calleeEnv, depth);
    }
  };

  ConstEnv emptyEnv;
  for (BasicBlock *bb : owned)
    for (Instruction &inst : *bb)
      if (auto *call = dyn_cast<CallInst>(&inst))
        if (!call->isInlineAsm())
          visitCall(call, emptyEnv, true, 1);

  while (!work.empty() && !aborted) {
    WorkItem item = std::move(work.back());
    work.pop_back();
    for (BasicBlock *bb : reachableBlocks(item.fn, item.env))
      for (Instruction &inst : *bb)
        if (auto *call = dyn_cast<CallInst>(&inst))
          if (!call->isInlineAsm())
            visitCall(call, item.env, false, item.depth + 1);
  }
  return aborted ? regionFuncsBroad(owned, DL, ft, M) : result;
}

// ITEM 4 (+4f interproc): per-cmd reachability. Seed cmd taint from given param indices; find cmd
// constants (switch + if(cmd==X)) on cmd-tainted values; each case's dominator subtree = its owned
// region. 4f: when a cmd-tainted value is passed to a callee, recurse with that callee's param index
// seeded — so nested dispatch (kvm_vcpu_ioctl default -> kvm_arch_vcpu_ioctl's own switch) is narrowed.
static const int CMD_MAX_DEPTH = 8;

static void enumCmdTablesUsedBy(Function &F, const std::string &origin, const DataLayout &DL,
                                std::map<std::string, std::set<std::string>> &ft, Module &M,
                                std::set<std::string> &emitted);

// Emit a cmd's region: the CMD row (handler + value-narrowed region funcs) + CMD-SCOPED def-use
// (CMDWRITE/CMDUSE over the owned BBs). Shared by switch-dispatch (owned = DominatorTree subtree of a
// case) and table-dispatch (owned = the handler function's whole body).
static void emitCmdRegion(const std::string &fn, uint64_t val, const std::string &regionId,
                          std::set<BasicBlock *> &owned, bool excl, int depth, const DataLayout &DL,
                          std::map<std::string, std::set<std::string>> &ft, Module &M,
                          const std::string &origin = "", const std::string &keyKind = "") {
  if (owned.empty())
    return;
  std::set<std::string> roots = regionFuncs(owned, DL, ft, M);
  outs() << "CMD\t" << fn << "\t" << val << "\t" << regionId << "\t" << owned.size() << "\t"
         << (excl ? "excl" : "shared") << "\td" << depth << "\t" << join(roots);
  if (!origin.empty())
    outs() << "\torigin=" << origin;
  if (!keyKind.empty())                 // per-ROW key semantics (iocnr): only THIS row gets a masked key,
    outs() << "\tkey_kind=" << keyKind;  // not the whole origin (which also holds full-value switch rows)
  outs() << "\n";
  for (auto *bb : owned)
    for (Instruction &I : *bb) {
      if (auto *SI = dyn_cast<StoreInst>(&I))
        outs() << "CMDWRITE\t" << fn << "\t" << val << "\t" << absLoc(SI->getPointerOperand(), DL)
               << "\t" << storeVal(SI->getValueOperand()) << "\n";
      else if (auto *AI = dyn_cast<AtomicRMWInst>(&I))
        outs() << "CMDWRITE\t" << fn << "\t" << val << "\t" << absLoc(AI->getPointerOperand(), DL)
               << "\t" << storeVal(AI->getValOperand()) << "\n";
      else if (auto *BI = dyn_cast<BranchInst>(&I)) {
        if (BI->isConditional()) {
          std::set<std::string> locs, bvals;
          sliceCond(BI->getCondition(), DL, locs, bvals);
          for (auto &l : locs)
            outs() << "CMDUSE\t" << fn << "\t" << val << "\t" << l << "\t" << join(bvals) << "\n";
        }
      }
    }
}

static void analyzeCmdRec(Function &F, const std::set<unsigned> &seedIdx,
                          const std::set<unsigned> &identitySeedIdx, const DataLayout &DL,
                          std::map<std::string, std::set<std::string>> &ft,
                          std::set<Function *> &analyzed, int depth,
                          std::set<std::pair<uint64_t, BasicBlock *>> &done,
                          std::set<std::string> &bridges, std::set<std::string> &tableBridges,
                          const std::string &origin, int maxDepth = CMD_MAX_DEPTH) {
  if (depth > maxDepth || F.isDeclaration())
    return;
  if (!analyzed.insert(&F).second)
    return;  // analyze each function once (cycle + re-work guard)
  std::set<Value *> cmd;
  for (Argument &A : F.args())
    if (seedIdx.count(A.getArgNo()))
      cmd.insert(&A);
  if (cmd.empty())
    return;
  // forward taint (fixpoint; a store taints its slot so reloads stay tainted)
  for (bool changed = true; changed;) {
    changed = false;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        if (cmd.count(&I))
          continue;
        bool aff = false;
        for (auto &op : I.operands()) {
          Value *v = op.get();
          if (cmd.count(v) || cmd.count(v->stripPointerCasts())) {
            aff = true;
            break;
          }
        }
        if (aff) {
          cmd.insert(&I);
          changed = true;
          if (auto *SI = dyn_cast<StoreInst>(&I))
            cmd.insert(SI->getPointerOperand()->stripPointerCasts());
        }
      }
  }
  auto isCmd = [&](Value *v) { return cmd.count(v) || cmd.count(v->stripPointerCasts()); };
  auto seedArgument = [&](Value *v) -> Argument * {
    for (int guard = 0; v && guard < 6; ++guard) {
      v = v->stripPointerCasts();
      if (auto *a = dyn_cast<Argument>(v))
        return identitySeedIdx.count(a->getArgNo()) ? a : nullptr;
      auto *cast = dyn_cast<CastInst>(v);
      if (!cast)
        return nullptr;
      v = cast->getOperand(0);
    }
    return nullptr;
  };
  auto keyKind = [&](Value *v) -> std::string {
    auto *bo = dyn_cast<BinaryOperator>(v->stripPointerCasts());
    if (!bo || bo->getOpcode() != Instruction::And || !bo->getType()->isIntegerTy(32))
      return "";
    ConstantInt *mask = dyn_cast<ConstantInt>(bo->getOperand(1));
    Value *source = bo->getOperand(0);
    if (!mask) {
      mask = dyn_cast<ConstantInt>(bo->getOperand(0));
      source = bo->getOperand(1);
    }
    if (!mask || !seedArgument(source))
      return "";  // only a direct cmd-argument mask; shifted/composed transforms need their own semantics
    return "mask:" + std::to_string(mask->getZExtValue() & 0xFFFFFFFFULL);
  };

  DominatorTree DT(F);
  std::string fn = F.getName().str();
  auto emit = [&](uint64_t val, BasicBlock *sb, const std::string &kind = "") {
    if (!done.insert({val, sb}).second)
      return;
    std::set<BasicBlock *> owned{sb};
    domSubtree(DT, sb, owned);
    emitCmdRegion(fn, val, sb->getName().str(), owned, sb->hasNPredecessors(1), depth, DL, ft,
                  *F.getParent(), origin, kind);
  };
  for (BasicBlock &BB : F) {
    Instruction *term = BB.getTerminator();
    if (auto *SW = dyn_cast<SwitchInst>(term)) {
      if (isCmd(SW->getCondition())) {
        std::string kind = keyKind(SW->getCondition());
        for (auto C : SW->cases())
          emit(C.getCaseValue()->getZExtValue(), C.getCaseSuccessor(), kind);
      }
    } else if (auto *BI = dyn_cast<BranchInst>(term)) {
      if (!BI->isConditional())
        continue;
      auto *IC = dyn_cast<ICmpInst>(BI->getCondition());
      if (!IC || !IC->isEquality())
        continue;
      ConstantInt *ci = dyn_cast<ConstantInt>(IC->getOperand(1));
      Value *other = IC->getOperand(0);
      if (!ci) {
        ci = dyn_cast<ConstantInt>(IC->getOperand(0));
        other = IC->getOperand(1);
      }
      if (ci && isCmd(other))
        emit(ci->getZExtValue(), BI->getSuccessor(0));
    }
  }
  enumCmdTablesUsedBy(F, origin, DL, ft, *F.getParent(), tableBridges);
  // 4f: propagate cmd taint into callees that receive a cmd-tainted argument
  for (BasicBlock &BB : F)
    for (Instruction &I : BB)
      if (auto *CI = dyn_cast<CallInst>(&I)) {
        if (CI->isInlineAsm())
          continue;
        std::set<unsigned> calleeIdx;
        std::set<unsigned> identityCalleeIdx;
        for (unsigned i = 0; i < CI->arg_size(); i++)
          if (isCmd(CI->getArgOperand(i))) {
            calleeIdx.insert(i);
            if (seedArgument(CI->getArgOperand(i)))
              identityCalleeIdx.insert(i);
          }
        if (calleeIdx.empty())
          continue;
        std::set<Function *> callees;
        if (Function *c = CI->getCalledFunction()) {
          if (!c->isIntrinsic() && !skipRuntimeFunction(c->getName()))
            for (unsigned idx : calleeIdx) {
              std::string key = origin + "\t" + fn + "\t" + c->getName().str() + "\t" +
                                std::to_string(idx) + "\t" + std::to_string(depth + 1);
              if (bridges.insert(key).second)
                outs() << "CMDBRIDGE\t" << origin << "\t" << fn << "\t" << c->getName().str()
                       << "\t" << idx << "\td" << (depth + 1) << "\n";
            }
          callees.insert(c);
        } else if (auto *L = dyn_cast<LoadInst>(CI->getCalledOperand())) {
          std::string loc = absLoc(L->getPointerOperand(), DL);
          if (loc.rfind("struct.", 0) == 0 || (!loc.empty() && loc[0] == '@'))
            for (unsigned idx : calleeIdx) {
              std::string key = "I\t" + origin + "\t" + fn + "\t" + loc + "\t" +
                                std::to_string(idx) + "\t" + std::to_string(depth + 1);
              if (bridges.insert(key).second)
                outs() << "CMDICALL\t" << origin << "\t" << fn << "\t" << loc << "\t"
                       << idx << "\td" << (depth + 1) << "\n";
            }
          auto it = ft.find(loc);
          if (it != ft.end())
            for (auto &nm : it->second)
              if (Function *cf = F.getParent()->getFunction(nm))
                callees.insert(cf);
        }
        for (Function *cf : callees) {
          if (cf->isDeclaration())
            continue;
          for (unsigned idx : calleeIdx) {
            std::string key = origin + "\t" + fn + "\t" + cf->getName().str() + "\t" +
                              std::to_string(idx) + "\t" + std::to_string(depth + 1);
            if (bridges.insert(key).second)
              outs() << "CMDBRIDGE\t" << origin << "\t" << fn << "\t" << cf->getName().str()
                     << "\t" << idx << "\td" << (depth + 1) << "\n";
          }
          analyzeCmdRec(*cf, calleeIdx, identityCalleeIdx, DL, ft, analyzed, depth + 1, done, bridges,
                        tableBridges, origin, maxDepth);
        }
      }
}

// The DWARF field NAME at byte offset `off` in struct `structName` (reverse of g_dwFieldOffset).  Empty if
// unknown.  Consumed by the op-offset ALIGNMENT gate: a FIELD_ICALL through struct.X+off is a sound edge for
// operation `op` only when the field there IS `op` (proto+40 == "ioctl"), never when it is a same-struct but
// different-op pointer (hid_ll_driver+56 == "wait_for_response", +64 == "raw_request" -- not "ioctl").
static std::string dwFieldNameAt(const std::string &structName, int64_t off) {
  auto it = g_dwFieldOffset.find(bareStructName(structName));
  if (it != g_dwFieldOffset.end())
    for (const auto &kv : it->second)
      if (kv.second == off)
        return kv.first;
  return "";
}

// In helper H, the callback param (H->arg(cbIdx)) is invoked somewhere; which arg of THAT indirect call is
// H's cmd param (H->arg(cmdIdx))?  -1 if the callback is never called with the cmd (so it is not a genuine
// cmd-callback bridge).  (Direct match only -- a helper that transforms the cmd before the call is missed.)
static int callbackCmdArg(Function *H, unsigned cbIdx, unsigned cmdIdx) {
  if (!H || H->isDeclaration() || cbIdx >= H->arg_size() || cmdIdx >= H->arg_size())
    return -1;
  Value *cbParam = H->getArg(cbIdx), *cmdParam = H->getArg(cmdIdx);
  for (BasicBlock &BB : *H)
    for (Instruction &I : BB)
      if (auto *CI = dyn_cast<CallInst>(&I))
        if (!CI->getCalledFunction() && !CI->isInlineAsm() &&
            CI->getCalledOperand()->stripPointerCasts() == cbParam)
          for (unsigned i = 0; i < CI->arg_size(); i++)
            if (CI->getArgOperand(i)->stripPointerCasts() == cmdParam)
              return (int)i;
  return -1;
}

// How does the callback dispatch on its cmd arg?  Collect the SwitchInst-case / equality-branch constants it
// routes on, then classify by whether they are _IOC-encoded (a magic TYPE byte in bits 8-15: dvb 0x6F2D).
//   "cmd"   -- routes on ioctl-encoded values -> a genuine SYSCALL cmd dispatch callback (dvb_*_do_ioctl).
//   "event" -- routes only on small enum/flag values (netdev NETDEV_UP=1, route RT6_LOOKUP_F_*, fs freeze):
//              a real dispatcher but NOT on a syscall cmd -- the resolver must not treat it as an ioctl bridge.
//   ""      -- does not route on the arg (uses it as a value: atkbd_set_* / text_poke / migrate_pages).
static std::string dispatchKind(Function *cb, unsigned argIdx) {
  if (!cb || cb->isDeclaration() || argIdx >= cb->arg_size())
    return "";
  std::set<Value *> t{cb->getArg(argIdx)};
  for (bool ch = true; ch;) {
    ch = false;
    for (BasicBlock &BB : *cb)
      for (Instruction &I : BB) {
        if (t.count(&I))
          continue;
        for (auto &op : I.operands())
          if (t.count(op.get()) || t.count(op.get()->stripPointerCasts())) {
            t.insert(&I);
            ch = true;
            break;
          }
      }
  }
  auto isT = [&](Value *v) { return t.count(v) || t.count(v->stripPointerCasts()); };
  auto iocEncoded = [](uint64_t v) { return ((v >> 8) & 0xFF) != 0; };   // has an _IOC TYPE (magic) byte
  int ioctlish = 0, total = 0;
  for (BasicBlock &BB : *cb) {
    Instruction *term = BB.getTerminator();
    if (auto *SW = dyn_cast<SwitchInst>(term)) {
      if (isT(SW->getCondition()))
        for (auto C : SW->cases()) {
          total++;
          if (iocEncoded(C.getCaseValue()->getZExtValue()))
            ioctlish++;
        }
    } else if (auto *BI = dyn_cast<BranchInst>(term)) {
      if (BI->isConditional())
        if (auto *IC = dyn_cast<ICmpInst>(BI->getCondition()))
          if (IC->isEquality()) {
            ConstantInt *k = dyn_cast<ConstantInt>(IC->getOperand(1));
            Value *o = IC->getOperand(0);
            if (!k) {
              k = dyn_cast<ConstantInt>(IC->getOperand(0));
              o = IC->getOperand(1);
            }
            if (k && isT(o)) {
              total++;
              if (iocEncoded(k->getZExtValue()))
                ioctlish++;
            }
          }
    }
  }
  if (total == 0)
    return "";
  return (ioctlish * 2 >= total) ? "cmd" : "event";   // majority _IOC-encoded -> syscall cmd dispatch
}

// CALLBACK_BRIDGE: a caller passes a HANDLER function as an argument to a helper, which then invokes it with
// the cmd -- the real switch lives in the callback (dvb_frontend_ioctl -> dvb_usercopy(.., cmd, .., FUNC) ->
// FUNC(.., cmd, ..)).  Emitted only when (a) the helper calls the callback WITH the cmd (callback_cmd_arg >=
// 0) AND (b) the callback DISPATCHES on that cmd arg -- so it is a proven cmd-dispatch callback, not just a
// function-pointer arg.  Resolver may then follow it directly.
//   CALLBACK_BRIDGE  caller  helper  callback_func  cmd_arg_from  callback_cmd_arg_to
static void enumCallbackBridges(Module &M) {
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::set<Value *> cmd;
    for (Argument &A : F.args())
      if (A.getType()->isIntegerTy())
        cmd.insert(&A);
    if (cmd.empty())
      continue;
    for (bool ch = true; ch;) {
      ch = false;
      for (BasicBlock &BB : F)
        for (Instruction &I : BB) {
          if (cmd.count(&I))
            continue;
          for (auto &op : I.operands())
            if (cmd.count(op.get()) || cmd.count(op.get()->stripPointerCasts())) {
              cmd.insert(&I);
              ch = true;
              break;
            }
        }
    }
    auto isCmd = [&](Value *v) { return cmd.count(v) || cmd.count(v->stripPointerCasts()); };
    std::string fn = F.getName().str();
    std::set<std::string> emitted;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || CI->isInlineAsm())
          continue;
        Function *H = CI->getCalledFunction();
        if (!H || H->isDeclaration())
          continue;
        Function *cb = nullptr;
        int cbIdx = -1, cmdIdx = -1;
        for (unsigned i = 0; i < CI->arg_size(); i++) {
          Value *a = CI->getArgOperand(i)->stripPointerCasts();
          if (auto *cf = dyn_cast<Function>(a))
            if (!cf->isDeclaration() && !cf->isIntrinsic()) {
              cb = cf;
              cbIdx = (int)i;
            }
          if (cmdIdx < 0 && isCmd(CI->getArgOperand(i)))
            cmdIdx = (int)i;
        }
        if (!cb || cmdIdx < 0 || cb == H || cb == &F)
          continue;
        int cbCmdArg = callbackCmdArg(H, (unsigned)cbIdx, (unsigned)cmdIdx);
        if (cbCmdArg < 0)                       // helper never calls the callback with the cmd -> not a bridge
          continue;
        std::string kind = dispatchKind(cb, (unsigned)cbCmdArg);
        if (kind.empty())                       // callback does not route on the arg -> not a dispatch callback
          continue;
        std::string key = H->getName().str() + "|" + cb->getName().str();
        if (emitted.insert(key).second)
          outs() << "CALLBACK_BRIDGE\t" << fn << "\t" << H->getName().str() << "\t" << cb->getName().str()
                 << "\t" << cmdIdx << "\t" << cbCmdArg << "\t" << kind << "\n";
      }
  }
}

// FIELD_ICALL: every indirect call through a struct field -- `call (obj->X.field)(...)` -> the field
// struct.X+off whose runtime value is the callee, PLUS the DWARF field name so the resolver can align it to
// the operation.  UNGATED by cmd-taint (unlike analyzeCmd's CMDICALL, which fires only with a cmd-tainted
// arg -- so it misses field-forwards in delegation helpers, e.g. sk_ioctl's sk->sk_prot->ioctl called with a
// constant cmd in one inlined path).  Format: FIELD_ICALL <fn> struct.X+off <field_name>.
static void enumFieldIcalls(Module &M, const DataLayout &DL) {
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::set<std::string> emitted;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || CI->isInlineAsm() || CI->getCalledFunction())
          continue;                                            // indirect calls only
        auto *L = dyn_cast<LoadInst>(CI->getCalledOperand()->stripPointerCasts());
        if (!L)
          continue;
        std::string loc = absLoc(L->getPointerOperand(), DL);  // resolve the load chain to struct.X+off
        if (loc.rfind("struct.", 0) != 0 || !emitted.insert(loc).second)
          continue;
        std::string fname;                                     // DWARF field name at this offset
        auto plus = loc.rfind('+');
        if (plus != std::string::npos)
          fname = dwFieldNameAt(loc.substr(7, plus - 7),
                                strtoll(loc.c_str() + plus + 1, nullptr, 10));
        outs() << "FIELD_ICALL\t" << F.getName().str() << "\t" << loc << "\t" << fname << "\n";
      }
  }
}

// FIELD_ICALL_SITE + CMD_REACH: SITE-LEVEL cmd reachability (P0 -- audit facts, resolver unchanged).  For a
// dispatcher D, which cmd VALUES reach each indirect-call site?  A site DOMINATED by cmd value C's case-block
// is C-specific (hiddev's raw_request under the HIDIOCGFEATURE case, NOT under HIDIOCGNAME); a site in the
// switch DEFAULT subtree is reached by cmds NOT in the case set (sk_ioctl's sk_prot->ioctl). An uncovered
// site is `*` only when no cmd-tainted terminator controls whether it is reached. This keeps callbacks behind
// object/null guards (v4l2) but rejects fallback sites reached by only part of a cmd switch (tty_ioctl).
// Join key: (fn, bb_idx).
//   FIELD_ICALL_SITE  fn  bb_idx  struct.X+off  field_name
//   CMD_REACH         fn  <cmd|*> bb_idx                 -- cmd (case-dominated) or * (unconditional)
//   CMD_REACH_NOT     fn  bb_idx  C1,C2,...              -- default subtree: reached by cmd NOT in {Ci}
static void enumFieldIcallSites(Module &M, const DataLayout &DL) {
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::map<BasicBlock *, int> bbIdx;
    int bi = 0;
    for (BasicBlock &BB : F)
      bbIdx[&BB] = bi++;
    std::vector<std::pair<BasicBlock *, std::string>> sites;   // (bb, "struct.X+off\tfield_name")
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || CI->isInlineAsm() || CI->getCalledFunction())
          continue;
        auto *L = dyn_cast<LoadInst>(CI->getCalledOperand()->stripPointerCasts());
        if (!L)
          continue;
        std::string loc = absLoc(L->getPointerOperand(), DL);
        if (loc.rfind("struct.", 0) != 0)
          continue;
        std::string fname;
        auto plus = loc.rfind('+');
        if (plus != std::string::npos)
          fname = dwFieldNameAt(loc.substr(7, plus - 7), strtoll(loc.c_str() + plus + 1, nullptr, 10));
        sites.push_back({&BB, loc + "\t" + fname});
      }
    if (sites.empty())
      continue;
    std::string fn = F.getName().str();
    for (auto &s : sites)
      outs() << "FIELD_ICALL_SITE\t" << fn << "\t" << bbIdx[s.first] << "\t" << s.second << "\n";
    DominatorTree DT(F);
    std::set<BasicBlock *> covered;
    std::vector<Instruction *> cmdTerminators;
    // cmd taint (forward fixpoint from integer args -- the cmd arg position is unknown here, so seed all).
    // No integer arg -> not a cmd dispatcher; its sites fall through to the unconditional `*` emission below.
    std::set<Value *> cmd;
    for (Argument &A : F.args())
      if (A.getType()->isIntegerTy())
        cmd.insert(&A);
    if (!cmd.empty()) {
      for (bool ch = true; ch;) {
        ch = false;
        for (BasicBlock &BB : F)
          for (Instruction &I : BB) {
            if (cmd.count(&I))
              continue;
            for (auto &op : I.operands())
              if (cmd.count(op.get()) || cmd.count(op.get()->stripPointerCasts())) {
                cmd.insert(&I);
                ch = true;
                if (auto *SI = dyn_cast<StoreInst>(&I))
                  cmd.insert(SI->getPointerOperand()->stripPointerCasts());
                break;
              }
          }
      }
      auto isCmd = [&](Value *v) { return cmd.count(v) || cmd.count(v->stripPointerCasts()); };
      auto dom = [&](uint64_t val, BasicBlock *sb) {
        std::set<BasicBlock *> owned{sb};
        domSubtree(DT, sb, owned);
        for (auto &s : sites)
          if (owned.count(s.first)) {
            outs() << "CMD_REACH\t" << fn << "\t" << val << "\t" << bbIdx[s.first] << "\n";
            covered.insert(s.first);
          }
      };
      for (BasicBlock &BB : F) {
        Instruction *t = BB.getTerminator();
        if (auto *SW = dyn_cast<SwitchInst>(t)) {
          if (!isCmd(SW->getCondition()))
            continue;
          cmdTerminators.push_back(SW);
          std::string cases;
          for (auto C : SW->cases()) {
            uint64_t v = C.getCaseValue()->getZExtValue();
            dom(v, C.getCaseSuccessor());
            cases += (cases.empty() ? "" : ",") + std::to_string(v);
          }
          std::set<BasicBlock *> dflt{SW->getDefaultDest()};
          domSubtree(DT, SW->getDefaultDest(), dflt);
          for (auto &s : sites)
            if (dflt.count(s.first) && !covered.count(s.first)) {
              outs() << "CMD_REACH_NOT\t" << fn << "\t" << bbIdx[s.first] << "\t" << cases << "\n";
              covered.insert(s.first);
            }
        } else if (auto *BI = dyn_cast<BranchInst>(t)) {
          if (!BI->isConditional())
            continue;
          if (isCmd(BI->getCondition()))
            cmdTerminators.push_back(BI);
          auto *IC = dyn_cast<ICmpInst>(BI->getCondition());
          if (!IC || !IC->isEquality())
            continue;
          ConstantInt *ci = dyn_cast<ConstantInt>(IC->getOperand(1));
          Value *o = IC->getOperand(0);
          if (!ci) {
            ci = dyn_cast<ConstantInt>(IC->getOperand(0));
            o = IC->getOperand(1);
          }
          if (ci && isCmd(o))
            dom(ci->getZExtValue(),
                IC->getPredicate() == ICmpInst::ICMP_EQ ? BI->getSuccessor(0) : BI->getSuccessor(1));
        }
      }
    }
    auto reachesWithoutLoopingThrough = [](BasicBlock *start, BasicBlock *target, BasicBlock *blocked) {
      std::vector<BasicBlock *> work{start};
      std::set<BasicBlock *> seen;
      while (!work.empty()) {
        BasicBlock *bb = work.back();
        work.pop_back();
        if (bb == target)
          return true;
        if (bb == blocked || !seen.insert(bb).second)
          continue;
        for (BasicBlock *succ : successors(bb))
          work.push_back(succ);
      }
      return false;
    };
    auto cmdControls = [&](BasicBlock *site) {
      for (Instruction *term : cmdTerminators) {
        unsigned reaches = 0;
        for (unsigned i = 0; i < term->getNumSuccessors(); ++i)
          if (reachesWithoutLoopingThrough(term->getSuccessor(i), site, term->getParent()))
            ++reaches;
        if (reaches > 0 && reaches < term->getNumSuccessors())
          return true;
      }
      return false;
    };
    for (auto &s : sites)
      if (!covered.count(s.first) && !cmdControls(s.first))
        outs() << "CMD_REACH\t" << fn << "\t*\t" << bbIdx[s.first] << "\n";
  }
}

// The arg index a function's opcode SWITCH dispatches on (traced through casts), or -1.  Used to detect a
// helper the syscall handler forwards its opcode to (do_fcntl switches on arg 1 = cmd).
static int cmdSwitchArgIndex(Function &H) {
  for (BasicBlock &BB : H)
    if (auto *SW = dyn_cast<SwitchInst>(BB.getTerminator())) {
      std::set<Argument *> a;
      std::set<Value *> s;
      argsBehind(SW->getCondition(), a, s);
      if (!a.empty())
        return (int)(*a.begin())->getArgNo();
    }
  return -1;
}

static void analyzeCmd(Function &F, const DataLayout &DL,
                       std::map<std::string, std::set<std::string>> &ft,
                       const std::set<unsigned> &entrySeedIdx = {},
                       const std::string &originOverride = "", int maxDepth = CMD_MAX_DEPTH) {
  Argument *cmdArg = nullptr;  // entry: cmd arg = discriminant of an arg-derived switch
  for (BasicBlock &BB : F)
    if (auto *SW = dyn_cast<SwitchInst>(BB.getTerminator())) {
      std::set<Argument *> a;
      std::set<Value *> s;
      argsBehind(SW->getCondition(), a, s);
      if (!a.empty()) {
        cmdArg = *a.begin();
        break;
      }
    }
  std::set<unsigned> seeds;
  if (cmdArg)
    seeds.insert((unsigned)cmdArg->getArgNo());
  else
    for (unsigned idx : entrySeedIdx)
      if (idx < F.arg_size())
        seeds.insert(idx);
  if (seeds.empty())
    return;
  std::set<Function *> analyzed;
  std::set<std::pair<uint64_t, BasicBlock *>> done;
  std::set<std::string> bridges, tableBridges;
  analyzeCmdRec(F, seeds, seeds, DL, ft, analyzed, 0, done, bridges, tableBridges,
                originOverride.empty() ? F.getName().str() : originOverride, maxDepth);
}

struct CmdTableInfo {
  GlobalVariable *gv = nullptr;
  Constant *init = nullptr;
  StructType *elemTy = nullptr;
  unsigned n = 0;
  int cmdFi = -1;
  int hFi = -1;
};

static Constant *peelKasanGlobal(Constant *C);

static bool looksLikeIoctlCmd(uint64_t v) {
  return v != 0 && ((v >> 8) & 0xff) != 0;
}

static bool detectCmdTable(GlobalVariable &gv, const DataLayout &DL, CmdTableInfo &out) {
  if (!gv.hasInitializer())
    return false;
  Constant *init = peelKasanGlobal(gv.getInitializer());
  // Find the table aggregate: either [N x S] (a real LLVM array), or a (packed) struct whose members are
  // all the same struct S.  clang emits the latter for ioctl-op tables whose element struct has internal
  // alignment padding -- e.g. iommufd_ioctl_ops's {u32 size,u32 min_size,u32 ioctl_num,[4 x i8],ptr
  // execute} becomes { <{ E, E, ... }> }, not [N x E] -- so an ArrayType-only check silently drops them.
  // Peel single-field wrapper structs (the outer { <{...}> }) to reach the entry aggregate.
  StructType *et = nullptr;
  unsigned N = 0;
  for (int guard = 0; guard < 4 && init; ++guard) {
    Type *t = init->getType();
    if (auto *at = dyn_cast<ArrayType>(t)) {
      et = dyn_cast<StructType>(at->getElementType());
      N = at->getNumElements();
      break;
    }
    auto *st = dyn_cast<StructType>(t);
    if (!st || st->getNumElements() == 0)
      return false;
    if (st->getNumElements() >= 2 && isa<StructType>(st->getElementType(0))) {
      Type *e0 = st->getElementType(0);            // homogeneous struct-of-structs = an array in disguise;
      unsigned k = 1;                              // count the LEADING run of identical entry structs and
      while (k < st->getNumElements() && st->getElementType(k) == e0)  // ignore a trailing pad element
        k++;                                       // (KASAN adds a [M x i8] redzone as the last member).
      if (k >= 2) {
        et = cast<StructType>(e0);
        N = k;
        break;
      }
    }
    if (st->getNumElements() == 1) {                 // single wrapper field { <{...}> } -> peel into it
      init = init->getAggregateElement(0u);
      continue;
    }
    return false;
  }
  if (!et || et->isOpaque() || N < 2)
    return false;
  if (getenv("CMDTAB_DEBUG"))
    errs() << "TABLE? @" << gv.getName() << " [" << N << " x " << tyName(et) << "] nfields="
           << et->getNumElements() << "\n";

  // cmd field: i32 field where (cmd & 0xff) - index is CONSTANT across non-zero entries. Large
  // sparse driver tables keep the original >=80% rule; small ioctl tables need stronger value-shape
  // proof because there are not eight entries to build statistical confidence.
  int cmdFi = -1;
  for (unsigned fi = 0; fi < et->getNumElements() && cmdFi < 0; fi++) {
    if (!et->getElementType(fi)->isIntegerTy(32))
      continue;
    std::map<unsigned, unsigned> deltaHist;
    unsigned seen = 0, ioctlLike = 0;
    for (unsigned i = 0; i < N; i++) {
      Constant *e = init->getAggregateElement(i);
      if (auto *ci = dyn_cast_or_null<ConstantInt>(e ? e->getAggregateElement(fi) : nullptr)) {
        uint64_t v = ci->getZExtValue() & 0xffffffff;
        if (v == 0)
          continue;  // gap (no ioctl at this NR)
        seen++;
        if (looksLikeIoctlCmd(v))
          ioctlLike++;
        deltaHist[((v & 0xff) - i) & 0xff]++;
      }
    }
    unsigned best = 0;
    for (auto &kv : deltaHist)
      best = std::max(best, kv.second);
    if (getenv("CMDTAB_DEBUG"))
      errs() << "  field " << fi << " nonzero=" << seen << " const-delta=" << best
             << " ioctl-like=" << ioctlLike << " (N=" << N << ")\n";
    bool large = seen >= 8 && best * 5 >= seen * 4;
    bool small = N < 8 && seen >= 3 && best == seen && ioctlLike == seen;
    if (large || small)
      cmdFi = (int)fi;
  }
  if (cmdFi < 0)
    return false;

  // handler field: first ptr field holding a Function across entries.
  int hFi = -1;
  for (unsigned fi = 0; fi < et->getNumElements() && hFi < 0; fi++) {
    if (!et->getElementType(fi)->isPointerTy())
      continue;
    for (unsigned i = 0; i < N; i++) {
      Constant *e = init->getAggregateElement(i);
      Constant *pf = e ? e->getAggregateElement(fi) : nullptr;
      if (pf && isa<Function>(pf->stripPointerCasts())) {
        hFi = (int)fi;
        break;
      }
    }
  }
  if (hFi < 0)
    return false;
  out = CmdTableInfo{&gv, init, et, N, cmdFi, hFi};
  (void)DL;
  return true;
}

static void emitCmdTable(const CmdTableInfo &ti, const DataLayout &DL,
                         std::map<std::string, std::set<std::string>> &ft, Module &M,
                         const std::string &origin = "") {
  // Attribute by the STRUCTURE, not a cmd magic value: a drm_ioctl_desc[] table IS the drm ioctl dispatch
  // descriptor, dispatched by drm_ioctl via dev->driver->ioctls[_IOC_NR] -- so element type drm_ioctl_desc =>
  // origin drm_ioctl + key_kind iocnr (a non-drm table that merely uses the 'd' magic won't have this elem
  // type, and v4l2/etc. have their own descriptor types).
  bool isDrm = ti.elemTy && bareStructName(tyName(ti.elemTy)) == "drm_ioctl_desc";
  for (unsigned i = 0; i < ti.n; i++) {
    Constant *e = ti.init->getAggregateElement(i);
    if (!e)
      continue;
    auto *ci = dyn_cast_or_null<ConstantInt>(e->getAggregateElement(ti.cmdFi));
    Constant *pf = e->getAggregateElement(ti.hFi);
    Function *hf = pf ? dyn_cast<Function>(pf->stripPointerCasts()) : nullptr;
    if (!ci || !hf || hf->isDeclaration() || ci->getZExtValue() == 0)
      continue;
    uint64_t val = ci->getZExtValue() & 0xFFFFFFFF;
    std::string o = isDrm ? "drm_ioctl" : origin;
    std::string kk = isDrm ? "iocnr" : "";
    std::set<BasicBlock *> owned;
    for (BasicBlock &bb : *hf)
      owned.insert(&bb);
    emitCmdRegion(hf->getName().str(), val, ti.gv->getName().str() + "[" + std::to_string(i) + "]", owned,
                  true, 0, DL, ft, M, o, kk);
  }
}

static bool valueMentionsGlobal(Value *v, GlobalVariable *gv, std::set<Value *> &seen) {
  if (!v || !seen.insert(v).second)
    return false;
  if (v->stripPointerCasts() == gv)
    return true;
  if (auto *c = dyn_cast<Constant>(v))
    for (Use &op : c->operands())
      if (valueMentionsGlobal(op.get(), gv, seen))
        return true;
  if (auto *u = dyn_cast<User>(v))
    for (Use &op : u->operands())
      if (valueMentionsGlobal(op.get(), gv, seen))
        return true;
  return false;
}

static bool functionMentionsGlobal(Function &F, GlobalVariable *gv) {
  for (BasicBlock &BB : F)
    for (Instruction &I : BB) {
      std::set<Value *> seen;
      if (valueMentionsGlobal(&I, gv, seen))
        return true;
    }
  return false;
}

// cmd-DISPATCH-TABLE enumeration — the modern-driver style ④'s switch-detection misses. v4l2/drm/
// media/input dispatch ioctls via a static `table[_IOC_NR(cmd)].handler`, not a switch. A dispatch
// table is a global `[N x %struct.E]` that SELF-IDENTIFIES (no global/type-name hardcoding): one i32
// field is the cmd and the table is _IOC_NR-indexed; one ptr field is the per-cmd handler function.
static std::vector<CmdTableInfo> collectCmdTables(Module &M, const DataLayout &DL) {
  std::vector<CmdTableInfo> tables;
  for (GlobalVariable &gv : M.globals()) {
    CmdTableInfo ti;
    if (detectCmdTable(gv, DL, ti))
      tables.push_back(ti);
  }
  return tables;
}

static void enumCmdTables(Module &M, const DataLayout &DL,
                          std::map<std::string, std::set<std::string>> &ft) {
  for (const CmdTableInfo &ti : collectCmdTables(M, DL))
    emitCmdTable(ti, DL, ft, M);
}

static void enumCmdTablesUsedBy(Function &F, const std::string &origin, const DataLayout &DL,
                                std::map<std::string, std::set<std::string>> &ft, Module &M,
                                std::set<std::string> &emitted) {
  if (origin.empty())
    return;
  for (const CmdTableInfo &ti : collectCmdTables(M, DL)) {
    std::string key = origin + "\t" + F.getName().str() + "\t" + ti.gv->getName().str();
    if (!emitted.insert(key).second)
      continue;
    if (functionMentionsGlobal(F, ti.gv))
      emitCmdTable(ti, DL, ft, M, origin);
  }
}

static Constant *peelKasanGlobal(Constant *C) {
  auto *cs = dyn_cast_or_null<ConstantStruct>(C);
  if (!cs || cs->getNumOperands() != 2)
    return C;
  auto *pad = dyn_cast<ArrayType>(cs->getOperand(1)->getType());
  if (!pad || !pad->getElementType()->isIntegerTy(8))
    return C;
  Constant *payload = cs->getOperand(0);
  return isa<ConstantStruct>(payload) || isa<ConstantArray>(payload) || isa<ConstantDataArray>(payload)
             ? payload
             : C;
}

static GlobalVariable *argGlobal(CallInst *CI, unsigned idx) {
  if (!CI || idx >= CI->arg_size())
    return nullptr;
  return dyn_cast<GlobalVariable>(CI->getArgOperand(idx)->stripPointerCasts());
}

static std::set<GlobalVariable *> globalsPassedTo(Module &M, const std::set<std::string> &callees,
                                                   unsigned argIdx) {
  std::set<GlobalVariable *> out;
  for (Function &F : M)
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || CI->isInlineAsm())
          continue;
        Function *cal = CI->getCalledFunction();
        if (!cal)
          continue;
        if (!callees.count(stripSuffix(cal->getName().str())))
          continue;
        if (GlobalVariable *gv = argGlobal(CI, argIdx))
          out.insert(gv);
      }
  return out;
}

// GENETLINK dispatch: a genl_family's ops/small_ops/split_ops array is a {cmd, doit} table dispatched
// by MATCHING genlmsghdr.cmd to entry.cmd (u8) — NOT _IOC_NR-indexed, so enumCmdTables misses it.
// Resolve each genl_family (stable type name) -> its .name (inline char[]) + ops array (the ptr field
// pointing to a [N x struct.genl_*ops]); per entry doit = first ptr field holding a Function, cmd =
// first i8 field. Emit GENLCMD<family><cmd><doit><region> so the aggregator binds sendmsg$FAMILY_CMD_X
// by (family,cmd) — genl cmds COLLIDE across families, hence the family tag (structural: from .name).
// Follow a field-index path into a constant aggregate (handlers may be nested inside a union).
static Constant *followPath(Constant *c, const std::vector<unsigned> &path) {
  for (unsigned idx : path) {
    if (!c)
      return nullptr;
    c = c->getAggregateElement(idx);
  }
  return c;
}
// Every pointer leaf of a struct type, as a field-index path, descending through nested structs.
static void ptrLeafPaths(Type *t, std::vector<unsigned> &cur,
                         std::vector<std::vector<unsigned>> &out) {
  if (t->isPointerTy()) {
    out.push_back(cur);
    return;
  }
  if (auto *st = dyn_cast<StructType>(t))
    for (unsigned i = 0; i < st->getNumElements(); i++) {
      cur.push_back(i);
      ptrLeafPaths(st->getElementType(i), cur, out);
      cur.pop_back();
    }
}

static void enumGenlTables(Module &M, const DataLayout &DL,
                           std::map<std::string, std::set<std::string>> &ft) {
  std::set<GlobalVariable *> families;
  for (GlobalVariable &gv : M.globals())
    if (gv.hasInitializer()) {
      Constant *init = peelKasanGlobal(gv.getInitializer());
      auto *st = dyn_cast<StructType>(init->getType());
      if (st && tyName(st) == "struct.genl_family")
        families.insert(&gv);
    }
  auto regs = globalsPassedTo(M, {"genl_register_family"}, 0);
  families.insert(regs.begin(), regs.end());
  auto puts = globalsPassedTo(M, {"genlmsg_put"}, 3);
  families.insert(puts.begin(), puts.end());

  std::set<std::string> emitted;
  std::vector<std::pair<std::string, Function *>> genlH;   // (family, handler) -- scanned for compat sub-cmds
  for (GlobalVariable *g : families) {
    if (!g || !g->hasInitializer())
      continue;
    Constant *fam = peelKasanGlobal(g->getInitializer());
    auto *st = dyn_cast<StructType>(fam->getType());
    if (!st)
      continue;
    std::string name;
    for (unsigned fi = 0; fi < st->getNumElements(); fi++)
      if (auto *at = dyn_cast<ArrayType>(st->getElementType(fi)))
        if (at->getElementType()->isIntegerTy(8))
          if (auto *cda = dyn_cast_or_null<ConstantDataArray>(fam->getAggregateElement(fi))) {
            StringRef raw = cda->getRawDataValues();
            std::string s = raw.substr(0, raw.find('\0')).str();
            if (!s.empty()) {
              name = s;
              break;
            }
          }
    if (name.empty())
      continue;
    for (unsigned fi = 0; fi < st->getNumElements(); fi++) {
      if (!st->getElementType(fi)->isPointerTy())
        continue;
      Constant *pv = fam->getAggregateElement(fi);
      auto *gops = pv ? dyn_cast<GlobalVariable>(pv->stripPointerCasts()) : nullptr;
      if (!gops || !gops->hasInitializer())
        continue;
      Constant *opsInit = peelKasanGlobal(gops->getInitializer());
      // The ops table is a homogeneous [N x genl_*ops] array, OR -- when entries use the do- vs dump-union
      // variant types -- a packed struct of per-entry genl_*ops structs.  Collect the entries either way.
      std::vector<Constant *> entries;
      StructType *et = nullptr;
      if (auto *at = dyn_cast<ArrayType>(opsInit->getType())) {
        et = dyn_cast<StructType>(at->getElementType());
        for (unsigned i = 0; i < at->getNumElements(); i++)
          entries.push_back(opsInit->getAggregateElement(i));
      } else if (auto *pt = dyn_cast<StructType>(opsInit->getType())) {
        for (unsigned i = 0; i < pt->getNumElements(); i++) {
          Constant *e = opsInit->getAggregateElement(i);
          if (e && isa<StructType>(e->getType())) {
            if (!et)
              et = cast<StructType>(e->getType());
            entries.push_back(e);
          }
        }
      }
      if (!et || entries.empty())
        continue;
      int cmdFi = -1;
      for (unsigned k = 0; k < et->getNumElements(); k++)
        if (et->getElementType(k)->isIntegerTy(8)) {
          cmdFi = (int)k;
          break;
        }
      // Handlers: a genl op carries a doit AND/OR a dumpit in SEPARATE pointer fields (genl_ops/small_ops)
      // or a shared union slot (genl_split_ops).  Dump-only commands (*_GET_*/*_DUMP_* -- e.g. NL80211_CMD_
      // GET_SCAN, BATADV_CMD_GET_*) set only dumpit, so keying on a single field dropped them.  Collect EVERY
      // pointer leaf (direct field or nested-union leaf) that holds a Function in >=1 entry, and emit each
      // entry's handler(s) -- derived from the struct, never a hardcoded offset.
      std::vector<std::vector<unsigned>> leaves;
      {
        std::vector<unsigned> cur;
        ptrLeafPaths(et, cur, leaves);
      }
      auto isHandlerLeaf = [&](const std::vector<unsigned> &p) {
        for (Constant *e : entries) {
          Constant *pf = followPath(e, p);
          if (pf && isa<Function>(pf->stripPointerCasts()))
            return true;
        }
        return false;
      };
      // Field identity: emit ONLY the doit/dumpit command endpoints.  genl_split_ops nests the endpoint in a
      // do/dump union whose OTHER members are pre_doit/post_doit (doit variant) + start/done (dumpit variant)
      // lifecycle hooks; ptrLeafPaths surfaces those too, but they are not command handlers and must not
      // become GENLCMD rows (they belong in the region roots).  Keep a leaf iff its DWARF field name
      // (recursing the anon union, dwFieldNameAtDeep) is doit/dumpit.  Fallback: if the ops struct exposes no
      // such DWARF identity, keep every function leaf (old over-approx) so no command is ever dropped --
      // genl_ops/genl_small_ops carry doit/dumpit as their only pointer fields anyway (no lifecycle noise).
      std::vector<std::vector<unsigned>> handlerPaths;
      std::string etn = tyName(et);
      for (auto &p : leaves) {
        int64_t boff = 0;
        Type *cur = et;
        for (unsigned idx : p) {
          auto *st2 = dyn_cast<StructType>(cur);
          if (!st2)
            break;
          boff += DL.getStructLayout(st2)->getElementOffset(idx);
          cur = st2->getElementType(idx);
        }
        std::string dn = dwFieldNameAtDeep(etn, boff);
        if ((dn == "doit" || dn == "dumpit") && isHandlerLeaf(p))
          handlerPaths.push_back(p);
      }
      if (handlerPaths.empty())          // no doit/dumpit DWARF identity -> old behavior (never drop a command)
        for (auto &p : leaves)
          if (isHandlerLeaf(p))
            handlerPaths.push_back(p);
      if (cmdFi < 0 || handlerPaths.empty())
        continue;
      for (Constant *e : entries) {
        if (!e)
          continue;
        auto *ci = dyn_cast_or_null<ConstantInt>(e->getAggregateElement(cmdFi));
        if (!ci)
          continue;
        for (auto &p : handlerPaths) {
          Constant *pf = followPath(e, p);
          Function *h = pf ? dyn_cast<Function>(pf->stripPointerCasts()) : nullptr;
          if (!h || h->isDeclaration())
            continue;
          std::string key =
              name + "\t" + std::to_string(ci->getZExtValue() & 0xff) + "\t" + h->getName().str();
          if (!emitted.insert(key).second)
            continue;
          std::set<BasicBlock *> owned;
          for (BasicBlock &bb : *h)
            owned.insert(&bb);
          std::set<std::string> roots = regionFuncs(owned, DL, ft, M);
          outs() << "GENLCMD\t" << name << "\t" << (ci->getZExtValue() & 0xff) << "\t" << h->getName().str()
                 << "\t" << join(roots) << "\n";
          genlH.push_back({name, h});
        }
      }
    }
  }

  // Compat sub-command multiplexers: a genl handler (e.g. tipc_nl_compat_recv) whose body SWITCHES on a
  // legacy 16-bit command and installs the per-command callbacks into a stack struct (tipc_nl_compat_cmd_
  // doit/dump) before a compat trampoline.  The genl_ops table exposes only the multiplexer (cmd 1), not
  // these sub-commands, whose codes exceed u8 (0x4102/0x800b -- they collide under &0xff), so emit GENLCMD
  // <family> <FULL cmd> <handler> per case.  Gated on ">=2 cases store a defined Function" so only a real
  // multiplexer matches, never an ordinary control-flow switch.  Precision: when a store's destination
  // resolves to the compat struct's .doit/.dumpit field, ONLY that entry callback is emitted; where it does
  // not (local-alloca stores whose DWARF field name is unavailable), the row set degrades to the case's
  // dispatch-region coverage -- >1 handler per legacy cmd (the entry + its transcode helper), not a single
  // precise handler.  The resolver treats the multiple as a candidate set; downstream must not read it as 1.
  std::set<Function *> analyzed;
  for (auto &fh : genlH) {
    Function *H = fh.second;
    if (!H || H->isDeclaration() || !analyzed.insert(H).second)
      continue;
    for (BasicBlock &BB : *H) {
      auto *SI = dyn_cast<SwitchInst>(BB.getTerminator());
      if (!SI || SI->getNumCases() < 3)
        continue;
      std::map<uint64_t, std::set<Function *>> caseEntry, caseAll;
      for (auto C : SI->cases()) {
        uint64_t cv = C.getCaseValue()->getZExtValue();
        // the case body may sit past a critical-edge trampoline (empty unconditional-branch block), so scan
        // the successor and follow the unconditional-branch chain a few hops to reach the handler store.
        BasicBlock *dst = C.getCaseSuccessor();
        for (int hop = 0; dst && hop < 3; hop++) {
          for (Instruction &I : *dst)
            if (auto *S = dyn_cast<StoreInst>(&I))
              if (auto *F = dyn_cast<Function>(S->getValueOperand()->stripPointerCasts()))
                if (!F->isDeclaration()) {
                  caseAll[cv].insert(F);
                  // Field identity: the command ENTRY is the callback stored into the compat cmd struct's
                  // .doit/.dumpit field; sibling stores (its .transcode/.format helper, or the real netlink
                  // handler the entry later delegates to) are region roots, NOT a second endpoint.
                  std::string loc = absLoc(S->getPointerOperand(), DL);
                  auto plus = loc.rfind('+');
                  if (loc.rfind("struct.", 0) == 0 && plus != std::string::npos) {
                    std::string fld = dwFieldNameAtDeep(loc.substr(7, plus - 7),
                                                        strtoll(loc.c_str() + plus + 1, nullptr, 10));
                    if (fld == "doit" || fld == "dumpit")
                      caseEntry[cv].insert(F);
                  }
                }
          auto *br = dyn_cast<BranchInst>(dst->getTerminator());
          dst = (br && br->isUnconditional()) ? br->getSuccessor(0) : nullptr;
        }
      }
      // Prefer the precise .doit/.dumpit entry callback per case; fall back to the full stored-function set
      // where no such field store resolves (never drop a sub-command).
      std::map<uint64_t, std::set<Function *>> caseFns;
      for (auto &kv : caseAll)
        caseFns[kv.first] = caseEntry.count(kv.first) ? caseEntry[kv.first] : kv.second;
      if (caseFns.size() < 2)
        continue;
      // H only FORWARDS to these sub-command endpoints -- it is not a terminal handler.  Mark it so the
      // resolver drops it from (family,cmd): the outer genl entry (GENLCMD TIPC 1 tipc_nl_compat_recv)
      // otherwise pollutes the legacy sub-command that shares that value (TIPC_CMD_GET_NODES == 1).
      outs() << "GENLMUX\t" << H->getName().str() << "\n";
      for (auto &cf : caseFns)
        for (Function *F : cf.second) {
          std::string key = fh.first + "\t" + std::to_string(cf.first) + "\t" + F->getName().str();
          if (!emitted.insert(key).second)
            continue;
          std::set<BasicBlock *> owned;
          for (BasicBlock &bb : *F)
            owned.insert(&bb);
          std::set<std::string> roots = regionFuncs(owned, DL, ft, M);
          outs() << "GENLCMD\t" << fh.first << "\t" << cf.first << "\t" << F->getName().str() << "\t"
                 << join(roots) << "\n";
        }
    }
  }
}

static std::string cstr(Value *v);  // defined in the ③ reg-API section below

// NFNETLINK dispatch (IPSET, nft, ...): a struct registered via nfnetlink_subsys_register; its .name is a
// pointer to a string and its .cb field points to an array of nfnl_callback whose .call (field 0) is the
// handler, indexed BY POSITION (the message type == cmd).  Emit as GENLCMD<name><cmd><call> so the
// aggregator binds sendmsg$FAMILY_CMD_X by (family,cmd), exactly like genetlink.
static void enumNfnetlinkTables(Module &M, const DataLayout &DL,
                                std::map<std::string, std::set<std::string>> &ft) {
  std::set<std::string> emitted;
  for (GlobalVariable *g : globalsPassedTo(M, {"nfnetlink_subsys_register"}, 0)) {
    if (!g || !g->hasInitializer())
      continue;
    Constant *sub = peelKasanGlobal(g->getInitializer());
    auto *st = dyn_cast<StructType>(sub->getType());
    if (!st)
      continue;
    std::string name;
    std::vector<Constant *> entries;
    StructType *et = nullptr;
    for (unsigned fi = 0; fi < st->getNumElements(); fi++) {
      if (!st->getElementType(fi)->isPointerTy())
        continue;
      Constant *pv = sub->getAggregateElement(fi);
      if (!pv)
        continue;
      if (name.empty()) {
        std::string s = cstr(pv->stripPointerCasts());
        if (!s.empty()) {
          name = s;
          continue;
        }
      }
      auto *gcb = dyn_cast<GlobalVariable>(pv->stripPointerCasts());
      if (!gcb || !gcb->hasInitializer() || !entries.empty())
        continue;
      Constant *cbInit = peelKasanGlobal(gcb->getInitializer());
      if (auto *at = dyn_cast<ArrayType>(cbInit->getType()))
        if (auto *cet = dyn_cast<StructType>(at->getElementType()))
          if (!cet->isOpaque()) {
            et = cet;
            for (unsigned i = 0; i < at->getNumElements(); i++)
              entries.push_back(cbInit->getAggregateElement(i));
          }
    }
    if (name.empty() || !et || entries.empty())
      continue;
    // .call = the first pointer field holding a Function (field 0 of nfnl_callback); cmd = the array index.
    int callFi = -1;
    for (unsigned k = 0; k < et->getNumElements() && callFi < 0; k++) {
      if (!et->getElementType(k)->isPointerTy())
        continue;
      for (Constant *e : entries) {
        Constant *pf = e ? e->getAggregateElement(k) : nullptr;
        if (pf && isa<Function>(pf->stripPointerCasts())) {
          callFi = (int)k;
          break;
        }
      }
    }
    if (callFi < 0)
      continue;
    for (unsigned i = 0; i < entries.size(); i++) {
      Constant *e = entries[i];
      Constant *pf = e ? e->getAggregateElement(callFi) : nullptr;
      Function *call = pf ? dyn_cast<Function>(pf->stripPointerCasts()) : nullptr;
      if (!call || call->isDeclaration())
        continue;
      if (!emitted.insert(name + "\t" + std::to_string(i) + "\t" + call->getName().str()).second)
        continue;
      std::set<BasicBlock *> owned;
      for (BasicBlock &bb : *call)
        owned.insert(&bb);
      std::set<std::string> roots = regionFuncs(owned, DL, ft, M);
      outs() << "GENLCMD\t" << name << "\t" << i << "\t" << call->getName().str() << "\t" << join(roots)
             << "\n";
    }
  }
}

// FILESYSTEM mount: register_filesystem(&X_fs_type); mount$X / syz_mount_image$X build the superblock
// via the fs's init_fs_context (or legacy .mount). A file_system_type (stable type name) global has
// .name (field 0, char*) + the mount handler (the first ptr field holding a Function — init_fs_context,
// else .mount). Emit FSMOUNT<fsname><handler><region> so the aggregator binds mount variants by fs name.
static void enumFsTypes(Module &M, const DataLayout &DL,
                        std::map<std::string, std::set<std::string>> &ft) {
  std::set<GlobalVariable *> fsTypes;
  for (GlobalVariable &gv : M.globals())
    if (gv.hasInitializer()) {
      Constant *init = peelKasanGlobal(gv.getInitializer());
      auto *st = dyn_cast<StructType>(init->getType());
      if (st && tyName(st) == "struct.file_system_type")
        fsTypes.insert(&gv);
    }
  auto regs = globalsPassedTo(M, {"register_filesystem"}, 0);
  fsTypes.insert(regs.begin(), regs.end());
  if (getenv("FSTAB_DEBUG"))
    errs() << "FSTAB candidates=" << fsTypes.size() << " register_calls=" << regs.size() << "\n";

  for (GlobalVariable *g : fsTypes) {
    if (!g || !g->hasInitializer())
      continue;
    Constant *fst = peelKasanGlobal(g->getInitializer());
    auto *st = dyn_cast<StructType>(fst->getType());
    if (!st)
      continue;
    std::string name = cstr(fst->getAggregateElement(0u));  // .name = field 0 (char *)
    if (getenv("FSTAB_DEBUG"))
      errs() << "FSTAB? @" << g->getName() << " fields=" << st->getNumElements() << " name=" << name << "\n";
    if (name.empty())
      continue;
    Function *hf = nullptr;
    for (unsigned fi = 1; fi < st->getNumElements() && !hf; fi++) {
      if (!st->getElementType(fi)->isPointerTy())
        continue;
      if (Constant *pf = fst->getAggregateElement(fi))
        if (auto *f = dyn_cast<Function>(pf->stripPointerCasts()))
          if (!f->isDeclaration())
            hf = f;
    }
    if (getenv("FSTAB_DEBUG"))
      errs() << "FSTAB handler=" << (hf ? hf->getName() : StringRef("-")) << "\n";
    if (!hf)
      continue;
    std::set<BasicBlock *> owned;
    for (BasicBlock &bb : *hf)
      owned.insert(&bb);
    outs() << "FSMOUNT\t" << name << "\t" << hf->getName().str() << "\t"
           << join(regionFuncs(owned, DL, ft, M)) << "\n";
  }
}

// ITEM 3: registration binding. Field offsets are facts, not silent fallbacks.
//
// Build one layout fact table before REG extraction. DWARF member metadata and explicit static
// build-layout rules are both inputs to that table; a field read never "falls back" after a failed
// parse. If both sources disagree, the field is marked conflict and read fail-closed.
struct LayoutRule {
  const char *structName;  // bare name, e.g. "file_operations"
  const char *fieldName;
  int64_t offset;
};

static const LayoutRule kLayoutRules[] = {
    {"file_operations", "open", 104},
    {"file_operations", "read", 24},
    {"file_operations", "write", 32},
    {"file_operations", "unlocked_ioctl", 80},
    {"file_operations", "ioctl", 80},
    {"block_device_operations", "open", 16},
    {"block_device_operations", "ioctl", 32},
    {"proto", "ioctl", 40},
    {"proto", "setsockopt", 72},
    {"proto", "getsockopt", 80},
    {"proto", "sendmsg", 104},
    {"proto", "recvmsg", 112},
    {"proto_ops", "ioctl", 72},
    {"proto_ops", "setsockopt", 112},
    {"proto_ops", "getsockopt", 120},
    {"proto_ops", "sendmsg", 136},
    {"proto_ops", "recvmsg", 144},
    {"miscdevice", "name", 8},
    {"miscdevice", "fops", 16},
    {"usb_class_driver", "name", 0},
    {"usb_class_driver", "fops", 16},
    {"drm_driver", "fops", 192},
};

struct FieldLoc {
  int64_t offset = -1;
  std::string source = "missing";
};

static std::map<std::string, std::map<std::string, FieldLoc>> g_layoutFacts;

static bool isDwarfSource(const std::string &s) {
  return s.rfind("DWARF.", 0) == 0;
}

static void installLayoutFact(const std::string &structName, const std::string &fieldName,
                              int64_t offset, const std::string &source) {
  FieldLoc &cur = g_layoutFacts[bareStructName(structName)][fieldName];
  if (cur.offset < 0 && cur.source == "missing") {
    cur = FieldLoc{offset, source};
    return;
  }
  if (cur.offset == offset) {
    if (isDwarfSource(source) && !isDwarfSource(cur.source))
      cur.source = source;  // DWARF is stronger provenance when it agrees with the static rule.
    return;
  }
  cur = FieldLoc{-1, "conflict:" + cur.source + "@" + std::to_string(cur.offset) +
                         "!=" + source + "@" + std::to_string(offset)};
}

static void buildLayoutFacts() {
  g_layoutFacts.clear();
  for (const LayoutRule &r : kLayoutRules)
    installLayoutFact(r.structName, r.fieldName, r.offset,
                      std::string("STATIC_BUILD_RULE.") + r.fieldName);
  for (const auto &st : g_dwFieldOffset)
    for (const auto &field : st.second)
      installLayoutFact(st.first, field.first, field.second,
                        std::string("DWARF.") + field.first);
}

// the constant living at byte `o` inside an aggregate initializer (navigates struct/array by layout).
static Constant *constAtOffset(Constant *C, int64_t o, const DataLayout &DL) {
  while (C) {
    if (auto *cs = dyn_cast<ConstantStruct>(C)) {
      if ((uint64_t)o >= DL.getTypeAllocSize(cs->getType()))
        return nullptr;
      const StructLayout *sl = DL.getStructLayout(cs->getType());
      unsigned i = sl->getElementContainingOffset(o);
      o -= sl->getElementOffset(i);
      C = cs->getOperand(i);
    } else if (auto *ca = dyn_cast<ConstantArray>(C)) {
      uint64_t esz = DL.getTypeAllocSize(ca->getType()->getElementType());
      if (!esz)
        return nullptr;
      unsigned i = o / esz;
      if (i >= ca->getNumOperands())
        return nullptr;
      o -= i * esz;
      C = ca->getOperand(i);
    } else {
      return o == 0 ? C : nullptr;
    }
  }
  return nullptr;
}

static GlobalVariable *asGlobal(Value *v) {
  return v ? dyn_cast<GlobalVariable>(v->stripPointerCasts()) : nullptr;
}

static std::string fname(Constant *c) {
  if (c)
    if (auto *F = dyn_cast<Function>(c->stripPointerCasts()))
      return F->getName().str();
  return "-";
}

// read a C-string global (for device names)
static std::string cstr(Value *v) {
  if (auto *gv = asGlobal(v))
    if (gv->hasInitializer())
      if (auto *cda = dyn_cast<ConstantDataArray>(peelKasanGlobal(gv->getInitializer())))
        if (cda->isCString())
          return cda->getAsCString().str();
  return "";
}

static std::string globalDebugStructName(GlobalVariable &gv) {
  SmallVector<DIGlobalVariableExpression *, 4> dbg;
  gv.getDebugInfo(dbg);
  for (auto *expr : dbg)
    if (auto *var = expr ? expr->getVariable() : nullptr)
      for (DIType *t = var->getType(); t;) {
        if (auto *d = dyn_cast<DIDerivedType>(t)) {
          t = d->getBaseType();
          continue;
        }
        auto *c = dyn_cast<DICompositeType>(t);
        if (!c)
          break;
        if (c->getTag() == dwarf::DW_TAG_array_type) {
          t = c->getBaseType();
          continue;
        }
        if (!c->getName().empty())
          return c->getName().str();
        break;
      }
  return "";
}

// Exact DWARF location for a runtime store. Unlike absLoc, this never names an LLVM struct by shape:
// the root object must have a source-level DWARF type, every GEP offset must be constant, and the final
// byte offset must name a real DWARF field. This is the runtime counterpart of TYPEDFIELD.
static std::string dwarfStoreLoc(Value *ptr, const DataLayout &DL) {
  if (!ptr)
    return "";
  int64_t offset = 0;
  Value *base = ptr;
  for (int guard = 0; guard < 12; ++guard) {
    base = base->stripPointerCasts();
    auto *gep = dyn_cast<GEPOperator>(base);
    if (!gep)
      break;
    APInt delta(DL.getIndexSizeInBits(gep->getPointerAddressSpace()), 0);
    if (!gep->accumulateConstantOffset(DL, delta))
      return "";
    offset += delta.getSExtValue();
    base = gep->getPointerOperand();
  }

  base = base->stripPointerCasts();
  std::string structName;
  if (auto *gv = dyn_cast<GlobalVariable>(base))
    structName = globalDebugStructName(*gv);
  if (structName.empty())
    structName = dwarfBaseStruct(base, DL, 0);
  if (structName.empty())
    return "";

  std::string loc = canonicalStructByteLoc(structName, offset);
  size_t plus = loc.rfind('+');
  if (loc.rfind("struct.", 0) != 0 || plus == std::string::npos)
    return "";
  std::string exactStruct = loc.substr(7, plus - 7);
  int64_t exactOffset = strtoll(loc.c_str() + plus + 1, nullptr, 10);
  return dwFieldNameAt(exactStruct, exactOffset).empty() ? "" : loc;
}

struct FunctionFieldRead {
  std::string value = "-";
  FieldLoc loc;
};

struct ConstFieldRead {
  Constant *value = nullptr;
  FieldLoc loc;
};

static FieldLoc layoutFieldLoc(const std::string &structName,
                               std::initializer_list<const char *> names) {
  std::string bare = bareStructName(structName);
  auto it = g_layoutFacts.find(bare);
  if (it == g_layoutFacts.end())
    return {};
  for (const char *name : names) {
    auto f = it->second.find(name);
    if (f != it->second.end())
      return f->second;
  }
  return {};
}

static std::string opsStructName(GlobalVariable &gv, Type *peeledType) {
  std::string tn = tyName(peeledType);
  if (tn.rfind("anon#", 0) != 0)
    return tn;
  std::string dbg = globalDebugStructName(gv);
  return dbg.empty() ? tn : "struct." + dbg;
}

static std::string firstElementStructName(GlobalVariable &gv, Type *peeledType) {
  Type *t = peeledType;
  while (auto *at = dyn_cast<ArrayType>(t))
    t = at->getElementType();
  return opsStructName(gv, t);
}

static FunctionFieldRead readFunctionField(Constant *ops, const std::string &structName,
                                           std::initializer_list<const char *> names,
                                           const DataLayout &DL) {
  FunctionFieldRead out;
  // Try each alias name and return the first whose slot is actually POPULATED, not merely the first that
  // exists in the struct layout.  This matters for iov_iter fops: struct file_operations always HAS a
  // .read field (offset 24), but proc_sys/tty/block/... leave it null and populate .read_iter instead --
  // the old "first name in layout" logic returned .read's null.  (Also makes unlocked_ioctl/ioctl robust.)
  for (const char *nm : names) {
    FieldLoc loc = layoutFieldLoc(structName, {nm});
    if (loc.offset < 0)
      continue;
    if (out.loc.offset < 0)
      out.loc = loc;                      // remember the primary field's location for the layout summary
    std::string v = fname(constAtOffset(ops, loc.offset, DL));
    if (v != "-") {
      out.value = v;
      out.loc = loc;
      break;
    }
  }
  return out;
}

static ConstFieldRead readConstField(GlobalVariable *gv, std::initializer_list<const char *> names,
                                     const DataLayout &DL) {
  ConstFieldRead out;
  if (!gv || !gv->hasInitializer())
    return out;
  Constant *init = peelKasanGlobal(gv->getInitializer());
  // The global's own DWARF struct type is authoritative for reading its initializer's fields.  Prefer it
  // over opsStructName's LLVM shape-match, which can collide on anonymous KASAN-peeled structs -- e.g.
  // @hiddev_class's inner {ptr,ptr,ptr,i32,[4xi8]} shape-matches kparam_array, hiding usb_class_driver.
  std::string dbg = globalDebugStructName(*gv);
  std::string tn = dbg.empty() ? opsStructName(*gv, init->getType()) : "struct." + dbg;
  out.loc = layoutFieldLoc(tn, names);
  if (out.loc.offset >= 0)
    out.value = constAtOffset(init, out.loc.offset, DL);
  return out;
}

struct OpsTableTarget {
  GlobalVariable *gv = nullptr;
  Constant *ops = nullptr;
  std::string structName;
};

static bool globalByteOffset(Value *v, const DataLayout &DL, GlobalVariable *&gv, int64_t &offset) {
  gv = nullptr;
  offset = 0;
  if (!v)
    return false;
  v = v->stripPointerCasts();
  if (auto *g = dyn_cast<GlobalVariable>(v)) {
    gv = g;
    return true;
  }
  auto *gep = dyn_cast<GEPOperator>(v);
  if (!gep)
    return false;
  APInt off(DL.getIndexSizeInBits(gep->getPointerAddressSpace()), 0);
  if (!gep->accumulateConstantOffset(DL, off))
    return false;
  auto *g = dyn_cast<GlobalVariable>(gep->getPointerOperand()->stripPointerCasts());
  if (!g)
    return false;
  gv = g;
  offset = off.getSExtValue();
  return offset >= 0;
}

static Constant *opsObjectAtOffset(Constant *init, int64_t offset, const DataLayout &DL) {
  Constant *C = peelKasanGlobal(init);
  while (auto *ca = dyn_cast_or_null<ConstantArray>(C)) {
    uint64_t esz = DL.getTypeAllocSize(ca->getType()->getElementType());
    if (!esz)
      return nullptr;
    unsigned i = offset / esz;
    if (i >= ca->getNumOperands())
      return nullptr;
    offset -= i * esz;
    C = ca->getOperand(i);
  }
  if (offset == 0)
    return C;
  return constAtOffset(C, offset, DL);
}

static OpsTableTarget resolveOpsTable(Value *v, const DataLayout &DL) {
  OpsTableTarget out;
  int64_t offset = 0;
  if (!globalByteOffset(v, DL, out.gv, offset) || !out.gv || !out.gv->hasInitializer())
    return out;
  out.ops = opsObjectAtOffset(out.gv->getInitializer(), offset, DL);
  if (!out.ops)
    return out;
  out.structName = opsStructName(*out.gv, out.ops->getType());
  return out;
}

static std::string locTag(const FieldLoc &loc) {
  if (loc.offset < 0)
    return loc.source.empty() ? "missing" : loc.source;
  return loc.source + "@" + std::to_string(loc.offset);
}

static std::string layoutSummary(std::initializer_list<std::pair<const char *, FieldLoc>> fields,
                                 const char *prefix = "layout") {
  std::string out = std::string(prefix) + "=";
  int n = 0;
  for (const auto &f : fields) {
    if (n++)
      out += ",";
    out += f.first;
    out += ":";
    out += locTag(f.second);
  }
  return out;
}

// Structural ops-table discovery by STRUCT TYPE NAME (the discriminator SyzDescribe uses,
// Manager.cpp:1163). A global whose (redzone-peeled) type is %struct.file_operations / proto /
// proto_ops / block_device_operations IS that ops-table — read its handlers, regardless of how it's
// installed (catches snd_pcm_f_ops, def_blk_fops, packet_ops, …). Type-name is injective, so it is
// immune to the size collision that made x86_emulate_ops (448B) masquerade as proto (448B).
static void enumOpsTables(Module &M, const DataLayout &DL) {
  for (GlobalVariable &gv : M.globals()) {
    if (!gv.hasInitializer())
      continue;
    Constant *ops = opsObjectAtOffset(gv.getInitializer(), 0, DL);
    if (!ops)
      continue;
    std::string tn = opsStructName(gv, ops->getType());
    std::string g = gv.getName().str();
    auto F = [&](std::initializer_list<const char *> names) {
      return readFunctionField(ops, tn, names, DL);
    };
    if (tn == "struct.file_operations") {
      auto open = F({"open"});
      // Modern iov_iter fops set .read_iter/.write_iter instead of .read/.write (proc_sys, tty, block,
      // kernfs, tap/tun, fuse, ...).  Fall back to them so read$/write$ variants on those files anchor to
      // the real handler (the iter fn IS the read/write behaviour; emitted under the read/write field name
      // so the resolver's DIRECT_FIELD read->"read"/write->"write" mapping matches).
      auto read = F({"read", "read_iter"});
      auto write = F({"write", "write_iter"});
      auto ioctl = F({"unlocked_ioctl", "ioctl"});
      outs() << "REG\tfops\t-\t" << g << "\topen=" << open.value
             << " read=" << read.value << " write=" << write.value
             << " ioctl=" << ioctl.value << "\t"
             << layoutSummary({{"open", open.loc}, {"read", read.loc}, {"write", write.loc},
                               {"ioctl", ioctl.loc}})
             << "\n";
    } else if (tn == "struct.block_device_operations") {
      auto open = F({"open"});
      auto ioctl = F({"ioctl"});
      outs() << "REG\tbdev\t-\t" << g << "\topen=" << open.value
             << " ioctl=" << ioctl.value << "\t"
             << layoutSummary({{"open", open.loc}, {"ioctl", ioctl.loc}}) << "\n";
    } else if (tn == "struct.proto") {
      auto ioctl = F({"ioctl"});
      auto setsockopt = F({"setsockopt"});
      auto getsockopt = F({"getsockopt"});
      auto sendmsg = F({"sendmsg"});
      auto recvmsg = F({"recvmsg"});
      outs() << "REG\tproto\t-\t" << g << "\tioctl=" << ioctl.value
             << " setsockopt=" << setsockopt.value << " getsockopt=" << getsockopt.value
             << " sendmsg=" << sendmsg.value << " recvmsg=" << recvmsg.value << "\t"
             << layoutSummary({{"ioctl", ioctl.loc}, {"setsockopt", setsockopt.loc},
                               {"getsockopt", getsockopt.loc}, {"sendmsg", sendmsg.loc},
                               {"recvmsg", recvmsg.loc}})
             << "\n";
    } else if (tn == "struct.proto_ops") {
      auto ioctl = F({"ioctl"});
      auto setsockopt = F({"setsockopt"});
      auto getsockopt = F({"getsockopt"});
      auto sendmsg = F({"sendmsg"});
      auto recvmsg = F({"recvmsg"});
      outs() << "REG\tproto_ops\t-\t" << g << "\tioctl=" << ioctl.value
             << " setsockopt=" << setsockopt.value << " getsockopt=" << getsockopt.value
             << " sendmsg=" << sendmsg.value << " recvmsg=" << recvmsg.value << "\t"
             << layoutSummary({{"ioctl", ioctl.loc}, {"setsockopt", setsockopt.loc},
                               {"getsockopt", getsockopt.loc}, {"sendmsg", sendmsg.loc},
                               {"recvmsg", recvmsg.loc}})
             << "\n";
    }
  }
}

static void analyzeReg(Module &M, const DataLayout &DL) {
  auto h = [&](const OpsTableTarget &ops, std::initializer_list<const char *> names) {
    FunctionFieldRead out;
    if (!ops.ops || ops.structName.empty())
      return out;
    return readFunctionField(ops.ops, ops.structName, names, DL);
  };
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || CI->isInlineAsm())
          continue;
        Function *cal = CI->getCalledFunction();
        if (!cal)
          continue;
        std::string n = stripSuffix(cal->getName().str());
        auto arg = [&](unsigned i) { return i < CI->arg_size() ? CI->getArgOperand(i) : nullptr; };
        Value *opsValue = nullptr;
        std::string kind, dev, regLayout;
        if (n == "misc_register") {
          kind = "misc";
          if (auto *md = asGlobal(arg(0)))
            if (md->hasInitializer()) {
              ConstFieldRead fopsField = readConstField(md, {"fops"}, DL);
              ConstFieldRead nameField = readConstField(md, {"name"}, DL);
              opsValue = fopsField.value;
              dev = cstr(nameField.value);
              regLayout = layoutSummary({{"fops", fopsField.loc}, {"name", nameField.loc}},
                                        "reglayout");
            }
        } else if (n == "cdev_init") {
          kind = "cdev";
          opsValue = arg(1);
        } else if (n == "register_chrdev") {
          kind = "chrdev";
          opsValue = arg(2);
        } else if (n == "__register_chrdev") {
          kind = "chrdev";
          opsValue = arg(4);
        } else if (n == "anon_inode_getfd" || n == "anon_inode_getfile") {
          kind = "anon";
          opsValue = arg(1);
          dev = cstr(arg(0));
        } else if (n == "usb_register_dev") {  // arg1 = usb_class_driver; .fops field -> fops
          kind = "usb";
          if (auto *cd = asGlobal(arg(1)))
            if (cd->hasInitializer()) {
              ConstFieldRead fopsField = readConstField(cd, {"fops"}, DL);
              ConstFieldRead nameField = readConstField(cd, {"name"}, DL);
              opsValue = fopsField.value;
              dev = cstr(nameField.value);
              regLayout = layoutSummary({{"fops", fopsField.loc}, {"name", nameField.loc}},
                                        "reglayout");
            }
        } else if (n == "__devm_drm_dev_alloc" || n == "drm_dev_alloc") {  // arg1 = drm_driver
          kind = "drm";
          if (auto *dd = asGlobal(arg(1)))
            if (dd->hasInitializer()) {
              ConstFieldRead fopsField = readConstField(dd, {"fops"}, DL);
              opsValue = fopsField.value;
              regLayout = layoutSummary({{"fops", fopsField.loc}}, "reglayout");
            }
        } else if (n == "snd_register_device") {  // arg3 = the file_operations* directly
          kind = "snd";
          opsValue = arg(3);
        } else if (n == "proto_register") {
          OpsTableTarget p = resolveOpsTable(arg(0), DL);
          if (p.gv && p.ops) {
            auto ioctl = h(p, {"ioctl"});
            auto setsockopt = h(p, {"setsockopt"});
            auto getsockopt = h(p, {"getsockopt"});
            auto sendmsg = h(p, {"sendmsg"});
            auto recvmsg = h(p, {"recvmsg"});
            outs() << "REG\tproto\t" << p.gv->getName().str() << "\t" << p.gv->getName().str()
                   << "\tioctl=" << ioctl.value << " setsockopt=" << setsockopt.value
                   << " getsockopt=" << getsockopt.value << " sendmsg=" << sendmsg.value
                   << " recvmsg=" << recvmsg.value << "\t"
                   << layoutSummary({{"ioctl", ioctl.loc}, {"setsockopt", setsockopt.loc},
                                     {"getsockopt", getsockopt.loc}, {"sendmsg", sendmsg.loc},
                                     {"recvmsg", recvmsg.loc}})
                   << "\n";
          }
          continue;
        } else {
          continue;
        }
        OpsTableTarget ops = resolveOpsTable(opsValue, DL);
        if (ops.gv && ops.ops) {
          auto open = h(ops, {"open"});
          auto read = h(ops, {"read"});
          auto write = h(ops, {"write"});
          auto ioctl = h(ops, {"unlocked_ioctl", "ioctl"});
          outs() << "REG\t" << kind << "\t" << (dev.empty() ? "-" : dev) << "\t" << ops.gv->getName().str()
                 << "\topen=" << open.value << " read=" << read.value << " write=" << write.value
                 << " ioctl=" << ioctl.value << "\t"
                 << layoutSummary({{"open", open.loc}, {"read", read.loc}, {"write", write.loc},
                                   {"ioctl", ioctl.loc}});
          if (!regLayout.empty())
            outs() << "\t" << regLayout;
          outs() << "\n";
        }
      }
  }
}

// module-wide caller-count (consumed by regionFuncs for value-specific region expansion).
static void buildCallerCount(Module &M, const DataLayout &DL,
                             std::map<std::string, std::set<std::string>> &ft) {
  for (Function &CF : M) {
    if (CF.isDeclaration())
      continue;
    std::set<std::string> callees;
    for (BasicBlock &BB : CF)
      for (Instruction &I : BB)
        if (auto *CI = dyn_cast<CallInst>(&I)) {
          if (CI->isInlineAsm())
            continue;
          if (Function *c = CI->getCalledFunction())
            callees.insert(c->getName().str());
          else if (auto *L = dyn_cast<LoadInst>(CI->getCalledOperand())) {
            auto it = ft.find(absLoc(L->getPointerOperand(), DL));
            if (it != ft.end())
              for (auto &t : it->second)
                callees.insert(t);
          }
        }
    for (auto &nm : callees)
      g_callerCount[nm]++;
  }
}

// For an indirect CALL, recover the field(s) whose RUNTIME value controls the target: fnField = the loaded
// function pointer's field; opsField = the ops-POINTER field when it's an obj->ops->fn dispatch (the fn
// pointer's GEP base is itself a load of a field), else "". The install writes fnField (direct install
// obj->handler=fn) or opsField (ops-table selection obj->ops=&table); keyed so writers⋈dispatch couple.
static void icallFields(CallInst *CI, const DataLayout &DL,
                        std::string &fnField, std::string &opsField) {
  fnField.clear(); opsField.clear();
  if (!CI || CI->isInlineAsm() || CI->getCalledFunction()) return;   // indirect calls only
  auto *L = dyn_cast<LoadInst>(CI->getCalledOperand());
  if (!L) return;
  Value *fnPtr = L->getPointerOperand();
  fnField = absLoc(fnPtr, DL);
  if (auto *gep = dyn_cast<GEPOperator>(fnPtr->stripPointerCasts()))
    if (auto *LI2 = dyn_cast<LoadInst>(gep->getPointerOperand()->stripPointerCasts()))
      opsField = absLoc(LI2->getPointerOperand(), DL);   // obj->ops field (runtime-selected table pointer)
}

// INNER-GATE slices: the node-bound (domSubtree of a gate) applied to EVERY state-field branch, not
// just the cmd switch. For each conditional branch whose condition reads a struct/global field F, the
// GATED side's dominator subtree -> regionFuncs = the deep code reachable ONLY through that branch =
// the slice a producer of F "unlocks". Bipartite by construction (one slice per gate, keyed by F);
// no writers×readers Cartesian, no field_hub. Emits:
//   GATE <fn> <fields> <reqvals> <gated_blocks> <region_size> <region_funcs>
// The deeper successor (larger domSubtree) is the gated slice (the shallow side is the cleanup/return).
static void analyzeGates(Module &M, const DataLayout &DL,
                         std::map<std::string, std::set<std::string>> &ft,
                         std::set<std::string> &want) {
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    if (!want.empty() && !want.count(F.getName().str()))
      continue;
    DominatorTree DT(F);
    std::string fn = F.getName().str();
    for (BasicBlock &BB : F) {
      auto *BI = dyn_cast<BranchInst>(BB.getTerminator());
      if (!BI || !BI->isConditional())
        continue;
      // backward slice of the condition: per loaded state field recover (field, S=provenance), and
      // collect the const reqvals (the P value B checks).
      std::map<std::string, std::string> fieldS;
      std::set<std::string> vals;
      std::set<std::string> ops;   // the PREDICATE B applies to F: eq/ne/rel(threshold)/and(flag)/nonzero
      std::set<Value *> seen;
      std::vector<Value *> wl{BI->getCondition()};
      while (!wl.empty()) {
        Value *v = wl.back();
        wl.pop_back();
        if (!seen.insert(v).second)
          continue;
        if (auto *cmp = dyn_cast<ICmpInst>(v)) {   // eq/ne = value protocol; u/s gt/lt/ge/le = threshold
          auto p = cmp->getPredicate();
          ops.insert(p == CmpInst::ICMP_EQ ? "eq" : p == CmpInst::ICMP_NE ? "ne" : "rel");
        } else if (auto *bo = dyn_cast<BinaryOperator>(v)) {
          if (bo->getOpcode() == Instruction::And) ops.insert("and");   // bitmask/flag test
        }
        if (auto *L = dyn_cast<LoadInst>(v)) {
          std::string loc = absLoc(L->getPointerOperand(), DL);
          if (loc.rfind("struct.", 0) == 0 || (!loc.empty() && loc[0] == '@'))
            fieldS.emplace(loc, provenanceRoot(L->getPointerOperand(), DL));
          std::string gl = globalLoc(L->getPointerOperand(), DL);  // E9: additive @global gate form — was
          if (!gl.empty())                                          // MISSING here (WRITE side has it) → 0
            fieldS.emplace(gl, "@global");                          // @global gates → global channel dead
          continue;
        }
        if (auto *ci = dyn_cast<ConstantInt>(v)) {
          vals.insert(apStr(ci->getValue(), true));
          continue;
        }
        // via-CALL gate: a branch on a container-LOOKUP result (if ((x = idr_find(coll, key)))) is a real
        // precondition keyed on the COLLECTION root — couples with an INS producer's membership WRITE on
        // the same root. Record arg0's (struct,off) as F + pred "lookup"; don't recurse (key args aren't F).
        if (auto *call = dyn_cast<CallInst>(v)) {
          if (Function *cf = call->getCalledFunction()) {
            const char *k = containerOp(cf->getName().str());
            if (k && std::string(k) == "LKP" && call->arg_size() > 0) {
              std::string loc = absLoc(call->getArgOperand(0), DL);
              if (loc.rfind("struct.", 0) == 0) {   // S="coll": couple by the collection ROOT + resource-gate
                fieldS.emplace(loc, "coll");         // (producer-arg vs consumer-internal-load S differ; the
                ops.insert("lookup");                //  collection field + a shared resource IS the identity)
              }
              continue;
            }
          }
        }
        if (auto *I = dyn_cast<Instruction>(v))
          for (auto &o : I->operands())
            wl.push_back(o.get());
      }
      if (fieldS.empty())
        continue;
      std::set<BasicBlock *> own0{BI->getSuccessor(0)}, own1{BI->getSuccessor(1)};
      domSubtree(DT, BI->getSuccessor(0), own0);
      domSubtree(DT, BI->getSuccessor(1), own1);
      bool zeroDeep = own0.size() >= own1.size();
      std::set<BasicBlock *> &owned = zeroDeep ? own0 : own1;   // gated (deeper) slice
      std::set<BasicBlock *> &openbb = zeroDeep ? own1 : own0;  // open (shallow) slice = paired CONTROL
      std::set<std::string> region = regionFuncs(owned, DL, ft, M);
      std::set<std::string> openreg = regionFuncs(openbb, DL, ft, M);
      std::string rv = join(vals), rfn = join(region), ofn = join(openreg);
      std::string opstr = ops.empty() ? "nonzero" : join(ops);  // empty = field branched on directly
      // GATE <fn> <field> <S> <reqvals(P)> <gated_blocks> <region_size> <region_funcs> <open_funcs> <pred>
      // open_funcs = the OTHER successor's domSubtree, reached from the same branch w/o the precondition:
      // the paired control for the hardness proof (gated dark + open covered => precondition is barrier).
      // pred = the predicate B applies to F (eq/ne=value protocol, rel=threshold, and=flag, nonzero=exists).
      for (auto &fs : fieldS)
        outs() << "GATE\t" << fn << "\t" << fs.first << "\t" << fs.second << "\t" << rv << "\t"
               << owned.size() << "\t" << region.size() << "\t" << rfn << "\t" << ofn << "\t" << opstr << "\n";
    }
    // fptr-install DISPATCH gates: an indirect call dispatches to the installed handler — R = the resolved
    // callee(s) (ft[fnField]). Emit on BOTH the function field (direct install obj->handler=fn) AND the
    // ops-POINTER field (ops-table selection obj->ops=&table); whichever has a matching install WRITE
    // couples, the other is inert. R IS the callee (no dominator slice). Skips mega-generic dispatch hubs.
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI) continue;
        std::string fnField, opsField;
        icallFields(CI, DL, fnField, opsField);
        if (fnField.empty()) continue;
        auto it = ft.find(fnField);                       // R = the candidate callees of the fn field
        if (it == ft.end() || it->second.empty() || it->second.size() > 64) continue;  // none/mega-generic
        std::string callees = join(it->second);
        auto emitDispatch = [&](const std::string &field) {
          if (field.rfind("struct.", 0) != 0 && !(!field.empty() && field[0] == '@')) return;
          // S="fptr": couple install⋈dispatch by the field + resource-gate (natural S mismatches — install
          // reaches the field via an arg, dispatch via an internal load, like container's "coll").
          outs() << "GATE\t" << fn << "\t" << field << "\tfptr\t-\t0\t"
                 << it->second.size() << "\t" << callees << "\t-\tdispatch\n";
        };
        emitDispatch(fnField);
        if (!opsField.empty() && opsField != fnField)
          emitDispatch(opsField);
      }
  }
}

// OPSFIELD: per-global field VALUE of selected ops structs (block/proto), so a recognizer can read
// "@<ops_global>'s .ioctl is <handler>" or ".family is <const>" without disassembling or guessing an
// offset.  Offset comes from the DWARF member map (named even for clang-anonymized types); value via
// constAtOffset.  Emits OPSFIELD<ops_global><struct.field><handler-or-int>.
static const std::set<std::string> g_opsFieldStructs = {
    "block_device_operations", "blk_mq_ops", "proto_ops"};

static void enumOpsFields(Module &M, const DataLayout &DL) {
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.hasInitializer())
      continue;
    SmallVector<DIGlobalVariableExpression *, 1> GVEs;
    GV.getDebugInfo(GVEs);
    Constant *init = peelKasanGlobal(GV.getInitializer());
    for (auto *E : GVEs) {
      DICompositeType *c = diComposite(E->getVariable()->getType());
      if (!c || !g_opsFieldStructs.count(c->getName().str()))
        continue;
      auto it = g_dwFieldOffset.find(c->getName().str());
      if (it == g_dwFieldOffset.end())
        continue;
      for (auto &mo : it->second) {                 // field name -> byte offset
        Constant *v = constAtOffset(init, mo.second, DL);
        if (!v)
          continue;
        std::string val;
        if (auto *F = dyn_cast<Function>(v->stripPointerCasts())) {
          if (F->isDeclaration() || skipRuntimeFunction(F->getName()))
            continue;
          val = F->getName().str();
        } else if (auto *ci = dyn_cast<ConstantInt>(v)) {
          val = std::to_string(ci->getSExtValue());
        } else {
          continue;
        }
        outs() << "OPSFIELD\t" << GV.getName().str() << "\t" << c->getName().str() << "." << mo.first
               << "\t" << val << "\n";
      }
    }
  }
}

// ANON: anon_inode_get{fd,file}*(name, fops, ...) [fops arg1] and alloc_file_pseudo(inode, mnt, name, flags,
// fops) [fops arg4 -- dma_buf/others build a pseudo-file the same way] attribute <fops> to the syscall
// handlers that reach the creating call (reverse call-graph BFS, <=5 hops), plus the direct creator -- so an
// anon-fd resource produced by a syscall anchors to its fops without name-matching.  Emits ANON<fn><fops>.
static bool isSyscallHandlerName(StringRef n) {
  return n.starts_with("__se_sys_") || n.starts_with("__do_sys_") || n.starts_with("__x64_sys_") ||
         n.starts_with("__ia32_sys_") || n.starts_with("__sys_") || n.starts_with("SyS_");
}

static void enumAnonInode(Module &M) {
  std::map<Function *, std::set<Function *>> callersOf;     // f -> {functions that call f}
  std::map<Function *, std::set<std::string>> directAnon;   // f -> {fops it directly passes to anon_inode}
  for (Function &F : M)
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *CI = dyn_cast<CallInst>(&I))
          if (Function *cal = CI->getCalledFunction()) {
            callersOf[cal].insert(&F);
            StringRef cn = cal->getName();
            int fopsArg = -1;
            if (cn.starts_with("anon_inode_") && cn.contains("get"))
              fopsArg = 1;
            else if (stripSuffix(cn.str()) == "alloc_file_pseudo" &&
                     // sockets are built with alloc_file_pseudo(&socket_file_ops) too, but a socket has its
                     // own resource type + proto_ops anchoring (build_sock_family_anchors); attributing the
                     // generic socket_file_ops would preempt that.  Skip the socket creator specifically.
                     stripSuffix(F.getName().str()) != "sock_alloc_file")
              fopsArg = 4;
            if (fopsArg >= 0 && (int)CI->arg_size() > fopsArg)
              if (auto *gv = dyn_cast<GlobalVariable>(CI->getArgOperand(fopsArg)->stripPointerCasts()))
                directAnon[&F].insert(gv->getName().str());
          }
  for (auto &kv : directAnon) {
    const std::set<std::string> &fopss = kv.second;
    for (auto &fops : fopss)
      outs() << "ANON\t" << kv.first->getName().str() << "\t" << fops << "\n";  // direct creator
    std::set<Function *> seen{kv.first};
    std::vector<Function *> frontier{kv.first};
    for (int hop = 0; hop < 5 && !frontier.empty(); hop++) {     // lift to syscall-handler ancestors
      std::vector<Function *> next;
      for (Function *f : frontier)
        for (Function *caller : callersOf[f]) {
          if (!seen.insert(caller).second)
            continue;
          next.push_back(caller);
          if (isSyscallHandlerName(caller->getName()))
            for (auto &fops : fopss)
              outs() << "ANON\t" << caller->getName().str() << "\t" << fops << "\n";
        }
      frontier = std::move(next);
    }
  }
}

// MISC: every miscdevice global's .name -> .fops.  Scans the global initializers directly (not just
// misc_register call sites, which miss devices registered indirectly e.g. btrfs-control/nvme-fabrics);
// name/fops offsets from the DWARF member map, values via cstr/constAtOffset.  Emits MISC<name><fops>.
static void enumMiscDevices(Module &M, const DataLayout &DL) {
  auto it = g_dwFieldOffset.find("miscdevice");
  if (it == g_dwFieldOffset.end())
    return;
  auto no = it->second.find("name"), fo = it->second.find("fops");
  if (no == it->second.end() || fo == it->second.end())
    return;
  auto nno = it->second.find("nodename");   // the /dev node path (may be absent in older layouts)
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.hasInitializer())
      continue;
    SmallVector<DIGlobalVariableExpression *, 1> GVEs;
    GV.getDebugInfo(GVEs);
    bool isMisc = false;
    for (auto *E : GVEs)
      if (DICompositeType *c = diComposite(E->getVariable()->getType()))
        isMisc |= (c->getName() == "miscdevice");
    if (!isMisc)
      continue;
    Constant *init = peelKasanGlobal(GV.getInitializer());
    Constant *nameC = constAtOffset(init, no->second, DL);
    Constant *fopsC = constAtOffset(init, fo->second, DL);
    std::string name = nameC ? cstr(nameC) : "";
    // miscdevice.nodename, when non-null, is the ACTUAL /dev node path -- it may carry a subdir that the
    // .name identifier omits (tun: .name="tun" but .nodename="net/tun" -> node at /dev/net/tun; ucma:
    // "infiniband/rdma_cm").  Prefer it so the emitted MISC devpath is EXACT and the downstream anchor needs
    // no basename guess (which would cross-match e.g. /proc/sys/kernel/watchdog to /dev/watchdog).
    if (nno != it->second.end())
      if (Constant *nodeC = constAtOffset(init, nno->second, DL)) {
        std::string node = cstr(nodeC);
        if (!node.empty())
          name = node;
      }
    auto *fopsGV = fopsC ? dyn_cast<GlobalVariable>(fopsC->stripPointerCasts()) : nullptr;
    if (!name.empty() && fopsGV && !fopsGV->getName().empty())
      outs() << "MISC\t" << name << "\t" << fopsGV->getName().str() << "\n";
  }
}

// IFOP: a file_operations whose address is taken in an INSTRUCTION (store i_fop/cdev->ops, a registration
// call arg, a select) is INSTALLED -- the structural install proof, vs a mere global-initializer reference.
// Plus file_operations referenced inside a proc pid_entry table (passed to proc_pident_lookup/readdir, the
// inode is populated from it).  file_operations identified by DWARF type, never by name.  Emits IFOP<fops>.
static bool gvHasDwarfType(GlobalVariable *gv, StringRef tn) {
  SmallVector<DIGlobalVariableExpression *, 1> GVEs;
  gv->getDebugInfo(GVEs);
  for (auto *E : GVEs)
    if (DICompositeType *c = diComposite(E->getVariable()->getType()))
      if (c->getName() == tn)
        return true;
  return false;
}

// file_operations by DWARF type (definitions) OR by struct VALUE type.  A fops installed via another TU's
// pid_entry/tree_descr table is only an `external constant %struct.file_operations` DECLARATION in this
// batch -- no DIGlobalVariable, so gvHasDwarfType misses it -- but it keeps the struct value type, and its
// .fop slot in the fill table is the install proof (this is still by type, never by name).
static bool gvIsFileOps(GlobalVariable *gv) {
  return gv && (gvHasDwarfType(gv, "file_operations") ||
                bareStructName(tyName(gv->getValueType())) == "file_operations");
}

static bool gvIsInodeOps(GlobalVariable *gv) {
  return gv && (gvHasDwarfType(gv, "inode_operations") ||
                bareStructName(tyName(gv->getValueType())) == "inode_operations");
}

static bool gvIsStashedOps(GlobalVariable *gv) {
  return gv && (gvHasDwarfType(gv, "stashed_operations") ||
                bareStructName(tyName(gv->getValueType())) == "stashed_operations");
}

// The INSTALL-STORE meta-form of the dispatch-install framework: the globals a function installs as an
// inode's i_fop (a store of a fops global).  SUBTREE's blanketFops, DYNCHILD, SPECIALFOP and PERSISTFOP are
// all this ONE scan -- they differ only in (reachability `maxHops`, an `exclude` set, and the `gate` that
// decides what counts as a fops global: gvIsFileOps by default; any global for SPECIALFOP; DWARF-only for
// PERSISTFOP).  Callers apply their own uniqueness / preconditions.
static std::set<std::string>
globalsInstalledIn(Function *start, int maxHops, const std::set<std::string> &exclude,
                   std::function<bool(GlobalVariable *)> gate) {
  std::set<std::string> found;
  std::set<Function *> seen;
  std::vector<std::pair<Function *, int>> work{{start, 0}};
  while (!work.empty()) {
    Function *F = work.back().first;
    int hop = work.back().second;
    work.pop_back();
    if (!F || F->isDeclaration() || !seen.insert(F).second)
      continue;
    for (BasicBlock &BB : *F)
      for (Instruction &I : BB) {
        if (auto *SI = dyn_cast<StoreInst>(&I))
          if (auto *gv = dyn_cast<GlobalVariable>(SI->getValueOperand()->stripPointerCasts()))
            if (gate(gv) && !exclude.count(gv->getName().str()))
              found.insert(gv->getName().str());
        if (hop < maxHops)
          if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *cal = CI->getCalledFunction())
              work.push_back({cal, hop + 1});
      }
  }
  return found;
}

static std::set<std::string>
fopsInstalledIn(Function *start, int maxHops = 0, const std::set<std::string> &exclude = {},
                std::function<bool(GlobalVariable *)> gate = gvIsFileOps) {
  return globalsInstalledIn(start, maxHops, exclude, gate);
}

// The base global a value ultimately refers to through GEP/ptrtoint/bitcast constant-expr chains (the loop
// base of `for (e = table; ...; e++)`, ptrtoint'd table addresses from ASAN, etc.).  "" for non-global.
static GlobalVariable *baseGlobalOf(Value *v) {
  for (int i = 0; v && i < 8; i++) {
    v = v->stripPointerCasts();
    if (auto *gv = dyn_cast<GlobalVariable>(v))
      return gv;
    auto *ce = dyn_cast<ConstantExpr>(v);
    if (ce && (ce->getOpcode() == Instruction::GetElementPtr || ce->getOpcode() == Instruction::PtrToInt))
      v = ce->getOperand(0);
    else
      return nullptr;
  }
  return nullptr;
}

static void enumInstalledFops(Module &M, const DataLayout &DL) {
  std::set<std::string> proven;
  // Recursively harvest every file_operations global inside a fops table's initializer (its .fop/.fops slot).
  auto walkTable = [&](GlobalVariable *tbl) {
    if (!tbl || !tbl->hasInitializer())
      return;
    std::vector<Constant *> work{peelKasanGlobal(tbl->getInitializer())};
    while (!work.empty()) {
      Constant *c = work.back();
      work.pop_back();
      if (!c)
        continue;
      if (auto *gv = dyn_cast<GlobalVariable>(c->stripPointerCasts()))
        if (gvIsFileOps(gv))                        // accept external decls: cross-TU .fop in this fill table
          proven.insert(gv->getName().str());
      if (auto *agg = dyn_cast<ConstantAggregate>(c))
        for (unsigned i = 0; i < agg->getNumOperands(); i++)
          if (Constant *e = agg->getAggregateElement(i))
            work.push_back(e);
    }
  };
  // Emit the NAME->fops of each entry in a pid_entry / tree_descr fill table (the structural typed table:
  // key = the entry's name string, handler = its file_operations pointer).  Lets the resolver join a syz
  // open path's terminal name to the installed fops WITHOUT a hardcoded resource->fops map -- e.g.
  // attr_dir_stuff["current"]=proc_pid_attr_operations, tgid_base_stuff["pagemap"]=proc_pagemap_operations,
  // bm_files["register"]=bm_register_operations.  Fields found by TYPE (a c-string ptr / a file_operations
  // ptr), never by hardcoded offset.
  // Collect every pid_entry/tree_descr ENTRY (any aggregate holding BOTH a name c-string ptr and a
  // file_operations ptr: pid_entry {name,len,mode,iop,fop} / tree_descr {name,ops,mode}).  Recurse through
  // the table's array/packed-struct/KASAN wrappers uniformly -- a sparse tree_descr init lowers to a packed
  // struct of mixed entry types, not a [N x tree_descr] array.  Also keep each entry's NON-fops globals (its
  // inode_operations) so the nesting below can link a DIR entry to the sub-table its lookup installs.
  struct Ent { GlobalVariable *tbl; std::string name, fops; std::vector<GlobalVariable *> ops; };
  std::vector<Ent> ents;
  std::function<void(GlobalVariable *, Constant *)> collect = [&](GlobalVariable *tbl, Constant *c) {
    auto *agg = dyn_cast_or_null<ConstantAggregate>(c);
    if (!agg)
      return;
    std::string name, fops;
    std::vector<GlobalVariable *> ops;
    for (unsigned j = 0; j < agg->getNumOperands(); j++) {
      Constant *op = agg->getAggregateElement(j);
      if (!op)
        continue;
      if (auto *gv = dyn_cast<GlobalVariable>(op->stripPointerCasts())) {
        ops.push_back(gv);                        // keep every op global (iop AND fop) for the nesting check
        if (gvIsFileOps(gv)) {
          if (fops.empty())
            fops = gv->getName().str();
        } else if (name.empty()) {
          std::string s = cstr(op);               // name string ptr; ops globals read as ""
          if (!s.empty())
            name = s;
        }
        continue;
      }
      if (name.empty()) {
        std::string s = cstr(op);
        if (!s.empty())
          name = s;
      }
    }
    if (!name.empty() && !fops.empty()) {
      ents.push_back({tbl, name, fops, ops});
      return;                                     // leaf entry
    }
    for (unsigned j = 0; j < agg->getNumOperands(); j++)   // table/array/wrapper -> recurse
      collect(tbl, agg->getAggregateElement(j));
  };
  auto emitNamed = [&](GlobalVariable *tbl) {
    if (tbl && tbl->hasInitializer())
      collect(tbl, peelKasanGlobal(tbl->getInitializer()));
  };
  for (GlobalVariable &GV : M.globals()) {       // (1) address taken in an instruction == installed
    if (!gvHasDwarfType(&GV, "file_operations"))
      continue;
    for (User *U : GV.users())
      if (isa<Instruction>(U)) {
        proven.insert(GV.getName().str());
        break;
      }
  }
  for (GlobalVariable *tbl :                      // (2) file_operations inside a name->fops fill table PASSED
       globalsPassedTo(M, {"proc_pident_lookup", "proc_pident_readdir",  // to the installer: proc pid_entry
                           "simple_fill_super"}, 2)) {                   // (arg2), simple_fill_super (arg2)
    walkTable(tbl);
    emitNamed(tbl);                              // + the name->fops pairs (TFOP) for the path join
  }
  // (3) a name->fops table ITERATED locally by an installer (binder loops binder_debugfs_entries[] to call
  // debugfs_create_file(e->fops)) is passed to no known callee, but the installer references the table
  // global directly.  Walk fops tables referenced in any function that calls debugfs_create_file(_full).
  std::set<GlobalVariable *> localTabs;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    bool installs = false;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *CI = dyn_cast<CallInst>(&I))
          if (Function *cal = CI->getCalledFunction())
            if (stripSuffix(cal->getName().str()).rfind("debugfs_create_file", 0) == 0)
              installs = true;
    if (!installs)
      continue;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        for (Value *op : I.operands())
          if (GlobalVariable *g = baseGlobalOf(op))
            localTabs.insert(g);
  }
  for (GlobalVariable *tbl : localTabs)
    walkTable(tbl);
  // TFOP nesting: a pident SUB-table is looked up (proc_pident_lookup(sub)) by a fn referenced as .lookup in
  // the parent DIR entry's inode_operations -> that parent entry's NAME is the sub-table's path prefix.  Emit
  // each entry's path RELATIVE to its fs root (attr/current, clear_refs, register) so the resolver matches
  // the FULL syz path and a basename that recurs across dirs (/proc/<pid>/cgroup vs /proc/<pid>/ns/cgroup)
  // cannot collide.
  std::map<GlobalVariable *, Function *> pidentCaller;
  for (Function &F : M)
    if (!F.isDeclaration())
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *cal = CI->getCalledFunction()) {
              std::string cn = stripSuffix(cal->getName().str());
              if ((cn == "proc_pident_lookup" || cn == "proc_pident_readdir"))
                if (GlobalVariable *t = argGlobal(CI, 2))
                  pidentCaller[t] = &F;
            }
  std::map<GlobalVariable *, std::string> prefix;
  for (auto &kv : pidentCaller) {
    std::string cn = kv.second->getName().str();
    for (auto &e : ents) {                        // parent DIR entry whose ops reference this sub-table's caller
      bool hit = false;
      for (GlobalVariable *g : e.ops) {
        if (!g || !g->hasInitializer())
          continue;
        std::vector<Constant *> work{g->getInitializer()};
        while (!work.empty() && !hit) {
          Constant *c = work.back();
          work.pop_back();
          if (!c)
            continue;
          if (auto *fn = dyn_cast<Function>(c->stripPointerCasts()))
            hit |= (fn->getName() == cn);
          if (auto *agg = dyn_cast<ConstantAggregate>(c))
            for (unsigned i = 0; i < agg->getNumOperands(); i++)
              work.push_back(agg->getAggregateElement(i));
        }
        if (hit)
          break;
      }
      if (hit) {
        prefix[kv.first] = e.name;
        break;
      }
    }
  }
  std::set<std::string> emittedT;
  auto relpath = [&](const Ent &e) {
    auto pit = prefix.find(e.tbl);
    return (pit != prefix.end() ? pit->second + "/" : "") + e.name;
  };
  for (auto &e : ents) {
    std::string rel = relpath(e);
    if (emittedT.insert(rel + "\t" + e.fops).second)
      outs() << "TFOP\t" << rel << "\t" << e.fops << "\n";
  }
  // MAGICCALL: a fill-table directory entry whose lookup installs a symlink inode_operations with a
  // get_link callback that performs nd_jump_link.  Emit a direct callee only when one of its arguments is
  // the SAME SSA path pointer passed to nd_jump_link, including that argument index.  The resolver later
  // intersects (function,arg-index) with PATHFOP from other linked batches.  This preserves the cross-batch
  // semantic edge without guessing that a directory named "ns" belongs to nsfs or accepting an unrelated
  // path-producing call in the same get_link callback.
  std::set<std::string> emittedMagic;
  for (auto &e : ents)
    for (GlobalVariable *dirOps : e.ops) {
      if (!gvIsInodeOps(dirOps))
        continue;
      ConstFieldRead lookupField = readConstField(dirOps, {"lookup"}, DL);
      auto *lookup = dyn_cast_or_null<Function>(
          lookupField.value ? lookupField.value->stripPointerCasts() : nullptr);
      if (!lookup)
        continue;
      for (const std::string &opsName :
           globalsInstalledIn(lookup, 2, {}, gvIsInodeOps)) {
        GlobalVariable *linkOps = M.getNamedGlobal(opsName);
        ConstFieldRead getLinkField = readConstField(linkOps, {"get_link"}, DL);
        auto *getLink = dyn_cast_or_null<Function>(
            getLinkField.value ? getLinkField.value->stripPointerCasts() : nullptr);
        if (!getLink)
          continue;
        std::set<Value *> jumpPaths;
        for (BasicBlock &BB : *getLink)
          for (Instruction &I : BB)
            if (auto *CI = dyn_cast<CallInst>(&I))
              if (Function *cal = CI->getCalledFunction())
                if (stripSuffix(cal->getName().str()) == "nd_jump_link" && CI->arg_size() >= 1)
                  jumpPaths.insert(CI->getArgOperand(0)->stripPointerCasts());
        if (jumpPaths.empty())
          continue;
        std::string rel = relpath(e);
        for (BasicBlock &BB : *getLink)
          for (Instruction &I : BB)
            if (auto *CI = dyn_cast<CallInst>(&I))
              if (Function *cal = CI->getCalledFunction()) {
                if (cal->isIntrinsic() || stripSuffix(cal->getName().str()) == "nd_jump_link")
                  continue;
                for (unsigned arg = 0; arg < CI->arg_size(); ++arg) {
                  Value *value = CI->getArgOperand(arg)->stripPointerCasts();
                  if (!jumpPaths.count(value))
                    continue;
                  std::string key = rel + "\t" + cal->getName().str() + "\t" + std::to_string(arg);
                  if (emittedMagic.insert(key).second)
                    outs() << "MAGICCALL\t" << key << "\n";
                }
              }
      }
    }
  for (auto &f : proven)
    outs() << "IFOP\t" << f << "\n";
}

// PATHFOP: a function calls path_from_stashed with a mount loaded from global M and passes one of its own
// arguments as the output path.  M is initialized from kern_mount(FSTYPE); FSTYPE.init_fs_context stores a
// typed stashed_operations table; that table's init_inode installs exactly one file_operations.  Therefore
// the (function,path-argument-index) resolves a path whose inode dispatches through that fops.  Every hop is
// recovered from SSA, typed global fields, or a registration API; no filesystem/function/global name is
// matched.  MAGICCALL joins this exact argument identity across linked batches.
static void enumPathResolvedFops(Module &M, const DataLayout &DL) {
  std::map<GlobalVariable *, std::set<GlobalVariable *>> mountTypes;
  for (Function &F : M)
    if (!F.isDeclaration())
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *SI = dyn_cast<StoreInst>(&I)) {
            auto *mount = dyn_cast<GlobalVariable>(SI->getPointerOperand()->stripPointerCasts());
            auto *create = dyn_cast<CallInst>(SI->getValueOperand()->stripPointerCasts());
            if (!mount || !create)
              continue;
            Function *cal = create->getCalledFunction();
            if (!cal || stripSuffix(cal->getName().str()) != "kern_mount" || create->arg_size() < 1)
              continue;
            if (GlobalVariable *fsType = argGlobal(create, 0))
              mountTypes[mount].insert(fsType);
          }

  std::map<GlobalVariable *, std::set<std::string>> mountFops;
  for (auto &entry : mountTypes)
    for (GlobalVariable *fsType : entry.second) {
      ConstFieldRead initField = readConstField(fsType, {"init_fs_context"}, DL);
      auto *initContext = dyn_cast_or_null<Function>(
          initField.value ? initField.value->stripPointerCasts() : nullptr);
      if (!initContext || initContext->isDeclaration())
        continue;
      std::set<GlobalVariable *> stashedTables;
      for (BasicBlock &BB : *initContext)
        for (Instruction &I : BB)
          if (auto *SI = dyn_cast<StoreInst>(&I))
            if (auto *gv = dyn_cast<GlobalVariable>(
                    SI->getValueOperand()->stripPointerCasts()))
              if (gvIsStashedOps(gv))
                stashedTables.insert(gv);
      for (GlobalVariable *table : stashedTables) {
        ConstFieldRead inodeField = readConstField(table, {"init_inode"}, DL);
        auto *initInode = dyn_cast_or_null<Function>(
            inodeField.value ? inodeField.value->stripPointerCasts() : nullptr);
        if (!initInode)
          continue;
        std::set<std::string> installed = fopsInstalledIn(initInode);
        mountFops[entry.first].insert(installed.begin(), installed.end());
      }
    }

  std::set<std::string> emitted;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || CI->arg_size() < 2)
          continue;
        Function *cal = CI->getCalledFunction();
        if (!cal || stripSuffix(cal->getName().str()) != "path_from_stashed")
          continue;
        if (CI->arg_size() < 4)
          continue;
        auto *pathArg = dyn_cast<Argument>(CI->getArgOperand(3)->stripPointerCasts());
        if (!pathArg || pathArg->getParent() != &F)
          continue;
        auto *load = dyn_cast<LoadInst>(CI->getArgOperand(1)->stripPointerCasts());
        auto *mount = load ? dyn_cast<GlobalVariable>(
            load->getPointerOperand()->stripPointerCasts()) : nullptr;
        if (!mount)
          continue;
        auto fit = mountFops.find(mount);
        if (fit == mountFops.end() || fit->second.size() != 1)
          continue;
        std::string key = F.getName().str() + "\t" + std::to_string(pathArg->getArgNo()) +
                          "\t" + *fit->second.begin();
        if (emitted.insert(key).second)
          outs() << "PATHFOP\t" << key << "\n";
      }
  }
}

static std::vector<Constant *> constantTableEntries(GlobalVariable *table) {
  std::vector<Constant *> entries;
  if (!table || !table->hasInitializer())
    return entries;
  Constant *init = peelKasanGlobal(table->getInitializer());
  if (auto *array = dyn_cast<ConstantArray>(init)) {
    for (unsigned index = 0; index < array->getNumOperands(); ++index)
      entries.push_back(array->getOperand(index));
    return entries;
  }
  if (auto *packed = dyn_cast<ConstantStruct>(init))
    for (unsigned index = 0; index < packed->getNumOperands(); ++index)
      if (auto *entry = dyn_cast<Constant>(packed->getOperand(index)))
        if (isa<StructType>(entry->getType()))
          entries.push_back(entry);
  return entries;
}

static std::string constantCString(Constant *value) {
  if (!value)
    return "";
  if (std::string indirect = cstr(value); !indirect.empty())
    return indirect;
  value = peelKasanGlobal(value);
  auto *bytes = dyn_cast<ConstantDataArray>(value);
  if (!bytes || !bytes->getElementType()->isIntegerTy(8))
    return "";
  StringRef raw = bytes->getRawDataValues();
  return raw.substr(0, raw.find('\0')).str();
}

static Argument *loadedFieldBaseArgument(Value *value, const DataLayout &DL,
                                         std::string &fieldName) {
  auto *load = dyn_cast<LoadInst>(value ? value->stripPointerCasts() : nullptr);
  if (!load)
    return nullptr;
  std::string loc = absLoc(load->getPointerOperand(), DL);
  auto plus = loc.rfind('+');
  if (loc.rfind("struct.", 0) == 0 && plus != std::string::npos)
    fieldName = dwFieldNameAt(loc.substr(7, plus - 7),
                              strtoll(loc.c_str() + plus + 1, nullptr, 10));
  Value *base = load->getPointerOperand()->stripPointerCasts();
  while (auto *gep = dyn_cast<GEPOperator>(base))
    base = gep->getPointerOperand()->stripPointerCasts();
  return dyn_cast<Argument>(base);
}

// CFTYPE/CFTOWNER/CGNAME/CGLEGACY: recover the complete cgroup control-file dispatch key and its typed
// callback from bitcode.  A raw cftype name such as "max" is NOT a userspace key by itself: cgroup prefixes
// it with the owning subsystem's default or legacy name (memory.max, pids.max, blkio.max, ...).  Emitting
// table ownership prevents same-leaf callbacks from different controllers being merged by a basename join.
//
// Ownership arrives through three forms, all represented as the same fact:
//   * cgroup_subsys.{dfl_cftypes,legacy_cftypes} initializer fields;
//   * direct cgroup_add_{dfl,legacy}_cftypes(&subsys, table) calls;
//   * an interprocedural installer summary where such a call reads the table field from a function argument
//     (blkcg_policy_register), joined to globals passed at its callsites.
// Field identity comes from DWARF, callback values from constant initializers, and the subsystem name from
// the parallel cgroup_subsys[] / cgroup_subsys_name[] registration tables.
static void enumCftypeTables(Module &M, const DataLayout &DL) {
  std::set<std::string> emitted;
  auto emit = [&](const std::string &kind, const std::string &payload) {
    std::string row = kind + "\t" + payload;
    if (emitted.insert(row).second)
      outs() << row << "\n";
  };
  auto emitOwner = [&](GlobalVariable *table, StringRef mode, GlobalVariable *subsys) {
    if (table && subsys)
      emit("CFTOWNER", table->getName().str() + "\t" + mode.str() + "\t" +
                           subsys->getName().str());
  };

  for (GlobalVariable &table : M.globals()) {
    std::vector<Constant *> entries = constantTableEntries(&table);
    if (entries.empty())
      continue;
    std::string structName = firstElementStructName(table, entries.front()->getType());
    if (bareStructName(structName) != "cftype")
      continue;
    FieldLoc nameLoc = layoutFieldLoc(structName, {"name"});
    if (nameLoc.offset < 0)
      continue;
    for (Constant *entry : entries) {
      std::string key = constantCString(constAtOffset(entry, nameLoc.offset, DL));
      if (key.empty())
        continue;
      auto emitCallbacks = [&](StringRef role, std::initializer_list<const char *> fields) {
        for (const char *field : fields) {
          FunctionFieldRead callback = readFunctionField(entry, structName, {field}, DL);
          if (callback.value != "-")
            emit("CFTYPE", table.getName().str() + "\t" + key + "\t" + role.str() +
                               "\t" + callback.value);
        }
      };
      emitCallbacks("write", {"write", "write_u64", "write_s64"});
      emitCallbacks("read", {"read_u64", "read_s64", "seq_show"});
      emitCallbacks("open", {"open"});
    }
  }

  for (GlobalVariable &subsys : M.globals()) {
    if (globalDebugStructName(subsys) != "cgroup_subsys")
      continue;
    ConstFieldRead dfl = readConstField(&subsys, {"dfl_cftypes"}, DL);
    ConstFieldRead legacy = readConstField(&subsys, {"legacy_cftypes"}, DL);
    emitOwner(asGlobal(dfl.value), "dfl", &subsys);
    emitOwner(asGlobal(legacy.value), "legacy", &subsys);
    ConstFieldRead legacyName = readConstField(&subsys, {"legacy_name"}, DL);
    std::string name = constantCString(legacyName.value);
    if (!name.empty())
      emit("CGLEGACY", subsys.getName().str() + "\t" + name);
  }

  GlobalVariable *subsystems = M.getNamedGlobal("cgroup_subsys");
  GlobalVariable *subsystemNames = M.getNamedGlobal("cgroup_subsys_name");
  std::vector<Constant *> subsystemEntries = constantTableEntries(subsystems);
  std::vector<Constant *> nameEntries = constantTableEntries(subsystemNames);
  if (subsystemEntries.size() == nameEntries.size())
    for (unsigned index = 0; index < subsystemEntries.size(); ++index) {
      auto *subsys = asGlobal(subsystemEntries[index]);
      std::string name = constantCString(nameEntries[index]);
      if (subsys && !name.empty())
        emit("CGNAME", subsys->getName().str() + "\t" + name);
    }

  struct OwnerSummary {
    Function *function;
    unsigned argument;
    std::string mode;
    GlobalVariable *subsys;
  };
  std::vector<OwnerSummary> summaries;
  for (Function &function : M) {
    if (function.isDeclaration())
      continue;
    for (BasicBlock &block : function)
      for (Instruction &instruction : block) {
        auto *call = dyn_cast<CallInst>(&instruction);
        Function *callee = call ? call->getCalledFunction() : nullptr;
        if (!callee || call->arg_size() < 2)
          continue;
        std::string calleeName = stripSuffix(callee->getName().str());
        std::string mode;
        if (calleeName == "cgroup_add_dfl_cftypes")
          mode = "dfl";
        else if (calleeName == "cgroup_add_legacy_cftypes")
          mode = "legacy";
        else
          continue;
        GlobalVariable *subsys = argGlobal(call, 0);
        if (!subsys)
          continue;
        if (GlobalVariable *table = argGlobal(call, 1)) {
          emitOwner(table, mode, subsys);
          continue;
        }
        std::string fieldName;
        if (Argument *argument = loadedFieldBaseArgument(call->getArgOperand(1), DL, fieldName))
          if (argument->getParent() == &function &&
              fieldName == (mode == "dfl" ? "dfl_cftypes" : "legacy_cftypes"))
            summaries.push_back({&function, argument->getArgNo(), mode, subsys});
      }
  }

  for (const OwnerSummary &summary : summaries)
    for (Function &caller : M)
      for (BasicBlock &block : caller)
        for (Instruction &instruction : block) {
          auto *call = dyn_cast<CallInst>(&instruction);
          if (!call || call->getCalledFunction() != summary.function ||
              summary.argument >= call->arg_size())
            continue;
          GlobalVariable *descriptor = argGlobal(call, summary.argument);
          if (!descriptor)
            continue;
          const char *field = summary.mode == "dfl" ? "dfl_cftypes" : "legacy_cftypes";
          ConstFieldRead table = readConstField(descriptor, {field}, DL);
          emitOwner(asGlobal(table.value), summary.mode, summary.subsys);
        }
}

// KERNFSOPEN: kernfs_get_inode installs one of several fops according to node type (the source-level
// kernfs_init_inode helper is inlined into it in this build).  Among those installed fops, recover the unique
// table whose typed .open field is populated.  A cftype-backed control file is a KERNFS_FILE, so its outer
// VFS open dispatch enters this handler before any optional cftype.open callback.  The recognizer names the
// stable kernfs API but never matches the fops or handler symbol.
static void enumKernfsOpen(Module &M, const DataLayout &DL) {
  Function *getInode = M.getFunction("kernfs_get_inode");
  if (!getInode)
    return;
  std::set<std::pair<std::string, std::string>> candidates;
  for (const std::string &opsName : fopsInstalledIn(getInode)) {
    GlobalVariable *ops = M.getNamedGlobal(opsName);
    ConstFieldRead openField = readConstField(ops, {"open"}, DL);
    auto *handler = dyn_cast_or_null<Function>(
        openField.value ? openField.value->stripPointerCasts() : nullptr);
    if (handler)
      candidates.insert({opsName, handler->getName().str()});
  }
  if (candidates.size() == 1)
    outs() << "KERNFSOPEN\t" << candidates.begin()->first << "\t"
           << candidates.begin()->second << "\n";
}

// SUBTREE: a "blanket" file_operations installed on EVERY inode of a proc subtree (the ① subtree-blanket
// ObjectId method of the dispatch-install framework).  proc_mkdir(NAME) creates a subtree root and stores
// its inode_operations IOPS into the PDE's proc_iops; IOPS.lookup instantiates each child by reaching a
// make-inode that does child->i_fop = &F for a CONSTANT F.  So every file under /proc/NAME dispatches
// through F (sysctl: /proc/sys/* -> proc_sys_file_operations), letting the resolver bind such opens WITHOUT
// a hardcoded path->fops map.  Fields by TYPE (proc_iops = the sole inode_operations stored into the PDE;
// i_fop = the sole file_operations store in the make-inode), never by hardcoded offset; the fops must be
// uniquely determined (else a conservative skip).
static void enumSubtreeBlanket(Module &M) {
  // The subtree's blanket LEAF fops = the single file_operations the lookup's make-inode installs, EXCLUDING
  // the dir's own fops (lookup instantiates both child dirs and child files); "" if none or ambiguous (>1) ->
  // a conservative skip.  The install-store scan is the shared fopsInstalledIn primitive.
  auto blanketFops = [&](Function *start, int maxHops, const std::set<std::string> &exclude) -> std::string {
    std::set<std::string> found = fopsInstalledIn(start, maxHops, exclude);
    return found.size() == 1 ? *found.begin() : "";
  };
  std::set<std::string> emitted;
  for (Function &Fn : M)
    for (BasicBlock &BB : Fn)
      for (Instruction &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI)
          continue;
        Function *cal = CI->getCalledFunction();
        if (!cal || stripSuffix(cal->getName().str()) != "proc_mkdir" || CI->arg_size() < 1)
          continue;
        std::string name = cstr(CI->getArgOperand(0));
        if (name.empty())
          continue;
        // the ops stored into the PDE (proc_mkdir result)'s fields: proc_iops (the sole inode_operations) is
        // the subtree's dir inode-ops; proc_dir_ops (a file_operations) is the dir's OWN fops -- excluded so
        // the leaf-file fops is what the make-inode uniquely leaves.  Type-gated, so offsets are never hardcoded.
        GlobalVariable *iops = nullptr;
        std::set<std::string> dirFops;
        for (User *U : CI->users()) {
          auto *gep = dyn_cast<GetElementPtrInst>(U);
          if (!gep)
            continue;
          for (User *GU : gep->users())
            if (auto *SI = dyn_cast<StoreInst>(GU))
              if (auto *gv = dyn_cast<GlobalVariable>(SI->getValueOperand()->stripPointerCasts())) {
                if (gvIsInodeOps(gv))
                  iops = gv;
                else if (gvIsFileOps(gv))
                  dirFops.insert(gv->getName().str());
              }
        }
        if (!iops || !iops->hasInitializer())
          continue;
        // IOPS.lookup (inode_operations field 0) instantiates children -> follow it to the blanket make-inode
        Function *lookup = nullptr;
        if (auto *agg = dyn_cast<ConstantAggregate>(peelKasanGlobal(iops->getInitializer())))
          if (agg->getNumOperands() > 0 && agg->getAggregateElement(0u))
            lookup = dyn_cast<Function>(agg->getAggregateElement(0u)->stripPointerCasts());
        if (!lookup)
          continue;
        std::string f = blanketFops(lookup, 2, dirFops);
        if (!f.empty() && emitted.insert(name + "\t" + f).second)
          outs() << "SUBTREE\t" << name << "\t" << f << "\n";
      }
  // register_sysctl_mount_point(REL) marks /proc/sys/REL as a MOUNT POINT -- another fs (binfmt_misc,
  // fuse/connections) mounts there, so files below it are NOT the sysctl blanket fops.  Emit SUBTREEHOLE so
  // the resolver carves that prefix out of the subtree join.
  for (Function &Fn : M)
    for (BasicBlock &BB : Fn)
      for (Instruction &I : BB)
        if (auto *CI = dyn_cast<CallInst>(&I))
          if (Function *cal = CI->getCalledFunction())
            if (stripSuffix(cal->getName().str()) == "register_sysctl_mount_point" && CI->arg_size() >= 1) {
              std::string rel = cstr(CI->getArgOperand(0));
              if (!rel.empty() && emitted.insert("HOLE\t" + rel).second)
                outs() << "SUBTREEHOLE\t" << rel << "\n";
            }
  // DYNCHILD: a fn that installs a SINGLE file_operations as the i_fop of an inode it creates -> the fops of
  // the DYNAMIC children it spawns.  binfmt_misc's register-file write (bm_register_write) creates each
  // runtime-named entry with bm_entry_operations; the resolver joins this to a static file's .write handler
  // to type the dynamic siblings below that fs's mount.  Unique-gated (a fn storing >1 distinct fops is skipped).
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::set<std::string> installed = fopsInstalledIn(&F);   // install-store meta-form (direct, gated, unique)
    if (installed.size() == 1)
      outs() << "DYNCHILD\t" << F.getName().str() << "\t" << *installed.begin() << "\n";
  }
}

// SPECIALFOP: a file_operations whose address is stored inside init_special_inode -- a device-node inode
// (S_ISCHR -> def_chr_fops, S_ISBLK -> def_blk_fops, fifo/sock) gets its i_fop here, not via
// cdev_add/misc_register, so the devnode/cdev recognizers miss it.  Mechanism (a store in this one
// function), never a name.  Emits SPECIALFOP<fops>.
static void enumSpecialInodeFops(Module &M) {
  Function *F = M.getFunction("init_special_inode");
  if (!F)
    return;
  // install-store meta-form: every global init_special_inode stores as i_fop (def_chr_fops/def_blk_fops/...);
  // the any-global gate keeps the original ungated behaviour (this fn only ever stores fops there).
  for (auto &f : fopsInstalledIn(F, 0, {}, [](GlobalVariable *) { return true; }))
    outs() << "SPECIALFOP\t" << f << "\n";
}

// PERSISTFOP: a file_operations stored in a function that also makes its dentry persistent (calls
// d_make_persistent) -- the inode-construction path of a persistent pseudo-fs.  d_make_persistent is shared
// (binderfs binder_fops/binder_ctl_fops, binfmt_misc, fuse-ctl, pstore, eventfs, rpc_pipe, ...), so this is
// the general "installed on a persistent pseudo-fs dentry" proof; each consumer filters to its own fops
// (e.g. binderfs checks binder_fops/binder_ctl_fops).  Structural (store + persist call), never the name.
static void enumPersistentDentryFops(Module &M) {
  std::set<std::string> out;
  for (Function &F : M) {
    bool persists = false;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *CI = dyn_cast<CallInst>(&I))
          if (Function *c = CI->getCalledFunction())
            if (stripSuffix(c->getName().str()) == "d_make_persistent")
              persists = true;
    if (!persists)
      continue;
    // install-store meta-form, DWARF-only gate (a persistent pseudo-fs dentry's i_fop)
    for (auto &f : fopsInstalledIn(&F, 0, {},
                                   [](GlobalVariable *gv) { return gvHasDwarfType(gv, "file_operations"); }))
      out.insert(f);
  }
  for (auto &f : out)
    outs() << "PERSISTFOP\t" << f << "\n";
}

// PROTOSW: inet_protosw entries (type, protocol, ops, prot/sk_prot, core|ext) -- the inet socket dispatch
// table.  inet_protosw is anonymized in the IR, so fields are read at DWARF member offsets via constAtOffset.
// core = an array-of-inet_protosw global (@inetsw_array/@inetsw6_array, registered via a pointer loop so
// globalsPassedTo can't see it); ext = a standalone inet_protosw global (inet_register_protosw).  Family is
// NOT emitted here -- the consumer joins it from OPSFIELD proto_ops.family (aggregated, so cross-batch ops
// resolve).  Identified by DWARF type, never by global name.  Emits PROTOSW<type><proto><ops><prot><src>.
static int inetProtoswKind(GlobalVariable &GV) {  // 1 = array (core), 2 = single (ext), 0 = not
  SmallVector<DIGlobalVariableExpression *, 1> GVEs;
  GV.getDebugInfo(GVEs);
  for (auto *E : GVEs) {
    DICompositeType *c = diComposite(E->getVariable()->getType());
    if (!c)
      continue;
    if (c->getTag() == dwarf::DW_TAG_array_type) {
      if (auto *el = diComposite(c->getBaseType()))
        if (el->getName() == "inet_protosw")
          return 1;
    } else if (c->getName() == "inet_protosw") {
      return 2;
    }
  }
  return 0;
}

// SOCKPROTO: the sk_prot (struct proto) a NON-inet socket family installs.  inet recovers this from the
// inet_protosw[] table (enumProtosw); non-inet families assign sk_prot imperatively in their .create path
// -- sk_alloc(net, FAMILY, gfp, prot, kern) carries the proto as arg3, but as a VALUE, not a direct global
// (a PHI of @ieee802154_dgram/raw_prot for wpan; a param threaded from l2cap_sock_create(&l2cap_proto) via
// bt_sock_alloc for bluetooth; a per-protocol table load for phonet).  Backward-slice arg3 through
// phi/select/interprocedural-args to the proto global(s), keyed by the family const at the sk_alloc call.
// The proto globals are already REG proto rows -- this recovers only the family->proto BINDING the inet
// protosw scan cannot see.  (Direct/phi/param handled; a table load -- phonet -- is not yet followed.)
static void collectSkProtos(Value *V, std::set<GlobalVariable *> &out, std::set<Value *> &seen, int depth) {
  if (!V || depth > 8 || !seen.insert(V).second)
    return;
  V = V->stripPointerCasts();
  if (auto *gv = dyn_cast<GlobalVariable>(V)) {
    if (gvHasDwarfType(gv, "proto"))
      out.insert(gv);
    return;
  }
  if (auto *phi = dyn_cast<PHINode>(V)) {
    for (Value *iv : phi->incoming_values())
      collectSkProtos(iv, out, seen, depth + 1);
  } else if (auto *sel = dyn_cast<SelectInst>(V)) {
    collectSkProtos(sel->getTrueValue(), out, seen, depth + 1);
    collectSkProtos(sel->getFalseValue(), out, seen, depth + 1);
  } else if (auto *arg = dyn_cast<Argument>(V)) {          // interprocedural: proto threaded from callers
    Function *F = arg->getParent();
    unsigned idx = arg->getArgNo();
    for (User *u : F->users()) {
      auto *ci = dyn_cast<CallInst>(u);
      if (ci && ci->getCalledFunction() == F && idx < ci->arg_size())
        collectSkProtos(ci->getArgOperand(idx), out, seen, depth + 1);
    }
  }
}

static void protosInFn(Function *F, std::set<GlobalVariable *> &out) {   // proto globals a fn's body passes
  if (!F || F->isDeclaration())
    return;
  for (BasicBlock &BB : *F)
    for (Instruction &I : BB)
      if (auto *ci = dyn_cast<CallInst>(&I))
        for (Value *a : ci->args())
          if (auto *gv = dyn_cast<GlobalVariable>(a->stripPointerCasts()))
            if (gvHasDwarfType(gv, "proto"))
              out.insert(gv);
}

static void protoOpsInFn(Function *F, std::set<GlobalVariable *> &out) {  // proto_ops globals a fn installs
  if (!F || F->isDeclaration())
    return;
  for (BasicBlock &BB : *F)
    for (Instruction &I : BB)
      for (Value *op : I.operands())      // sock->ops = &l2cap_sock_ops -> the store's global operand
        if (auto *gv = dyn_cast<GlobalVariable>(op->stripPointerCasts()))
          if (gvHasDwarfType(gv, "proto_ops"))
            out.insert(gv);
}

static void enumSockProto(Module &M, const DataLayout &DL) {
  std::set<std::tuple<int64_t, int64_t, std::string>> rows;   // SOCKPROTO (family, protocol|-1, proto)
  std::set<std::tuple<int64_t, int64_t, std::string>> opsRows; // SOCKOPS (family, protocol|-1, proto_ops)
  // FAMILY-LEVEL (protocol=-1): sk_alloc(net, FAMILY, gfp, prot, kern) arg3 backward-slice (edge B: the
  // create->proto data flow).  Covers every family that threads the proto to sk_alloc as a value.
  if (Function *skAlloc = M.getFunction("sk_alloc"))
    for (User *u : skAlloc->users()) {
      auto *ci = dyn_cast<CallInst>(u);
      if (!ci || ci->getCalledFunction() != skAlloc || ci->arg_size() < 4)
        continue;
      auto *fam = dyn_cast<ConstantInt>(ci->getArgOperand(1));
      if (!fam)
        continue;
      int64_t family = fam->getSExtValue();
      if (family == 2 || family == 10)        // AF_INET/AF_INET6: precise via enumProtosw's inet_protosw
        continue;
      std::set<GlobalVariable *> protos;
      std::set<Value *> seen;
      collectSkProtos(ci->getArgOperand(3), protos, seen, 0);
      for (GlobalVariable *p : protos)
        rows.emplace(family, -1, p->getName().str());
    }
  // PROTOCOL-LEVEL: join edge A (the per-protocol registration `X_register(protocol, &entry)`) with edge B.
  //   bluetooth  bt_sock_register(protocol, ops): ops.create's body installs the proto (edge B on create).
  //   phonet     phonet_proto_register(protocol, entry): entry.prot IS the proto (a table-family like inet,
  //              whose proto reaches sk_alloc via a proto_tab[] load the slice can't follow -- read it here).
  // Emit both the protocol-level row AND a family-level (-1) fallback.  inet is already protocol-precise via
  // enumProtosw (inet_protosw carries type+protocol), so it needs no entry here.
  auto regLoop = [&](const char *fn, int64_t family, bool viaCreate) {
    Function *R = M.getFunction(fn);
    if (!R)
      return;
    for (User *u : R->users()) {
      auto *ci = dyn_cast<CallInst>(u);
      if (!ci || ci->getCalledFunction() != R || ci->arg_size() < 2)
        continue;
      auto *proto = dyn_cast<ConstantInt>(ci->getArgOperand(0));
      GlobalVariable *entry = asGlobal(ci->getArgOperand(1));
      if (!proto || !entry)
        continue;
      std::set<GlobalVariable *> protos, opses;
      if (viaCreate) {
        ConstFieldRead cf = readConstField(entry, {"create"}, DL);
        if (auto *createFn =
                dyn_cast_or_null<Function>(cf.value ? cf.value->stripPointerCasts() : nullptr)) {
          protosInFn(createFn, protos);       // sk_prot (for sk_prot-forwarding families)
          protoOpsInFn(createFn, opses);      // proto_ops = sock->ops (bluetooth anchors getsockopt here)
        }
      } else {
        ConstFieldRead pf = readConstField(entry, {"prot"}, DL);
        if (auto *p = dyn_cast_or_null<GlobalVariable>(pf.value ? pf.value->stripPointerCasts() : nullptr))
          protos.insert(p);
      }
      int64_t pv = proto->getSExtValue();
      for (GlobalVariable *p : protos) {
        rows.emplace(family, pv, p->getName().str());       // protocol-precise
        rows.emplace(family, -1, p->getName().str());       // family-level fallback
      }
      for (GlobalVariable *o : opses) {
        opsRows.emplace(family, pv, o->getName().str());
        opsRows.emplace(family, -1, o->getName().str());
      }
    }
  };
  regLoop("bt_sock_register", 31, true);
  regLoop("phonet_proto_register", 35, false);
  for (auto &r : rows)
    outs() << "SOCKPROTO\t" << std::get<0>(r) << "\t" << std::get<1>(r) << "\t" << std::get<2>(r) << "\n";
  for (auto &r : opsRows)
    outs() << "SOCKOPS\t" << std::get<0>(r) << "\t" << std::get<1>(r) << "\t" << std::get<2>(r) << "\n";
}

static void enumProtosw(Module &M, const DataLayout &DL) {
  auto ip = g_dwFieldOffset.find("inet_protosw");
  if (ip == g_dwFieldOffset.end())
    return;
  auto off = [&](const char *f) -> int64_t {
    auto it = ip->second.find(f);
    return it == ip->second.end() ? -1 : it->second;
  };
  int64_t tOff = off("type"), pOff = off("protocol"), prOff = off("prot"), opOff = off("ops");
  if (tOff < 0 || pOff < 0 || opOff < 0)
    return;
  auto emit = [&](Constant *entry, const char *src) {
    if (!entry)
      return;
    auto *ti = dyn_cast_or_null<ConstantInt>(constAtOffset(entry, tOff, DL));
    auto *pi = dyn_cast_or_null<ConstantInt>(constAtOffset(entry, pOff, DL));
    Constant *oc = constAtOffset(entry, opOff, DL);
    auto *ops = oc ? dyn_cast<GlobalVariable>(oc->stripPointerCasts()) : nullptr;
    if (!ti || !pi || !ops)
      return;
    Constant *prc = prOff >= 0 ? constAtOffset(entry, prOff, DL) : nullptr;
    auto *prot = prc ? dyn_cast<GlobalVariable>(prc->stripPointerCasts()) : nullptr;
    outs() << "PROTOSW\t" << ti->getSExtValue() << "\t" << pi->getSExtValue() << "\t"
           << ops->getName().str() << "\t" << (prot ? prot->getName().str() : "-") << "\t" << src << "\n";
  };
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.hasInitializer())
      continue;
    int kind = inetProtoswKind(GV);
    if (!kind)
      continue;
    Constant *payload = peelKasanGlobal(GV.getInitializer());
    if (kind == 1) {                       // core: array of inet_protosw, in registration order
      Constant *arr = payload;
      if (!isa<ConstantArray>(arr))
        if (auto *cs = dyn_cast<ConstantStruct>(arr))
          arr = cs->getNumOperands() ? cs->getAggregateElement(0u) : nullptr;
      if (auto *ca = dyn_cast_or_null<ConstantArray>(arr))
        for (unsigned i = 0; i < ca->getNumOperands(); i++)
          emit(ca->getAggregateElement(i), "core");
    } else {
      emit(payload, "ext");
    }
  }
}

// CDEV*: raw per-function facts for fd.py's extract_cdev_paths /dev-path recognizer.  The SPLIT migration:
// ir_defuse emits the structural IR facts (which fn calls which device-registration API, with which fops
// global / name-format string), and the Python side keeps the join + norm_devpath logic.  Faithful to the
// old llvm-dis regex pass: name-format strings are emitted VERBATIM (Python applies _devpath_from_format /
// _subst_format / norm_devpath), fops are emitted UNFILTERED (Python intersects with known_fops from
// reg.tsv).  The link-unit boundary the per-unit joins need = the fields.by_tu object_rel (one batch per
// ir_defuse run).  Facts:
//   CDEVADD    <fn>                      fn calls cdev_add/cdev_device_add
//   CDEVINIT   <fn> <fopsA,fopsB,...>    one per cdev_init call; ordered fops candidates (a select/phi over
//                                        fops); the first surviving the known_fops filter is the primary
//   REGCHRDEV  <fn> <name> <fops>        __register_chrdev(name, fops) -> /dev/<name>#
//   CDEVNAME   <fn> <api> <fmt> [subst]  device-name printf format by API (set_name/sprintf/kasprintf/
//                                        device_create); device_create appends its %s string-literal args
//   CHRDEVREGION <fn> <name>             (alloc|register)_chrdev_region name (the numbered region's base)
//   CLASSDEV   <class_gv> <fn>           a Function ptr inside a struct.class initializer (its .devnode cb)
//   CLASSREF   <fn> <class_gv>           fn references a struct.class global (registers/uses it)
//   MEMDEV     <name> <fops>             drivers/char/mem.c @devlist entry {name, fops}
//   CDEVFILE   <fn> <srcfile>            DISubprogram source file (per-DIFile name<->fops join)
//   CDEVFOPS   <fn> <fops>              a file_operations global referenced in fn (DWARF-typed, not by name)
//   V4L2OK / V4L2NAME <name>            __video_register_device's video/radio/vbi... family idiom
static bool isDotStr(GlobalVariable *gv) { return gv && gv->getName().starts_with(".str"); }
static bool cdevWs(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; }
// cheap, LOSS-FREE prefilter: _devpath_from_format/_devpath_pattern_from_format strip() then reject any
// internal whitespace, so a name format with interior whitespace can never be a /dev path -- skip emitting
// it (cuts the high-volume debug-printf noise: " %02x", " = %d", "%s %s") without dropping a real path.
static bool cdevPathish(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && cdevWs(s[a]))
    a++;
  while (b > a && cdevWs(s[b - 1]))
    b--;
  if (a >= b)
    return false;
  for (size_t i = a; i < b; i++)
    if (cdevWs(s[i]))
      return false;
  return true;
}
// a name/format field must not contain a TSV separator (a tab/newline would corrupt the column split on
// the Python side); a /dev path or device name never does, so this guard is loss-free.
static bool cdevClean(const std::string &s) {
  return s.find('\t') == std::string::npos && s.find('\n') == std::string::npos &&
         s.find('\r') == std::string::npos;
}
// strip leading/trailing whitespace -- the Python _devpath_from_format/_devpath_pattern_from_format do
// `.strip()` first, so emitting the trimmed format is semantically identical AND TSV-safe: cdevPathish
// already rejected interior whitespace, so a trimmed-then-pathish string has NO whitespace at all (a bare
// leading "\n%30s" debug format would otherwise leak its newline into the row).
static std::string cdevTrim(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && cdevWs(s[a]))
    a++;
  while (b > a && cdevWs(s[b - 1]))
    b--;
  return s.substr(a, b - a);
}
static void addRefGlobals(Constant *c, std::set<GlobalVariable *> &out, int depth) {
  if (!c || depth > 6)
    return;
  if (auto *gv = dyn_cast<GlobalVariable>(c)) {
    out.insert(gv);
    return;
  }
  if (isa<ConstantExpr>(c) || isa<ConstantAggregate>(c))
    for (unsigned i = 0; i < c->getNumOperands(); i++)
      addRefGlobals(dyn_cast<Constant>(c->getOperand(i)), out, depth + 1);
}

static void enumCdevRaw(Module &M, const DataLayout &DL) {
  // (0) struct.class globals -> the Function ptrs in their initializer (the .devnode callback).
  std::set<GlobalVariable *> classGlobals;
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.hasInitializer())
      continue;
    Constant *init = peelKasanGlobal(GV.getInitializer());
    if (tyName(init->getType()) != "struct.class")
      continue;
    classGlobals.insert(&GV);
    std::set<Function *> fns;
    std::vector<Constant *> work{init};
    std::set<Constant *> seen;
    while (!work.empty()) {
      Constant *c = work.back();
      work.pop_back();
      if (!c || !seen.insert(c).second)
        continue;
      if (auto *f = dyn_cast<Function>(c->stripPointerCasts()))
        fns.insert(f);
      if (isa<ConstantExpr>(c) || isa<ConstantAggregate>(c))
        for (unsigned i = 0; i < c->getNumOperands(); i++)
          if (auto *oc = dyn_cast<Constant>(c->getOperand(i)))
            work.push_back(oc);
    }
    for (Function *f : fns)
      outs() << "CLASSDEV\t" << GV.getName().str() << "\t" << f->getName().str() << "\n";
  }

  // (1) per-function device-registration API calls.
  bool v4l2Fops = false, v4l2Cdev = false, v4l2Name = false;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::string fn = F.getName().str();
    bool isVdev = (fn == "__video_register_device");
    bool hasCdevAdd = false, nameOrInit = false;
    std::set<GlobalVariable *> refGlobals;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        for (Use &u : I.operands())
          if (auto *c = dyn_cast<Constant>(u.get()))
            addRefGlobals(c, refGlobals, 0);
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || CI->isInlineAsm())
          continue;
        Function *cal = CI->getCalledFunction();
        if (!cal)
          continue;
        StringRef cn = cal->getName();
        auto argStr = [&](unsigned idx, bool dotOnly) -> std::string {
          if (idx >= CI->arg_size())
            return "";
          auto *gv = dyn_cast<GlobalVariable>(CI->getArgOperand(idx)->stripPointerCasts());
          if (!gv || (dotOnly && !isDotStr(gv)))
            return "";
          return cstr(gv);
        };
        if (cn == "cdev_add" || cn == "cdev_device_add") {
          hasCdevAdd = true;
          if (isVdev)
            v4l2Cdev = true;
        } else if (cn == "cdev_init" && CI->arg_size() > 1) {
          Value *fa = CI->getArgOperand(1)->stripPointerCasts();
          std::vector<std::string> cands;
          auto addGV = [&](Value *v) {
            if (auto *gv = dyn_cast<GlobalVariable>(v->stripPointerCasts()))
              cands.push_back(gv->getName().str());
          };
          if (auto *gv = dyn_cast<GlobalVariable>(fa))
            cands.push_back(gv->getName().str());
          else if (auto *sel = dyn_cast<SelectInst>(fa)) {
            addGV(sel->getTrueValue());
            addGV(sel->getFalseValue());
          } else if (auto *phi = dyn_cast<PHINode>(fa))
            for (Value *iv : phi->incoming_values())
              addGV(iv);
          if (!cands.empty()) {
            nameOrInit = true;
            outs() << "CDEVINIT\t" << fn << "\t";
            for (size_t i = 0; i < cands.size(); i++)
              outs() << (i ? "," : "") << cands[i];
            outs() << "\n";
          }
        } else if (cn == "__register_chrdev" && CI->arg_size() > 4) {
          auto *nameGV = dyn_cast<GlobalVariable>(CI->getArgOperand(3)->stripPointerCasts());
          auto *fopsGV = dyn_cast<GlobalVariable>(CI->getArgOperand(4)->stripPointerCasts());
          std::string nm = nameGV ? cstr(nameGV) : "";
          if (!nm.empty() && fopsGV && cdevClean(nm))
            outs() << "REGCHRDEV\t" << fn << "\t" << nm << "\t" << fopsGV->getName().str() << "\n";
        } else if (cn == "dev_set_name") {
          std::string fmt = cdevTrim(argStr(1, true));
          if (isVdev && fmt == "%s%d")
            v4l2Name = true;
          if (cdevPathish(fmt)) {
            nameOrInit = true;
            outs() << "CDEVNAME\t" << fn << "\tset_name\t" << fmt << "\n";
          }
        } else if (cn == "sprintf") {
          std::string fmt = cdevTrim(argStr(1, false));
          if (cdevPathish(fmt)) {
            nameOrInit = true;
            outs() << "CDEVNAME\t" << fn << "\tsprintf\t" << fmt << "\n";
          }
        } else if (cn == "snprintf" || cn == "scnprintf") {
          std::string fmt = cdevTrim(argStr(2, false));
          if (cdevPathish(fmt)) {
            nameOrInit = true;
            outs() << "CDEVNAME\t" << fn << "\tsprintf\t" << fmt << "\n";
          }
        } else if (cn == "kasprintf") {
          std::string fmt = cdevTrim(argStr(1, false));
          if (cdevPathish(fmt)) {
            nameOrInit = true;
            outs() << "CDEVNAME\t" << fn << "\tkasprintf\t" << fmt << "\n";
          }
        } else if (cn == "device_create" || cn == "device_create_with_groups") {
          std::vector<std::string> strs;
          for (unsigned i = 0; i < CI->arg_size(); i++)
            if (auto *gv = dyn_cast<GlobalVariable>(CI->getArgOperand(i)->stripPointerCasts()))
              if (isDotStr(gv))
                strs.push_back(cstr(gv));
          bool ok = !strs.empty();
          for (auto &s : strs)
            ok = ok && cdevClean(s);
          if (ok) {
            nameOrInit = true;
            outs() << "CDEVNAME\t" << fn << "\tdevice_create\t" << strs[0];
            for (size_t i = 1; i < strs.size(); i++)
              outs() << "\t" << strs[i];
            outs() << "\n";
          }
        } else if (cn == "alloc_chrdev_region" || cn == "register_chrdev_region") {
          for (unsigned i = 0; i < CI->arg_size(); i++)
            if (auto *gv = dyn_cast<GlobalVariable>(CI->getArgOperand(i)->stripPointerCasts()))
              if (isDotStr(gv)) {
                std::string nm = cstr(gv);
                if (!nm.empty() && cdevClean(nm))
                  outs() << "CHRDEVREGION\t" << fn << "\t" << nm << "\n";
                break;
              }
        }
      }
    if (isVdev)
      for (GlobalVariable *gv : refGlobals)
        if (gv->getName() == "v4l2_fops")
          v4l2Fops = true;
    if (hasCdevAdd)
      outs() << "CDEVADD\t" << fn << "\n";
    for (GlobalVariable *gv : refGlobals) {
      // CDEVFOPS only for cdev_add fns -- the Python consumes fops_in_fn solely inside `for fn in cdev_in_fn`.
      if (hasCdevAdd && gvHasDwarfType(gv, "file_operations"))
        outs() << "CDEVFOPS\t" << fn << "\t" << gv->getName().str() << "\n";
      else if (classGlobals.count(gv))
        outs() << "CLASSREF\t" << fn << "\t" << gv->getName().str() << "\n";
    }
    if (nameOrInit)
      if (DISubprogram *sp = F.getSubprogram())
        if (DIFile *file = sp->getFile())
          outs() << "CDEVFILE\t" << fn << "\t" << file->getFilename().str() << "\n";
  }

  // (2) MEMDEV: drivers/char/mem.c @devlist entries {name, fops, ...}.  clang lowers the mixed zero/non-zero
  // initializer array into a PACKED STRUCT of per-entry structs (not a ConstantArray), so iterate any
  // aggregate; each entry's field0 = name, field1 = fops (zeroinit slots have a null name -> skipped).
  for (GlobalVariable &GV : M.globals()) {
    if (GV.getName() != "devlist" || !GV.hasInitializer())
      continue;
    Constant *init = peelKasanGlobal(GV.getInitializer());
    auto *agg = dyn_cast<ConstantAggregate>(init);
    if (!agg)
      continue;
    for (unsigned i = 0; i < agg->getNumOperands(); i++) {
      Constant *e = agg->getAggregateElement(i);
      if (!e)
        continue;
      Constant *nameC = e->getAggregateElement(0u);
      Constant *fopsC = e->getAggregateElement(1u);
      std::string nm = nameC ? cstr(nameC) : "";
      auto *fopsGV = fopsC ? dyn_cast<GlobalVariable>(fopsC->stripPointerCasts()) : nullptr;
      if (!nm.empty() && fopsGV && !fopsGV->getName().empty() && cdevClean(nm))
        outs() << "MEMDEV\t" << nm << "\t" << fopsGV->getName().str() << "\n";
    }
  }

  // (3) V4L2 family idiom: __video_register_device installs video/radio/vbi/... nodes via v4l2_fops.
  if (v4l2Fops && v4l2Cdev && v4l2Name) {
    outs() << "V4L2OK\n";
    static const char *kNames[] = {"video", "vbi", "radio", "v4l-subdev", "v4l-swradio", "v4l-touch"};
    std::set<std::string> want(std::begin(kNames), std::end(kNames));
    std::set<std::string> found;
    for (GlobalVariable &GV : M.globals())
      if (GV.hasInitializer()) {
        std::string s = cstr(&GV);
        if (want.count(s))
          found.insert(s);
      }
    for (auto &n : found)
      outs() << "V4L2NAME\t" << n << "\n";
  }
}

// DBGFS: per-function dentry-dataflow events for the debugfs/tracefs path recognizer (fd.py
// extract_debugfs_paths).  SPLIT migration: ir_defuse emits the raw IR dataflow (field GEP / ptr load / phi
// / ptr store + debugfs_create_dir/file calls) the Python recognizer's per-function pass consumed from
// llvm-dis text; the Python keeps the cross-.bc fixpoint resolution unchanged.  Values are keyed by a
// per-function synthetic id -- the token text never reaches the output (rows are path/fops/bc/fn), so any
// consistent id works; GEP field names are emitted explicitly (from the IR value name, == _norm_field_name).
// Only debugfs-relevant modules/functions are processed.  Facts:
//   DBGFS <fn> PARAMS <p0,p1,...>              the function's parameter tokens (NULL-parent call edge)
//   DBGFS <fn> GEP   <tok> <byteoff> <field|->  %t = getelementptr i8, ptr B, i64 off   (field dentry key)
//   DBGFS <fn> LDG   <tok> <@global> / LDF <tok> <geptok>   %t = load ptr (from global / from field gep)
//   DBGFS <fn> PHI   <tok> <op,op,...>          %t = phi ptr [...]
//   DBGFS <fn> STG   <valtok> <@global> / STF <valtok> <geptok>   store ptr val (to global / field gep)
//   DBGFS <fn> CDIR  <restok> <nameref> <parref> <root>     *_create_dir(name, parent)
//   DBGFS <fn> CFILE <nameref> <parref> <fops,...> <root>   *_create_file*(name,,parent,,fops)
//   DBGFS <fn> CALL  <callee> <nullidx,...>     a call passing NULL (callee's param at idx == fs root)
//   DBGFSSTR <@name> <literal>                  a string global used as a create name arg
static std::string dbgNormField(StringRef nmRef) {
  std::string s = nmRef.str();
  size_t dot = s.find('.');                       // strip trailing ".word"+ (LLVM inline/uniquifier suffix)
  if (dot != std::string::npos)
    s = s.substr(0, dot);
  while (!s.empty() && s.back() >= '0' && s.back() <= '9')   // strip trailing digits
    s.pop_back();
  for (char c : s)
    if (((c | 32) >= 'a' && (c | 32) <= 'z'))
      return s;
  return "";                                      // no alpha -> unnamed field (None)
}

static void enumDebugfsRaw(Module &M) {
  static const std::map<std::string, std::string> kDir = {
      {"debugfs_create_dir", "/sys/kernel/debug"}, {"tracefs_create_dir", "/sys/kernel/tracing"}};
  static const std::map<std::string, std::string> kFile = {
      {"debugfs_create_file_full", "/sys/kernel/debug"}, {"debugfs_create_file_unsafe", "/sys/kernel/debug"},
      {"debugfs_create_file", "/sys/kernel/debug"}, {"tracefs_create_file", "/sys/kernel/tracing"},
      {"trace_create_file", "/sys/kernel/tracing"}};
  bool modRel = false;
  for (auto &kv : kDir) modRel |= (M.getFunction(kv.first) != nullptr);
  for (auto &kv : kFile) modRel |= (M.getFunction(kv.first) != nullptr);
  if (!modRel)
    return;
  auto isI8FieldGep = [](GetElementPtrInst *g, int64_t &off) -> bool {
    if (!g || !g->isInBounds() || !g->getSourceElementType()->isIntegerTy(8) || g->getNumIndices() != 1)
      return false;
    auto *ci = dyn_cast<ConstantInt>(g->getOperand(1));
    if (!ci || ci->getSExtValue() < 0)
      return false;
    off = ci->getSExtValue();
    return true;
  };
  auto nullIdx = [](CallInst *CI) -> std::string {     // comma-joined indices of NULL ptr args
    std::string idxs;
    int k = 0;
    for (unsigned a = 0; a < CI->arg_size(); a++)
      if (isa<ConstantPointerNull>(CI->getArgOperand(a)))
        idxs += (k++ ? "," : "") + std::to_string(a);
    return k ? idxs : "";
  };
  std::set<GlobalVariable *> usedStrings;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    // A function is processed only if it CALLS a create API (its dentry chains are sliced out), or is a pure
    // forwarder that passes NULL to another function (it then only contributes the NULL-parent call edge).
    // This bounds the fact volume to the actual dentry dataflow -- the broad "any ptr-store" set explodes
    // (mm: 28k lines).  A cross-.bc producer creates the dentry it stores, so it always has a create call.
    std::vector<CallInst *> creates;
    bool hasNullCall = false;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *CI = dyn_cast<CallInst>(&I))
          if (Function *c = CI->getCalledFunction()) {
            const std::string cn = c->getName().str();
            if (kDir.count(cn) || kFile.count(cn))
              creates.push_back(CI);
            else if (!c->isDeclaration() && !nullIdx(CI).empty())
              hasNullCall = true;
          }
    if (creates.empty() && !hasNullCall)
      continue;
    std::string fn = F.getName().str();
    std::map<Value *, int> id;                      // per-fn synthetic token ids (args first, then insts)
    int n = 0;
    for (Argument &A : F.args())
      id[&A] = n++;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        id[&I] = n++;
    auto tok = [&](Value *v) -> std::string {        // direct operand token (dataflow keys)
      if (auto *gv = dyn_cast<GlobalVariable>(v))
        return "@" + gv->getName().str();
      if (isa<ConstantPointerNull>(v))
        return "null";
      auto it = id.find(v);
      return it != id.end() ? "%" + std::to_string(it->second) : "";
    };
    auto refTok = [&](Value *v) -> std::string {     // create name/parent/fops: see through no-op casts
      Value *s = v->stripPointerCasts();
      if (auto *gv = dyn_cast<GlobalVariable>(s))
        return "@" + gv->getName().str();
      if (isa<ConstantPointerNull>(s))
        return "null";
      auto it = id.find(s);
      if (it == id.end())
        it = id.find(v);
      return it != id.end() ? "%" + std::to_string(it->second) : "";
    };
    auto nz = [](const std::string &s) { return s.empty() ? std::string("-") : s; };

    if (creates.empty()) {                           // forwarder: emit only the NULL-arg call edges
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *c = CI->getCalledFunction())
              if (!c->isDeclaration() && !kDir.count(c->getName().str()) && !kFile.count(c->getName().str())) {
                std::string idxs = nullIdx(CI);
                if (!idxs.empty())
                  outs() << "DBGFS\t" << fn << "\tCALL\t" << c->getName().str() << "\t" << idxs << "\n";
              }
      continue;
    }

    // cand = dentry-candidate values: closure of {create results, ptr loads} through phi/select/cast.
    std::set<Value *> cand;
    std::vector<Value *> cwl;
    auto addCand = [&](Value *v) { if (cand.insert(v).second) cwl.push_back(v); };
    for (CallInst *cr : creates)
      addCand(cr);
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *ld = dyn_cast<LoadInst>(&I))
          if (ld->getType()->isPointerTy())
            addCand(ld);
    while (!cwl.empty()) {
      Value *v = cwl.back();
      cwl.pop_back();
      for (User *U : v->users())
        if ((isa<PHINode>(U) || isa<SelectInst>(U) || isa<CastInst>(U)) && U->getType()->isPointerTy())
          addCand(cast<Value>(U));
    }
    // candStores = a cand dentry stored into a global / i8-field (the producers feeding the cross-.bc maps)
    std::set<StoreInst *> candStores;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *st = dyn_cast<StoreInst>(&I))
          if (st->getValueOperand()->getType()->isPointerTy() && cand.count(st->getValueOperand())) {
            Value *d = st->getPointerOperand();
            int64_t o;
            if (isa<GlobalVariable>(d) ||
                (isa<GetElementPtrInst>(d) && isI8FieldGep(cast<GetElementPtrInst>(d), o)))
              candStores.insert(st);
          }
    // backward slice: the GEP/load/phi instructions feeding create parents + candStore value/dest.
    std::set<Instruction *> slice;
    std::vector<Instruction *> swl;
    auto addSink = [&](Value *v) {
      if (auto *I = dyn_cast<Instruction>(v))
        swl.push_back(I);
    };
    for (CallInst *cr : creates) {
      const std::string cn = cr->getCalledFunction()->getName().str();
      if (kDir.count(cn) && cr->arg_size() >= 2)
        addSink(cr->getArgOperand(1));
      else if (kFile.count(cn) && cr->arg_size() >= 5)
        addSink(cr->getArgOperand(2));
    }
    for (StoreInst *st : candStores) {
      addSink(st->getValueOperand());
      addSink(st->getPointerOperand());
    }
    while (!swl.empty()) {
      Instruction *I = swl.back();
      swl.pop_back();
      if (!slice.insert(I).second)
        continue;
      for (Use &u : I->operands())
        if (auto *oi = dyn_cast<Instruction>(u.get()))
          swl.push_back(oi);
    }

    outs() << "DBGFS\t" << fn << "\tPARAMS\t";
    {
      int k = 0;
      for (Argument &A : F.args())
        outs() << (k++ ? "," : "") << tok(&A);
    }
    outs() << "\n";
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        if (auto *CI = dyn_cast<CallInst>(&I)) {
          Function *c = CI->getCalledFunction();
          if (!c)
            continue;
          const std::string cn = c->getName().str();
          auto dit = kDir.find(cn);
          auto fit = kFile.find(cn);
          if (dit != kDir.end() && CI->arg_size() >= 2) {
            if (auto *sg = dyn_cast<GlobalVariable>(CI->getArgOperand(0)->stripPointerCasts()))
              usedStrings.insert(sg);
            outs() << "DBGFS\t" << fn << "\tCDIR\t" << tok(CI) << "\t" << nz(refTok(CI->getArgOperand(0)))
                   << "\t" << nz(refTok(CI->getArgOperand(1))) << "\t" << dit->second << "\n";
          } else if (fit != kFile.end() && CI->arg_size() >= 5) {
            if (auto *sg = dyn_cast<GlobalVariable>(CI->getArgOperand(0)->stripPointerCasts()))
              usedStrings.insert(sg);
            std::string fops;
            int k = 0;
            for (unsigned a = 4; a < CI->arg_size(); a++)
              fops += (k++ ? "," : "") + nz(refTok(CI->getArgOperand(a)));
            outs() << "DBGFS\t" << fn << "\tCFILE\t" << nz(refTok(CI->getArgOperand(0))) << "\t"
                   << nz(refTok(CI->getArgOperand(2))) << "\t" << nz(fops) << "\t" << fit->second << "\n";
          } else if (!c->isDeclaration()) {
            std::string idxs = nullIdx(CI);
            if (!idxs.empty())
              outs() << "DBGFS\t" << fn << "\tCALL\t" << cn << "\t" << idxs << "\n";
          }
          continue;
        }
        if (auto *st = dyn_cast<StoreInst>(&I)) {       // only dentry-candidate stores reach the maps
          if (!candStores.count(st))
            continue;
          Value *val = st->getValueOperand(), *d = st->getPointerOperand();
          if (auto *gv = dyn_cast<GlobalVariable>(d))
            outs() << "DBGFS\t" << fn << "\tSTG\t" << tok(val) << "\t@" << gv->getName().str() << "\n";
          else
            outs() << "DBGFS\t" << fn << "\tSTF\t" << tok(val) << "\t" << tok(d) << "\n";
          continue;
        }
        if (!slice.count(&I))                           // only the sliced dentry dataflow
          continue;
        if (auto *g = dyn_cast<GetElementPtrInst>(&I)) {
          int64_t off;
          if (isI8FieldGep(g, off))
            outs() << "DBGFS\t" << fn << "\tGEP\t" << tok(g) << "\t" << off << "\t"
                   << nz(dbgNormField(g->getName())) << "\n";
        } else if (auto *ld = dyn_cast<LoadInst>(&I)) {
          if (ld->getType()->isPointerTy()) {
            Value *p = ld->getPointerOperand();
            if (auto *gv = dyn_cast<GlobalVariable>(p))
              outs() << "DBGFS\t" << fn << "\tLDG\t" << tok(ld) << "\t@" << gv->getName().str() << "\n";
            else if (isa<Instruction>(p) || isa<Argument>(p))
              outs() << "DBGFS\t" << fn << "\tLDF\t" << tok(ld) << "\t" << tok(p) << "\n";
          }
        } else if (auto *phi = dyn_cast<PHINode>(&I)) {
          if (phi->getType()->isPointerTy()) {
            std::string ops;
            int k = 0;
            for (Value *iv : phi->incoming_values()) {
              std::string t = tok(iv);
              if (!t.empty())
                ops += (k++ ? "," : "") + t;
            }
            if (k)
              outs() << "DBGFS\t" << fn << "\tPHI\t" << tok(phi) << "\t" << ops << "\n";
          }
        }
      }
  }
  for (GlobalVariable *gv : usedStrings) {
    std::string lit = cstr(gv);
    if (!lit.empty() && cdevClean(lit))
      outs() << "DBGFSSTR\t@" << gv->getName().str() << "\t" << lit << "\n";
  }
}

// SND/DVB devnodes: ALSA + DVB split-registration device nodes (snd_devnodes.py / dvb_devnodes.py /
// extract_snd_oss_devnodes).  ALSA registers fops via snd_register_device() but names the node via a
// SEPARATE dev_set_name() in the same .c -> recovered by a per-DIFile join (SNDSET/SNDREG/SNDFILE).  OSS
// registers via snd_register_oss_device(type,card,dev,fops) -> SNDOSS<type><dev><fops> (Python maps type/dev
// to the soundcore node names, a kernel constant).  DVB registers via dvb_register_device(template,type):
// the fops is the template's .fops (or the runtime fops stored in the fn) and the name is @dnames[type], a
// kernel type->name table -> DVBNODE<fops><typename> (joined in ir_defuse since dvb-core is one batch).
static GlobalVariable *gepBaseGlobal(Value *v) {  // resolve a (possibly array-indexed) ptr arg to its base
  if (!v)                                          // global -- @snd_pcm_f_ops[1] is gep(@snd_pcm_f_ops,272)
    return nullptr;
  v = v->stripPointerCasts();
  while (auto *gep = dyn_cast<GEPOperator>(v))
    v = gep->getPointerOperand()->stripPointerCasts();
  return dyn_cast<GlobalVariable>(v);
}
static void sndCollectCstrPtrs(Constant *c, std::vector<std::string> &out) {  // ptr-to-cstring leaves, in order
  if (!c)
    return;
  if (auto *gv = dyn_cast<GlobalVariable>(c->stripPointerCasts())) {
    out.push_back(cstr(gv));
    return;
  }
  if (isa<ConstantArray>(c) || isa<ConstantStruct>(c))
    for (unsigned i = 0; i < c->getNumOperands(); i++)
      sndCollectCstrPtrs(c->getAggregateElement(i), out);
}
static bool sndFirstNonStrGlobal(Constant *c, std::string &out) {  // first real @global (== template .fops)
  if (!c)
    return false;
  if (auto *gv = dyn_cast<GlobalVariable>(c->stripPointerCasts())) {
    StringRef n = gv->getName();
    if (!n.starts_with(".str") && !n.starts_with("llvm") && !n.starts_with("__asan")) {
      out = n.str();
      return true;
    }
    return false;
  }
  if (isa<ConstantArray>(c) || isa<ConstantStruct>(c))
    for (unsigned i = 0; i < c->getNumOperands(); i++)
      if (sndFirstNonStrGlobal(c->getAggregateElement(i), out))
        return true;
  return false;
}

static void enumSndDevnodes(Module &M, const DataLayout &DL) {
  Function *sndReg = M.getFunction("snd_register_device");
  Function *ossReg = M.getFunction("snd_register_oss_device");
  Function *dvbReg = M.getFunction("dvb_register_device");
  auto calls = [](Function *f) {
    if (f)
      for (User *U : f->users())
        if (isa<CallInst>(U))
          return true;
    return false;
  };
  bool callsSnd = calls(sndReg), callsOss = calls(ossReg), callsDvb = calls(dvbReg);
  if (!callsSnd && !callsOss && !callsDvb)
    return;

  auto baseName = [](Function &F) -> std::string {
    if (DISubprogram *sp = F.getSubprogram())
      if (DIFile *fl = sp->getFile()) {
        std::string f = fl->getFilename().str();
        size_t s = f.rfind('/');
        return s == std::string::npos ? f : f.substr(s + 1);
      }
    return "";
  };

  // (1) ALSA: snd_register_device fops + dev_set_name node name, per source file.
  if (callsSnd)
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      std::string fn = F.getName().str();
      bool any = false;
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *c = CI->getCalledFunction()) {
              StringRef cn = c->getName();
              if (cn == "dev_set_name" && CI->arg_size() > 1) {
                Value *fa = CI->getArgOperand(1)->stripPointerCasts();
                std::vector<GlobalVariable *> strs;
                auto add = [&](Value *v) {
                  if (auto *gv = dyn_cast<GlobalVariable>(v->stripPointerCasts()))
                    if (isDotStr(gv))
                      strs.push_back(gv);
                };
                if (auto *gv = dyn_cast<GlobalVariable>(fa)) {
                  if (isDotStr(gv))
                    strs.push_back(gv);
                } else if (auto *sel = dyn_cast<SelectInst>(fa)) {
                  add(sel->getTrueValue());
                  add(sel->getFalseValue());
                } else if (auto *phi = dyn_cast<PHINode>(fa))
                  for (Value *v : phi->incoming_values())
                    add(v);
                for (GlobalVariable *gv : strs) {
                  std::string fmt = cstr(gv);
                  if (!fmt.empty() && cdevClean(fmt)) {
                    any = true;
                    outs() << "SNDSET\t" << fn << "\t" << fmt << "\n";
                  }
                }
              } else if (cn == "snd_register_device" && CI->arg_size() >= 4) {
                auto *ty = dyn_cast<ConstantInt>(CI->getArgOperand(0));
                GlobalVariable *fops = gepBaseGlobal(CI->getArgOperand(3));
                if (ty && fops) {
                  any = true;
                  outs() << "SNDREG\t" << fn << "\t" << fops->getName().str() << "\t" << ty->getSExtValue()
                         << "\n";
                }
              }
            }
      if (any) {
        std::string bn = baseName(F);
        if (!bn.empty() && cdevClean(bn))
          outs() << "SNDFILE\t" << fn << "\t" << bn << "\n";
      }
    }

  // (2) ALSA OSS: snd_register_oss_device(type, card, dev, fops).
  if (callsOss)
    for (Function &F : M)
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *c = CI->getCalledFunction())
              if (c->getName() == "snd_register_oss_device" && CI->arg_size() >= 4) {
                auto *ty = dyn_cast<ConstantInt>(CI->getArgOperand(0));
                auto *dev = dyn_cast<ConstantInt>(CI->getArgOperand(2));
                GlobalVariable *fops = gepBaseGlobal(CI->getArgOperand(3));
                if (ty && dev && fops)
                  outs() << "SNDOSS\t" << ty->getSExtValue() << "\t" << dev->getSExtValue() << "\t"
                         << fops->getName().str() << "\n";
              }

  // (3) DVB: dvb_register_device(adap, pdvbdev, template, priv, type) -> template.fops + @dnames[type].
  if (callsDvb) {
    std::vector<std::string> dnames;
    if (GlobalVariable *dn = M.getGlobalVariable("dnames", true))
      if (dn->hasInitializer())
        sndCollectCstrPtrs(peelKasanGlobal(dn->getInitializer()), dnames);
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      std::set<std::string> stored;                  // runtime-template fops stored in F
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *SI = dyn_cast<StoreInst>(&I))
            if (auto *gv = dyn_cast<GlobalVariable>(SI->getValueOperand()->stripPointerCasts()))
              if (gvHasDwarfType(gv, "file_operations") || gv->getName().ends_with("_fops"))
                stored.insert(gv->getName().str());
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *c = CI->getCalledFunction())
              if (c->getName() == "dvb_register_device" && CI->arg_size() >= 5) {
                auto *ty = dyn_cast<ConstantInt>(CI->getArgOperand(4));
                if (!ty)
                  continue;
                int64_t t = ty->getSExtValue();
                if (t < 0 || (size_t)t >= dnames.size() || dnames[t].empty())
                  continue;
                std::string fops;
                if (GlobalVariable *tmpl = gepBaseGlobal(CI->getArgOperand(2)))
                  sndFirstNonStrGlobal(peelKasanGlobal(tmpl->hasInitializer() ? tmpl->getInitializer()
                                                                              : nullptr),
                                       fops);
                if (fops.empty() && stored.size() == 1)
                  fops = *stored.begin();
                if (!fops.empty())
                  outs() << "DVBNODE\t" << fops << "\t" << dnames[t] << "\n";
              }
    }
  }
}

// DRMMINOR: the structural proof that the DRM core registers its /dev/dri minor nodes (card/renderD/
// controlD) carrying drm_stub_fops (devnode.py _has_drm_minor_devnode_proof).  The drm-core batch must
// DEFINE the registration chain (drm_dev_register -> drm_minor_register -> drm_sysfs_minor_alloc, +
// drm_devnode/drm_stub_open + the @drm_stub_fops global), name the nodes via dev_set_name with the
// card%d/renderD%d/controlD%d/dri/%s literals, and register all three minor types {0,2,32}.  Self-contained
// in one batch, so ir_defuse emits the boolean proof (DRMMINOR<types>); the Python just reads it.
static void enumDrmMinor(Module &M) {
  for (const char *n : {"drm_dev_register", "drm_devnode", "drm_minor_register", "drm_sysfs_minor_alloc",
                        "drm_stub_open"}) {
    Function *f = M.getFunction(n);
    if (!f || f->isDeclaration())
      return;
  }
  if (!M.getGlobalVariable("drm_stub_fops", true))
    return;
  Function *devSet = M.getFunction("dev_set_name");
  if (!devSet || devSet->use_empty())
    return;
  static const char *strs[] = {"card%d", "renderD%d", "controlD%d", "dri/%s"};
  bool found[4] = {false, false, false, false};
  for (GlobalVariable &GV : M.globals()) {
    std::string s = cstr(&GV);
    if (s.empty())
      continue;
    for (int i = 0; i < 4; i++)
      if (s.rfind(strs[i], 0) == 0)              // value starts with the node-name format
        found[i] = true;
  }
  for (bool b : found)
    if (!b)
      return;
  std::set<int64_t> types;                       // drm_minor_register(dev, <const type>)
  Function *reg = M.getFunction("drm_minor_register");
  for (User *U : reg->users())
    if (auto *CI = dyn_cast<CallInst>(U))
      if (CI->getCalledFunction() == reg && CI->arg_size() >= 2)
        if (auto *ci = dyn_cast<ConstantInt>(CI->getArgOperand(1)))
          types.insert(ci->getSExtValue());
  if (!types.count(0) || !types.count(2) || !types.count(32))
    return;
  std::string ts;
  int k = 0;
  for (int64_t t : types)
    ts += (k++ ? "," : "") + std::to_string(t);
  outs() << "DRMMINOR\t" << ts << "\n";
}

// CDROMBDOPS: a block disk registered as a CD-ROM device -- a function that calls BOTH register_cdrom and
// device_add_disk and references a block_device_operations global (its gendisk->fops).  ir_defuse emits
// CDROMBDOPS<fn><ops>; the Python joins <ops> to that table's .ioctl handlers (read_block_dops_tables,
// from OPSFIELD facts).  block_device_operations identified by DWARF type, never by name.
static void enumCdromBdops(Module &M) {
  Function *regCdrom = M.getFunction("register_cdrom");
  Function *addDisk = M.getFunction("device_add_disk");
  if (!regCdrom || !addDisk)
    return;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    bool hasReg = false, hasAdd = false;
    std::set<GlobalVariable *> refs;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        if (auto *CI = dyn_cast<CallInst>(&I))
          if (Function *c = CI->getCalledFunction()) {
            if (c == regCdrom)
              hasReg = true;
            else if (c == addDisk)
              hasAdd = true;
          }
        for (Use &u : I.operands())
          if (auto *cst = dyn_cast<Constant>(u.get()))
            addRefGlobals(cst, refs, 0);
      }
    if (!hasReg || !hasAdd)
      continue;
    for (GlobalVariable *gv : refs)
      if (gvHasDwarfType(gv, "block_device_operations"))
        outs() << "CDROMBDOPS\t" << F.getName().str() << "\t" << gv->getName().str() << "\n";
  }
}

// DEVN*: per-function devnode-recognizer facts (devnode.py _ir_function_summaries) -- ALSA-style cdev nodes
// whose name (dev_set_name) and fops (cdev_init) co-locate in one fn or a one-hop call, plus the usb/rtc
// special chains.  ir_defuse emits the raw per-fn facts; the Python join (build_kernel_devpath_rows) keeps
// its same_fn / one_hop / usb / rtc idioms + norm_devpath.  Faithful to the old per-TU .ll summaries:
//   DEVNPAT  <fn> <dev_set_name fmt>   every .str arg of a dev_set_name call (Python: norm_devpath -> pattern)
//   DEVNOPS  <fn> <ops>                every cdev_init ops global (Python: intersect REG ops)
//   DEVNADD  <fn>                      calls cdev_add / cdev_device_add
//   DEVNCALL <fn> <callee>             direct calls (only for fns that have a DEVNPAT -- one_hop/rtc callers)
//   DEVNSTR  <fn> <string>             every .str ref in usb_devnode (Python: norm_devpath -> path_strings)
//   DEVNFILE <fn> <source file>        DISubprogram file (rtc class.c/dev.c checks + evidence)
static void enumDevnodeSummary(Module &M) {
  Function *devSet = M.getFunction("dev_set_name");
  Function *cdevInit = M.getFunction("cdev_init");
  Function *cdevAdd = M.getFunction("cdev_add");
  Function *cdevDevAdd = M.getFunction("cdev_device_add");
  auto called = [](Function *f) { return f && !f->use_empty(); };
  if (!called(devSet) && !called(cdevInit) && !called(cdevAdd) && !called(cdevDevAdd) &&
      !M.getFunction("usb_devnode"))
    return;
  auto isInstr = [](StringRef n) {                       // compiler instrumentation -- never a devnode callee
    return n.starts_with("__asan") || n.starts_with("__kasan") || n.starts_with("__sanitizer") ||
           n.starts_with("__ubsan") || n.starts_with("__tsan") || n.starts_with("__msan") ||
           n.starts_with("__sancov") || n.starts_with("llvm.") || n.contains("_cov_trace");
  };
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::string fn = F.getName().str();
    bool isUsbDevnode = (fn == "usb_devnode");
    bool hasAdd = false, gated = isUsbDevnode;
    std::vector<std::string> pats;
    std::set<std::string> ops, callees, strs;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        if (isUsbDevnode)
          for (Use &u : I.operands())
            if (auto *gv = dyn_cast<GlobalVariable>(u.get()->stripPointerCasts()))
              if (isDotStr(gv)) {
                std::string s = cstr(gv);
                if (!s.empty() && cdevClean(s))
                  strs.insert(s);
              }
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || CI->isInlineAsm())
          continue;
        Function *c = CI->getCalledFunction();
        if (!c)
          continue;
        if (!isInstr(c->getName()))                     // keep real callees (incl cross-batch decls like
          callees.insert(c->getName().str());           // posix_clock_register); drop instrumentation noise
        StringRef cn = c->getName();
        if (cn == "dev_set_name") {
          gated = true;
          for (unsigned a = 1; a < CI->arg_size(); a++)   // every .str arg (fmt + any string varargs)
            if (auto *gv = dyn_cast<GlobalVariable>(CI->getArgOperand(a)->stripPointerCasts()))
              if (isDotStr(gv)) {
                std::string s = cstr(gv);
                if (!s.empty() && cdevClean(s))
                  pats.push_back(s);
              }
        } else if (cn == "cdev_init" && CI->arg_size() > 1) {
          gated = true;
          Value *fa = CI->getArgOperand(1)->stripPointerCasts();
          auto add = [&](Value *v) {
            if (auto *gv = dyn_cast<GlobalVariable>(v->stripPointerCasts()))
              ops.insert(gv->getName().str());
          };
          if (auto *gv = dyn_cast<GlobalVariable>(fa))
            ops.insert(gv->getName().str());
          else if (auto *sel = dyn_cast<SelectInst>(fa)) {
            add(sel->getTrueValue());
            add(sel->getFalseValue());
          } else if (auto *phi = dyn_cast<PHINode>(fa))
            for (Value *iv : phi->incoming_values())
              add(iv);
        } else if (cn == "cdev_add" || cn == "cdev_device_add") {
          gated = true;
          hasAdd = true;
        }
      }
    if (!gated)
      continue;
    if (hasAdd)
      outs() << "DEVNADD\t" << fn << "\n";
    for (auto &p : pats)
      outs() << "DEVNPAT\t" << fn << "\t" << p << "\n";
    for (auto &o : ops)
      outs() << "DEVNOPS\t" << fn << "\t" << o << "\n";
    if (!pats.empty() || hasAdd)                          // calls matter for one_hop (pattern) + rtc (cdev_add)
      for (auto &callee : callees)
        outs() << "DEVNCALL\t" << fn << "\t" << callee << "\n";
    for (auto &s : strs)
      outs() << "DEVNSTR\t" << fn << "\t" << s << "\n";
    if (DISubprogram *sp = F.getSubprogram())
      if (DIFile *file = sp->getFile()) {
        std::string fl = file->getFilename().str();
        if (cdevClean(fl))
          outs() << "DEVNFILE\t" << fn << "\t" << fl << "\n";
      }
  }
}

int main(int argc, char **argv) {
  bool cmdMode = (argc >= 2 && std::string(argv[1]) == "--cmd");
  bool gatesMode = (argc >= 2 && std::string(argv[1]) == "--gates");
  bool fieldsMode = (argc >= 2 && std::string(argv[1]) == "--fields");
  bool regMode = (argc >= 2 && std::string(argv[1]) == "--reg");
  int mi = (cmdMode || gatesMode || fieldsMode || regMode) ? 2 : 1;  // index of the module argument
  if (argc < mi + 1) {
    errs() << "usage: ir_defuse [--cmd|--gates|--fields|--reg] <module.ll/.bc> [func ...]\n";
    return 1;
  }
  LLVMContext ctx;
  SMDiagnostic err;
  auto M = parseIRFile(argv[mi], err, ctx);
  if (!M) {
    err.print(argv[0], errs());
    return 1;
  }
  const DataLayout &DL = M->getDataLayout();
  g_DL = &DL;
  g_named = M->getIdentifiedStructTypes();  // for anon-struct -> named canonicalization in tyName
  for (StructType *st : g_named)            // KallGraph {fieldNum,size} -> name (anon unification)
    if (st->hasName() && st->isSized())
      g_shape2name.emplace(std::make_pair(st->getNumElements(), (uint64_t)DL.getTypeAllocSize(st)),
                           stripSuffix(st->getName().str()));
  buildDwarfMembers(*M);                    // DWARF struct member map for load-chain type recovery
  buildLayoutFacts();                       // REG layout facts: DWARF + explicit static rules

  if (regMode) {  // ITEM 3: registration binding (reg-API installs + named generic ops-tables)
    analyzeReg(*M, DL);
    enumOpsTables(*M, DL);
    return 0;
  }

  // field-based devirt table: (struct+offset) -> functions stored/initialized there.
  // Two sources: (a) static ops-table global initializers; (b) runtime function-valued stores.
  std::map<std::string, std::set<std::string>> fieldTargets;
  std::set<std::string> typedFieldFacts;
  std::set<std::string> typedStoreFacts;
  for (GlobalVariable &GV : M->globals())
    if (GV.hasInitializer()) {
      scanConst(GV.getInitializer(), DL, fieldTargets);
      // Also key the static ops-table by the global's DWARF struct name (DIGlobalVariable type) with the
      // DWARF member byte offsets, so clang-anonymized ops structs -- which scanConst can only name anon#N
      // -- become reachable by their real name (e.g. hid_ll_driver).  The offset comes from the DWARF
      // member map and the handler from constAtOffset; no offset is guessed.
      SmallVector<DIGlobalVariableExpression *, 1> GVEs;
      GV.getDebugInfo(GVEs);
      Constant *init = peelKasanGlobal(GV.getInitializer());
      for (auto *E : GVEs) {
        DICompositeType *c = diComposite(E->getVariable()->getType());
        if (!c || c->getName().empty())
          continue;
        auto it = g_dwFieldOffset.find(c->getName().str());
        if (it == g_dwFieldOffset.end())
          continue;
        for (auto &mo : it->second) {
          Constant *v = constAtOffset(init, mo.second, DL);
          if (auto *F = dyn_cast_or_null<Function>(v ? v->stripPointerCasts() : nullptr)) {
            if (skipRuntimeFunction(F->getName()))
              continue;
            typedFieldFacts.insert(GV.getName().str() + "\t" + c->getName().str() + "\t" +
                                   std::to_string(mo.second) + "\t" + mo.first + "\t" +
                                   F->getName().str());
            if (!F->isDeclaration())
              fieldTargets["struct." + c->getName().str() + "+" + std::to_string(mo.second)]
                  .insert(F->getName().str());
          }
        }
      }
    }
  for (Function &F : *M)
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *SI = dyn_cast<StoreInst>(&I))
          if (auto *F2 = dyn_cast<Function>(SI->getValueOperand()->stripPointerCasts()))
            if (!skipRuntimeFunction(F2->getName())) {
              if (!F2->isDeclaration())
                fieldTargets[absLoc(SI->getPointerOperand(), DL)].insert(F2->getName().str());
              std::string loc = dwarfStoreLoc(SI->getPointerOperand(), DL);
              size_t plus = loc.rfind('+');
              if (!loc.empty() && plus != std::string::npos) {
                std::string structName = loc.substr(7, plus - 7);
                int64_t offset = strtoll(loc.c_str() + plus + 1, nullptr, 10);
                std::string fieldName = dwFieldNameAt(structName, offset);
                typedStoreFacts.insert(F.getName().str() + "\t" + structName + "\t" +
                                       std::to_string(offset) + "\t" + fieldName + "\t" +
                                       F2->getName().str());
              }
            }

  if (fieldsMode) {  // dump the (struct+byteOffset -> functions) devirt table for cross-check
    for (auto &kv : fieldTargets) {
      // FIELD is a MACHINE fact: fixpoint.py imports c[3] verbatim as the handler set at this (struct,off),
      // so it MUST be complete -- truncating to 8 + a literal "..." both dropped real handlers AND injected
      // "..." as a bogus handler.  Emit every handler; human-readable capping belongs only in debug dumps.
      outs() << "FIELD\t" << kv.first << "\t" << kv.second.size() << "\t";
      int k = 0;
      for (auto &t : kv.second) {
        if (k++) outs() << ",";
        outs() << t;
      }
      outs() << "\n";
    }
    for (const std::string &fact : typedFieldFacts)
      outs() << "TYPEDFIELD\t" << fact << "\n";
    for (const std::string &fact : typedStoreFacts)
      outs() << "TYPEDSTORE\t" << fact << "\n";
    enumOpsFields(*M, DL);  // OPSFIELD: per-global block/proto field values (read_block_dops, proto family)
    enumAnonInode(*M);      // ANON: anon_inode fops lifted to syscall handlers (anon-fd provenance)
    enumMiscDevices(*M, DL); // MISC: miscdevice global .name -> .fops (device-node provenance)
    enumInstalledFops(*M, DL);  // IFOP/TFOP/MAGICCALL: installed fops, fill tables, magic-link exits
    enumPathResolvedFops(*M, DL); // PATHFOP: mount-context path resolution -> installed inode fops
    enumCftypeTables(*M, DL); // CFTYPE/CFTOWNER: complete cgroup key -> typed callbacks
    enumKernfsOpen(*M, DL); // KERNFSOPEN: typed kernfs file fops -> outer open handler
    enumSubtreeBlanket(*M); // SUBTREE: blanket fops of a proc subtree (proc_mkdir -> IOPS.lookup -> make-inode)
    enumSpecialInodeFops(*M); // SPECIALFOP: fops stored in init_special_inode (char/block/fifo device nodes)
    enumPersistentDentryFops(*M);  // PERSISTFOP: fops on a persistent pseudo-fs dentry (binderfs, fuse-ctl, ...)
    enumProtosw(*M, DL);    // PROTOSW: inet_protosw entries (inet socket family/type/proto -> ops)
    enumSockProto(*M, DL);  // SOCKPROTO: non-inet family -> sk_prot (proto) via sk_alloc arg3 backward-slice
    enumCdevRaw(*M, DL);    // CDEV*: raw device-registration facts for the /dev-path recognizer (cdev paths)
    enumDebugfsRaw(*M);     // DBGFS*: raw dentry-dataflow events for the debugfs/tracefs path recognizer
    enumSndDevnodes(*M, DL); // SND*/DVBNODE: ALSA + DVB split-registration device-node facts
    enumDrmMinor(*M);       // DRMMINOR: proof the DRM core registers /dev/dri minor nodes (drm_stub_fops)
    enumCdromBdops(*M);     // CDROMBDOPS: block disk registered as CD-ROM (register_cdrom + device_add_disk)
    enumDevnodeSummary(*M); // DEVN*: per-fn devnode summary facts (same_fn/one_hop/usb/rtc cdev devnodes)
    return 0;
  }

  std::set<std::string> want;
  std::map<std::string, std::set<unsigned>> cmdEntrySeeds;
  auto addWant = [&](const std::string &tok) {
    size_t eq = tok.find('=');
    if (eq == std::string::npos) {
      want.insert(tok);
      return;
    }
    std::string op = tok.substr(0, eq);
    std::string fn = tok.substr(eq + 1);
    if (fn.empty())
      return;
    if (op == "ioctl") {
      want.insert(fn);
      cmdEntrySeeds[fn].insert(1);
    } else if (op == "setsockopt" || op == "getsockopt") {
      want.insert(fn);
      cmdEntrySeeds[fn].insert(2);
    } else if (op.rfind("arg", 0) == 0) {
      char *end = nullptr;
      unsigned long idx = std::strtoul(op.c_str() + 3, &end, 10);
      if (end && *end == '\0') {
        want.insert(fn);
        cmdEntrySeeds[fn].insert((unsigned)idx);
      } else {
        want.insert(tok);
      }
    } else {
      want.insert(tok);
    }
  };
  for (int i = mi + 1; i < argc; i++)
    addWant(argv[i]);

  if (gatesMode) {  // inner-gate slices: domSubtree(state-field branch) -> regionFuncs (bipartite, no hub)
    buildCallerCount(*M, DL, fieldTargets);
    analyzeGates(*M, DL, fieldTargets, want);
    return 0;
  }

  if (cmdMode) {
    buildCallerCount(*M, DL, fieldTargets);  // region value-specificity (consumed by regionFuncs)
    for (Function &F : *M) {
      // only the ③ dispatchers (want); empty want = no blind all-functions sweep — table-dispatch and
      // direct-syscall enumeration below cover the non-③ cases principally.
      if (F.isDeclaration() || want.empty() || !want.count(F.getName().str()))
        continue;
      auto it = cmdEntrySeeds.find(F.getName().str());
      static const std::set<unsigned> emptySeeds;
      analyzeCmd(F, DL, fieldTargets, it == cmdEntrySeeds.end() ? emptySeeds : it->second);
    }
    enumFieldIcalls(*M, DL);              // FIELD_ICALL: every indirect call through a struct field (ungated)
    enumFieldIcallSites(*M, DL);          // FIELD_ICALL_SITE + CMD_REACH: site-level cmd reachability (P0)
    enumCallbackBridges(*M);              // CALLBACK_BRIDGE: handler passed to a helper that calls it w/ cmd
    enumCmdTables(*M, DL, fieldTargets);  // table-dispatch (v4l2/drm/...) that switch-detection misses
    enumGenlTables(*M, DL, fieldTargets); // genetlink {cmd,doit} families (cmd-matched, not indexed)
    enumNfnetlinkTables(*M, DL, fieldTargets); // nfnetlink subsystems (IPSET, ...): cb[] indexed by cmd
    enumFsTypes(*M, DL, fieldTargets);    // filesystem mount via file_system_type.init_fs_context
    // DIRECT syscalls (bpf/keyctl/prctl/...): the opcode multiplexing switch lives in the
    // SYSCALL_DEFINE handler (__sys_X / __se_sys_X / __do_sys_X), which takes the opcode as a DIRECT
    // arg (the __x64_sys_X pt_regs wrapper loads it from regs->di and forwards it). Run ④ on those —
    // it auto-detects the arg-switch and emits opcode CMD rows. The SYSCALL_DEFINE naming is the
    // kernel's contract (like ③'s reg-API names); the binding itself is FOUND by ④'s switch detection.
    // The aggregator disambiguates the (small-int, colliding) opcodes by syscall base.
    for (Function &F : *M) {
      if (F.isDeclaration())
        continue;
      StringRef n = F.getName();
      if (!(n.starts_with("__sys_") || n.starts_with("__se_sys_") || n.starts_with("__do_sys_")))
        continue;
      // maxDepth 0: a syscall's opcode multiplex is a TOP-LEVEL switch (opcode -> handler region); emit only
      // those rows.  Following the opcode deeper explodes syscalls whose arg switch feeds a big computation
      // (mbind/get_mempolicy switch on a policy mode, then descend the mm subsystem: thousands of d1-d8 rows
      // that never match an opcode variant).  The aggregator only needs the top opcode->handler mapping.
      analyzeCmd(F, DL, fieldTargets, {}, "", 0);   // INLINE opcode switch (prctl/bpf/keyctl/...)
      // HELPER-forward: the handler forwards the opcode UNCHANGED to a helper that SWITCHES on it
      // (__se_sys_fcntl -> do_fcntl).  Analyze that helper's switch attributed to THIS handler (origin), so
      // the aggregator's syscall_base filter binds the rows.  Gated on the forwarded arg being the helper's
      // switch arg, so no broad follow.  (Single-TU: a cross-TU trampoline -- __se_sys_ptrace -> arch_ptrace
      // [decl] -> ptrace_request -- is not reachable here.)
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *H = CI->getCalledFunction())
              if (!H->isDeclaration() && H != &F) {
                int swIdx = cmdSwitchArgIndex(*H);
                if (swIdx < 0 || (unsigned)swIdx >= CI->arg_size())
                  continue;
                std::set<Argument *> a;
                std::set<Value *> s;
                argsBehind(CI->getArgOperand(swIdx), a, s);   // opcode forwarded from F's arg?
                for (Argument *arg : a)
                  if (arg->getParent() == &F) {
                    // maxDepth 0: emit only the helper's OWN opcode switch (the cmd->handler rows the
                    // aggregator needs).  Following the cmd deeper explodes non-multiplexer helpers whose
                    // cases sub-dispatch (mbind/kill/io_uring: 10-34k rows each).
                    analyzeCmd(*H, DL, fieldTargets, {}, F.getName().str(), 0);
                    break;
                  }
              }
    }
    return 0;
  }

  // fields whose RUNTIME value controls an indirect call (fn field for direct installs, ops-pointer field
  // for ops-table selection) — a WRITE of a function/global to one of these is a fptr install (paired with
  // the dispatch GATEs analyzeGates emits on the same fields).
  std::set<std::string> dispatchFields;
  for (Function &F : *M)
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *CI = dyn_cast<CallInst>(&I)) {
          std::string ff, of;
          icallFields(CI, DL, ff, of);
          auto isF = [](const std::string &s) {       // recoverable fields only (junk byte-GEPs are inert)
            return s.rfind("struct.", 0) == 0 || (!s.empty() && s[0] == '@');
          };
          if (isF(ff)) dispatchFields.insert(ff);
          if (isF(of)) dispatchFields.insert(of);
        }

  for (Function &F : *M) {
    if (F.isDeclaration())
      continue;
    if (!want.empty() && !want.count(F.getName().str()))
      continue;
    std::string fn = F.getName().str();
    // cmd-region partition: the top-level cmd-switch case-region (DominatorTree subtree) that owns each BB, so a
    // WRITE/GATE/CALL can be scoped to the specific cmd.  loop's SET_FD/CLR_FD/SET_STATUS all bind to lo_ioctl;
    // only the case-BB separates them (probe: the CMD-fact slots ARE these case-BBs).  Emitted as a per-BB RBB
    // marker preceding that BB's facts in stream order.  "-" = no cmd-switch (fn attributed via CALL-closure
    // from its callers); "common" = pre-switch setup / post-switch merge (excluded from per-cmd def-use);
    // "?" = dominated by >1 case.
    std::map<BasicBlock *, std::string> bb2cmd;
    bool hasCmdSw = false;
    {
      std::vector<std::pair<std::string, BasicBlock *>> cases;   // (cmd value, case-entry BB)
      SwitchInst *cmdSw = nullptr;
      for (BasicBlock &SB : F)
        if (auto *SW = dyn_cast<SwitchInst>(SB.getTerminator())) {
          std::set<Argument *> aa;
          std::set<Value *> ss;
          argsBehind(SW->getCondition(), aa, ss);
          if (!aa.empty()) { cmdSw = SW; break; }   // first arg-driven switch = the cmd dispatch
        }
      if (cmdSw) {
        for (auto Cs : cmdSw->cases())
          cases.emplace_back(apStr(Cs.getCaseValue()->getValue(), true), Cs.getCaseSuccessor());
      } else {
        // if-chain dispatch: RBB missed handlers that use `if(cmd==K1) ... else if(cmd==K2) ...` (no SwitchInst,
        // e.g. acm_tty_ioctl/evdev_ioctl).  An arg compared eq/ne against >= 3 distinct constants IS the cmd;
        // each compare's ==K edge is that cmd's case region (dominated by the ==K successor, same as a switch case).
        std::map<Argument *, std::vector<std::pair<std::string, BasicBlock *>>> byArg;
        std::map<Argument *, std::set<uint64_t>> nk;
        for (BasicBlock &SB : F) {
          auto *BI = dyn_cast<BranchInst>(SB.getTerminator());
          if (!BI || !BI->isConditional())
            continue;
          auto *IC = dyn_cast<ICmpInst>(BI->getCondition());
          if (!IC || (IC->getPredicate() != CmpInst::ICMP_EQ && IC->getPredicate() != CmpInst::ICMP_NE))
            continue;
          Value *v = IC->getOperand(0);
          ConstantInt *K = dyn_cast<ConstantInt>(IC->getOperand(1));
          if (!K) { K = dyn_cast<ConstantInt>(IC->getOperand(0)); v = IC->getOperand(1); }
          if (!K)
            continue;
          std::set<Argument *> aa;
          std::set<Value *> ss;
          argsBehind(v, aa, ss);
          if (aa.size() != 1)                                    // compared value traces to exactly one arg
            continue;
          BasicBlock *eqSucc = BI->getSuccessor(IC->getPredicate() == CmpInst::ICMP_EQ ? 0 : 1);  // the ==K edge
          byArg[*aa.begin()].emplace_back(apStr(K->getValue(), true), eqSucc);
          nk[*aa.begin()].insert(K->getValue().getZExtValue());
        }
        Argument *cmdArg = nullptr;
        size_t best = 0;
        for (auto &kv : nk)
          if (kv.second.size() > best) { best = kv.second.size(); cmdArg = kv.first; }
        if (cmdArg && best >= 3)                                 // >= 3 distinct cmds = a real dispatch, not a guard
          cases = byArg[cmdArg];
      }
      if (!cases.empty()) {
        hasCmdSw = true;
        DominatorTree DT(F);
        for (auto &c : cases) {
          std::set<BasicBlock *> sub;
          sub.insert(c.second);
          domSubtree(DT, c.second, sub);
          for (BasicBlock *b : sub) {
            auto it = bb2cmd.find(b);
            if (it == bb2cmd.end()) bb2cmd[b] = c.first;
            else if (it->second != c.first) it->second = "?";
          }
        }
      }
    }
    auto region = [&](BasicBlock *b) -> std::string {
      if (!hasCmdSw) return "-";
      auto it = bb2cmd.find(b);
      return it != bb2cmd.end() ? it->second : "common";
    };
    for (BasicBlock &BB : F) {
      outs() << "RBB\t" << fn << "\t" << region(&BB) << "\n";   // cmd-region of the facts that follow
      for (Instruction &I : BB) {
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
          std::string srcf = sourceField(SI->getValueOperand(), DL);   // col5 = source field G if F<-G
          outs() << "WRITE\t" << fn << "\t" << absLoc(SI->getPointerOperand(), DL) << "\t"
                 << storeVal(SI->getValueOperand()) << "\t"
                 << provenanceRoot(SI->getPointerOperand(), DL)        // col4 = S (object identity)
                 << (srcf.empty() ? "" : "\t" + srcf) << "\n";          // col5 = F derives from field G
          std::string gw = globalLoc(SI->getPointerOperand(), DL);  // E9: additive global-state write
          if (!gw.empty())
            outs() << "WRITE\t" << fn << "\t" << gw << "\t" << storeVal(SI->getValueOperand()) << "\t@global\n";
          // fptr install: a runtime WRITE of a POINTER into a dispatch-controlling field — a function
          // (direct obj->handler=fn) or an ops table (selection obj->ops=&table OR =looked_up_ops). The
          // dispatchFields gate is the signal (the field's value determines an indirect-call target); it
          // excludes ordinary data-field stores. Couples with the dispatch GATE on the same field (S="fptr").
          std::string ploc = absLoc(SI->getPointerOperand(), DL);
          if (dispatchFields.count(ploc) && SI->getValueOperand()->getType()->isPointerTy())
            outs() << "WRITE\t" << fn << "\t" << ploc << "\tfptr-install\tfptr\n";
        } else if (auto *AI = dyn_cast<AtomicRMWInst>(&I)) {
          outs() << "WRITE\t" << fn << "\t" << absLoc(AI->getPointerOperand(), DL) << "\t"
                 << storeVal(AI->getValOperand()) << "\n";
        } else if (auto *CI = dyn_cast<CallInst>(&I)) {
          if (CI->isInlineAsm()) {
            auto *ia = cast<InlineAsm>(CI->getCalledOperand());
            std::string a = ia->getAsmString();
            if (a.find("bts") != std::string::npos || a.find("btr") != std::string::npos ||
                a.find("orb") != std::string::npos || a.find("orq") != std::string::npos ||
                a.find("lock or") != std::string::npos) {
              std::string loc = "?";
              std::string bit = "?";
              for (Value *op : CI->args()) {
                if (op->getType()->isPointerTy() && loc == "?")
                  loc = absLoc(op, DL);
                if (auto *ci = dyn_cast<ConstantInt>(op))
                  bit = apStr(ci->getValue(), false);
              }
              outs() << "WRITE\t" << fn << "\t" << loc << "\tasmbit:" << bit << "\n";
            }
          } else if (Function *cal = CI->getCalledFunction()) {
            std::string cn = cal->getName().str();
            outs() << "CALL\t" << fn << "\t" << cn << "\tdirect\n";
            if (const char *k = containerOp(cn))    // idr/xarray collection coupling (E4)
              if (CI->arg_size() > 0) {
                std::string cloc = containerLoc(CI->getArgOperand(0), DL);  // non-drill: drm_file+136, not spinlock+0
                if (cloc.rfind("struct.", 0) == 0 || (!cloc.empty() && cloc[0] == '@')) {  // named-struct or global collection
                  outs() << "CONTAINER\t" << fn << "\t" << k << "\t" << cloc << "\n";
                  if (std::string(k) == "INS")   // ALSO a WRITE(membership) on the root (S="coll") so the
                    // S/P/R writers⋈gates join couples INS -> lookup-gate (producer establishes membership=P).
                    outs() << "WRITE\t" << fn << "\t" << cloc << "\tmembership\tcoll\n";
                }
              }
          } else {
            // opaque-pointer field-based devirt: fptr loaded from a (struct,field) GEP whose type
            // survives in getSourceElementType(); targets = functions stored/initialized there.
            Value *co = CI->getCalledOperand();
            std::string loc = "?";
            if (auto *L = dyn_cast<LoadInst>(co))
              loc = absLoc(L->getPointerOperand(), DL);
            auto it = fieldTargets.find(loc);
            int nt = (it == fieldTargets.end()) ? 0 : (int)it->second.size();
            outs() << "ICALL\t" << fn << "\t" << loc << "\t" << nt << "\t";
            if (it != fieldTargets.end()) {
              int k = 0;
              for (auto &t : it->second) {
                if (k++) outs() << ",";
                if (k > 12) { outs() << "..."; break; }
                outs() << t;
              }
            }
            outs() << "\n";
          }
        } else if (auto *BI = dyn_cast<BranchInst>(&I)) {
          if (BI->isConditional()) {
            std::set<std::string> locs, vals;
            sliceCond(BI->getCondition(), DL, locs, vals);
            for (auto &l : locs)
              outs() << "BRANCHUSE\t" << fn << "\t" << l << "\t" << join(vals) << "\n";
            // E7 relational: a direct `field op const` guard (op != ==; == is const_eq's via BRANCHUSE).
            if (auto *IC = dyn_cast<ICmpInst>(BI->getCondition()))
              if (IC->getPredicate() != CmpInst::ICMP_EQ) {
                Value *a = IC->getOperand(0), *b = IC->getOperand(1);
                LoadInst *ld = dyn_cast<LoadInst>(a);
                ConstantInt *k = dyn_cast<ConstantInt>(b);
                if (!ld) { ld = dyn_cast<LoadInst>(b); k = dyn_cast<ConstantInt>(a); }
                if (ld && k) {
                  std::string sl = absLoc(ld->getPointerOperand(), DL);
                  std::string gl = globalLoc(ld->getPointerOperand(), DL);
                  std::string pn(CmpInst::getPredicateName(IC->getPredicate()));
                  std::string vs = apStr(k->getValue(), true);
                  if (sl.rfind("struct.", 0) == 0)
                    outs() << "BRANCHREL\t" << fn << "\t" << sl << "\t" << pn << "\t" << vs << "\n";
                  if (!gl.empty())
                    outs() << "BRANCHREL\t" << fn << "\t" << gl << "\t" << pn << "\t" << vs << "\n";
                }
              }
          }
        } else if (auto *SW = dyn_cast<SwitchInst>(&I)) {
          std::set<std::string> locs, vals;
          sliceCond(SW->getCondition(), DL, locs, vals);
          std::string condloc = locs.empty() ? "(reg)" : *locs.begin();
          for (auto &l : locs)
            outs() << "BRANCHUSE\t" << fn << "\t" << l << "\tswitch\n";
          for (auto C : SW->cases())
            outs() << "SWITCH\t" << fn << "\t" << condloc << "\t"
                   << apStr(C.getCaseValue()->getValue(), true) << "\t"
                   << C.getCaseSuccessor()->getName().str() << "\n";
        }
      }
    }
  }
  return 0;
}
