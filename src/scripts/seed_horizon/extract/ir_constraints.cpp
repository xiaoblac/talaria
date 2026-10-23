#include "llvm/ADT/APInt.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugProgramInstruction.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

namespace {

std::string cleanCell(StringRef value) {
  std::string result = value.str();
  for (char &character : result) {
    if (character == '\t' || character == '\n' || character == '\r')
      character = ' ';
  }
  return result.empty() ? "-" : result;
}

std::string signedString(const APInt &value) {
  SmallString<40> buffer;
  value.toString(buffer, 10, true);
  return std::string(buffer.str());
}

std::string unsignedString(const APInt &value) {
  SmallString<40> buffer;
  value.toString(buffer, 10, false);
  return std::string(buffer.str());
}

std::string stripStructSuffix(std::string name) {
  if (name.rfind("struct.", 0) == 0)
    name = name.substr(7);
  size_t firstDot = name.find('.');
  if (firstDot == std::string::npos)
    return name;
  size_t secondDot = name.find('.', firstDot + 1);
  return secondDot == std::string::npos ? name : name.substr(0, secondDot);
}

DICompositeType *compositeType(DIType *type) {
  for (unsigned depth = 0; type && depth < 8; ++depth) {
    if (auto *composite = dyn_cast<DICompositeType>(type))
      return composite;
    auto *derived = dyn_cast<DIDerivedType>(type);
    if (!derived)
      return nullptr;
    type = derived->getBaseType();
  }
  return nullptr;
}

std::string pointedStructName(DIType *type) {
  auto *derived = dyn_cast_or_null<DIDerivedType>(type);
  if (!derived || derived->getTag() != dwarf::DW_TAG_pointer_type)
    return "";
  auto *composite = compositeType(derived->getBaseType());
  return composite && !composite->getName().empty() ? composite->getName().str() : "";
}

DITypeRefArray subroutineTypes(const Function *function) {
  DISubprogram *subprogram = function ? function->getSubprogram() : nullptr;
  auto *subroutine = subprogram ? dyn_cast_or_null<DISubroutineType>(subprogram->getType()) : nullptr;
  return subroutine ? subroutine->getTypeArray() : DITypeRefArray();
}

std::string debugValueStruct(const Value *value) {
  if (!value)
    return "";
  SmallVector<DbgValueInst *, 4> debugValues;
  SmallVector<DbgVariableRecord *, 4> debugRecords;
  findDbgValues(debugValues, const_cast<Value *>(value), &debugRecords);
  for (DbgValueInst *debugValue : debugValues) {
    DILocalVariable *variable = debugValue ? debugValue->getVariable() : nullptr;
    DICompositeType *composite = variable ? compositeType(variable->getType()) : nullptr;
    if (composite && !composite->getName().empty())
      return composite->getName().str();
  }
  for (DbgVariableRecord *debugRecord : debugRecords) {
    if (!debugRecord || !debugRecord->isValueOfVariable())
      continue;
    DILocalVariable *variable = debugRecord->getVariable();
    DICompositeType *composite = variable ? compositeType(variable->getType()) : nullptr;
    if (composite && !composite->getName().empty())
      return composite->getName().str();
  }
  return "";
}

class ConstraintEmitter {
 public:
  explicit ConstraintEmitter(Module &module)
      : module_(module), layout_(module.getDataLayout()) {
    buildInstructionIds();
    buildGlobalNames();
    buildDwarfFields();
  }

  void run() {
    emitNullObject();
    emitGlobalObjects();
    emitFunctionObjects();
    emitAliases();
    emitGlobalInitializers();
    emitFunctions();
  }

 private:
  Module &module_;
  const DataLayout layout_;
  std::map<const Instruction *, unsigned> instructionIds_;
  std::map<const GlobalValue *, std::string> globalNames_;
  std::map<std::string, std::map<int64_t, std::string>> dwarfFields_;
  std::set<std::string> emittedObjects_;
  std::set<std::string> emittedSeeds_;
  std::set<std::string> emittedExpressions_;
  std::map<Type *, bool> pointerContainment_;
  std::set<Type *> pointerContainmentActive_;

  void buildInstructionIds() {
    for (Function &function : module_) {
      if (function.isDeclaration())
        continue;
      unsigned ordinal = 0;
      for (BasicBlock &block : function)
        for (Instruction &instruction : block)
          instructionIds_[&instruction] = ordinal++;
    }
  }

  void buildGlobalNames() {
    unsigned globalOrdinal = 0;
    for (GlobalVariable &global : module_.globals())
      globalNames_[&global] = global.hasName()
                                  ? cleanCell(global.getName())
                                  : "unnamed_global_" + std::to_string(globalOrdinal++);
    unsigned functionOrdinal = 0;
    for (Function &function : module_)
      globalNames_[&function] = function.hasName()
                                    ? cleanCell(function.getName())
                                    : "unnamed_function_" + std::to_string(functionOrdinal++);
    unsigned aliasOrdinal = 0;
    for (GlobalAlias &alias : module_.aliases())
      globalNames_[&alias] = alias.hasName()
                                 ? cleanCell(alias.getName())
                                 : "unnamed_alias_" + std::to_string(aliasOrdinal++);
  }

  std::string symbolName(const GlobalValue &value) const {
    auto iterator = globalNames_.find(&value);
    return iterator == globalNames_.end() ? cleanCell(value.getName()) : iterator->second;
  }

  void buildDwarfFields() {
    DebugInfoFinder finder;
    finder.processModule(module_);
    std::vector<const DICompositeType *> composites;
    for (const DIType *type : finder.types())
      if (auto *composite = dyn_cast<DICompositeType>(type))
        composites.push_back(composite);
    for (GlobalVariable &global : module_.globals()) {
      SmallVector<DIGlobalVariableExpression *, 2> expressions;
      global.getDebugInfo(expressions);
      for (DIGlobalVariableExpression *expression : expressions) {
        DIGlobalVariable *variable = expression ? expression->getVariable() : nullptr;
        if (auto *composite = variable ? compositeType(variable->getType()) : nullptr)
          composites.push_back(composite);
      }
    }
    std::set<const DICompositeType *> seen;
    for (const DICompositeType *composite : composites) {
      if (!composite || composite->getName().empty() || !seen.insert(composite).second)
        continue;
      std::string structName = stripStructSuffix(composite->getName().str());
      for (DINode *element : composite->getElements()) {
        auto *member = dyn_cast_or_null<DIDerivedType>(element);
        if (!member || member->getTag() != dwarf::DW_TAG_member || member->getName().empty())
          continue;
        dwarfFields_[structName].emplace(
            static_cast<int64_t>(member->getOffsetInBits() / 8), member->getName().str());
      }
    }
  }

  std::string instructionName(const Instruction &instruction) const {
    auto iterator = instructionIds_.find(&instruction);
    return iterator == instructionIds_.end() ? "-" : "i" + std::to_string(iterator->second);
  }

  std::string functionName(const Function *function) const {
    return function ? cleanCell(function->getName()) : "-";
  }

  std::string debugLocation(const Instruction *instruction) const {
    if (!instruction)
      return "-";
    DebugLoc location = instruction->getDebugLoc();
    if (!location)
      return "-";
    auto *scope = dyn_cast_or_null<DIScope>(location.getScope());
    std::string file = scope ? scope->getFilename().str() : "";
    if (file.empty())
      file = "?";
    return cleanCell(file) + ":" + std::to_string(location.getLine()) + ":" +
           std::to_string(location.getCol());
  }

  std::string debugLocation(const Function *function) const {
    DISubprogram *subprogram = function ? function->getSubprogram() : nullptr;
    DIFile *file = subprogram ? subprogram->getFile() : nullptr;
    if (!subprogram || !file)
      return "-";
    return cleanCell(file->getFilename()) + ":" + std::to_string(subprogram->getLine()) + ":0";
  }

  int64_t fixedTypeSize(Type *type) const {
    if (!type || !type->isSized())
      return -1;
    TypeSize size = layout_.getTypeAllocSize(type);
    return size.isScalable() ? -1 : static_cast<int64_t>(size.getFixedValue());
  }

  std::string typeLabel(Type *type, unsigned depth = 0) const {
    if (!type)
      return "-";
    if (type->isPointerTy())
      return "ptr";
    if (auto *integer = dyn_cast<IntegerType>(type))
      return "i" + std::to_string(integer->getBitWidth());
    if (auto *structure = dyn_cast<StructType>(type)) {
      if (structure->hasName())
        return "struct." + stripStructSuffix(structure->getName().str());
      return "anon_struct:" + std::to_string(structure->getNumElements()) + ":" +
             std::to_string(fixedTypeSize(structure));
    }
    if (auto *array = dyn_cast<ArrayType>(type)) {
      if (depth >= 2)
        return "array[" + std::to_string(array->getNumElements()) + "]";
      return "array[" + std::to_string(array->getNumElements()) + "]:" +
             typeLabel(array->getElementType(), depth + 1);
    }
    if (auto *vector = dyn_cast<FixedVectorType>(type))
      return "vector[" + std::to_string(vector->getNumElements()) + "]:" +
             typeLabel(vector->getElementType(), depth + 1);
    if (type->isFunctionTy())
      return "function";
    if (type->isVoidTy())
      return "void";
    if (type->isFloatingPointTy())
      return "float";
    return "type:" + std::to_string(type->getTypeID());
  }

  bool containsPointer(Type *type) {
    if (!type)
      return false;
    if (type->isPointerTy())
      return true;
    auto cached = pointerContainment_.find(type);
    if (cached != pointerContainment_.end())
      return cached->second;
    if (!pointerContainmentActive_.insert(type).second)
      return false;
    bool result = false;
    if (auto *structure = dyn_cast<StructType>(type)) {
      if (!structure->isOpaque())
        for (Type *element : structure->elements())
          result = result || containsPointer(element);
    } else if (auto *array = dyn_cast<ArrayType>(type)) {
      result = containsPointer(array->getElementType());
    } else if (auto *vector = dyn_cast<FixedVectorType>(type)) {
      result = containsPointer(vector->getElementType());
    }
    pointerContainmentActive_.erase(type);
    pointerContainment_[type] = result;
    return result;
  }

  struct TypeEvidence {
    std::set<std::string> structures;
    bool complete = true;
  };

  void collectContainedStructs(Type *type, TypeEvidence &evidence,
                               std::set<Type *> &active) const {
    if (!type) {
      evidence.complete = false;
      return;
    }
    if (type->isPointerTy() || !active.insert(type).second)
      return;
    if (auto *structure = dyn_cast<StructType>(type)) {
      if (structure->hasName())
        evidence.structures.insert(stripStructSuffix(structure->getName().str()));
      if (structure->isOpaque()) {
        evidence.complete = false;
      } else {
        for (Type *element : structure->elements())
          collectContainedStructs(element, evidence, active);
      }
    } else if (auto *array = dyn_cast<ArrayType>(type)) {
      collectContainedStructs(array->getElementType(), evidence, active);
    } else if (auto *vector = dyn_cast<FixedVectorType>(type)) {
      collectContainedStructs(vector->getElementType(), evidence, active);
    }
    active.erase(type);
  }

  void collectDebugStructs(DIType *type, TypeEvidence &evidence,
                           std::set<DIType *> &active) const {
    if (!type) {
      evidence.complete = false;
      return;
    }
    unsigned tag = type->getTag();
    if (tag == dwarf::DW_TAG_pointer_type || tag == dwarf::DW_TAG_reference_type ||
        tag == dwarf::DW_TAG_rvalue_reference_type ||
        tag == dwarf::DW_TAG_ptr_to_member_type || tag == dwarf::DW_TAG_subroutine_type)
      return;
    if (!active.insert(type).second)
      return;
    if (auto *composite = dyn_cast<DICompositeType>(type)) {
      if (composite->isForwardDecl())
        evidence.complete = false;
      if ((tag == dwarf::DW_TAG_structure_type || tag == dwarf::DW_TAG_union_type ||
           tag == dwarf::DW_TAG_class_type) &&
          !composite->getName().empty())
        evidence.structures.insert(stripStructSuffix(composite->getName().str()));
      if (tag == dwarf::DW_TAG_array_type) {
        collectDebugStructs(composite->getBaseType(), evidence, active);
      } else if (tag == dwarf::DW_TAG_structure_type || tag == dwarf::DW_TAG_union_type ||
                 tag == dwarf::DW_TAG_class_type) {
        for (Metadata *element : composite->getElements())
          if (auto *elementType = dyn_cast<DIType>(element))
            collectDebugStructs(elementType, evidence, active);
      }
    } else if (auto *derived = dyn_cast<DIDerivedType>(type)) {
      if (DIType *base = derived->getBaseType())
        collectDebugStructs(base, evidence, active);
      else
        evidence.complete = false;
    }
    active.erase(type);
  }

  bool collectDebugValueStructs(const Value *value, TypeEvidence &evidence) const {
    if (!value)
      return false;
    bool found = false;
    auto collectVariable = [&](DILocalVariable *variable) {
      if (!variable || !variable->getType())
        return;
      found = true;
      std::set<DIType *> active;
      collectDebugStructs(variable->getType(), evidence, active);
    };
    if (auto *global = dyn_cast<GlobalVariable>(value)) {
      SmallVector<DIGlobalVariableExpression *, 2> expressions;
      global->getDebugInfo(expressions);
      for (DIGlobalVariableExpression *expression : expressions) {
        DIGlobalVariable *variable = expression ? expression->getVariable() : nullptr;
        if (!variable || !variable->getType())
          continue;
        found = true;
        std::set<DIType *> active;
        collectDebugStructs(variable->getType(), evidence, active);
      }
      return found;
    }
    SmallVector<DbgValueInst *, 4> debugValues;
    SmallVector<DbgVariableRecord *, 4> debugRecords;
    findDbgValues(debugValues, const_cast<Value *>(value), &debugRecords);
    for (DbgValueInst *debugValue : debugValues)
      collectVariable(debugValue ? debugValue->getVariable() : nullptr);
    for (DbgVariableRecord *debugRecord : debugRecords)
      if (debugRecord && debugRecord->isValueOfVariable())
        collectVariable(debugRecord->getVariable());
    return found;
  }

  std::string containedStructs(Type *type, const Value *value) const {
    if (!type)
      return "";
    TypeEvidence evidence;
    std::set<Type *> active;
    collectContainedStructs(type, evidence, active);
    if (isa<StructType>(type) || isa<ArrayType>(type) || isa<FixedVectorType>(type))
      collectDebugValueStructs(value, evidence);
    std::string result;
    for (const std::string &name : evidence.structures) {
      if (!result.empty())
        result += ',';
      result += name;
    }
    if (!evidence.complete)
      return "?" + result;
    return result;
  }

  bool batchScoped(const GlobalValue &value) const {
    return value.hasLocalLinkage() || value.hasAppendingLinkage();
  }

  std::string scope(const GlobalValue &value) const {
    return batchScoped(value) ? "batch" : "symbol";
  }

  std::string symbolPrefix(const GlobalValue &value) const {
    return batchScoped(value) ? "local" : "sym";
  }

  std::string globalValueId(const GlobalValue &value, StringRef category) const {
    return symbolPrefix(value) + ":value:" + category.str() + ":" + symbolName(value);
  }

  std::string globalObjectId(const GlobalValue &value, StringRef category) const {
    return symbolPrefix(value) + ":object:" + category.str() + ":" + symbolName(value);
  }

  std::string ssaValueId(const Argument &argument) const {
    return "ssa:" + functionName(argument.getParent()) + ":arg:" +
           std::to_string(argument.getArgNo());
  }

  std::string ssaValueId(const Instruction &instruction) const {
    return "ssa:" + functionName(instruction.getFunction()) + ":" + instructionName(instruction);
  }

  std::string siteName(const Function *function, const Instruction *instruction,
                       StringRef suffix = "") const {
    std::string result = functionName(function) + ":" +
                         (instruction ? instructionName(*instruction) : "global");
    if (!suffix.empty())
      result += ":" + cleanCell(suffix);
    return result;
  }

  void emitObject(StringRef objectId, StringRef kind, StringRef objectScope, StringRef symbol,
                  StringRef parent, StringRef byteOffset, Type *type, int64_t size,
                  const Function *function, const Instruction *instruction, StringRef detail,
                  const Value *value = nullptr) {
    std::string id = objectId.str();
    if (!emittedObjects_.insert(id).second)
      return;
    outs() << "COBJ\t" << cleanCell(id) << "\t" << cleanCell(kind) << "\t"
           << cleanCell(objectScope) << "\t" << cleanCell(symbol) << "\t" << cleanCell(parent)
           << "\t" << cleanCell(byteOffset) << "\t" << cleanCell(typeLabel(type)) << "\t"
           << cleanCell(containedStructs(type, value)) << "\t" << size
           << "\t" << functionName(function) << "\t"
           << (instruction ? instructionName(*instruction) : "-") << "\t"
           << (instruction ? debugLocation(instruction) : debugLocation(function)) << "\t"
           << cleanCell(detail) << "\n";
  }

  void emitPoint(StringRef kind, StringRef destination, StringRef source, StringRef objectId,
                 StringRef byteOffset, StringRef offsetKind, StringRef structType,
                 StringRef fieldName, const Function *function, const Instruction *instruction,
                 StringRef opcode, StringRef detail, StringRef dynamicBase = "-",
                 StringRef dynamicStride = "-", StringRef dynamicCount = "-",
                 StringRef sourceType = "-") {
    outs() << "CPT\t" << cleanCell(kind) << "\t" << cleanCell(destination) << "\t"
           << cleanCell(source) << "\t" << cleanCell(objectId) << "\t" << cleanCell(byteOffset)
           << "\t" << cleanCell(offsetKind) << "\t" << cleanCell(structType) << "\t"
           << cleanCell(fieldName) << "\t" << functionName(function) << "\t"
           << (instruction ? instructionName(*instruction) : "-") << "\t" << cleanCell(opcode)
           << "\t" << (instruction ? debugLocation(instruction) : debugLocation(function)) << "\t"
           << cleanCell(detail) << "\t" << cleanCell(dynamicBase) << "\t"
           << cleanCell(dynamicStride) << "\t" << cleanCell(dynamicCount) << "\t"
           << cleanCell(sourceType) << "\n";
  }

  void emitMemory(StringRef kind, StringRef destination, StringRef pointer, StringRef source,
                  StringRef objectId, StringRef byteOffset, StringRef size,
                  const Function *function, const Instruction *instruction, StringRef opcode,
                  StringRef detail) {
    outs() << "CMEM\t" << cleanCell(kind) << "\t" << cleanCell(destination) << "\t"
           << cleanCell(pointer) << "\t" << cleanCell(source) << "\t" << cleanCell(objectId)
           << "\t" << cleanCell(byteOffset) << "\t" << cleanCell(size) << "\t"
           << functionName(function) << "\t"
           << (instruction ? instructionName(*instruction) : "-") << "\t" << cleanCell(opcode)
           << "\t" << (instruction ? debugLocation(instruction) : debugLocation(function)) << "\t"
           << cleanCell(detail) << "\n";
  }

  void emitCall(StringRef kind, StringRef callsite, StringRef caller, StringRef callee,
                StringRef targetObject, StringRef index, StringRef value, StringRef result,
                const Function *function, const Instruction *instruction, StringRef opcode,
                StringRef attributes, StringRef detail) {
    outs() << "CCALL\t" << cleanCell(kind) << "\t" << cleanCell(callsite) << "\t"
           << cleanCell(caller) << "\t" << cleanCell(callee) << "\t" << cleanCell(targetObject)
           << "\t" << cleanCell(index) << "\t" << cleanCell(value) << "\t" << cleanCell(result)
           << "\t" << functionName(function) << "\t"
           << (instruction ? instructionName(*instruction) : "-") << "\t" << cleanCell(opcode)
           << "\t" << cleanCell(attributes) << "\t"
           << (instruction ? debugLocation(instruction) : debugLocation(function)) << "\t"
           << cleanCell(detail) << "\n";
  }

  void emitAddressSeed(StringRef destination, StringRef objectId, const Function *function,
                       const Instruction *instruction, StringRef opcode, StringRef detail,
                       StringRef kind = "ADDR_OF") {
    std::string key = kind.str() + "\t" + destination.str() + "\t" + objectId.str();
    if (!emittedSeeds_.insert(key).second)
      return;
    emitPoint(kind, destination, "-", objectId, "0", "exact", "-", "-", function,
              instruction, opcode, detail);
  }

  void emitNullObject() {
    emitObject("special:object:null", "null", "special", "null", "-", "-", nullptr, 0,
               nullptr, nullptr, "canonical null object");
    emitAddressSeed("special:value:null", "special:object:null", nullptr, nullptr, "constant",
                    "null pointer");
  }

  void ensureGlobalValue(GlobalValue &value) {
    if (auto *function = dyn_cast<Function>(&value)) {
      if (function->isDeclaration())
        return;
      std::string objectId = globalObjectId(*function, "function");
      emitObject(objectId, "function", scope(*function), symbolName(*function), "-", "-",
                 function->getFunctionType(), 0, function, nullptr,
                 function->hasAddressTaken() ? "address-taken" : "defined");
      emitAddressSeed(globalValueId(*function, "function"), objectId, function, nullptr,
                      "symbol", "function address");
      return;
    }
    if (auto *global = dyn_cast<GlobalVariable>(&value)) {
      if (global->isDeclaration())
        return;
      std::string objectId = globalObjectId(*global, "global");
      emitObject(objectId, "global", scope(*global), symbolName(*global), "-", "-",
                 global->getValueType(), fixedTypeSize(global->getValueType()), nullptr, nullptr,
                 global->isThreadLocal() ? "thread-local" : "defined", global);
      emitAddressSeed(globalValueId(*global, "global"), objectId, nullptr, nullptr, "symbol",
                      "global address");
    }
  }

  void emitGlobalObjects() {
    for (GlobalVariable &global : module_.globals())
      ensureGlobalValue(global);
  }

  void emitFunctionObjects() {
    for (Function &function : module_)
      ensureGlobalValue(function);
  }

  std::string pointerValue(Value *value, StringRef hint, const Function *function,
                           const Instruction *instruction) {
    if (!value || !value->getType()->isPointerTy())
      return "-";
    if (auto *argument = dyn_cast<Argument>(value))
      return ssaValueId(*argument);
    if (auto *ssaInstruction = dyn_cast<Instruction>(value))
      return ssaValueId(*ssaInstruction);
    if (auto *functionValue = dyn_cast<Function>(value)) {
      ensureGlobalValue(*functionValue);
      return globalValueId(*functionValue, "function");
    }
    if (auto *global = dyn_cast<GlobalVariable>(value)) {
      ensureGlobalValue(*global);
      return globalValueId(*global, "global");
    }
    if (isa<ConstantPointerNull>(value))
      return "special:value:null";
    if (auto *alias = dyn_cast<GlobalAlias>(value)) {
      std::string aliasId = globalValueId(*alias, "alias");
      if (emittedExpressions_.insert(aliasId).second) {
        std::string aliaseeId = pointerValue(alias->getAliasee(), aliasId + ":aliasee", function,
                                             instruction);
        emitPoint("COPY", aliasId, aliaseeId, "-", "-", "-", "-", "-", function,
                  instruction, "alias", "global alias");
      }
      return aliasId;
    }
    if (auto *expression = dyn_cast<ConstantExpr>(value))
      return emitConstantExpression(*expression, hint, function, instruction);
    if (auto *blockAddress = dyn_cast<BlockAddress>(value)) {
      Function *owner = blockAddress->getFunction();
      std::string valueId = "expr:" + cleanCell(hint) + ":blockaddress";
      std::string objectId = "site:object:block:" + cleanCell(hint);
      emitObject(objectId, "block", "site", owner ? owner->getName() : "-", "-", "-",
                 nullptr, 0, function, instruction, "blockaddress");
      emitAddressSeed(valueId, objectId, function, instruction, "blockaddress", "block address");
      return valueId;
    }
    return emitUnknownValue(value->getType(), hint, function, instruction, "unsupported constant");
  }

  std::string emitUnknownValue(Type *type, StringRef hint, const Function *function,
                               const Instruction *instruction, StringRef detail) {
    std::string valueId = "expr:" + cleanCell(hint) + ":unknown";
    std::string objectId = "site:object:unknown:" + cleanCell(hint);
    emitObject(objectId, "unknown", "site", "-", "-", "-", type, -1, function,
               instruction, detail);
    emitAddressSeed(valueId, objectId, function, instruction, "unknown", detail,
                    "UNKNOWN_ADDR");
    return valueId;
  }

  std::string emitConstantExpression(ConstantExpr &expression, StringRef hint,
                                     const Function *function, const Instruction *instruction) {
    std::string destination = "expr:" + cleanCell(hint);
    if (!emittedExpressions_.insert(destination).second)
      return destination;
    unsigned opcode = expression.getOpcode();
    if (opcode == Instruction::BitCast || opcode == Instruction::AddrSpaceCast) {
      std::string source = pointerValue(expression.getOperand(0), destination + ":source", function,
                                        instruction);
      emitPoint("COPY", destination, source, "-", "-", "-", "-", "-", function,
                instruction, expression.getOpcodeName(), "constant pointer cast");
      return destination;
    }
    if (opcode == Instruction::GetElementPtr) {
      auto *gep = cast<GEPOperator>(&expression);
      std::string source = pointerValue(gep->getPointerOperand(), destination + ":base", function,
                                        instruction);
      emitGepConstraint(destination, source, *gep, function, instruction,
                        expression.getOpcodeName(), "constant expression GEP");
      return destination;
    }
    if (opcode == Instruction::Select) {
      for (unsigned operandIndex : {1U, 2U}) {
        std::string source = pointerValue(expression.getOperand(operandIndex),
                                          destination + ":select:" + std::to_string(operandIndex),
                                          function, instruction);
        emitPoint("COPY", destination, source, "-", "-", "-", "-", "-", function,
                  instruction, expression.getOpcodeName(), "constant select");
      }
      return destination;
    }
    emitUnknownForDestination(destination, expression.getType(), hint, function, instruction,
                              expression.getOpcodeName(), "unsupported ConstantExpr");
    return destination;
  }

  void emitUnknownForDestination(StringRef destination, Type *type, StringRef hint,
                                 const Function *function, const Instruction *instruction,
                                 StringRef opcode, StringRef detail) {
    std::string objectId = "site:object:unknown:" + cleanCell(hint);
    emitObject(objectId, "unknown", "site", "-", "-", "-", type, -1, function,
               instruction, detail);
    emitAddressSeed(destination, objectId, function, instruction, opcode, detail,
                    "UNKNOWN_ADDR");
  }

  std::string sourceStruct(const Value *base, Type *sourceType) const {
    Type *candidate = sourceType;
    while (auto *array = dyn_cast_or_null<ArrayType>(candidate))
      candidate = array->getElementType();
    if (auto *structure = dyn_cast_or_null<StructType>(candidate))
      if (structure->hasName())
        return stripStructSuffix(structure->getName().str());

    if (std::string debugStruct = debugValueStruct(base); !debugStruct.empty())
      return stripStructSuffix(debugStruct);

    const Value *stripped = base ? base->stripPointerCasts() : nullptr;
    if (auto *argument = dyn_cast_or_null<Argument>(stripped)) {
      DITypeRefArray types = subroutineTypes(argument->getParent());
      unsigned typeIndex = argument->getArgNo() + 1;
      if (types && typeIndex < types.size())
        return stripStructSuffix(pointedStructName(types[typeIndex]));
    }
    if (auto *call = dyn_cast_or_null<CallBase>(stripped)) {
      Function *callee = call->getCalledFunction();
      DITypeRefArray types = subroutineTypes(callee);
      if (types && types.size() > 0)
        return stripStructSuffix(pointedStructName(types[0]));
    }
    return "";
  }

  std::string fieldName(StringRef structType, int64_t offset) const {
    if (structType.empty())
      return "";
    auto structIterator = dwarfFields_.find(stripStructSuffix(structType.str()));
    if (structIterator == dwarfFields_.end())
      return "";
    auto fieldIterator = structIterator->second.find(offset);
    return fieldIterator == structIterator->second.end() ? "" : fieldIterator->second;
  }

  struct StridedOffset {
    int64_t base;
    int64_t stride;
    uint64_t count;
  };

  template <typename GepType>
  std::optional<StridedOffset> stridedOffset(GepType &gep,
                                             const Instruction *instruction) const {
    unsigned bits = layout_.getIndexTypeSizeInBits(gep.getType());
    bits = bits ? bits : 64;
    SmallMapVector<Value *, APInt, 4> variableOffsets;
    APInt constantOffset(bits, 0, true);
    if (!gep.collectOffset(layout_, bits, variableOffsets, constantOffset) ||
        variableOffsets.size() != 1 || bits > 64 || !constantOffset.isSignedIntN(64))
      return std::nullopt;

    Value *variable = variableOffsets.front().first;
    const APInt &multiplier = variableOffsets.front().second;
    if (!variable->getType()->isIntegerTy() || variable->getType()->getIntegerBitWidth() > 64 ||
        !multiplier.isSignedIntN(64))
      return std::nullopt;

    ConstantRange range = computeConstantRange(variable, true, true, nullptr, instruction);
    if (range.isEmptySet() || range.isFullSet() || range.isSignWrappedSet())
      return std::nullopt;

    int64_t lower = range.getSignedMin().getSExtValue();
    int64_t upper = range.getSignedMax().getSExtValue();
    if (upper < lower)
      return std::nullopt;
    unsigned __int128 count = static_cast<unsigned __int128>(
        static_cast<__int128>(upper) - static_cast<__int128>(lower) + 1);
    if (count == 0 || count > std::numeric_limits<uint64_t>::max())
      return std::nullopt;

    int64_t stride = multiplier.getSExtValue();
    __int128 base = static_cast<__int128>(constantOffset.getSExtValue()) +
                    static_cast<__int128>(stride) * lower;
    __int128 last = base + static_cast<__int128>(stride) *
                               static_cast<__int128>(count - 1);
    if (base < std::numeric_limits<int64_t>::min() ||
        base > std::numeric_limits<int64_t>::max() ||
        last < std::numeric_limits<int64_t>::min() ||
        last > std::numeric_limits<int64_t>::max())
      return std::nullopt;
    return StridedOffset{static_cast<int64_t>(base), stride, static_cast<uint64_t>(count)};
  }

  template <typename GepType>
  void emitGepConstraint(StringRef destination, StringRef source, GepType &gep,
                         const Function *function, const Instruction *instruction,
                         StringRef opcode, StringRef detail) {
    unsigned bits = layout_.getIndexTypeSizeInBits(gep.getType());
    APInt offset(bits ? bits : 64, 0, true);
    bool constant = gep.accumulateConstantOffset(layout_, offset);
    std::string structType = sourceStruct(gep.getPointerOperand(), gep.getSourceElementType());
    std::string sourceType = typeLabel(gep.getSourceElementType());
    int64_t signedOffset = constant && offset.getBitWidth() <= 64 ? offset.getSExtValue() : 0;
    std::string field = constant ? fieldName(structType, signedOffset) : "";
    if (constant) {
      emitPoint("FIELD_ADDR", destination, source, "-", signedString(offset), "constant",
                structType, field, function, instruction, opcode, detail,
                "-", "-", "-", sourceType);
      return;
    }
    if (std::optional<StridedOffset> strided = stridedOffset(gep, instruction)) {
      emitPoint("FIELD_ADDR_STRIDED", destination, source, "-", "-", "strided",
                structType, "-", function, instruction, opcode, detail,
                std::to_string(strided->base), std::to_string(strided->stride),
                std::to_string(strided->count), sourceType);
      return;
    }
    emitPoint("FIELD_ADDR_DYNAMIC", destination, source, "-", "-", "dynamic",
              structType, "-", function, instruction, opcode, detail,
              "-", "-", "-", sourceType);
  }

  void emitAliases() {
    for (GlobalAlias &alias : module_.aliases())
      pointerValue(&alias, "alias:" + symbolName(alias), nullptr, nullptr);
  }

  Constant *aggregateElement(Constant *constant, unsigned index, Type *elementType) const {
    if (Constant *element = constant->getAggregateElement(index))
      return element;
    if (isa<ConstantAggregateZero>(constant))
      return Constant::getNullValue(elementType);
    if (isa<UndefValue>(constant) || isa<PoisonValue>(constant))
      return UndefValue::get(elementType);
    return nullptr;
  }

  void scanInitializer(GlobalVariable &global, Constant *constant, Type *type, uint64_t offset,
                       StringRef path) {
    if (!constant || !type || !containsPointer(type))
      return;
    if (type->isPointerTy()) {
      if (isa<ConstantPointerNull>(constant))
        return;
      std::string source = pointerValue(constant,
                                        "global:" + symbolName(global) + ":" +
                                            std::to_string(offset) + ":" + cleanCell(path),
                                        nullptr, nullptr);
      emitMemory("STORE_OBJECT", "-", "-", source, globalObjectId(global, "global"),
                 std::to_string(offset), std::to_string(fixedTypeSize(type)), nullptr, nullptr,
                 "global-init", path);
      return;
    }
    if (auto *structure = dyn_cast<StructType>(type)) {
      if (structure->isOpaque())
        return;
      const StructLayout *structLayout = layout_.getStructLayout(structure);
      for (unsigned index = 0; index < structure->getNumElements(); ++index) {
        Type *elementType = structure->getElementType(index);
        if (!containsPointer(elementType))
          continue;
        Constant *element = aggregateElement(constant, index, elementType);
        scanInitializer(global, element, elementType,
                        offset + structLayout->getElementOffset(index),
                        path.str() + "." + std::to_string(index));
      }
      return;
    }
    if (auto *array = dyn_cast<ArrayType>(type)) {
      Type *elementType = array->getElementType();
      if (!containsPointer(elementType))
        return;
      uint64_t stride = static_cast<uint64_t>(fixedTypeSize(elementType));
      for (uint64_t index = 0; index < array->getNumElements(); ++index) {
        Constant *element = aggregateElement(constant, static_cast<unsigned>(index), elementType);
        scanInitializer(global, element, elementType, offset + index * stride,
                        path.str() + "." + std::to_string(index));
      }
      return;
    }
    if (auto *vector = dyn_cast<FixedVectorType>(type)) {
      Type *elementType = vector->getElementType();
      if (!containsPointer(elementType))
        return;
      uint64_t stride = static_cast<uint64_t>(fixedTypeSize(elementType));
      for (unsigned index = 0; index < vector->getNumElements(); ++index) {
        Constant *element = aggregateElement(constant, index, elementType);
        scanInitializer(global, element, elementType, offset + index * stride,
                        path.str() + "." + std::to_string(index));
      }
    }
  }

  void emitGlobalInitializers() {
    for (GlobalVariable &global : module_.globals()) {
      if (!global.hasInitializer() || global.isDeclaration() ||
          !containsPointer(global.getValueType()))
        continue;
      scanInitializer(global, global.getInitializer(), global.getValueType(), 0,
                      "global-init:" + symbolName(global));
    }
  }

  std::string parameterAttributes(const CallBase &call, unsigned index) const {
    std::vector<std::string> attributes;
    AttributeList attributeList = call.getAttributes();
    auto add = [&](Attribute::AttrKind kind, StringRef name) {
      if (attributeList.hasParamAttr(index, kind))
        attributes.push_back(name.str());
    };
    add(Attribute::ByVal, "byval");
    add(Attribute::StructRet, "sret");
    add(Attribute::InAlloca, "inalloca");
    add(Attribute::Nest, "nest");
    add(Attribute::NoAlias, "noalias");
    if (attributes.empty())
      return "-";
    std::string result;
    for (unsigned position = 0; position < attributes.size(); ++position) {
      if (position)
        result += ',';
      result += attributes[position];
    }
    return result;
  }

  void emitFunctionFormals(Function &function) {
    for (Argument &argument : function.args()) {
      if (!argument.getType()->isPointerTy())
        continue;
      emitCall("FUNCTION_FORMAL", "-", "-", function.getName(), "-",
               std::to_string(argument.getArgNo()), ssaValueId(argument), "-", &function,
               nullptr, "formal", "-", "pointer formal");
    }
  }

  void emitCallConstraints(CallBase &call) {
    Function *caller = call.getFunction();
    std::string callsite = "callsite:" + siteName(caller, &call);
    std::string result = call.getType()->isPointerTy() ? ssaValueId(call) : "-";
    Function *callee = call.getCalledFunction();
    if (!call.isInlineAsm()) {
      if (callee) {
        std::string targetObject = globalObjectId(*callee, "function");
        emitCall("CALL_TARGET", callsite, caller->getName(), callee->getName(), targetObject,
                 "-", "-", result, caller, &call, call.getOpcodeName(), "-", "direct call");
      } else {
        std::string calleeValue = pointerValue(call.getCalledOperand(), callsite + ":callee",
                                               caller, &call);
        emitCall("CALL_CALLEE_VALUE", callsite, caller->getName(), "-", "-", "-",
                 calleeValue, result, caller, &call, call.getOpcodeName(), "-",
                 "indirect call");
      }
      for (unsigned index = 0; index < call.arg_size(); ++index) {
        Value *actual = call.getArgOperand(index);
        if (!actual->getType()->isPointerTy())
          continue;
        std::string actualId = pointerValue(actual,
                                            callsite + ":arg:" + std::to_string(index), caller,
                                            &call);
        emitCall("CALL_ACTUAL", callsite, caller->getName(),
                 callee ? callee->getName() : "-", "-", std::to_string(index), actualId,
                 result, caller, &call, call.getOpcodeName(), parameterAttributes(call, index),
                 "pointer actual");
      }
      if (call.getType()->isPointerTy())
        emitCall("CALL_RESULT", callsite, caller->getName(),
                 callee ? callee->getName() : "-", "-", "-", "-", result, caller, &call,
                 call.getOpcodeName(), "-", "pointer call result");
    } else if (call.getType()->isPointerTy()) {
      emitUnknownForDestination(result, call.getType(), callsite + ":inline-asm", caller, &call,
                                call.getOpcodeName(), "inline asm pointer result");
    }

    if (auto *transfer = dyn_cast<MemTransferInst>(&call)) {
      std::string destination = pointerValue(transfer->getRawDest(), callsite + ":mem-dst",
                                             caller, &call);
      std::string source = pointerValue(transfer->getRawSource(), callsite + ":mem-src",
                                        caller, &call);
      std::string size = "-";
      if (auto *constantSize = dyn_cast<ConstantInt>(transfer->getLength()))
        size = unsignedString(constantSize->getValue());
      emitMemory(isa<MemMoveInst>(transfer) ? "MEMMOVE" : "MEMCPY", destination,
                 destination, source, "-", "-", size, caller, &call, call.getOpcodeName(),
                 "memory transfer");
    }

    if (callee && call.getType()->isPointerTy() && call.arg_size() > 0 &&
        call.getArgOperand(0)->getType()->isPointerTy()) {
      StringRef name = callee->getName();
      if (name.starts_with("llvm.launder.invariant.group") ||
          name.starts_with("llvm.strip.invariant.group") || name.starts_with("llvm.ptrmask") ||
          name.starts_with("llvm.preserve.")) {
        std::string source = pointerValue(call.getArgOperand(0), callsite + ":intrinsic-source",
                                          caller, &call);
        emitPoint("COPY", result, source, "-", "-", "-", "-", "-", caller, &call,
                  call.getOpcodeName(), "pointer-preserving intrinsic");
      }
    }
  }

  void emitInstruction(Instruction &instruction) {
    Function *function = instruction.getFunction();
    std::string destination = instruction.getType()->isPointerTy() ? ssaValueId(instruction) : "-";
    bool handledPointerResult = false;

    if (auto *alloca = dyn_cast<AllocaInst>(&instruction)) {
      std::string objectId = "site:object:stack:" + siteName(function, &instruction);
      int64_t size = fixedTypeSize(alloca->getAllocatedType());
      if (auto *count = dyn_cast<ConstantInt>(alloca->getArraySize())) {
        if (size >= 0 && count->getValue().getActiveBits() <= 63)
          size *= static_cast<int64_t>(count->getZExtValue());
      } else {
        size = -1;
      }
      emitObject(objectId, "stack", "site", "-", "-", "-", alloca->getAllocatedType(), size,
                 function, &instruction, "alloca site", alloca);
      emitAddressSeed(destination, objectId, function, &instruction, instruction.getOpcodeName(),
                      "alloca address");
      handledPointerResult = true;
    } else if (auto *gep = dyn_cast<GetElementPtrInst>(&instruction)) {
      std::string source = pointerValue(gep->getPointerOperand(),
                                        siteName(function, &instruction, "gep-base"), function,
                                        &instruction);
      emitGepConstraint(destination, source, *gep, function, &instruction,
                        instruction.getOpcodeName(), "instruction GEP");
      handledPointerResult = true;
    } else if (auto *phi = dyn_cast<PHINode>(&instruction)) {
      if (phi->getType()->isPointerTy()) {
        for (unsigned index = 0; index < phi->getNumIncomingValues(); ++index) {
          std::string source = pointerValue(phi->getIncomingValue(index),
                                            siteName(function, &instruction,
                                                     "phi:" + std::to_string(index)),
                                            function, &instruction);
          emitPoint("COPY", destination, source, "-", "-", "-", "-", "-", function,
                    &instruction, instruction.getOpcodeName(), "phi incoming");
        }
        handledPointerResult = true;
      }
    } else if (auto *select = dyn_cast<SelectInst>(&instruction)) {
      if (select->getType()->isPointerTy()) {
        for (Value *sourceValue : {select->getTrueValue(), select->getFalseValue()}) {
          std::string source = pointerValue(sourceValue,
                                            siteName(function, &instruction, "select"), function,
                                            &instruction);
          emitPoint("COPY", destination, source, "-", "-", "-", "-", "-", function,
                    &instruction, instruction.getOpcodeName(), "select arm");
        }
        handledPointerResult = true;
      }
    } else if (auto *freeze = dyn_cast<FreezeInst>(&instruction)) {
      if (freeze->getType()->isPointerTy()) {
        std::string source = pointerValue(freeze->getOperand(0),
                                          siteName(function, &instruction, "freeze"), function,
                                          &instruction);
        emitPoint("COPY", destination, source, "-", "-", "-", "-", "-", function,
                  &instruction, instruction.getOpcodeName(), "freeze pointer");
        handledPointerResult = true;
      }
    } else if (auto *castInstruction = dyn_cast<CastInst>(&instruction)) {
      if (castInstruction->getType()->isPointerTy()) {
        if (isa<BitCastInst>(castInstruction) || isa<AddrSpaceCastInst>(castInstruction)) {
          std::string source = pointerValue(castInstruction->getOperand(0),
                                            siteName(function, &instruction, "cast"), function,
                                            &instruction);
          emitPoint("COPY", destination, source, "-", "-", "-", "-", "-", function,
                    &instruction, instruction.getOpcodeName(), "pointer cast");
        } else {
          emitUnknownForDestination(destination, instruction.getType(),
                                    siteName(function, &instruction, "inttoptr"), function,
                                    &instruction, instruction.getOpcodeName(), "integer to pointer");
        }
        handledPointerResult = true;
      }
    } else if (auto *load = dyn_cast<LoadInst>(&instruction)) {
      if (load->getType()->isPointerTy()) {
        std::string pointer = pointerValue(load->getPointerOperand(),
                                           siteName(function, &instruction, "load-ptr"), function,
                                           &instruction);
        emitMemory("LOAD", destination, pointer, "-", "-", "-",
                   std::to_string(fixedTypeSize(load->getType())), function, &instruction,
                   instruction.getOpcodeName(), load->isVolatile() ? "volatile" : "plain");
        handledPointerResult = true;
      }
    } else if (auto *call = dyn_cast<CallBase>(&instruction)) {
      emitCallConstraints(*call);
      handledPointerResult = call->getType()->isPointerTy();
    }

    if (auto *store = dyn_cast<StoreInst>(&instruction)) {
      Value *stored = store->getValueOperand();
      if (stored->getType()->isPointerTy()) {
        std::string pointer = pointerValue(store->getPointerOperand(),
                                           siteName(function, &instruction, "store-ptr"), function,
                                           &instruction);
        std::string source = pointerValue(stored,
                                          siteName(function, &instruction, "store-value"), function,
                                          &instruction);
        emitMemory("STORE", "-", pointer, source, "-", "-",
                   std::to_string(fixedTypeSize(stored->getType())), function, &instruction,
                   instruction.getOpcodeName(), store->isVolatile() ? "volatile" : "plain");
      }
    } else if (auto *compareExchange = dyn_cast<AtomicCmpXchgInst>(&instruction)) {
      Value *newValue = compareExchange->getNewValOperand();
      if (newValue->getType()->isPointerTy()) {
        std::string pointer = pointerValue(compareExchange->getPointerOperand(),
                                           siteName(function, &instruction, "cmpxchg-ptr"), function,
                                           &instruction);
        std::string source = pointerValue(newValue,
                                          siteName(function, &instruction, "cmpxchg-value"), function,
                                          &instruction);
        emitMemory("STORE", "-", pointer, source, "-", "-",
                   std::to_string(fixedTypeSize(newValue->getType())), function, &instruction,
                   instruction.getOpcodeName(), "cmpxchg new pointer");
      }
    }

    if (auto *returnInstruction = dyn_cast<ReturnInst>(&instruction)) {
      Value *returned = returnInstruction->getReturnValue();
      if (returned && returned->getType()->isPointerTy()) {
        std::string value = pointerValue(returned,
                                         siteName(function, &instruction, "return"), function,
                                         &instruction);
        emitCall("RETURN_VALUE", "-", function->getName(), function->getName(), "-", "-",
                 value, "-", function, &instruction, instruction.getOpcodeName(), "-",
                 "pointer return");
      }
    }

    if (instruction.getType()->isPointerTy() && !handledPointerResult) {
      emitUnknownForDestination(destination, instruction.getType(),
                                siteName(function, &instruction, "unsupported"), function,
                                &instruction, instruction.getOpcodeName(),
                                "unsupported pointer-producing instruction");
    }
  }

  void emitFunctions() {
    for (Function &function : module_) {
      if (function.isDeclaration())
        continue;
      emitFunctionFormals(function);
      for (BasicBlock &block : function)
        for (Instruction &instruction : block)
          emitInstruction(instruction);
    }
  }
};

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    errs() << "usage: ir_constraints <module.ll/.bc>\n";
    return 1;
  }
  LLVMContext context;
  SMDiagnostic diagnostic;
  std::unique_ptr<Module> module = parseIRFile(argv[1], diagnostic, context);
  if (!module) {
    diagnostic.print(argv[0], errs());
    return 1;
  }
  ConstraintEmitter emitter(*module);
  emitter.run();
  return 0;
}
