#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr uint32_t NONE = std::numeric_limits<uint32_t>::max();
// P1 object-sensitivity: reserved receiver-root identity for the explicit-unknown union context
// (design §2). Outside the object-id range, distinct from NONE.
constexpr uint32_t SHARED_UNKNOWN_ROOT = std::numeric_limits<uint32_t>::max() - 1;
constexpr int64_t DYN_OFFSET = std::numeric_limits<int64_t>::min();
constexpr int64_t INSTALL_OFFSET = std::numeric_limits<int64_t>::min() + 1;
constexpr int64_t HARD_OFFSET_CAP = 1LL << 21;
constexpr int64_t UNKNOWN_OFFSET_CAP = 1LL << 16;

uint64_t hashBytes(std::string_view value) {
  uint64_t hash = 1469598103934665603ULL;
  for (unsigned char byte : value) {
    hash ^= byte;
    hash *= 1099511628211ULL;
  }
  return hash ? hash : 1;
}

uint64_t mix64(uint64_t value) {
  value ^= value >> 30;
  value *= 0xbf58476d1ce4e5b9ULL;
  value ^= value >> 27;
  value *= 0x94d049bb133111ebULL;
  value ^= value >> 31;
  return value;
}

std::vector<std::string_view> splitTabs(const std::string &line) {
  std::vector<std::string_view> columns;
  size_t start = 0;
  while (true) {
    size_t tab = line.find('\t', start);
    if (tab == std::string::npos) {
      columns.emplace_back(line.data() + start, line.size() - start);
      break;
    }
    columns.emplace_back(line.data() + start, tab - start);
    start = tab + 1;
  }
  return columns;
}

int64_t parseI64(std::string_view value, int64_t fallback = 0) {
  if (value.empty() || value == "-")
    return fallback;
  bool negative = value.front() == '-';
  size_t index = negative ? 1 : 0;
  int64_t result = 0;
  for (; index < value.size(); ++index) {
    char character = value[index];
    if (character < '0' || character > '9')
      return fallback;
    result = result * 10 + (character - '0');
  }
  return negative ? -result : result;
}

uint32_t parseU32(std::string_view value, uint32_t fallback = 0) {
  int64_t parsed = parseI64(value, fallback);
  return parsed < 0 || parsed > std::numeric_limits<uint32_t>::max()
             ? fallback
             : static_cast<uint32_t>(parsed);
}

uint64_t parseU64(std::string_view value, uint64_t fallback = 0) {
  if (value.empty() || value == "-")
    return fallback;
  uint64_t result = 0;
  for (char character : value) {
    if (character < '0' || character > '9')
      return fallback;
    uint64_t digit = static_cast<uint64_t>(character - '0');
    if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10)
      return fallback;
    result = result * 10 + digit;
  }
  return result;
}

std::string jsonEscape(std::string_view value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (char character : value) {
    switch (character) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out += character; break;
    }
  }
  return out;
}

class StringIds {
 public:
  explicit StringIds(size_t initialSlots = 1024) {
    size_t slots = 1;
    while (slots < initialSlots)
      slots <<= 1;
    table_.resize(slots);
  }

  uint32_t intern(std::string_view value) {
    if ((ids_.size() + 1) * 10 >= table_.size() * 7)
      rehash(table_.size() * 2);
    uint64_t hash = hashBytes(value);
    size_t slot = locate(value, hash);
    if (table_[slot].hash)
      return table_[slot].id;
    uint32_t id = static_cast<uint32_t>(ids_.size());
    uint32_t offset = static_cast<uint32_t>(arena_.size());
    arena_.insert(arena_.end(), value.begin(), value.end());
    ids_.push_back({offset, static_cast<uint32_t>(value.size())});
    table_[slot] = {hash, id};
    return id;
  }

  std::optional<uint32_t> find(std::string_view value) const {
    uint64_t hash = hashBytes(value);
    size_t mask = table_.size() - 1;
    size_t slot = hash & mask;
    while (table_[slot].hash) {
      if (table_[slot].hash == hash && name(table_[slot].id) == value)
        return table_[slot].id;
      slot = (slot + 1) & mask;
    }
    return std::nullopt;
  }

  std::string_view name(uint32_t id) const {
    const Name &entry = ids_[id];
    return std::string_view(arena_.data() + entry.offset, entry.length);
  }

  size_t size() const { return ids_.size(); }
  size_t bytes() const { return arena_.size(); }

 private:
  struct Slot {
    uint64_t hash = 0;
    uint32_t id = 0;
  };
  struct Name {
    uint32_t offset;
    uint32_t length;
  };

  size_t locate(std::string_view value, uint64_t hash) const {
    size_t mask = table_.size() - 1;
    size_t slot = hash & mask;
    while (table_[slot].hash) {
      if (table_[slot].hash == hash && name(table_[slot].id) == value)
        return slot;
      slot = (slot + 1) & mask;
    }
    return slot;
  }

  void rehash(size_t size) {
    std::vector<Slot> old = std::move(table_);
    table_.assign(size, {});
    for (const Slot &entry : old) {
      if (!entry.hash)
        continue;
      std::string_view value = name(entry.id);
      table_[locate(value, entry.hash)] = entry;
    }
  }

  std::vector<Slot> table_;
  std::vector<Name> ids_;
  std::vector<char> arena_;
};

enum class ObjectKind : uint8_t {
  Other,
  Function,
  Stack,
  Unknown,
  Synthetic,
  Null,
};

class Objects {
 public:
  uint32_t intern(std::string_view id, int64_t size, ObjectKind kind,
                  std::string_view symbol = "-", bool completeAggregateType = false,
                  std::string_view containedStructs = "-") {
    size_t previous = names_.size();
    uint32_t object = names_.intern(id);
    if (names_.size() != previous) {
      sizes_.push_back(size);
      kinds_.push_back(kind);
      symbols_.push_back(symbol == "-" ? NONE : symbolNames_.intern(symbol));
      completeAggregateTypes_.push_back(false);
      containedStructs_.emplace_back();
    } else {
      if (size > 0)
        sizes_[object] = size;
      if (kind != ObjectKind::Other)
        kinds_[object] = kind;
      if (symbol != "-")
        symbols_[object] = symbolNames_.intern(symbol);
    }
    if (completeAggregateType)
      setTypeEvidence(object, containedStructs);
    return object;
  }

  uint32_t internLike(std::string_view id, uint32_t original) {
    uint32_t object = intern(id, size(original), kind(original), symbol(original));
    completeAggregateTypes_[object] = completeAggregateTypes_[original];
    containedStructs_[object] = containedStructs_[original];
    return object;
  }

  uint32_t internStruct(std::string_view name) {
    return name.empty() || name == "-" ? NONE : structNames_.intern(name);
  }

  bool hasCompleteAggregateType(uint32_t object) const {
    return object < completeAggregateTypes_.size() && completeAggregateTypes_[object];
  }

  bool containsStruct(uint32_t object, uint32_t structure) const {
    if (structure == NONE || object >= containedStructs_.size())
      return false;
    const std::vector<uint32_t> &contained = containedStructs_[object];
    return std::find(contained.begin(), contained.end(), structure) != contained.end();
  }

  std::string_view structName(uint32_t structure) const {
    return structure == NONE ? std::string_view("-") : structNames_.name(structure);
  }

  std::optional<uint32_t> find(std::string_view id) const { return names_.find(id); }
  std::string_view name(uint32_t object) const { return names_.name(object); }
  int64_t size(uint32_t object) const { return sizes_[object]; }
  ObjectKind kind(uint32_t object) const { return kinds_[object]; }
  bool isFunction(uint32_t object) const { return kind(object) == ObjectKind::Function; }
  bool isUnknown(uint32_t object) const { return kind(object) == ObjectKind::Unknown; }
  bool isNull(uint32_t object) const { return kind(object) == ObjectKind::Null; }
  std::string_view symbol(uint32_t object) const {
    return symbols_[object] == NONE ? std::string_view("-") : symbolNames_.name(symbols_[object]);
  }
  size_t size() const { return names_.size(); }
  size_t stringBytes() const { return names_.bytes() + symbolNames_.bytes(); }

 private:
  void setTypeEvidence(uint32_t object, std::string_view containedStructs) {
    bool complete = true;
    if (!containedStructs.empty() && containedStructs.front() == '?') {
      complete = false;
      containedStructs.remove_prefix(1);
    }
    completeAggregateTypes_[object] = complete;
    std::vector<uint32_t> &contained = containedStructs_[object];
    contained.clear();
    if (containedStructs.empty() || containedStructs == "-")
      return;
    size_t start = 0;
    while (start <= containedStructs.size()) {
      size_t comma = containedStructs.find(',', start);
      std::string_view name = containedStructs.substr(
          start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
      if (!name.empty() && name != "-")
        contained.push_back(structNames_.intern(name));
      if (comma == std::string_view::npos)
        break;
      start = comma + 1;
    }
  }

  StringIds names_{1 << 20};
  StringIds symbolNames_{1 << 16};
  StringIds structNames_{1 << 14};
  std::vector<int64_t> sizes_;
  std::vector<ObjectKind> kinds_;
  std::vector<uint32_t> symbols_;
  std::vector<uint8_t> completeAggregateTypes_;
  std::vector<std::vector<uint32_t>> containedStructs_;
};

enum class SourceTable : uint8_t {
  None = 0,
  Points = 1,
  Memory = 2,
  Calls = 3,
  Registration = 4,
  ApiSummary = 5,
  Synthetic = 6,
};

uint64_t sourceRef(SourceTable table, uint64_t line) {
  return (static_cast<uint64_t>(table) << 56) | (line & ((1ULL << 56) - 1));
}

std::string renderSource(uint64_t source) {
  SourceTable table = static_cast<SourceTable>(source >> 56);
  uint64_t line = source & ((1ULL << 56) - 1);
  const char *name = "none";
  switch (table) {
    case SourceTable::Points: name = "points_to_constraints.tsv"; break;
    case SourceTable::Memory: name = "memory_constraints.tsv"; break;
    case SourceTable::Calls: name = "call_constraints.tsv"; break;
    case SourceTable::Registration: name = "registration_seeds.tsv"; break;
    case SourceTable::ApiSummary: name = "api_summaries.tsv"; break;
    case SourceTable::Synthetic: name = "synthetic"; break;
    default: break;
  }
  return std::string(name) + ":" + std::to_string(line);
}

struct ObjKey {
  uint32_t root = NONE;
  uint32_t region = NONE;
  int64_t offset = 0;

  ObjKey() = default;
  ObjKey(uint32_t rootId, int64_t byteOffset)
      : root(rootId), region(NONE), offset(byteOffset) {}

  static ObjKey affine(uint32_t rootId, uint32_t regionId) {
    ObjKey object;
    object.root = rootId;
    object.region = regionId;
    return object;
  }

  bool isAffine() const { return region != NONE; }

  bool operator==(const ObjKey &other) const {
    return root == other.root && region == other.region && offset == other.offset;
  }
};

struct ObjKeyHash {
  size_t operator()(const ObjKey &key) const {
    uint64_t identity = (static_cast<uint64_t>(key.root) << 32) ^ key.region;
    return mix64(identity ^ mix64(static_cast<uint64_t>(key.offset)));
  }
};

static_assert(sizeof(ObjKey) == 16);

struct AffineRegion {
  int64_t base;
  int64_t stride;
  int64_t bound;

  bool operator==(const AffineRegion &other) const {
    return base == other.base && stride == other.stride && bound == other.bound;
  }
};

struct AffineRegionHash {
  size_t operator()(const AffineRegion &region) const {
    uint64_t hash = mix64(static_cast<uint64_t>(region.base));
    hash ^= mix64(static_cast<uint64_t>(region.stride));
    hash ^= mix64(static_cast<uint64_t>(region.bound));
    return mix64(hash);
  }
};

class AffineRegions {
 public:
  uint32_t intern(int64_t base, int64_t stride, int64_t bound) {
    AffineRegion region{base, stride, bound};
    auto found = ids_.find(region);
    if (found != ids_.end())
      return found->second;
    uint32_t id = static_cast<uint32_t>(regions_.size());
    regions_.push_back(region);
    ids_.emplace(region, id);
    return id;
  }

  std::optional<uint32_t> find(int64_t base, int64_t stride, int64_t bound) const {
    auto found = ids_.find({base, stride, bound});
    return found == ids_.end() ? std::nullopt : std::optional<uint32_t>(found->second);
  }

  const AffineRegion &get(uint32_t id) const { return regions_[id]; }
  size_t size() const { return regions_.size(); }

 private:
  std::vector<AffineRegion> regions_;
  std::unordered_map<AffineRegion, uint32_t, AffineRegionHash> ids_;
};

enum class Rule : uint8_t {
  AddressOf,
  UnknownAddress,
  Copy,
  FieldAddress,
  DynamicField,
  StridedField,
  Load,
  Store,
  StoreObject,
  CallArgument,
  CallReturn,
  ObjectSeed,
  Install,
  MemoryCopy,
  MemoryAlias,
  AffineRegion,
};

enum class CallFlowMode : uint8_t {
  None,
  Reachable,
  Callsite,
  Global,
};

enum class ContextObjectMode : uint8_t {
  Shared,
  Stack,
};

enum class ContextScope : uint8_t {
  Handler,
  Global,
};

enum class ContextModel : uint8_t {
  CallString,  // context = K-limited call string (legacy)
  Signature,   // context = CI actual-set signature, with per-callee overflow budget
};

enum class ContextRefinePropagation : uint8_t {
  Linear,
  All,
};

enum class ContextValueSlice : uint8_t {
  All,
  Interface,
  Escape,
};

enum class OffsetPolicy : uint8_t {
  Dynamic,
  Drop,
  Exact,
};

enum class FieldDynamicPolicy : uint8_t {
  RootDynamic,
  Drop,
  Strided,
};

enum class FieldTypePolicy : uint8_t {
  All,
  Compatible,
};

enum class FieldLocationPolicy : uint8_t {
  RootWide,   // any offset in [-size, size) is reachable (legacy)
  Subobject,  // a known-size top-level object restricts final offsets to [0, size);
              // a negative final offset points before the allocation and is illegal
};

enum class FieldCyclePolicy : uint8_t {
  Iterate,
  RootDynamic,
  Affine,
  Drop,
};

enum class DynamicAliasPolicy : uint8_t {
  None,
  Root,
};

enum class AffineCanonPolicy : uint8_t {
  None,         // keep every affine region distinct (legacy)
  Subsumption,  // canonicalize each affine region to the maximal region of its (root,
                // stride, congruence) class, so subsumed/overlapping regions collapse
};

const char *callFlowName(CallFlowMode mode) {
  switch (mode) {
    case CallFlowMode::None: return "none";
    case CallFlowMode::Reachable: return "reachable";
    case CallFlowMode::Callsite: return "callsite";
    case CallFlowMode::Global: return "global";
  }
  return "unknown";
}

const char *contextObjectName(ContextObjectMode mode) {
  return mode == ContextObjectMode::Stack ? "stack" : "shared";
}

const char *contextScopeName(ContextScope scope) {
  return scope == ContextScope::Global ? "global" : "handler";
}

const char *contextModelName(ContextModel model) {
  return model == ContextModel::Signature ? "signature" : "callstring";
}

const char *contextRefinePropagationName(ContextRefinePropagation mode) {
  return mode == ContextRefinePropagation::Linear ? "linear" : "all";
}

const char *contextValueSliceName(ContextValueSlice mode) {
  switch (mode) {
    case ContextValueSlice::All: return "all";
    case ContextValueSlice::Interface: return "interface";
    case ContextValueSlice::Escape: return "escape";
  }
  return "unknown";
}

const char *offsetPolicyName(OffsetPolicy policy) {
  switch (policy) {
    case OffsetPolicy::Dynamic: return "dynamic";
    case OffsetPolicy::Drop: return "drop";
    case OffsetPolicy::Exact: return "exact";
  }
  return "unknown";
}

const char *fieldDynamicPolicyName(FieldDynamicPolicy policy) {
  switch (policy) {
    case FieldDynamicPolicy::RootDynamic: return "root_dyn";
    case FieldDynamicPolicy::Drop: return "drop";
    case FieldDynamicPolicy::Strided: return "strided";
  }
  return "unknown";
}

const char *fieldTypePolicyName(FieldTypePolicy policy) {
  return policy == FieldTypePolicy::Compatible ? "compatible" : "all";
}

const char *fieldLocationPolicyName(FieldLocationPolicy policy) {
  return policy == FieldLocationPolicy::Subobject ? "subobject" : "root-wide";
}

const char *fieldCyclePolicyName(FieldCyclePolicy policy) {
  switch (policy) {
    case FieldCyclePolicy::Iterate: return "iterate";
    case FieldCyclePolicy::RootDynamic: return "root_dyn";
    case FieldCyclePolicy::Affine: return "affine";
    case FieldCyclePolicy::Drop: return "drop";
  }
  return "unknown";
}

const char *dynamicAliasPolicyName(DynamicAliasPolicy policy) {
  return policy == DynamicAliasPolicy::Root ? "root" : "none";
}

const char *affineCanonPolicyName(AffineCanonPolicy policy) {
  return policy == AffineCanonPolicy::Subsumption ? "subsumption" : "none";
}

const char *ruleName(Rule rule) {
  switch (rule) {
    case Rule::AddressOf: return "ADDR_OF";
    case Rule::UnknownAddress: return "UNKNOWN_ADDR";
    case Rule::Copy: return "COPY";
    case Rule::FieldAddress: return "FIELD_ADDR";
    case Rule::DynamicField: return "FIELD_ADDR_DYNAMIC";
    case Rule::StridedField: return "FIELD_ADDR_STRIDED";
    case Rule::Load: return "LOAD";
    case Rule::Store: return "STORE";
    case Rule::StoreObject: return "STORE_OBJECT";
    case Rule::CallArgument: return "CALL_ARGUMENT";
    case Rule::CallReturn: return "CALL_RETURN";
    case Rule::ObjectSeed: return "OBJECT_SEED";
    case Rule::Install: return "INSTALL";
    case Rule::MemoryCopy: return "MEMORY_COPY";
    case Rule::MemoryAlias: return "MEMORY_ALIAS";
    case Rule::AffineRegion: return "AFFINE_REGION";
  }
  return "UNKNOWN";
}

struct AddressSeed { uint32_t dst, root; int64_t offset; uint64_t source; Rule rule; };
struct CopyConstraint {
  uint32_t src, dst;
  uint64_t source;
  Rule rule;
  uint32_t caller = NONE;
  uint32_t directSite = NONE;
};
struct FieldConstraint {
  uint32_t src, dst;
  int64_t offset;
  uint64_t source;
  uint32_t structType = NONE;
};
struct DynamicFieldConstraint {
  uint32_t src, dst;
  uint64_t source;
  uint32_t structType = NONE;
};
struct StridedFieldConstraint {
  uint32_t src, dst;
  int64_t base, stride;
  uint64_t count, source;
  uint32_t structType = NONE;
};
struct SimpleConstraint { uint32_t first, second; uint64_t source; };
struct StoreObjectConstraint { uint32_t root, src; int64_t offset; uint64_t source; };
struct MemoryCopyConstraint { uint32_t dst, src; uint64_t size, source; };
struct Actual { uint32_t index, value; uint64_t source; };

struct FunctionInfo {
  std::vector<std::pair<uint32_t, uint32_t>> formals;
  std::vector<uint32_t> returns;
};

struct IndirectSite {
  uint32_t callsiteName;
  uint32_t callerFunction;
  uint32_t callerContext;
  uint32_t calleeValue;
  uint32_t actualStart;
  uint32_t actualCount;
  uint32_t result;
  uint64_t source;
};

struct DirectSite {
  uint32_t callsiteName;
  uint32_t callerFunction;
  uint32_t calleeFunction;
  uint32_t actualStart;
  uint32_t actualCount;
  uint32_t result;
  uint64_t source;
};

struct CallArgRelation {
  uint32_t actual;
  uint32_t formal;
  uint32_t index;
  uint64_t source;
};

struct CallReturnRelation {
  uint32_t returned;
  uint32_t result;
  uint64_t source;
};

struct CallTransfer {
  bool indirect;
  bool contextual;
  bool flowEnabled;
  uint32_t siteIndex;
  uint32_t callerContext;
  uint32_t calleeFunction;
  uint32_t calleeContext;
  uint32_t expectedArgs;
  uint32_t expectedReturns;
  uint64_t source;
  std::vector<CallArgRelation> args;
  std::vector<CallReturnRelation> returns;
};

struct RootSeed {
  uint32_t rootName;
  uint32_t rootValue;
  uint32_t rootObject;
  uint32_t dispatchObject;
  uint64_t source;
};

struct NamedSummary {
  uint32_t object;
  uint32_t key;
  uint32_t handler;
  uint64_t source;
};

struct Counts {
  uint64_t objectRows = 0;
  uint64_t pointRows = 0;
  uint64_t memoryRows = 0;
  uint64_t callRows = 0;
  uint64_t addressSeeds = 0;
  uint64_t unknownSeeds = 0;
  uint64_t copies = 0;
  uint64_t fields = 0;
  uint64_t dynamicFields = 0;
  uint64_t stridedFields = 0;
  uint64_t loads = 0;
  uint64_t stores = 0;
  uint64_t storeObjects = 0;
  uint64_t memoryCopies = 0;
  uint64_t directCalls = 0;
  uint64_t indirectCalls = 0;
  uint64_t unresolvedObjects = 0;
  uint64_t unresolvedFunctions = 0;
  uint64_t seedRows = 0;
  uint64_t seedRelations = 0;
  uint64_t seedUnresolved = 0;
  uint64_t dispatchSummaries = 0;
  uint64_t cmdSummaries = 0;
  uint64_t handlerRootFunctions = 0;
  uint64_t handlerReachableFunctions = 0;
  uint64_t handlerReachableDirectSites = 0;
  uint64_t contextEligibleDirectSites = 0;
  uint64_t contextSkippedDirectSites = 0;
  uint64_t contextIrrelevantDirectSites = 0;
  uint64_t projectedCallsiteValues = 0;
  uint64_t projectedCallsiteObjects = 0;
  uint64_t projectedCallsiteInvocations = 0;
  uint64_t projectedCallsiteConstraints = 0;
  uint64_t contextSensitiveValues = 0;
  uint64_t contextSensitiveMemoryFunctions = 0;
  uint64_t materializedContexts = 0;
  uint64_t materializedValues = 0;
  uint64_t materializedObjects = 0;
  uint64_t materializedConstraints = 0;
  uint64_t refinedContextFunctions = 0;
  uint64_t refinedContextConeFunctions = 0;
  uint64_t refinedContextTransitions = 0;
  uint64_t baselineCallerTransitions = 0;
  uint64_t baselineDeadCallerSites = 0;
  uint64_t deferredDirectSites = 0;
  uint64_t deferredDirectTransfers = 0;
  uint64_t receiverFunctions = 0;
  uint64_t uniqueReceiverFunctions = 0;
  uint64_t multiReceiverFunctions = 0;
  uint64_t objectTemplateFunctions = 0;
  uint64_t objectTemplateValues = 0;
  uint64_t objectTemplateComponents = 0;
  uint64_t objectTemplateCopyEdges = 0;
  uint64_t objectTemplateStackObjects = 0;
  uint64_t objectTemplateAddressSeeds = 0;
  uint64_t objectTemplateFields = 0;
  uint64_t objectTemplateDynamicFields = 0;
  uint64_t objectTemplateStridedFields = 0;
  uint64_t objectTemplateLoads = 0;
  uint64_t objectTemplateStores = 0;
  uint64_t objectTemplateStoreObjects = 0;
  uint64_t objectTemplateMemoryCopies = 0;
  uint64_t objectTemplateDirectSites = 0;
  uint64_t objectTemplateIndirectSites = 0;
  uint64_t resolvedIndirectSites = 0;
  uint64_t resolvedIndirectPairs = 0;
  uint64_t signatureOriginalSites = 0;
  uint64_t signatureUnique = 0;
  uint64_t signatureEquivalenceMerged = 0;
  uint64_t signatureOverflowFunctions = 0;
  uint64_t signatureOverflowMerged = 0;
};

// P1 object-sensitivity: interner for ObjectContext = (callee_function, receiver_formal_index,
// receiver_root) — design §2. context_id 0 is the reserved BASELINE / no-context identity and is
// never interned. A receiver root of SHARED_UNKNOWN_ROOT interns the per-(callee,formal)
// explicit-unknown union context (its own id, distinct from baseline); a concrete object root
// interns that root's concrete context. Same key -> same id (global object-sensitive reuse).
struct ObjectContextKey {
  uint32_t callee;
  uint32_t formalIndex;
  uint32_t receiverRoot;
  bool operator==(const ObjectContextKey &other) const {
    return callee == other.callee && formalIndex == other.formalIndex &&
           receiverRoot == other.receiverRoot;
  }
};
struct ObjectContextKeyHash {
  size_t operator()(const ObjectContextKey &key) const {
    return static_cast<size_t>(
        mix64(mix64(key.callee) ^ mix64(static_cast<uint64_t>(key.formalIndex) + 1) ^
              mix64(static_cast<uint64_t>(key.receiverRoot) + 0x9e3779b9ull)));
  }
};
class ObjectContexts {
 public:
  static constexpr uint32_t BASELINE = 0;
  ObjectContexts() { keys_.push_back({NONE, NONE, NONE}); }  // index 0 = baseline sentinel

  uint32_t ensure(uint32_t callee, uint32_t formalIndex, uint32_t receiverRoot) {
    ObjectContextKey key{callee, formalIndex, receiverRoot};
    auto found = ids_.find(key);
    if (found != ids_.end())
      return found->second;
    uint32_t id = static_cast<uint32_t>(keys_.size());
    keys_.push_back(key);
    ids_.emplace(key, id);
    return id;
  }
  bool isBaseline(uint32_t id) const { return id == BASELINE; }
  bool isSharedUnknown(uint32_t id) const {
    return id != BASELINE && id < keys_.size() &&
           keys_[id].receiverRoot == SHARED_UNKNOWN_ROOT;
  }
  const ObjectContextKey &key(uint32_t id) const { return keys_[id]; }
  uint32_t size() const { return static_cast<uint32_t>(keys_.size()); }

 private:
  std::unordered_map<ObjectContextKey, uint32_t, ObjectContextKeyHash> ids_;
  std::vector<ObjectContextKey> keys_;
};

struct TemplateCopyEdge {
  uint32_t srcComponent;
  uint32_t dstComponent;
  uint64_t source;
};

struct ObjectFunctionTemplate {
  uint32_t function = NONE;
  std::vector<uint32_t> componentRepresentatives;
  std::vector<TemplateCopyEdge> copyEdges;
  std::vector<uint32_t> stackObjects;
  std::vector<uint32_t> addressSeeds;
  std::vector<uint32_t> fields;
  std::vector<uint32_t> dynamicFields;
  std::vector<uint32_t> stridedFields;
  std::vector<uint32_t> loads;
  std::vector<uint32_t> stores;
  std::vector<uint32_t> storeObjects;
  std::vector<uint32_t> memoryCopies;
  std::vector<uint32_t> directSites;
  std::vector<uint32_t> indirectSites;
};

class Database {
 public:
  explicit Database(bool keepUnknown) : keepUnknown_(keepUnknown) {}

  void setBatchFilter(const std::string &csv) {
    if (csv.empty() || csv == "all")
      return;
    size_t start = 0;
    while (start <= csv.size()) {
      size_t comma = csv.find(',', start);
      batches_.insert(csv.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
      if (comma == std::string::npos)
        break;
      start = comma + 1;
    }
  }

  bool allBatches() const { return batches_.empty(); }

  bool keepRow(const std::vector<std::string_view> &columns, size_t batchColumn,
               bool symbolObject = false) const {
    if (allBatches())
      return true;
    if (symbolObject)
      return true;
    return columns.size() > batchColumn && batches_.count(std::string(columns[batchColumn]));
  }

  uint32_t value(std::string_view name) {
    uint32_t id = values.intern(name);
    if (valueOwners.size() < values.size())
      valueOwners.resize(values.size(), NONE);
    return id;
  }

  uint32_t valueInFunction(std::string_view name, std::string_view batch,
                           std::string_view function) {
    uint32_t id = value(name);
    if (function == "-" || name.find(":ssa:") == std::string_view::npos)
      return id;
    uint32_t owner = functionObject(batch, function);
    if (owner != NONE) {
      if (valueOwners[id] != NONE && valueOwners[id] != owner)
        throw std::runtime_error("value has conflicting function owners: " + std::string(name));
      valueOwners[id] = owner;
    }
    return id;
  }

  void loadObjects(const fs::path &path) {
    std::ifstream input(path);
    std::string line;
    uint64_t lineNumber = 0;
    bool schemaV3 = false;
    while (std::getline(input, line)) {
      ++lineNumber;
      if (line.empty())
        continue;
      if (line[0] == '#') {
        schemaV3 = line.find("\tcontained_structs\t") != std::string::npos;
        objectSchemaVersion_ = schemaV3 ? 3 : 2;
        continue;
      }
      auto columns = splitTabs(line);
      size_t sizeColumn = schemaV3 ? 8 : 7;
      size_t batchColumn = schemaV3 ? 9 : 8;
      size_t functionColumn = schemaV3 ? 10 : 9;
      if (columns.size() <= functionColumn + 3)
        continue;
      bool symbolObject = columns[0].rfind("sym:", 0) == 0 ||
                          columns[0].rfind("special:", 0) == 0;
      if (!keepRow(columns, batchColumn, symbolObject))
        continue;
      ObjectKind kind = ObjectKind::Other;
      if (columns[1] == "function")
        kind = ObjectKind::Function;
      else if (columns[1] == "stack")
        kind = ObjectKind::Stack;
      else if (columns[1] == "unknown")
        kind = ObjectKind::Unknown;
      else if (columns[1] == "null")
        kind = ObjectKind::Null;
      if (!keepUnknown_ && kind == ObjectKind::Unknown)
        continue;
      bool aggregateType = false;
      if (schemaV3 && (columns[1] == "global" || columns[1] == "stack")) {
        std::string_view type = columns[6];
        aggregateType = type.rfind("struct.", 0) == 0 ||
                        type.rfind("anon_struct:", 0) == 0 ||
                        type.rfind("array[", 0) == 0 ||
                        type.rfind("vector[", 0) == 0;
      }
      uint32_t objectId = objects.intern(
          columns[0], parseI64(columns[sizeColumn], 0), kind, columns[3], aggregateType,
          schemaV3 ? columns[7] : std::string_view("-"));
      if (objectOwners.size() < objects.size())
        objectOwners.resize(objects.size(), NONE);
      if (kind == ObjectKind::Stack && columns[functionColumn] != "-") {
        std::string local = "batch:" + std::string(columns[batchColumn]) +
                            ":local:object:function:" +
                            std::string(columns[functionColumn]);
        if (auto owner = objects.find(local)) {
          objectOwners[objectId] = *owner;
        } else {
          std::string symbol =
              "sym:object:function:" + std::string(columns[functionColumn]);
          if (auto owner = objects.find(symbol))
            objectOwners[objectId] = *owner;
        }
      }
      ++counts.objectRows;
    }
  }

  std::optional<uint32_t> object(std::string_view name) const { return objects.find(name); }

  uint32_t requireObject(std::string_view name, ObjectKind fallback = ObjectKind::Other) {
    if (auto found = objects.find(name))
      return *found;
    ++counts.unresolvedObjects;
    return objects.intern(name, 0, fallback);
  }

  void loadPoints(const fs::path &path) {
    std::ifstream input(path);
    std::string line;
    uint64_t lineNumber = 0;
    while (std::getline(input, line)) {
      ++lineNumber;
      if (line.empty() || line[0] == '#')
        continue;
      auto columns = splitTabs(line);
      if (columns.size() < 15 || !keepRow(columns, 9))
        continue;
      ++counts.pointRows;
      uint64_t source = sourceRef(SourceTable::Points, lineNumber);
      auto scopedValue = [&](size_t column) {
        return valueInFunction(columns[column], columns[9], columns[10]);
      };
      if (columns[1] == "ADDR_OF") {
        addressSeeds.push_back({scopedValue(2), requireObject(columns[4]),
                                parseI64(columns[5]), source, Rule::AddressOf});
        ++counts.addressSeeds;
      } else if (columns[1] == "UNKNOWN_ADDR") {
        if (!keepUnknown_)
          continue;
        addressSeeds.push_back({scopedValue(2), requireObject(columns[4], ObjectKind::Unknown),
                                0, source, Rule::UnknownAddress});
        ++counts.unknownSeeds;
      } else if (columns[1] == "COPY") {
        copies.push_back({scopedValue(3), scopedValue(2), source, Rule::Copy});
        ++counts.copies;
      } else if (columns[1] == "FIELD_ADDR") {
        fields.push_back({scopedValue(3), scopedValue(2), parseI64(columns[5]), source,
                          objects.internStruct(columns[7])});
        ++counts.fields;
      } else if (columns[1] == "FIELD_ADDR_DYNAMIC") {
        dynamicFields.push_back({scopedValue(3), scopedValue(2), source,
                                 objects.internStruct(columns[7])});
        ++counts.dynamicFields;
      } else if (columns[1] == "FIELD_ADDR_STRIDED" && columns.size() >= 18) {
        stridedFields.push_back({scopedValue(3), scopedValue(2), parseI64(columns[15]),
                                 parseI64(columns[16]), parseU64(columns[17]), source,
                                 objects.internStruct(columns[7])});
        ++counts.stridedFields;
      }
    }
  }

  void loadMemory(const fs::path &path) {
    std::ifstream input(path);
    std::string line;
    uint64_t lineNumber = 0;
    while (std::getline(input, line)) {
      ++lineNumber;
      if (line.empty() || line[0] == '#')
        continue;
      auto columns = splitTabs(line);
      if (columns.size() < 14 || !keepRow(columns, 8))
        continue;
      ++counts.memoryRows;
      uint64_t source = sourceRef(SourceTable::Memory, lineNumber);
      auto scopedValue = [&](size_t column) {
        return valueInFunction(columns[column], columns[8], columns[9]);
      };
      if (columns[1] == "LOAD") {
        loads.push_back({scopedValue(3), scopedValue(2), source});
        ++counts.loads;
      } else if (columns[1] == "STORE") {
        stores.push_back({scopedValue(3), scopedValue(4), source});
        ++counts.stores;
      } else if (columns[1] == "STORE_OBJECT") {
        storeObjects.push_back({requireObject(columns[5]), scopedValue(4),
                                parseI64(columns[6]), source});
        ++counts.storeObjects;
      } else if (columns[1] == "MEMCPY" || columns[1] == "MEMMOVE") {
        memoryCopies.push_back({scopedValue(2), scopedValue(4),
                                static_cast<uint64_t>(parseI64(columns[7], 0)), source});
        ++counts.memoryCopies;
      }
    }
  }

  uint32_t functionObject(std::string_view batch, std::string_view name) {
    std::string local = "batch:" + std::string(batch) + ":local:object:function:" + std::string(name);
    if (auto found = objects.find(local))
      return *found;
    std::string symbol = "sym:object:function:" + std::string(name);
    if (auto found = objects.find(symbol))
      return *found;
    ++counts.unresolvedFunctions;
    return NONE;
  }

  void loadFunctionInterfaces(const fs::path &path) {
    std::ifstream input(path);
    std::string line;
    uint64_t lineNumber = 0;
    while (std::getline(input, line)) {
      ++lineNumber;
      if (line.empty() || line[0] == '#')
        continue;
      auto columns = splitTabs(line);
      if (columns.size() < 16 || !keepRow(columns, 9))
        continue;
      if (columns[1] != "FUNCTION_FORMAL" && columns[1] != "RETURN_VALUE")
        continue;
      uint32_t function = functionObject(columns[9], columns[4]);
      if (function == NONE)
        continue;
      FunctionInfo &info = functions[function];
      if (columns[1] == "FUNCTION_FORMAL")
        info.formals.push_back({parseU32(columns[6]),
                                valueInFunction(columns[7], columns[9], columns[10])});
      else
        info.returns.push_back(valueInFunction(columns[7], columns[9], columns[10]));
    }
  }

  void loadCalls(const fs::path &path) {
    struct Group {
      std::string callsite;
      uint32_t callerObject = NONE;
      uint32_t directObject = NONE;
      uint32_t calleeValue = NONE;
      uint32_t result = NONE;
      uint64_t source = 0;
      std::vector<Actual> actuals;
    } group;

    auto flush = [&]() {
      if (group.callsite.empty())
        return;
      if (group.directObject != NONE) {
        ++counts.directCalls;
        uint32_t start = static_cast<uint32_t>(directActuals.size());
        directActuals.insert(directActuals.end(), group.actuals.begin(), group.actuals.end());
        uint32_t siteIndex = static_cast<uint32_t>(directSites.size());
        directSites.push_back({callsiteNames.intern(group.callsite), group.callerObject,
                               group.directObject, start,
                               static_cast<uint32_t>(group.actuals.size()), group.result,
                               group.source});
        if (group.callerObject != NONE)
          directCallEdges.push_back({group.callerObject, group.directObject});
        wireStaticCall(group.callerObject, group.directObject, group.actuals,
                       group.result, group.source, siteIndex);
      }
      if (group.calleeValue != NONE) {
        ++counts.indirectCalls;
        uint32_t start = static_cast<uint32_t>(indirectActuals.size());
        indirectActuals.insert(indirectActuals.end(), group.actuals.begin(), group.actuals.end());
        indirectSites.push_back({callsiteNames.intern(group.callsite), group.callerObject,
                                 NONE, group.calleeValue, start,
                                 static_cast<uint32_t>(group.actuals.size()), group.result, group.source});
      }
      group = {};
    };

    std::ifstream input(path);
    std::string line;
    uint64_t lineNumber = 0;
    while (std::getline(input, line)) {
      ++lineNumber;
      if (line.empty() || line[0] == '#')
        continue;
      auto columns = splitTabs(line);
      if (columns.size() < 16 || !keepRow(columns, 9))
        continue;
      ++counts.callRows;
      if (columns[1] == "FUNCTION_FORMAL" || columns[1] == "RETURN_VALUE")
        continue;
      std::string_view callsite = columns[2];
      if (callsite == "-")
        continue;
      if (!group.callsite.empty() && group.callsite != callsite)
        flush();
      if (group.callsite.empty())
        group.callsite.assign(callsite);
      if (group.callerObject == NONE)
        group.callerObject = functionObject(columns[9], columns[3]);
      uint64_t source = sourceRef(SourceTable::Calls, lineNumber);
      if (!group.source)
        group.source = source;
      if (columns[1] == "CALL_TARGET") {
        group.directObject = requireObject(columns[5], ObjectKind::Function);
      } else if (columns[1] == "CALL_CALLEE_VALUE") {
        group.calleeValue = valueInFunction(columns[7], columns[9], columns[10]);
      } else if (columns[1] == "CALL_ACTUAL") {
        group.actuals.push_back({parseU32(columns[6]),
                                 valueInFunction(columns[7], columns[9], columns[10]), source});
      } else if (columns[1] == "CALL_RESULT") {
        group.result = valueInFunction(columns[8], columns[9], columns[10]);
      }
    }
    flush();
  }

  void wireStaticCall(uint32_t caller, uint32_t function, const std::vector<Actual> &actuals,
                      uint32_t result, uint64_t source, uint32_t siteIndex = NONE) {
    auto found = functions.find(function);
    if (found == functions.end())
      return;
    const FunctionInfo &info = found->second;
    for (const Actual &actual : actuals) {
      auto formal = std::find_if(info.formals.begin(), info.formals.end(),
                                 [&](const auto &item) { return item.first == actual.index; });
      if (formal != info.formals.end())
        copies.push_back({actual.value, formal->second, actual.source, Rule::CallArgument,
                          caller, siteIndex});
    }
    if (result != NONE) {
      for (uint32_t returned : info.returns)
        copies.push_back({returned, result, source, Rule::CallReturn, caller, siteIndex});
    }
  }

  // Consumes a prior round's indirect_call_targets.tsv and promotes each resolved
  // (indirect callsite, target function) pair to a synthetic direct site keyed by the
  // indirect callsite. materializeCallsiteContexts then contextualizes those sites with
  // the same hybrid policy as real direct calls, so an indirect callback dispatched from
  // one site no longer merges its actuals into the shared target baseline formal. The
  // Solver suppresses the context-insensitive baseline wiring for any pair recorded here.
  // Targets are an over-approximation refined monotonically across rounds; this is the
  // demand-driven realization of plan §10.1 item 4.
  void loadResolvedIndirectTargets(const fs::path &path) {
    std::ifstream input(path);
    if (!input)
      return;
    std::vector<std::pair<std::string, std::string>> pairs;
    std::string line;
    while (std::getline(input, line)) {
      if (line.empty() || line[0] == '#')
        continue;
      auto columns = splitTabs(line);
      if (columns.size() < 2)
        continue;
      pairs.emplace_back(columns[0], columns[1]);
    }
    promoteIndirectPairs(pairs);
  }

  // Promotes each (indirect callsite name, target function-object name) pair to a synthetic
  // direct site, exactly as loadResolvedIndirectTargets does from a file. Callers that iterate
  // a monotone in-memory frontier (the indirect-target bootstrap) use this directly so no
  // per-round temp file is needed; string identities keep the set stable across fresh
  // databases whose interned integer ids differ.
  void promoteIndirectPairs(
      const std::vector<std::pair<std::string, std::string>> &pairs) {
    if (syntheticDirectSiteStart == NONE)
      syntheticDirectSiteStart = static_cast<uint32_t>(directSites.size());
    std::unordered_map<uint32_t, uint32_t> siteByCallsite;
    for (uint32_t index = 0; index < indirectSites.size(); ++index)
      siteByCallsite.emplace(indirectSites[index].callsiteName, index);
    for (const auto &[callsiteStr, targetStr] : pairs) {
      uint32_t callsiteName = callsiteNames.intern(callsiteStr);
      auto site = siteByCallsite.find(callsiteName);
      if (site == siteByCallsite.end())
        continue;
      auto target = objects.find(targetStr);
      if (!target || !objects.isFunction(*target))
        continue;
      uint64_t pairKey = (static_cast<uint64_t>(callsiteName) << 32) | *target;
      if (!contextualizedIndirectPairs.insert(pairKey).second)
        continue;
      ++counts.resolvedIndirectPairs;
      const IndirectSite &original = indirectSites[site->second];
      std::vector<Actual> actuals;
      actuals.reserve(original.actualCount);
      uint32_t start = static_cast<uint32_t>(directActuals.size());
      for (uint32_t offset = 0; offset < original.actualCount; ++offset) {
        actuals.push_back(indirectActuals[original.actualStart + offset]);
        directActuals.push_back(actuals.back());
      }
      uint32_t siteIndex = static_cast<uint32_t>(directSites.size());
      directSites.push_back({original.callsiteName, original.callerFunction, *target,
                             start, original.actualCount, original.result,
                             original.source});
      if (original.callerFunction != NONE)
        directCallEdges.push_back({original.callerFunction, *target});
      wireStaticCall(original.callerFunction, *target, actuals, original.result,
                     original.source, siteIndex);
      ++counts.resolvedIndirectSites;
    }
  }

  bool indirectPairContextualized(uint32_t callsiteName, uint32_t function) const {
    if (contextualizedIndirectPairs.empty())
      return false;
    return contextualizedIndirectPairs.count(
               (static_cast<uint64_t>(callsiteName) << 32) | function) != 0;
  }

  void loadRegistrationSeeds(const fs::path &path) {
    std::ifstream input(path);
    std::string line;
    uint64_t lineNumber = 0;
    std::unordered_set<std::string> seen;
    while (std::getline(input, line)) {
      ++lineNumber;
      if (line.empty() || line[0] == '#')
        continue;
      auto columns = splitTabs(line);
      if (columns.size() < 15)
        continue;
      ++counts.seedRows;
      if (columns[8] == "unresolved") {
        ++counts.seedUnresolved;
        continue;
      }
      std::string relation = std::string(columns[1]) + "\t" + std::string(columns[2]) + "\t" +
                             std::string(columns[3]) + "\t" + std::string(columns[6]);
      if (!seen.insert(relation).second)
        continue;
      uint32_t dispatch;
      if (auto found = objects.find(columns[6])) {
        dispatch = *found;
      } else if (columns[8] == "synthetic") {
        dispatch = objects.intern(columns[6], 0, ObjectKind::Synthetic);
      } else {
        ++counts.seedUnresolved;
        continue;
      }
      std::string rootLabel = std::string(columns[2]) + ":" + std::string(columns[3]);
      uint32_t rootName = rootNames.intern(rootLabel);
      std::string valueName = "seed:value:root:" + rootLabel;
      uint32_t rootValue = value(valueName);
      std::string objectName = "seed:object:install:" + rootLabel + ":" + std::string(columns[6]);
      uint32_t rootObject = objects.intern(objectName, 0, ObjectKind::Synthetic);
      rootSeeds.push_back({rootName, rootValue, rootObject, dispatch,
                           sourceRef(SourceTable::Registration, lineNumber)});
      ++counts.seedRelations;
    }
  }

  void loadApiSummaries(const fs::path &path) {
    std::ifstream input(path);
    std::string line;
    uint64_t lineNumber = 0;
    std::unordered_set<std::string> seenDispatch;
    while (std::getline(input, line)) {
      ++lineNumber;
      if (line.empty() || line[0] == '#')
        continue;
      auto columns = splitTabs(line);
      if (columns.size() < 11)
        continue;
      if (columns[1] == "dispatch_field" || columns[1] == "context_field") {
        auto subject = objects.find(columns[3]);
        if (!subject && columns[3].rfind("seed:", 0) == 0)
          subject = objects.intern(columns[3], 0, ObjectKind::Synthetic);
        if (!subject)
          continue;
        std::string identity = std::string(columns[3]) + "\t" + std::string(columns[4]) + "\t" +
                               std::string(columns[6]);
        if (!seenDispatch.insert(identity).second)
          continue;
        namedSummaries.push_back({*subject, summaryKeys.intern(columns[4]),
                                  handlerNames.intern(columns[6]),
                                  sourceRef(SourceTable::ApiSummary, lineNumber)});
        ++counts.dispatchSummaries;
      } else if (columns[1] == "cmd_selector") {
        ++counts.cmdSummaries;
      }
    }
  }

  void computeHandlerReachability() {
    std::unordered_set<uint32_t> dispatchRoots;
    for (const RootSeed &seed : rootSeeds)
      dispatchRoots.insert(seed.dispatchObject);

    auto handlerFunction = [&](const NamedSummary &summary) -> std::optional<uint32_t> {
      std::string_view handler = handlerNames.name(summary.handler);
      std::string_view subject = objects.name(summary.object);
      if (subject.rfind("batch:", 0) == 0) {
        size_t local = subject.find(":local:");
        if (local != std::string_view::npos) {
          std::string id = "batch:" + std::string(subject.substr(6, local - 6)) +
                           ":local:object:function:" + std::string(handler);
          if (auto found = objects.find(id))
            return found;
        }
      }
      return objects.find("sym:object:function:" + std::string(handler));
    };

    std::vector<uint32_t> work;
    auto addRoot = [&](uint32_t function) {
      handlerRootFunctions.insert(function);
      if (handlerReachableFunctions.insert(function).second)
        work.push_back(function);
    };
    for (const NamedSummary &summary : namedSummaries) {
      if (!dispatchRoots.count(summary.object))
        continue;
      if (auto function = handlerFunction(summary))
        addRoot(*function);
    }
    std::unordered_map<uint32_t, std::vector<uint32_t>> addressFunctions;
    for (const AddressSeed &seed : addressSeeds) {
      if (seed.offset == 0 && objects.isFunction(seed.root))
        addressFunctions[seed.dst].push_back(seed.root);
    }
    for (const StoreObjectConstraint &constraint : storeObjects) {
      if (!dispatchRoots.count(constraint.root))
        continue;
      auto found = addressFunctions.find(constraint.src);
      if (found == addressFunctions.end())
        continue;
      for (uint32_t function : found->second)
        addRoot(function);
    }
    counts.handlerRootFunctions = work.size();

    std::sort(directCallEdges.begin(), directCallEdges.end());
    directCallEdges.erase(std::unique(directCallEdges.begin(), directCallEdges.end()),
                          directCallEdges.end());
    for (size_t cursor = 0; cursor < work.size(); ++cursor) {
      uint32_t caller = work[cursor];
      auto begin = std::lower_bound(directCallEdges.begin(), directCallEdges.end(),
                                    std::pair<uint32_t, uint32_t>{caller, 0});
      auto end = std::upper_bound(
          begin, directCallEdges.end(),
          std::pair<uint32_t, uint32_t>{caller, std::numeric_limits<uint32_t>::max()});
      for (auto iterator = begin; iterator != end; ++iterator) {
        if (handlerReachableFunctions.insert(iterator->second).second)
          work.push_back(iterator->second);
      }
    }
    counts.handlerReachableFunctions = handlerReachableFunctions.size();
  }

  // P1 object-sensitivity (design §3): static receiver-formal selection. A formal is a receiver
  // if the object passed to it is dereferenced — LOCALLY (its intra-procedural, non-call value
  // flow reaches a FIELD_ADDR/LOAD/STORE/indirect-callee base), OR by being forwarded into
  // another function's receiver formal (inter-procedural backward least fixpoint over direct-call
  // argument forwarding, so pointer-forwarding wrappers are not misclassified as zero-receiver).
  // Fills receiverArity[F] (distinct receiver arg indices) and receiverFormalIndex[F] (the unique
  // receiver arg index when arity==1, else NONE — the V1 unique-receiver gate).
  void computeReceiverFormals() {
    const uint32_t n = static_cast<uint32_t>(values.size());
    // (1) Dereference bases: the pointer operand of every field/load/store/indirect-callee.
    std::vector<uint8_t> deref(n, 0);
    auto markBase = [&](uint32_t v) {
      if (v != NONE && v < n)
        deref[v] = 1;
    };
    for (const FieldConstraint &c : fields) markBase(c.src);
    for (const DynamicFieldConstraint &c : dynamicFields) markBase(c.src);
    for (const StridedFieldConstraint &c : stridedFields) markBase(c.src);
    for (const SimpleConstraint &c : loads) markBase(c.first);
    for (const SimpleConstraint &c : stores) markBase(c.first);
    for (const IndirectSite &s : indirectSites) markBase(s.calleeValue);

    // (2) Intra-procedural, non-call, same-owner copy graph (reverse adjacency dst -> [src]).
    std::vector<std::vector<uint32_t>> copyPred(n);
    for (const CopyConstraint &c : copies) {
      if (c.rule == Rule::CallArgument || c.rule == Rule::CallReturn)
        continue;
      if (c.src >= n || c.dst >= n || c.src >= valueOwners.size() ||
          c.dst >= valueOwners.size())
        continue;
      uint32_t srcOwner = valueOwners[c.src], dstOwner = valueOwners[c.dst];
      if (srcOwner == NONE || srcOwner != dstOwner)
        continue;  // same-owner only; call edges already excluded above
      copyPred[c.dst].push_back(c.src);
    }
    // LocalDeref = ancestors-or-self of a deref base over copyPred (v forward-reaches a base).
    std::vector<uint8_t> localDeref(n, 0);
    std::vector<uint32_t> work;
    for (uint32_t v = 0; v < n; ++v)
      if (deref[v]) {
        localDeref[v] = 1;
        work.push_back(v);
      }
    while (!work.empty()) {
      uint32_t v = work.back();
      work.pop_back();
      for (uint32_t p : copyPred[v])
        if (!localDeref[p]) {
          localDeref[p] = 1;
          work.push_back(p);
        }
    }

    // (3) Seed receivers from formals with LocalDeref; backward inter-proc fixpoint over
    //     direct-call forwarding.  receiver key = (function << 32) | argIndex.
    std::unordered_set<uint64_t> receiver;
    std::vector<uint64_t> rwork;
    auto keyOf = [](uint32_t f, uint32_t i) {
      return (static_cast<uint64_t>(f) << 32) | i;
    };
    auto addReceiver = [&](uint32_t f, uint32_t i) {
      if (receiver.insert(keyOf(f, i)).second)
        rwork.push_back(keyOf(f, i));
    };
    for (const auto &[func, info] : functions)
      for (const auto &[argIndex, formalValue] : info.formals)
        if (formalValue < n && localDeref[formalValue])
          addReceiver(func, argIndex);

    std::unordered_map<uint32_t, std::vector<uint32_t>> sitesByCallee;
    for (uint32_t s = 0; s < directSites.size(); ++s)
      sitesByCallee[directSites[s].calleeFunction].push_back(s);

    // ancestorFormals(w): arg indices of owner(w)'s formals that forward-reach w (w is a
    // descendant). Backward walk from w over copyPred within owner(w); a reused stamp avoids
    // O(n) reallocation per call.
    std::vector<uint32_t> stamp(n, 0);
    uint32_t stampEpoch = 0;
    std::vector<uint32_t> stack;
    auto forEachAncestorFormal = [&](uint32_t w, auto &&emit) {
      if (w >= n || w >= valueOwners.size())
        return;
      uint32_t owner = valueOwners[w];
      if (owner == NONE)
        return;
      auto it = functions.find(owner);
      if (it == functions.end())
        return;
      ++stampEpoch;
      stack.clear();
      stamp[w] = stampEpoch;
      stack.push_back(w);
      while (!stack.empty()) {
        uint32_t v = stack.back();
        stack.pop_back();
        for (const auto &[argIndex, formalValue] : it->second.formals)
          if (formalValue == v)
            emit(argIndex);
        for (uint32_t p : copyPred[v])
          if (p < n && stamp[p] != stampEpoch) {
            stamp[p] = stampEpoch;
            stack.push_back(p);
          }
      }
    };

    while (!rwork.empty()) {
      uint64_t k = rwork.back();
      rwork.pop_back();
      uint32_t calleeFn = static_cast<uint32_t>(k >> 32);
      uint32_t argIndex = static_cast<uint32_t>(k & 0xffffffffu);
      auto sit = sitesByCallee.find(calleeFn);
      if (sit == sitesByCallee.end())
        continue;
      for (uint32_t s : sit->second) {
        const DirectSite &site = directSites[s];
        if (site.callerFunction == NONE)
          continue;
        for (uint32_t off = 0; off < site.actualCount; ++off) {
          const Actual &actual = directActuals[site.actualStart + off];
          if (actual.index != argIndex)
            continue;
          forEachAncestorFormal(actual.value,
                                [&](uint32_t fi) { addReceiver(site.callerFunction, fi); });
        }
      }
    }

    // (4) Arity + unique-receiver gate.
    std::unordered_map<uint32_t, std::vector<uint32_t>> byFunction;
    for (uint64_t k : receiver)
      byFunction[static_cast<uint32_t>(k >> 32)].push_back(static_cast<uint32_t>(k & 0xffffffffu));
    receiverFormalIndex.assign(objects.size(), NONE);
    receiverArity.assign(objects.size(), 0);
    for (auto &[func, indices] : byFunction) {
      if (func >= receiverArity.size())
        continue;
      receiverArity[func] = static_cast<uint32_t>(indices.size());
      if (indices.size() == 1)
        receiverFormalIndex[func] = indices[0];
    }
    counts.receiverFunctions = byFunction.size();
    for (const auto &[func, indices] : byFunction) {
      if (indices.size() == 1)
        ++counts.uniqueReceiverFunctions;
      else
        ++counts.multiReceiverFunctions;
    }
  }

  // P1 object-sensitivity (design §4.1): build one call-free copy-SCC template for every
  // unique-receiver function. Only ordinary COPY constraints whose endpoints are both owned
  // by the same selected function participate. CALL_ARGUMENT/CALL_RETURN and cross-owner
  // copies are therefore structurally unable to merge two function templates.
  void computeObjectSensitivityTemplates() {
    const uint32_t valueCount = static_cast<uint32_t>(values.size());
    templateComponentOrdinal.assign(valueCount, NONE);
    templateStackObjectOrdinal.assign(objects.size(), NONE);
    objectTemplateIndex.assign(objects.size(), NONE);
    objectFunctionTemplates.clear();
    counts.objectTemplateFunctions = 0;
    counts.objectTemplateValues = 0;
    counts.objectTemplateComponents = 0;
    counts.objectTemplateCopyEdges = 0;
    counts.objectTemplateStackObjects = 0;
    counts.objectTemplateAddressSeeds = 0;
    counts.objectTemplateFields = 0;
    counts.objectTemplateDynamicFields = 0;
    counts.objectTemplateStridedFields = 0;
    counts.objectTemplateLoads = 0;
    counts.objectTemplateStores = 0;
    counts.objectTemplateStoreObjects = 0;
    counts.objectTemplateMemoryCopies = 0;
    counts.objectTemplateDirectSites = 0;
    counts.objectTemplateIndirectSites = 0;

    auto selectedOwner = [&](uint32_t owner) {
      return owner != NONE && owner < receiverArity.size() && receiverArity[owner] == 1 &&
             receiverFormalIndex[owner] != NONE;
    };

    std::vector<uint8_t> eligible(valueCount);
    for (uint32_t valueId = 0; valueId < valueCount; ++valueId) {
      uint32_t owner = valueId < valueOwners.size() ? valueOwners[valueId] : NONE;
      if (!selectedOwner(owner))
        continue;
      eligible[valueId] = 1;
      ++counts.objectTemplateValues;
    }

    auto templateCopy = [&](const CopyConstraint &constraint) {
      if (constraint.rule != Rule::Copy || constraint.src >= valueCount ||
          constraint.dst >= valueCount || constraint.src == constraint.dst ||
          !eligible[constraint.src] || !eligible[constraint.dst])
        return false;
      return valueOwners[constraint.src] == valueOwners[constraint.dst];
    };

    std::vector<uint32_t> forwardStart(valueCount + 1), reverseStart(valueCount + 1);
    uint64_t edgeCount = 0;
    for (const CopyConstraint &constraint : copies) {
      if (!templateCopy(constraint))
        continue;
      ++forwardStart[constraint.src + 1];
      ++reverseStart[constraint.dst + 1];
      ++edgeCount;
    }
    if (edgeCount > std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("object template copy graph exceeds 32-bit edge capacity");
    for (uint32_t valueId = 1; valueId <= valueCount; ++valueId) {
      forwardStart[valueId] += forwardStart[valueId - 1];
      reverseStart[valueId] += reverseStart[valueId - 1];
    }
    std::vector<uint32_t> forwardEdges(edgeCount), reverseEdges(edgeCount);
    std::vector<uint32_t> forwardCursor = forwardStart;
    std::vector<uint32_t> reverseCursor = reverseStart;
    for (const CopyConstraint &constraint : copies) {
      if (!templateCopy(constraint))
        continue;
      forwardEdges[forwardCursor[constraint.src]++] = constraint.dst;
      reverseEdges[reverseCursor[constraint.dst]++] = constraint.src;
    }

    struct Frame {
      uint32_t value;
      uint32_t cursor;
    };
    std::vector<uint8_t> state(valueCount);
    std::vector<uint32_t> order;
    order.reserve(counts.objectTemplateValues);
    std::vector<Frame> frames;
    for (uint32_t start = 0; start < valueCount; ++start) {
      if (!eligible[start] || state[start])
        continue;
      state[start] = 1;
      frames.push_back({start, forwardStart[start]});
      while (!frames.empty()) {
        Frame &frame = frames.back();
        if (frame.cursor < forwardStart[frame.value + 1]) {
          uint32_t next = forwardEdges[frame.cursor++];
          if (!state[next]) {
            state[next] = 1;
            frames.push_back({next, forwardStart[next]});
          }
          continue;
        }
        order.push_back(frame.value);
        frames.pop_back();
      }
    }

    struct TemporaryComponent {
      uint32_t function;
      uint32_t representative;
    };
    std::vector<uint32_t> componentOfValue(valueCount, NONE);
    std::vector<TemporaryComponent> components;
    std::vector<uint32_t> stack;
    for (auto iterator = order.rbegin(); iterator != order.rend(); ++iterator) {
      uint32_t start = *iterator;
      if (componentOfValue[start] != NONE)
        continue;
      uint32_t component = static_cast<uint32_t>(components.size());
      uint32_t representative = start;
      uint32_t function = valueOwners[start];
      componentOfValue[start] = component;
      stack.push_back(start);
      while (!stack.empty()) {
        uint32_t valueId = stack.back();
        stack.pop_back();
        representative = std::min(representative, valueId);
        for (uint32_t edge = reverseStart[valueId]; edge < reverseStart[valueId + 1]; ++edge) {
          uint32_t next = reverseEdges[edge];
          if (componentOfValue[next] != NONE)
            continue;
          componentOfValue[next] = component;
          stack.push_back(next);
        }
      }
      components.push_back({function, representative});
    }

    std::vector<uint32_t> componentOrder(components.size());
    std::iota(componentOrder.begin(), componentOrder.end(), 0);
    std::sort(componentOrder.begin(), componentOrder.end(), [&](uint32_t left, uint32_t right) {
      return std::tie(components[left].function, components[left].representative) <
             std::tie(components[right].function, components[right].representative);
    });
    std::vector<uint32_t> ordinalOfComponent(components.size(), NONE);
    for (uint32_t component : componentOrder) {
      const TemporaryComponent &item = components[component];
      uint32_t templateIndex = objectTemplateIndex[item.function];
      if (templateIndex == NONE) {
        templateIndex = static_cast<uint32_t>(objectFunctionTemplates.size());
        objectTemplateIndex[item.function] = templateIndex;
        objectFunctionTemplates.push_back({});
        objectFunctionTemplates.back().function = item.function;
      }
      ObjectFunctionTemplate &functionTemplate = objectFunctionTemplates[templateIndex];
      ordinalOfComponent[component] =
          static_cast<uint32_t>(functionTemplate.componentRepresentatives.size());
      functionTemplate.componentRepresentatives.push_back(item.representative);
    }
    for (uint32_t valueId = 0; valueId < valueCount; ++valueId) {
      if (componentOfValue[valueId] == NONE)
        continue;
      templateComponentOrdinal[valueId] = ordinalOfComponent[componentOfValue[valueId]];
    }

    for (const CopyConstraint &constraint : copies) {
      if (!templateCopy(constraint))
        continue;
      uint32_t src = templateComponentOrdinal[constraint.src];
      uint32_t dst = templateComponentOrdinal[constraint.dst];
      if (src == dst)
        continue;
      uint32_t function = valueOwners[constraint.src];
      objectFunctionTemplates[objectTemplateIndex[function]].copyEdges.push_back(
          {src, dst, constraint.source});
      ++counts.objectTemplateCopyEdges;
    }

    for (uint32_t objectId = 0; objectId < objectOwners.size(); ++objectId) {
      uint32_t owner = objectOwners[objectId];
      if (!selectedOwner(owner) || owner >= objectTemplateIndex.size())
        continue;
      uint32_t templateIndex = objectTemplateIndex[owner];
      if (templateIndex == NONE)
        continue;
      ObjectFunctionTemplate &functionTemplate = objectFunctionTemplates[templateIndex];
      templateStackObjectOrdinal[objectId] =
          static_cast<uint32_t>(functionTemplate.stackObjects.size());
      functionTemplate.stackObjects.push_back(objectId);
      ++counts.objectTemplateStackObjects;
    }

    auto ownerOfValues = [&](std::initializer_list<uint32_t> operands) {
      uint32_t owner = NONE;
      for (uint32_t operand : operands) {
        if (operand == NONE || operand >= valueOwners.size())
          continue;
        uint32_t current = valueOwners[operand];
        if (current == NONE)
          continue;
        if (owner != NONE && owner != current)
          return NONE;
        owner = current;
      }
      return owner;
    };
    auto appendIndex = [&](uint32_t owner, uint32_t index,
                           std::vector<uint32_t> ObjectFunctionTemplate::*member,
                           uint64_t &count) {
      if (!selectedOwner(owner) || owner >= objectTemplateIndex.size())
        return;
      uint32_t templateIndex = objectTemplateIndex[owner];
      if (templateIndex == NONE)
        return;
      (objectFunctionTemplates[templateIndex].*member).push_back(index);
      ++count;
    };

    for (uint32_t index = 0; index < addressSeeds.size(); ++index)
      appendIndex(ownerOfValues({addressSeeds[index].dst}), index,
                  &ObjectFunctionTemplate::addressSeeds,
                  counts.objectTemplateAddressSeeds);
    for (uint32_t index = 0; index < fields.size(); ++index)
      appendIndex(ownerOfValues({fields[index].src, fields[index].dst}), index,
                  &ObjectFunctionTemplate::fields, counts.objectTemplateFields);
    for (uint32_t index = 0; index < dynamicFields.size(); ++index)
      appendIndex(ownerOfValues({dynamicFields[index].src, dynamicFields[index].dst}), index,
                  &ObjectFunctionTemplate::dynamicFields,
                  counts.objectTemplateDynamicFields);
    for (uint32_t index = 0; index < stridedFields.size(); ++index)
      appendIndex(ownerOfValues({stridedFields[index].src, stridedFields[index].dst}), index,
                  &ObjectFunctionTemplate::stridedFields,
                  counts.objectTemplateStridedFields);
    for (uint32_t index = 0; index < loads.size(); ++index)
      appendIndex(ownerOfValues({loads[index].first, loads[index].second}), index,
                  &ObjectFunctionTemplate::loads, counts.objectTemplateLoads);
    for (uint32_t index = 0; index < stores.size(); ++index)
      appendIndex(ownerOfValues({stores[index].first, stores[index].second}), index,
                  &ObjectFunctionTemplate::stores, counts.objectTemplateStores);
    for (uint32_t index = 0; index < storeObjects.size(); ++index) {
      uint32_t owner = ownerOfValues({storeObjects[index].src});
      uint32_t root = storeObjects[index].root;
      uint32_t rootOwner = root < objectOwners.size() ? objectOwners[root] : NONE;
      if (rootOwner != NONE) {
        if (owner != NONE && owner != rootOwner)
          continue;
        owner = rootOwner;
      }
      appendIndex(owner, index, &ObjectFunctionTemplate::storeObjects,
                  counts.objectTemplateStoreObjects);
    }
    for (uint32_t index = 0; index < memoryCopies.size(); ++index)
      appendIndex(ownerOfValues({memoryCopies[index].dst, memoryCopies[index].src}), index,
                  &ObjectFunctionTemplate::memoryCopies,
                  counts.objectTemplateMemoryCopies);
    for (uint32_t index = 0; index < directSites.size(); ++index)
      appendIndex(directSites[index].callerFunction, index,
                  &ObjectFunctionTemplate::directSites,
                  counts.objectTemplateDirectSites);
    for (uint32_t index = 0; index < indirectSites.size(); ++index)
      appendIndex(indirectSites[index].callerFunction, index,
                  &ObjectFunctionTemplate::indirectSites,
                  counts.objectTemplateIndirectSites);

    counts.objectTemplateFunctions = objectFunctionTemplates.size();
    counts.objectTemplateComponents = components.size();
  }

  const ObjectFunctionTemplate *objectTemplate(uint32_t function) const {
    if (function >= objectTemplateIndex.size())
      return nullptr;
    uint32_t index = objectTemplateIndex[function];
    return index == NONE ? nullptr : &objectFunctionTemplates[index];
  }

  uint32_t objectTemplateComponent(uint32_t valueId) const {
    return valueId < templateComponentOrdinal.size() ? templateComponentOrdinal[valueId] : NONE;
  }

  bool directSiteHasPointerFlow(const DirectSite &site) const {
    auto found = functions.find(site.calleeFunction);
    if (found == functions.end())
      return false;
    const FunctionInfo &info = found->second;
    if (site.result != NONE && !info.returns.empty())
      return true;
    for (uint32_t offset = 0; offset < site.actualCount; ++offset) {
      const Actual &actual = directActuals[site.actualStart + offset];
      if (std::any_of(info.formals.begin(), info.formals.end(),
                      [&](const auto &formal) { return formal.first == actual.index; }))
        return true;
    }
    return false;
  }

  void writeCallsiteContextCensus(const fs::path &path) {
    std::vector<uint64_t> ownedValues(objects.size());
    std::vector<uint64_t> ownedObjects(objects.size());
    std::vector<uint64_t> ownedConstraints(objects.size());
    for (uint32_t owner : valueOwners)
      if (owner != NONE)
        ++ownedValues[owner];
    for (uint32_t owner : objectOwners)
      if (owner != NONE)
        ++ownedObjects[owner];
    auto countConstraint = [&](uint32_t value) {
      if (value < valueOwners.size() && valueOwners[value] != NONE)
        ++ownedConstraints[valueOwners[value]];
    };
    for (const AddressSeed &seed : addressSeeds)
      countConstraint(seed.dst);
    for (const CopyConstraint &constraint : copies)
      if (constraint.rule == Rule::Copy)
        countConstraint(constraint.dst);
    for (const FieldConstraint &constraint : fields)
      countConstraint(constraint.dst);
    for (const DynamicFieldConstraint &constraint : dynamicFields)
      countConstraint(constraint.dst);
    for (const StridedFieldConstraint &constraint : stridedFields)
      countConstraint(constraint.dst);
    for (const SimpleConstraint &constraint : loads)
      countConstraint(constraint.second);
    for (const SimpleConstraint &constraint : stores)
      countConstraint(constraint.first);
    for (const MemoryCopyConstraint &constraint : memoryCopies)
      countConstraint(constraint.dst);
    std::vector<uint64_t> contexts(objects.size());
    std::vector<uint64_t> outgoingSites(objects.size());
    for (uint32_t function : handlerRootFunctions)
      ++contexts[function];
    uint64_t reachableSites = 0;
    for (const DirectSite &site : directSites) {
      if (!handlerReachableFunctions.count(site.callerFunction) ||
          !handlerReachableFunctions.count(site.calleeFunction) ||
          !directSiteHasPointerFlow(site))
        continue;
      ++contexts[site.calleeFunction];
      ++outgoingSites[site.callerFunction];
      ++reachableSites;
    }

    struct Row {
      uint64_t projected;
      uint64_t contexts;
      uint64_t values;
      uint64_t objects;
      uint64_t outgoing;
      uint64_t invocations;
      uint64_t constraints;
      uint64_t projectedConstraints;
      uint32_t function;
    };
    std::vector<Row> rows;
    uint64_t projectedTotal = 0;
    uint64_t projectedObjectTotal = 0;
    uint64_t invocationTotal = 0;
    uint64_t constraintTotal = 0;
    for (uint32_t function : handlerReachableFunctions) {
      if (!contexts[function] || !ownedValues[function])
        continue;
      uint64_t projected = contexts[function] * ownedValues[function];
      uint64_t projectedObjects = contexts[function] * ownedObjects[function];
      uint64_t invocations = contexts[function] * outgoingSites[function];
      uint64_t projectedConstraints = contexts[function] * ownedConstraints[function];
      projectedTotal += projected;
      projectedObjectTotal += projectedObjects;
      invocationTotal += invocations;
      constraintTotal += projectedConstraints;
      rows.push_back({projected, contexts[function], ownedValues[function],
                      ownedObjects[function],
                      outgoingSites[function], invocations, ownedConstraints[function],
                      projectedConstraints, function});
    }
    std::sort(rows.begin(), rows.end(), [](const Row &left, const Row &right) {
      if (left.projected != right.projected)
        return left.projected > right.projected;
      return left.function < right.function;
    });
    counts.handlerReachableDirectSites = reachableSites;
    counts.projectedCallsiteValues = projectedTotal;
    counts.projectedCallsiteObjects = projectedObjectTotal;
    counts.projectedCallsiteInvocations = invocationTotal;
    counts.projectedCallsiteConstraints = constraintTotal;

    std::ofstream out(path);
    out << "#function_object\tfunction\towned_values\tcontexts\tprojected_values"
           "\towned_stack_objects\tprojected_stack_objects"
           "\toutgoing_sites\tprojected_invocations\towned_constraints"
           "\tprojected_constraints\n";
    for (const Row &row : rows)
      out << objects.name(row.function) << '\t' << objects.symbol(row.function) << '\t'
          << row.values << '\t' << row.contexts << '\t' << row.projected << '\t'
          << row.objects << '\t' << row.objects * row.contexts << '\t'
          << row.outgoing << '\t' << row.invocations << '\t' << row.constraints << '\t'
          << row.projectedConstraints << '\n';
  }

  void writeObjectTemplateCensus(const fs::path &path) const {
    std::ofstream out(path);
    out << "#function_object\tfunction\tcomponents\tcopy_edges\tstack_objects"
           "\taddress_seeds\tfields\tdynamic_fields\tstrided_fields\tloads\tstores"
           "\tstore_objects\tmemory_copies\tdirect_sites\tindirect_sites\n";
    for (const ObjectFunctionTemplate &functionTemplate : objectFunctionTemplates) {
      out << objects.name(functionTemplate.function) << '\t'
          << objects.symbol(functionTemplate.function) << '\t'
          << functionTemplate.componentRepresentatives.size() << '\t'
          << functionTemplate.copyEdges.size() << '\t'
          << functionTemplate.stackObjects.size() << '\t'
          << functionTemplate.addressSeeds.size() << '\t'
          << functionTemplate.fields.size() << '\t'
          << functionTemplate.dynamicFields.size() << '\t'
          << functionTemplate.stridedFields.size() << '\t'
          << functionTemplate.loads.size() << '\t'
          << functionTemplate.stores.size() << '\t'
          << functionTemplate.storeObjects.size() << '\t'
          << functionTemplate.memoryCopies.size() << '\t'
          << functionTemplate.directSites.size() << '\t'
          << functionTemplate.indirectSites.size() << '\n';
    }
  }

  void materializeCallsiteContexts(ContextScope scope, ContextObjectMode objectMode,
                                   uint32_t contextDepth,
                                   ContextValueSlice valueSlice,
                                   uint32_t refineMinContexts,
                                   uint32_t refineDepth,
                                   ContextRefinePropagation refinePropagation,
                                   const std::vector<uint8_t> *enabledDirectSites,
                                   uint64_t maxContexts,
                                   const std::vector<uint32_t> *signatureOf = nullptr,
                                   const std::vector<uint8_t> *deferFlowSites = nullptr) {
    if (contextDepth == 0 || contextDepth > 4)
      throw std::runtime_error("context depth must be between 1 and 4");
    // Signature mode keys each context by the callsite's context-insensitive actual-set
    // signature (see computeSignatureContexts) instead of the call string, so callsites
    // with the same abstract input share one clone. Selection is then bounded by the
    // per-callee signature budget rather than the escape/activity filters.
    const bool signatureMode = signatureOf != nullptr;
    contextCallTransfers.clear();
    const uint32_t originalValueCount = static_cast<uint32_t>(values.size());
    contextValueOrigins.resize(originalValueCount, NONE);
    const size_t originalAddressCount = addressSeeds.size();
    const size_t originalFieldCount = fields.size();
    const size_t originalDynamicCount = dynamicFields.size();
    const size_t originalStridedCount = stridedFields.size();
    const size_t originalLoadCount = loads.size();
    const size_t originalStoreCount = stores.size();
    const size_t originalStoreObjectCount = storeObjects.size();
    const size_t originalMemoryCopyCount = memoryCopies.size();
    const size_t originalIndirectSiteCount = indirectSites.size();

    const size_t originalCopyCount = copies.size();

    auto functionInScope = [&](uint32_t function) {
      return function != NONE &&
             (scope == ContextScope::Global ||
              handlerReachableFunctions.count(function));
    };

    auto forEachContextDependency = [&](auto &&visit) {
      for (const CopyConstraint &constraint : copies)
        if (constraint.rule != Rule::CallArgument &&
            constraint.rule != Rule::CallReturn)
          visit(constraint.src, constraint.dst);
      for (const FieldConstraint &constraint : fields)
        visit(constraint.src, constraint.dst);
      for (const DynamicFieldConstraint &constraint : dynamicFields)
        visit(constraint.src, constraint.dst);
      for (const StridedFieldConstraint &constraint : stridedFields)
        visit(constraint.src, constraint.dst);
      for (const SimpleConstraint &constraint : loads)
        visit(constraint.first, constraint.second);
      auto addCallResultDependencies = [&](const auto &sites, const auto &actuals) {
        for (const auto &site : sites) {
          if (site.result == NONE)
            continue;
          for (uint32_t offset = 0; offset < site.actualCount; ++offset)
            visit(actuals[site.actualStart + offset].value, site.result);
        }
      };
      addCallResultDependencies(directSites, directActuals);
      addCallResultDependencies(indirectSites, indirectActuals);
    };

    std::vector<uint32_t> contextDependencyStarts(originalValueCount + 1);
    auto validContextDependency = [&](uint32_t src, uint32_t dst) {
      if (src == NONE || dst == NONE || src >= originalValueCount ||
          dst >= originalValueCount)
        return false;
      uint32_t srcOwner = src < valueOwners.size() ? valueOwners[src] : NONE;
      uint32_t dstOwner = dst < valueOwners.size() ? valueOwners[dst] : NONE;
      return srcOwner != NONE && srcOwner == dstOwner &&
             functionInScope(dstOwner);
    };
    forEachContextDependency([&](uint32_t src, uint32_t dst) {
      if (validContextDependency(src, dst))
        ++contextDependencyStarts[src + 1];
    });
    for (uint32_t valueId = 1; valueId <= originalValueCount; ++valueId)
      contextDependencyStarts[valueId] += contextDependencyStarts[valueId - 1];
    std::vector<uint32_t> contextDependencies(contextDependencyStarts.back());
    std::vector<uint32_t> contextDependencyCursor = contextDependencyStarts;
    forEachContextDependency([&](uint32_t src, uint32_t dst) {
      if (validContextDependency(src, dst))
        contextDependencies[contextDependencyCursor[src]++] = dst;
    });

    std::vector<uint8_t> escapeRelevantValues(originalValueCount);
    if (valueSlice == ContextValueSlice::Escape) {
      std::vector<uint8_t> hasLocalTarget(originalValueCount);
      std::vector<uint8_t> mayTargetNonLocal(originalValueCount);
      std::vector<uint32_t> targetWork;
      auto markTargetKind = [&](uint32_t valueId, bool nonLocal) {
        if (valueId == NONE || valueId >= originalValueCount)
          return;
        bool changed = !hasLocalTarget[valueId] ||
                       (nonLocal && !mayTargetNonLocal[valueId]);
        hasLocalTarget[valueId] = 1;
        mayTargetNonLocal[valueId] = mayTargetNonLocal[valueId] || nonLocal;
        if (changed)
          targetWork.push_back(valueId);
      };
      for (const auto &[function, info] : functions) {
        if (!functionInScope(function))
          continue;
        for (const auto &[index, formal] : info.formals) {
          (void)index;
          markTargetKind(formal, true);
        }
      }
      for (const AddressSeed &seed : addressSeeds) {
        uint32_t owner = seed.dst < valueOwners.size() ? valueOwners[seed.dst] : NONE;
        bool localStack = seed.root < objectOwners.size() &&
                          objects.kind(seed.root) == ObjectKind::Stack &&
                          objectOwners[seed.root] == owner;
        markTargetKind(seed.dst, !localStack);
      }
      for (const SimpleConstraint &constraint : loads)
        markTargetKind(constraint.second, true);
      auto markCallResults = [&](const auto &sites) {
        for (const auto &site : sites)
          if (site.result != NONE)
            markTargetKind(site.result, true);
      };
      markCallResults(directSites);
      markCallResults(indirectSites);
      for (size_t index = 0; index < targetWork.size(); ++index) {
        uint32_t source = targetWork[index];
        for (uint32_t edge = contextDependencyStarts[source];
             edge < contextDependencyStarts[source + 1]; ++edge) {
          uint32_t destination = contextDependencies[edge];
          markTargetKind(destination, mayTargetNonLocal[source]);
        }
      }

      std::vector<uint32_t> escapeStarts(originalValueCount + 1);
      for (uint32_t source = 0; source < originalValueCount; ++source) {
        for (uint32_t edge = contextDependencyStarts[source];
             edge < contextDependencyStarts[source + 1]; ++edge)
          ++escapeStarts[contextDependencies[edge] + 1];
      }
      auto countFormalActual = [&](const DirectSite &site) {
        auto found = functions.find(site.calleeFunction);
        if (found == functions.end())
          return;
        for (uint32_t offset = 0; offset < site.actualCount; ++offset) {
          const Actual &actual = directActuals[site.actualStart + offset];
          auto formal = std::find_if(
              found->second.formals.begin(), found->second.formals.end(),
              [&](const auto &item) { return item.first == actual.index; });
          if (formal != found->second.formals.end() &&
              formal->second < originalValueCount && actual.value < originalValueCount)
            ++escapeStarts[formal->second + 1];
        }
      };
      for (const DirectSite &site : directSites)
        countFormalActual(site);
      for (uint32_t valueId = 1; valueId <= originalValueCount; ++valueId)
        escapeStarts[valueId] += escapeStarts[valueId - 1];
      std::vector<uint32_t> escapeDependencies(escapeStarts.back());
      std::vector<uint32_t> escapeCursor = escapeStarts;
      for (uint32_t source = 0; source < originalValueCount; ++source) {
        for (uint32_t edge = contextDependencyStarts[source];
             edge < contextDependencyStarts[source + 1]; ++edge) {
          uint32_t destination = contextDependencies[edge];
          escapeDependencies[escapeCursor[destination]++] = source;
        }
      }
      auto addFormalActual = [&](const DirectSite &site) {
        auto found = functions.find(site.calleeFunction);
        if (found == functions.end())
          return;
        for (uint32_t offset = 0; offset < site.actualCount; ++offset) {
          const Actual &actual = directActuals[site.actualStart + offset];
          auto formal = std::find_if(
              found->second.formals.begin(), found->second.formals.end(),
              [&](const auto &item) { return item.first == actual.index; });
          if (formal != found->second.formals.end() &&
              formal->second < originalValueCount && actual.value < originalValueCount)
            escapeDependencies[escapeCursor[formal->second]++] = actual.value;
        }
      };
      for (const DirectSite &site : directSites)
        addFormalActual(site);

      std::vector<uint32_t> escapeWork;
      auto markEscape = [&](uint32_t valueId) {
        if (valueId == NONE || valueId >= originalValueCount ||
            escapeRelevantValues[valueId])
          return;
        escapeRelevantValues[valueId] = 1;
        escapeWork.push_back(valueId);
      };
      for (const auto &[function, info] : functions) {
        if (!functionInScope(function))
          continue;
        for (uint32_t returned : info.returns)
          markEscape(returned);
      }
      for (const IndirectSite &site : indirectSites) {
        if (!functionInScope(site.callerFunction))
          continue;
        markEscape(site.calleeValue);
        for (uint32_t offset = 0; offset < site.actualCount; ++offset)
          markEscape(indirectActuals[site.actualStart + offset].value);
      }
      for (const SimpleConstraint &constraint : stores) {
        bool external = constraint.first >= hasLocalTarget.size() ||
                        !hasLocalTarget[constraint.first] ||
                        mayTargetNonLocal[constraint.first];
        if (external) {
          markEscape(constraint.first);
          markEscape(constraint.second);
        }
      }
      for (const StoreObjectConstraint &constraint : storeObjects) {
        uint32_t owner = constraint.src < valueOwners.size()
                             ? valueOwners[constraint.src]
                             : NONE;
        bool localStack = constraint.root < objectOwners.size() &&
                          objects.kind(constraint.root) == ObjectKind::Stack &&
                          objectOwners[constraint.root] == owner;
        if (!localStack)
          markEscape(constraint.src);
      }
      for (const MemoryCopyConstraint &constraint : memoryCopies) {
        bool external = constraint.dst >= hasLocalTarget.size() ||
                        !hasLocalTarget[constraint.dst] ||
                        mayTargetNonLocal[constraint.dst];
        if (external) {
          markEscape(constraint.dst);
          markEscape(constraint.src);
        }
      }
      for (size_t index = 0; index < escapeWork.size(); ++index) {
        uint32_t destination = escapeWork[index];
        for (uint32_t edge = escapeStarts[destination];
             edge < escapeStarts[destination + 1]; ++edge)
          markEscape(escapeDependencies[edge]);
      }
    }

    std::vector<uint8_t> contextSensitiveValues(originalValueCount);
    std::vector<uint32_t> contextSensitiveWork;
    auto markContextSensitive = [&](uint32_t valueId) {
      if (valueId == NONE || valueId >= originalValueCount ||
          contextSensitiveValues[valueId])
        return;
      contextSensitiveValues[valueId] = 1;
      contextSensitiveWork.push_back(valueId);
    };
    for (const auto &[function, info] : functions) {
      if (!functionInScope(function))
        continue;
      for (const auto &[index, formal] : info.formals) {
        (void)index;
        if (valueSlice != ContextValueSlice::Escape ||
            (formal < escapeRelevantValues.size() && escapeRelevantValues[formal]))
          markContextSensitive(formal);
      }
    }
    if (objectMode == ContextObjectMode::Stack) {
      for (const AddressSeed &seed : addressSeeds) {
        if (seed.root < objectOwners.size() && objectOwners[seed.root] != NONE)
          markContextSensitive(seed.dst);
      }
    }
    size_t contextSensitiveCursor = 0;
    auto closeContextSensitiveValues = [&]() {
      while (contextSensitiveCursor < contextSensitiveWork.size()) {
        uint32_t source = contextSensitiveWork[contextSensitiveCursor++];
        for (uint32_t edge = contextDependencyStarts[source];
             edge < contextDependencyStarts[source + 1]; ++edge)
          markContextSensitive(contextDependencies[edge]);
      }
    };
    closeContextSensitiveValues();

    std::vector<uint8_t> contextSensitiveMemoryFunctions(objects.size());
    if (valueSlice != ContextValueSlice::All) {
      bool changed = true;
      while (changed) {
        size_t previousValues = contextSensitiveWork.size();
        auto markMemoryFunction = [&](std::initializer_list<uint32_t> operands) {
          uint32_t owner = NONE;
          bool sensitive = false;
          for (uint32_t operand : operands) {
            if (operand == NONE || operand >= originalValueCount)
              continue;
            uint32_t current = operand < valueOwners.size() ? valueOwners[operand] : NONE;
            if (current != NONE)
              owner = current;
            sensitive = sensitive || contextSensitiveValues[operand];
          }
          if (sensitive && owner != NONE && owner < contextSensitiveMemoryFunctions.size())
            contextSensitiveMemoryFunctions[owner] = 1;
        };
        for (const SimpleConstraint &constraint : stores)
          markMemoryFunction({constraint.first, constraint.second});
        for (const StoreObjectConstraint &constraint : storeObjects)
          markMemoryFunction({constraint.src});
        for (const MemoryCopyConstraint &constraint : memoryCopies)
          markMemoryFunction({constraint.dst, constraint.src});
        for (const SimpleConstraint &constraint : loads) {
          uint32_t owner = constraint.second < valueOwners.size()
                               ? valueOwners[constraint.second]
                               : NONE;
          if (owner != NONE && owner < contextSensitiveMemoryFunctions.size() &&
              contextSensitiveMemoryFunctions[owner])
            markContextSensitive(constraint.second);
        }
        closeContextSensitiveValues();
        changed = contextSensitiveWork.size() != previousValues;
      }
    }
    if (valueSlice == ContextValueSlice::All) {
      for (uint32_t valueId = 0; valueId < originalValueCount; ++valueId) {
        uint32_t owner = valueId < valueOwners.size() ? valueOwners[valueId] : NONE;
        if (functionInScope(owner))
          markContextSensitive(valueId);
      }
    }
    counts.contextSensitiveValues = contextSensitiveWork.size();
    counts.contextSensitiveMemoryFunctions = std::count(
        contextSensitiveMemoryFunctions.begin(), contextSensitiveMemoryFunctions.end(), 1);

    std::unordered_map<uint32_t, std::vector<uint32_t>> ownedValues;
    std::unordered_map<uint32_t, std::vector<uint32_t>> ownedObjects;
    std::vector<uint32_t> valueOrdinals(originalValueCount, NONE);
    std::vector<uint32_t> objectOrdinals(objects.size(), NONE);
    for (uint32_t valueId = 0; valueId < originalValueCount; ++valueId) {
      uint32_t owner = valueId < valueOwners.size() ? valueOwners[valueId] : NONE;
      if (owner == NONE || !contextSensitiveValues[valueId])
        continue;
      std::vector<uint32_t> &functionValues = ownedValues[owner];
      valueOrdinals[valueId] = static_cast<uint32_t>(functionValues.size());
      functionValues.push_back(valueId);
    }
    if (objectMode == ContextObjectMode::Stack) {
      for (uint32_t objectId = 0; objectId < objectOwners.size(); ++objectId) {
        uint32_t owner = objectOwners[objectId];
        if (owner == NONE)
          continue;
        std::vector<uint32_t> &functionObjects = ownedObjects[owner];
        objectOrdinals[objectId] = static_cast<uint32_t>(functionObjects.size());
        functionObjects.push_back(objectId);
      }
    }

    struct Context {
      uint32_t function;
      uint32_t baseValue;
      uint32_t valueCount;
      uint32_t baseObject;
      uint32_t objectCount;
      uint8_t callStringLength;
      std::array<uint32_t, 4> callString;
      uint32_t refinementToken;
      uint32_t refinementRemaining;
    };
    struct ContextKey {
      uint32_t function;
      uint8_t length;
      std::array<uint32_t, 4> sites;
      uint32_t refinementToken;
      uint32_t refinementRemaining;
      bool operator==(const ContextKey &other) const {
        return function == other.function && length == other.length &&
               sites == other.sites && refinementToken == other.refinementToken &&
               refinementRemaining == other.refinementRemaining;
      }
    };
    struct ContextKeyHash {
      size_t operator()(const ContextKey &key) const {
        uint64_t hash = mix64(key.function);
        for (uint32_t index = 0; index < key.length; ++index)
          hash = mix64(hash ^ mix64(key.sites[index]));
        hash = mix64(hash ^ mix64(key.refinementToken));
        hash = mix64(hash ^ mix64(key.refinementRemaining));
        return hash;
      }
    };
    std::vector<Context> contexts;
    std::unordered_map<ContextKey, uint32_t, ContextKeyHash> contextIds;

    auto directSiteHasEscapeFlow = [&](const DirectSite &site) {
      auto found = functions.find(site.calleeFunction);
      if (found == functions.end())
        return false;
      if (site.result != NONE && !found->second.returns.empty())
        return true;
      for (uint32_t offset = 0; offset < site.actualCount; ++offset) {
        const Actual &actual = directActuals[site.actualStart + offset];
        auto formal = std::find_if(
            found->second.formals.begin(), found->second.formals.end(),
            [&](const auto &item) { return item.first == actual.index; });
        if (formal != found->second.formals.end() &&
            formal->second < escapeRelevantValues.size() &&
            escapeRelevantValues[formal->second])
          return true;
      }
      return false;
    };

    std::vector<uint32_t> pointerFlowSites;
    contextualDirectSites.assign(directSites.size(), 0);
    siteContextId.assign(directSites.size(), NONE);
    std::vector<uint64_t> baseContextCounts(objects.size());
    if (scope == ContextScope::Handler)
      for (uint32_t function : handlerRootFunctions)
        ++baseContextCounts[function];
    for (uint32_t siteIndex = 0; siteIndex < directSites.size(); ++siteIndex) {
      const DirectSite &site = directSites[siteIndex];
      if (!functionInScope(site.callerFunction) ||
          !functionInScope(site.calleeFunction) ||
          !directSiteHasPointerFlow(site))
        continue;
      // Synthetic sites promoted from resolved indirect targets are concrete call
      // targets; always contextualize them so the indirect callback is isolated, and
      // do not apply the escape/activity precision filters meant for static direct sites.
      // Signature mode contextualizes every pointer-flow site (the per-callee budget is
      // the bound), so it also bypasses the escape/activity site filters.
      bool synthetic = siteIndex >= syntheticDirectSiteStart;
      if (!synthetic && !signatureMode) {
        if (valueSlice == ContextValueSlice::Escape &&
            !directSiteHasEscapeFlow(site)) {
          ++counts.contextIrrelevantDirectSites;
          continue;
        }
        if (enabledDirectSites &&
            (siteIndex >= enabledDirectSites->size() || !(*enabledDirectSites)[siteIndex])) {
          ++counts.contextSkippedDirectSites;
          continue;
        }
      }
      pointerFlowSites.push_back(siteIndex);
      contextualDirectSites[siteIndex] = 1;
      ++counts.contextEligibleDirectSites;
      ++baseContextCounts[site.calleeFunction];
    }

    std::vector<uint8_t> refinedCallers(objects.size());
    if (refineMinContexts && refineDepth) {
      for (uint32_t siteIndex : pointerFlowSites) {
        uint32_t caller = directSites[siteIndex].callerFunction;
        if (baseContextCounts[caller] < refineMinContexts || refinedCallers[caller])
          continue;
        refinedCallers[caller] = 1;
        ++counts.refinedContextFunctions;
      }
    }

    auto refinesCaller = [&](uint32_t function) {
      return function < refinedCallers.size() && refinedCallers[function];
    };

    std::unordered_map<uint32_t, std::vector<uint32_t>> pointerFlowCallees;
    for (uint32_t siteIndex : pointerFlowSites) {
      const DirectSite &site = directSites[siteIndex];
      pointerFlowCallees[site.callerFunction].push_back(site.calleeFunction);
    }
    std::vector<uint32_t> refinementDistance(objects.size(), NONE);
    std::vector<std::pair<uint32_t, uint32_t>> refinementWork;
    for (uint32_t function = 0; function < refinedCallers.size(); ++function) {
      if (!refinedCallers[function])
        continue;
      refinementDistance[function] = 0;
      refinementWork.push_back({function, 0});
    }
    for (size_t index = 0; index < refinementWork.size(); ++index) {
      uint32_t function = refinementWork[index].first;
      uint32_t distance = refinementWork[index].second;
      if (distance + 1 >= refineDepth)
        continue;
      auto found = pointerFlowCallees.find(function);
      if (found == pointerFlowCallees.end())
        continue;
      for (uint32_t callee : found->second) {
        uint32_t nextDistance = distance + 1;
        auto calleeOutgoing = pointerFlowCallees.find(callee);
        if (refinePropagation == ContextRefinePropagation::Linear &&
            (calleeOutgoing == pointerFlowCallees.end() ||
             calleeOutgoing->second.size() != 1))
          continue;
        if (refinementDistance[callee] != NONE &&
            refinementDistance[callee] <= nextDistance)
          continue;
        refinementDistance[callee] = nextDistance;
        refinementWork.push_back({callee, nextDistance});
      }
    }
    counts.refinedContextConeFunctions = std::count_if(
        refinementDistance.begin(), refinementDistance.end(),
        [](uint32_t distance) { return distance != NONE; });
    auto inRefinementCone = [&](uint32_t function) {
      return function < refinementDistance.size() &&
             refinementDistance[function] != NONE;
    };

    auto makeKey = [&](uint32_t function, uint32_t callerContext,
                       uint32_t siteIndex) {
      ContextKey key{function, 0, {NONE, NONE, NONE, NONE}, NONE, 0};
      if (siteIndex == NONE)
        return key;
      if (signatureMode) {
        // Context identity is (callee function, signature id). Every caller instance that
        // reaches this callsite maps to the same callee context; the call string and
        // refinement token are unused.
        key.sites[0] = siteIndex < signatureOf->size() ? (*signatureOf)[siteIndex] : NONE;
        key.length = 1;
        return key;
      }
      const Context *caller = callerContext == NONE ? nullptr : &contexts[callerContext];
      uint32_t retained = caller == nullptr
                              ? 0
                              : std::min<uint32_t>(caller->callStringLength,
                                                   contextDepth - 1);
      if (caller != nullptr && retained) {
        uint32_t start = caller->callStringLength - retained;
        for (uint32_t index = 0; index < retained; ++index)
          key.sites[index] = caller->callString[start + index];
      }
      key.sites[retained] = siteIndex;
      key.length = static_cast<uint8_t>(retained + 1);
      if (caller != nullptr) {
        if (caller->refinementToken != NONE && caller->refinementRemaining &&
            inRefinementCone(caller->function)) {
          key.refinementToken = caller->refinementToken;
          key.refinementRemaining = caller->refinementRemaining - 1;
        } else if (caller->refinementToken == NONE &&
                   refinesCaller(caller->function)) {
          key.refinementToken = callerContext;
          key.refinementRemaining = refineDepth - 1;
        }
      }
      return key;
    };

    std::vector<uint64_t> materializedFunctionContexts(objects.size());
    auto createContext = [&](const ContextKey &key) {
      if (auto found = contextIds.find(key); found != contextIds.end())
        return found->second;
      if (maxContexts && contexts.size() >= maxContexts)
        throw std::runtime_error("call-string context limit exceeded");
      uint32_t contextId = static_cast<uint32_t>(contexts.size());
      auto found = ownedValues.find(key.function);
      uint32_t count = found == ownedValues.end()
                           ? 0
                           : static_cast<uint32_t>(found->second.size());
      uint32_t base = static_cast<uint32_t>(values.size());
      for (uint32_t ordinal = 0; ordinal < count; ++ordinal) {
        std::string name = "ctx:" + std::to_string(contextId) + ":" +
                           std::to_string(ordinal);
        uint32_t clone = value(name);
        if (clone != base + ordinal)
          throw std::runtime_error("context value name collision");
        valueOwners[clone] = key.function;
        if (contextValueOrigins.size() < values.size())
          contextValueOrigins.resize(values.size(), NONE);
        contextValueOrigins[clone] = found->second[ordinal];
      }
      auto objectFound = ownedObjects.find(key.function);
      uint32_t objectCount = objectFound == ownedObjects.end()
                                 ? 0
                                 : static_cast<uint32_t>(objectFound->second.size());
      uint32_t objectBase = static_cast<uint32_t>(objects.size());
      for (uint32_t ordinal = 0; ordinal < objectCount; ++ordinal) {
        uint32_t original = objectFound->second[ordinal];
        std::string name = "ctxobj:" + std::to_string(contextId) + ":" +
                           std::to_string(ordinal);
        uint32_t clone = objects.internLike(name, original);
        if (clone != objectBase + ordinal)
          throw std::runtime_error("context object name collision");
        if (objectOwners.size() < objects.size())
          objectOwners.resize(objects.size(), NONE);
        objectOwners[clone] = key.function;
      }
      contexts.push_back({key.function, base, count, objectBase, objectCount,
                          key.length, key.sites, key.refinementToken,
                          key.refinementRemaining});
      contextIds.emplace(key, contextId);
      ++materializedFunctionContexts[key.function];
      ++counts.materializedContexts;
      counts.materializedValues += count;
      counts.materializedObjects += objectCount;
      return contextId;
    };

    std::vector<uint32_t> roots;
    if (scope == ContextScope::Handler)
      roots.assign(handlerRootFunctions.begin(), handlerRootFunctions.end());
    std::sort(roots.begin(), roots.end());
    for (uint32_t function : roots)
      createContext(makeKey(function, NONE, NONE));

    std::unordered_map<uint32_t, std::vector<uint32_t>> outgoingSites;
    struct ContextTransition {
      uint32_t siteIndex;
      uint32_t callerContext;
      uint32_t calleeContext;
    };
    std::vector<ContextTransition> transitions;
    std::vector<uint32_t> deferredBaselineSites;
    for (uint32_t siteIndex : pointerFlowSites) {
      const DirectSite &site = directSites[siteIndex];
      outgoingSites[site.callerFunction].push_back(siteIndex);
      deferredBaselineSites.push_back(siteIndex);
    }

    size_t nextContextIndex = 0;
    auto expandContextTransitions = [&]() {
      while (nextContextIndex < contexts.size()) {
        size_t contextIndex = nextContextIndex++;
        const Context caller = contexts[contextIndex];
        auto found = outgoingSites.find(caller.function);
        if (found == outgoingSites.end())
          continue;
        for (uint32_t siteIndex : found->second) {
          const DirectSite &site = directSites[siteIndex];
          ContextKey key = makeKey(site.calleeFunction,
                                   static_cast<uint32_t>(contextIndex), siteIndex);
          if (key.refinementToken != NONE)
            ++counts.refinedContextTransitions;
          uint32_t calleeContext = createContext(key);
          if (siteIndex < siteContextId.size())
            siteContextId[siteIndex] = calleeContext;
          transitions.push_back(
              {siteIndex, static_cast<uint32_t>(contextIndex), calleeContext});
        }
      }
    };
    expandContextTransitions();

    // A selected callsite disables its baseline CALL_ARGUMENT/CALL_RETURN, so the caller's
    // baseline instance must still enter the contextual callee. But a caller whose baseline
    // instance can never carry pointer flow (every incoming edge is a selected callsite, and
    // it is neither a handler root, nor an address-taken indirect target, nor reached by an
    // unselected callsite) would only produce a redundant empty context. Skip those so the
    // baseline transition is created exactly when it can propagate real flow. This is a
    // conservative test: any ambiguity resolves to "live" so no baseline inflow is dropped.
    std::vector<uint8_t> hasSelectedIncoming(objects.size());
    std::vector<uint8_t> baselineInflow(objects.size());
    for (uint32_t function : handlerRootFunctions)
      if (function < baselineInflow.size())
        baselineInflow[function] = 1;
    for (uint32_t siteIndex = 0; siteIndex < directSites.size(); ++siteIndex) {
      const DirectSite &site = directSites[siteIndex];
      uint32_t callee = site.calleeFunction;
      if (callee == NONE || callee >= objects.size())
        continue;
      bool selected = siteIndex < contextualDirectSites.size() &&
                      contextualDirectSites[siteIndex];
      if (selected)
        hasSelectedIncoming[callee] = 1;
      else if (directSiteHasPointerFlow(site))
        baselineInflow[callee] = 1;
    }
    // Any address-taken function may be reached by an indirect call, which wires actuals into
    // its baseline formals at solve time; treat those as baseline-live conservatively.
    for (const AddressSeed &seed : addressSeeds) {
      if (seed.offset == 0 && seed.root < baselineInflow.size() &&
          objects.isFunction(seed.root))
        baselineInflow[seed.root] = 1;
    }
    auto baselineFunctionLive = [&](uint32_t function) {
      if (function == NONE || function >= objects.size())
        return true;
      if (!hasSelectedIncoming[function])
        return true;  // entry-like, or reached only by unselected/baseline edges
      return baselineInflow[function] != 0;
    };

    for (uint32_t siteIndex : deferredBaselineSites) {
      const DirectSite &site = directSites[siteIndex];
      if (!baselineFunctionLive(site.callerFunction)) {
        ++counts.baselineDeadCallerSites;
        continue;
      }
      uint32_t calleeContext = createContext(makeKey(site.calleeFunction, NONE, siteIndex));
      if (siteIndex < siteContextId.size())
        siteContextId[siteIndex] = calleeContext;
      transitions.push_back({siteIndex, NONE, calleeContext});
      ++counts.baselineCallerTransitions;
      expandContextTransitions();
    }

    auto contextualValue = [&](uint32_t contextId, uint32_t original) {
      if (contextId == NONE || original == NONE || original >= originalValueCount)
        return original;
      const Context &context = contexts[contextId];
      uint32_t owner = original < valueOwners.size() ? valueOwners[original] : NONE;
      if (owner == NONE)
        return original;
      if (owner != context.function || valueOrdinals[original] == NONE)
        return original;
      return context.baseValue + valueOrdinals[original];
    };

    auto contextualObject = [&](uint32_t contextId, uint32_t original) {
      if (contextId == NONE || objectMode != ContextObjectMode::Stack ||
          original >= objectOrdinals.size())
        return original;
      const Context &context = contexts[contextId];
      uint32_t owner = original < objectOwners.size() ? objectOwners[original] : NONE;
      if (owner != context.function || objectOrdinals[original] == NONE)
        return original;
      return context.baseObject + objectOrdinals[original];
    };

    struct FunctionConstraints {
      std::vector<uint32_t> addresses;
      std::vector<uint32_t> copies;
      std::vector<uint32_t> fields;
      std::vector<uint32_t> dynamics;
      std::vector<uint32_t> strideds;
      std::vector<uint32_t> loads;
      std::vector<uint32_t> stores;
      std::vector<uint32_t> storeObjects;
      std::vector<uint32_t> memoryCopies;
      std::vector<uint32_t> indirectSites;
    };
    std::unordered_map<uint32_t, FunctionConstraints> constraintsByFunction;

    auto ownerOf = [&](std::initializer_list<uint32_t> operands) {
      uint32_t owner = NONE;
      for (uint32_t operand : operands) {
        if (operand == NONE || operand >= originalValueCount)
          continue;
        uint32_t current = operand < valueOwners.size() ? valueOwners[operand] : NONE;
        if (current == NONE)
          continue;
        if (owner != NONE && owner != current)
          return NONE;
        owner = current;
      }
      return owner;
    };
    auto hasContextualValue = [&](std::initializer_list<uint32_t> operands) {
      return std::any_of(operands.begin(), operands.end(), [&](uint32_t operand) {
        return operand != NONE && operand < valueOrdinals.size() &&
               valueOrdinals[operand] != NONE;
      });
    };
    auto hasContextualObject = [&](uint32_t object) {
      return objectMode == ContextObjectMode::Stack &&
             object < objectOrdinals.size() && objectOrdinals[object] != NONE;
    };
    auto addOwned = [&](uint32_t owner, auto member, uint32_t index, bool contextual) {
      if (contextual && functionInScope(owner))
        (constraintsByFunction[owner].*member).push_back(index);
    };

    for (uint32_t index = 0; index < originalAddressCount; ++index) {
      const AddressSeed &constraint = addressSeeds[index];
      addOwned(ownerOf({constraint.dst}), &FunctionConstraints::addresses, index,
               hasContextualValue({constraint.dst}) ||
                   hasContextualObject(constraint.root));
    }
    for (uint32_t index = 0; index < originalCopyCount; ++index) {
      if (copies[index].rule == Rule::CallArgument ||
          copies[index].rule == Rule::CallReturn)
        continue;
      addOwned(ownerOf({copies[index].src, copies[index].dst}),
               &FunctionConstraints::copies, index,
               hasContextualValue({copies[index].src, copies[index].dst}));
    }
    for (uint32_t index = 0; index < originalFieldCount; ++index)
      addOwned(ownerOf({fields[index].src, fields[index].dst}),
               &FunctionConstraints::fields, index,
               hasContextualValue({fields[index].src, fields[index].dst}));
    for (uint32_t index = 0; index < originalDynamicCount; ++index)
      addOwned(ownerOf({dynamicFields[index].src, dynamicFields[index].dst}),
               &FunctionConstraints::dynamics, index,
               hasContextualValue(
                   {dynamicFields[index].src, dynamicFields[index].dst}));
    for (uint32_t index = 0; index < originalStridedCount; ++index)
      addOwned(ownerOf({stridedFields[index].src, stridedFields[index].dst}),
               &FunctionConstraints::strideds, index,
               hasContextualValue(
                   {stridedFields[index].src, stridedFields[index].dst}));
    for (uint32_t index = 0; index < originalLoadCount; ++index)
      addOwned(ownerOf({loads[index].first, loads[index].second}),
               &FunctionConstraints::loads, index,
               hasContextualValue({loads[index].first, loads[index].second}));
    for (uint32_t index = 0; index < originalStoreCount; ++index)
      addOwned(ownerOf({stores[index].first, stores[index].second}),
               &FunctionConstraints::stores, index,
               hasContextualValue({stores[index].first, stores[index].second}));
    for (uint32_t index = 0; index < originalStoreObjectCount; ++index) {
      const StoreObjectConstraint &constraint = storeObjects[index];
      uint32_t owner = ownerOf({constraint.src});
      if (owner == NONE && constraint.root < objectOwners.size())
        owner = objectOwners[constraint.root];
      addOwned(owner, &FunctionConstraints::storeObjects, index,
               hasContextualValue({constraint.src}) ||
                   hasContextualObject(constraint.root));
    }
    for (uint32_t index = 0; index < originalMemoryCopyCount; ++index)
      addOwned(ownerOf({memoryCopies[index].dst, memoryCopies[index].src}),
               &FunctionConstraints::memoryCopies, index,
               hasContextualValue(
                   {memoryCopies[index].dst, memoryCopies[index].src}));
    auto indirectSiteIsContextual = [&](const IndirectSite &site) {
      if (valueSlice == ContextValueSlice::All ||
          hasContextualValue({site.calleeValue, site.result}))
        return true;
      for (uint32_t offset = 0; offset < site.actualCount; ++offset) {
        if (hasContextualValue({indirectActuals[site.actualStart + offset].value}))
          return true;
      }
      return false;
    };
    for (uint32_t index = 0; index < originalIndirectSiteCount; ++index) {
      const IndirectSite &site = indirectSites[index];
      uint32_t owner = site.callerFunction;
      if (indirectSiteIsContextual(site) && functionInScope(owner))
        constraintsByFunction[owner].indirectSites.push_back(index);
    }

    for (uint32_t contextId = 0; contextId < contexts.size(); ++contextId) {
      const Context &context = contexts[contextId];
      auto found = constraintsByFunction.find(context.function);
      if (found == constraintsByFunction.end())
        continue;
      const FunctionConstraints &owned = found->second;
      for (uint32_t index : owned.addresses) {
        AddressSeed constraint = addressSeeds[index];
        constraint.dst = contextualValue(contextId, constraint.dst);
        constraint.root = contextualObject(contextId, constraint.root);
        addressSeeds.push_back(constraint);
        ++counts.materializedConstraints;
      }
      for (uint32_t index : owned.copies) {
        CopyConstraint constraint = copies[index];
        constraint.src = contextualValue(contextId, constraint.src);
        constraint.dst = contextualValue(contextId, constraint.dst);
        copies.push_back(constraint);
        ++counts.materializedConstraints;
      }
      for (uint32_t index : owned.fields) {
        FieldConstraint constraint = fields[index];
        constraint.src = contextualValue(contextId, constraint.src);
        constraint.dst = contextualValue(contextId, constraint.dst);
        fields.push_back(constraint);
        ++counts.materializedConstraints;
      }
      for (uint32_t index : owned.dynamics) {
        DynamicFieldConstraint constraint = dynamicFields[index];
        constraint.src = contextualValue(contextId, constraint.src);
        constraint.dst = contextualValue(contextId, constraint.dst);
        dynamicFields.push_back(constraint);
        ++counts.materializedConstraints;
      }
      for (uint32_t index : owned.strideds) {
        StridedFieldConstraint constraint = stridedFields[index];
        constraint.src = contextualValue(contextId, constraint.src);
        constraint.dst = contextualValue(contextId, constraint.dst);
        stridedFields.push_back(constraint);
        ++counts.materializedConstraints;
      }
      for (uint32_t index : owned.loads) {
        SimpleConstraint constraint = loads[index];
        constraint.first = contextualValue(contextId, constraint.first);
        constraint.second = contextualValue(contextId, constraint.second);
        loads.push_back(constraint);
        ++counts.materializedConstraints;
      }
      for (uint32_t index : owned.stores) {
        SimpleConstraint constraint = stores[index];
        constraint.first = contextualValue(contextId, constraint.first);
        constraint.second = contextualValue(contextId, constraint.second);
        stores.push_back(constraint);
        ++counts.materializedConstraints;
      }
      for (uint32_t index : owned.storeObjects) {
        StoreObjectConstraint constraint = storeObjects[index];
        constraint.root = contextualObject(contextId, constraint.root);
        constraint.src = contextualValue(contextId, constraint.src);
        storeObjects.push_back(constraint);
        ++counts.materializedConstraints;
      }
      for (uint32_t index : owned.memoryCopies) {
        MemoryCopyConstraint constraint = memoryCopies[index];
        constraint.dst = contextualValue(contextId, constraint.dst);
        constraint.src = contextualValue(contextId, constraint.src);
        memoryCopies.push_back(constraint);
        ++counts.materializedConstraints;
      }
      for (uint32_t index : owned.indirectSites) {
        const IndirectSite &original = indirectSites[index];
        uint32_t actualStart = static_cast<uint32_t>(indirectActuals.size());
        for (uint32_t offset = 0; offset < original.actualCount; ++offset) {
          Actual actual = indirectActuals[original.actualStart + offset];
          actual.value = contextualValue(contextId, actual.value);
          indirectActuals.push_back(actual);
        }
        indirectSites.push_back({original.callsiteName, original.callerFunction,
                                 contextId,
                                 contextualValue(contextId, original.calleeValue),
                                 actualStart, original.actualCount,
                                 contextualValue(contextId, original.result),
                                 original.source});
      }
    }

    auto wireDirectContext = [&](uint32_t siteIndex, uint32_t callerContext,
                                 uint32_t calleeContext) {
      // Discovery-mode deferral: an overflow direct context (a bounded-budget bucket that would
      // otherwise merge hundreds/thousands of a mega-fan-in utility callee's distinct actuals
      // into one formal) carries NO actual/return flow. Its site stays in contextualDirectSites
      // so the context-insensitive baseline is still disabled, so there is no broadcast at all
      // from these callsites. The callee body clone still exists (analyzed via its dedicated
      // contexts); this is the direct-call analog of deferring non-promoted indirect pairs.
      if (deferFlowSites && siteIndex < deferFlowSites->size() &&
          (*deferFlowSites)[siteIndex]) {
        // Honest accounting: this dropped a contextual transfer with no promotion/recovery, so
        // it is an under-approximation. The frontier's completion predicate requires this count
        // to reach zero, which only happens once selective refinement replaces the deferral.
        ++counts.deferredDirectTransfers;
        return;
      }
      const DirectSite &site = directSites[siteIndex];
      CallTransfer transfer{false, true, true, siteIndex, callerContext,
                            site.calleeFunction, calleeContext, site.actualCount,
                            0, site.source, {}, {}};
      auto found = functions.find(site.calleeFunction);
      if (found == functions.end()) {
        transfer.expectedReturns = site.result == NONE ? 0 : 1;
        contextCallTransfers.push_back(std::move(transfer));
        return;
      }
      const FunctionInfo &info = found->second;
      for (uint32_t offset = 0; offset < site.actualCount; ++offset) {
        const Actual &actual = directActuals[site.actualStart + offset];
        auto formal = std::find_if(info.formals.begin(), info.formals.end(),
                                   [&](const auto &item) {
                                     return item.first == actual.index;
                                   });
        if (formal == info.formals.end())
          continue;
        copies.push_back({contextualValue(callerContext, actual.value),
                          contextualValue(calleeContext, formal->second),
                          actual.source, Rule::CallArgument, site.callerFunction});
        transfer.args.push_back({contextualValue(callerContext, actual.value),
                                 contextualValue(calleeContext, formal->second),
                                 actual.index, actual.source});
        ++counts.materializedConstraints;
      }
      if (site.result != NONE) {
        transfer.expectedReturns = info.returns.empty()
                                       ? 1
                                       : static_cast<uint32_t>(info.returns.size());
        for (uint32_t returned : info.returns) {
          copies.push_back({contextualValue(calleeContext, returned),
                            contextualValue(callerContext, site.result),
                            site.source, Rule::CallReturn, site.callerFunction});
          transfer.returns.push_back({contextualValue(calleeContext, returned),
                                      contextualValue(callerContext, site.result),
                                      site.source});
          ++counts.materializedConstraints;
        }
      }
      contextCallTransfers.push_back(std::move(transfer));
    };

    for (const ContextTransition &transition : transitions)
      wireDirectContext(transition.siteIndex, transition.callerContext,
                        transition.calleeContext);

    contextInfo.clear();
    contextInfo.reserve(contexts.size());
    for (const Context &context : contexts)
      contextInfo.push_back({context.function, context.baseValue, context.valueCount});

    if (captureTransitions_) {
      capturedTransitions.clear();
      capturedTransitions.reserve(transitions.size());
      for (const ContextTransition &transition : transitions)
        capturedTransitions.push_back(
            {transition.siteIndex, transition.callerContext, transition.calleeContext});
    }
  }

  std::string renderValue(uint32_t valueId) const {
    std::string rendered(values.name(valueId));
    if (valueId < contextValueOrigins.size() && contextValueOrigins[valueId] != NONE) {
      rendered += '[';
      rendered += values.name(contextValueOrigins[valueId]);
      rendered += ']';
    }
    return rendered;
  }

  uint32_t objectSchemaVersion() const { return objectSchemaVersion_; }

  StringIds values{1 << 20};
  Objects objects;
  StringIds callsiteNames{1 << 16};
  StringIds rootNames{1 << 12};
  StringIds summaryKeys{1 << 12};
  StringIds handlerNames{1 << 16};
  AffineRegions affineRegions;
  std::vector<AddressSeed> addressSeeds;
  std::vector<CopyConstraint> copies;
  std::vector<FieldConstraint> fields;
  std::vector<DynamicFieldConstraint> dynamicFields;
  std::vector<StridedFieldConstraint> stridedFields;
  std::vector<SimpleConstraint> loads;
  std::vector<SimpleConstraint> stores;
  std::vector<StoreObjectConstraint> storeObjects;
  std::vector<MemoryCopyConstraint> memoryCopies;
  std::unordered_map<uint32_t, FunctionInfo> functions;
  std::vector<uint32_t> valueOwners;
  std::vector<uint32_t> contextValueOrigins;
  // Per materialized context: owning function and the [baseValue, baseValue+valueCount)
  // clone range. Lets a two-phase driver read each context's contextual formal points-to.
  struct ContextInfo {
    uint32_t function;
    uint32_t baseValue;
    uint32_t valueCount;
  };
  std::vector<ContextInfo> contextInfo;
  // Per direct site: the callee context it wires into (NONE if the site is not
  // contextualized). In signature/bootstrap mode every transition of a site shares one
  // callee context, so this is well defined.
  std::vector<uint32_t> siteContextId;
  // Optional capture of the materialized context transition graph (siteIndex, callerContext,
  // calleeContext) for the context-merge census. Only populated when captureTransitions_ is
  // set (the census-only mode); left empty on normal/discovery materialize so there is no cost.
  bool captureTransitions_ = false;
  std::vector<std::array<uint32_t, 3>> capturedTransitions;
  // P1 object-sensitivity: per function object id, the unique receiver arg index (NONE if the
  // function has 0 or >=2 receiver formals — the V1 unique-receiver gate), and the receiver
  // arity. Filled by computeReceiverFormals().
  std::vector<uint32_t> receiverFormalIndex;
  std::vector<uint32_t> receiverArity;
  // P1 object-sensitivity: interned (callee, receiver_formal_index, receiver_root) contexts.
  ObjectContexts objectContexts;
  // P1 object-sensitivity: call-free per-function copy-SCC templates. Component ordinals are
  // local to the owning function; stack-object ordinals are likewise local template ids.
  std::vector<ObjectFunctionTemplate> objectFunctionTemplates;
  std::vector<uint32_t> objectTemplateIndex;
  std::vector<uint32_t> templateComponentOrdinal;
  std::vector<uint32_t> templateStackObjectOrdinal;
  std::vector<uint32_t> objectOwners;
  std::vector<Actual> directActuals;
  std::vector<DirectSite> directSites;
  std::vector<uint8_t> contextualDirectSites;
  // Synthetic direct sites promoted from resolved indirect targets begin at this index;
  // they are always eligible for contextualization regardless of the --context-sites and
  // escape filters, since they are concrete resolved call targets. NONE means none exist.
  uint32_t syntheticDirectSiteStart = NONE;
  std::unordered_set<uint64_t> contextualizedIndirectPairs;
  std::vector<CallTransfer> contextCallTransfers;
  std::vector<Actual> indirectActuals;
  std::vector<IndirectSite> indirectSites;
  std::vector<std::pair<uint32_t, uint32_t>> directCallEdges;
  std::vector<RootSeed> rootSeeds;
  std::vector<NamedSummary> namedSummaries;
  std::unordered_set<uint32_t> handlerRootFunctions;
  std::unordered_set<uint32_t> handlerReachableFunctions;
  Counts counts;

 private:
  bool keepUnknown_;
  uint32_t objectSchemaVersion_ = 0;
  std::unordered_set<std::string> batches_;
};

enum class SolverNodeKind : uint8_t {
  BaselineValue,
  ContextValue,
  Memory,
};

// P2 object-sensitivity node namespace (design §4.4). Baseline values, dynamically-created
// context values, and memory cells share one append-only id space. No client may infer a node's
// kind or memory index from valueCount_ arithmetic once context nodes can be created mid-solve.
class SolverNodeArena {
 public:
  void resetBaseline(const std::vector<uint32_t> &origins,
                     const std::vector<uint8_t> &core) {
    kinds_.assign(origins.size(), SolverNodeKind::BaselineValue);
    payloads_ = origins;
    contexts_.assign(origins.size(), ObjectContexts::BASELINE);
    core_.resize(origins.size());
    for (uint32_t index = 0; index < origins.size(); ++index)
      core_[index] = index < core.size() && core[index];
  }

  uint32_t allocateMemory(uint32_t memoryIndex) {
    uint32_t node = size();
    kinds_.push_back(SolverNodeKind::Memory);
    payloads_.push_back(memoryIndex);
    contexts_.push_back(ObjectContexts::BASELINE);
    core_.push_back(0);
    return node;
  }

  uint32_t allocateContextBlock(uint32_t contextId,
                                const std::vector<uint32_t> &origins,
                                const std::vector<uint8_t> &core) {
    if (contextId == ObjectContexts::BASELINE)
      throw std::runtime_error("context node block cannot use baseline context id");
    uint32_t base = size();
    if (origins.size() > std::numeric_limits<uint32_t>::max() - base)
      throw std::runtime_error("solver node space exceeds 32-bit capacity");
    for (uint32_t index = 0; index < origins.size(); ++index) {
      kinds_.push_back(SolverNodeKind::ContextValue);
      payloads_.push_back(origins[index]);
      contexts_.push_back(contextId);
      core_.push_back(index < core.size() && core[index]);
    }
    return base;
  }

  uint32_t size() const { return static_cast<uint32_t>(kinds_.size()); }
  SolverNodeKind kind(uint32_t node) const { return kinds_[node]; }
  bool isValue(uint32_t node) const { return kind(node) != SolverNodeKind::Memory; }
  bool isMemory(uint32_t node) const { return kind(node) == SolverNodeKind::Memory; }
  bool core(uint32_t node) const { return core_[node] != 0; }
  uint32_t context(uint32_t node) const { return contexts_[node]; }
  uint32_t origin(uint32_t node) const {
    return isValue(node) ? payloads_[node] : NONE;
  }
  uint32_t memoryIndex(uint32_t node) const {
    return isMemory(node) ? payloads_[node] : NONE;
  }

 private:
  std::vector<SolverNodeKind> kinds_;
  std::vector<uint32_t> payloads_;
  std::vector<uint32_t> contexts_;
  std::vector<uint8_t> core_;
};

struct MaterializedTemplateCopyEdge {
  uint32_t src;
  uint32_t dst;
  uint64_t source;
};

// P1 object-sensitivity node identity (design §4.2/§4.3). This allocates one contiguous node
// range for each already-interned ObjectContext and records the parallel nodeContext/origin
// arrays. P1 uses eager materialization only in synthetic selftests; P2 will invoke the same
// mapping from receiver watches during the solver fixpoint.
class ObjectContextNodes {
 public:
  struct Range {
    uint32_t function = NONE;
    uint32_t base = NONE;
    uint32_t count = 0;
  };

  void reset() {
    ranges_.clear();
    copyEdges_.clear();
  }

  bool materialize(const Database &database, uint32_t contextId,
                   SolverNodeArena &nodeArena,
                   const std::vector<uint8_t> &coreValues) {
    if (contextId == ObjectContexts::BASELINE || contextId >= database.objectContexts.size())
      return false;
    if (ranges_.size() <= contextId)
      ranges_.resize(contextId + 1);
    if (ranges_[contextId].base != NONE)
      return false;

    const ObjectContextKey &key = database.objectContexts.key(contextId);
    const ObjectFunctionTemplate *functionTemplate = database.objectTemplate(key.callee);
    if (!functionTemplate)
      throw std::runtime_error("object context has no unique-receiver function template");
    uint32_t count = static_cast<uint32_t>(functionTemplate->componentRepresentatives.size());
    std::vector<uint8_t> componentCore(count);
    for (uint32_t ordinal = 0; ordinal < count; ++ordinal) {
      uint32_t origin = functionTemplate->componentRepresentatives[ordinal];
      componentCore[ordinal] = origin < coreValues.size() && coreValues[origin];
    }
    uint32_t base = nodeArena.allocateContextBlock(
        contextId, functionTemplate->componentRepresentatives, componentCore);
    ranges_[contextId] = {key.callee, base, count};
    for (const TemplateCopyEdge &edge : functionTemplate->copyEdges)
      copyEdges_.push_back({base + edge.srcComponent, base + edge.dstComponent, edge.source});
    return true;
  }

  uint32_t nodeForValue(const Database &database, uint32_t contextId, uint32_t valueId,
                        uint32_t baselineNode) const {
    if (contextId == ObjectContexts::BASELINE || contextId >= ranges_.size())
      return baselineNode;
    const Range &range = ranges_[contextId];
    if (range.base == NONE || contextId >= database.objectContexts.size())
      return baselineNode;
    uint32_t owner = valueId < database.valueOwners.size() ? database.valueOwners[valueId] : NONE;
    if (owner != range.function)
      return baselineNode;
    uint32_t ordinal = database.objectTemplateComponent(valueId);
    if (ordinal == NONE || ordinal >= range.count)
      return baselineNode;
    return range.base + ordinal;
  }

  const Range *range(uint32_t contextId) const {
    return contextId < ranges_.size() && ranges_[contextId].base != NONE
               ? &ranges_[contextId]
               : nullptr;
  }

  const std::vector<MaterializedTemplateCopyEdge> &copyEdges() const { return copyEdges_; }

 private:
  std::vector<Range> ranges_;
  std::vector<MaterializedTemplateCopyEdge> copyEdges_;
};

struct CopyEdge { uint32_t dst, next; uint64_t source; Rule rule; };
struct FieldEdge {
  uint32_t dst, next;
  int64_t offset;
  uint64_t source;
  uint32_t structType;
  bool cycleRootDynamic;
  bool cycleAffine;
};
struct StridedEdge {
  uint32_t dst, next;
  int64_t base, stride;
  uint64_t count, source;
  uint32_t structType;
  bool cycleRootDynamic;
  bool cycleAffine;
};
struct SimpleEdge { uint32_t value, next; uint64_t source; };
struct TypedSimpleEdge {
  uint32_t value, next;
  uint64_t source;
  uint32_t structType;
};
struct WatchEdge { uint32_t index, next; };
struct TransferPair { ObjKey dst, src; uint64_t size, source; uint32_t nextByRoot; };
struct FieldTypeDrop {
  uint32_t predecessor;
  uint32_t root;
  uint32_t structType;
  uint64_t source;
  Rule rule;
};
struct FieldCycleRecord {
  uint32_t src;
  uint32_t dst;
  int64_t base;
  int64_t stride;
  uint64_t count;
  uint64_t source;
  Rule rule;
  FieldCyclePolicy action;
};
struct AffineClipRecord {
  uint32_t root;
  int64_t inputBase;
  int64_t stride;
  int64_t inputBound;
  int64_t offset;
  int64_t outputBase;
  int64_t outputBound;
  uint64_t source;

  bool operator<(const AffineClipRecord &other) const {
    return std::tie(root, inputBase, stride, inputBound, offset, outputBase,
                    outputBound, source) <
           std::tie(other.root, other.inputBase, other.stride,
                    other.inputBound, other.offset, other.outputBase,
                    other.outputBound, other.source);
  }

  bool operator==(const AffineClipRecord &other) const {
    return std::tie(root, inputBase, stride, inputBound, offset, outputBase,
                    outputBound, source) ==
           std::tie(other.root, other.inputBase, other.stride,
                    other.inputBound, other.offset, other.outputBase,
                    other.outputBound, other.source);
  }
};

struct Tuple {
  uint32_t node;
  ObjKey object;
  uint32_t next;
  uint32_t predecessor;
  uint64_t source;
  Rule rule;
};

class TupleIndex {
 public:
  explicit TupleIndex(std::vector<Tuple> &tuples) : tuples_(tuples) { slots_.resize(1 << 20); }

  std::optional<uint32_t> find(uint32_t node, ObjKey object) const {
    uint64_t hash = tupleHash(node, object);
    size_t mask = slots_.size() - 1;
    size_t slot = hash & mask;
    while (slots_[slot].hash) {
      const Tuple &tuple = tuples_[slots_[slot].tuple];
      if (slots_[slot].hash == hash && tuple.node == node && tuple.object == object)
        return slots_[slot].tuple;
      slot = (slot + 1) & mask;
    }
    return std::nullopt;
  }

  void insert(uint32_t tuple) {
    if ((tuples_.size() + 1) * 10 >= slots_.size() * 7) {
      rehash(slots_.size() * 2);
      return;
    }
    const Tuple &entry = tuples_[tuple];
    uint64_t hash = tupleHash(entry.node, entry.object);
    size_t mask = slots_.size() - 1;
    size_t slot = hash & mask;
    while (slots_[slot].hash)
      slot = (slot + 1) & mask;
    slots_[slot] = {hash, tuple};
  }

 private:
  struct Slot { uint64_t hash = 0; uint32_t tuple = 0; };

  static uint64_t tupleHash(uint32_t node, ObjKey object) {
    uint64_t value = (static_cast<uint64_t>(node) << 32) ^ object.root;
    value ^= mix64(object.region);
    uint64_t hash = mix64(value ^ mix64(static_cast<uint64_t>(object.offset)));
    return hash ? hash : 1;
  }

  void rehash(size_t size) {
    slots_.assign(size, {});
    for (uint32_t index = 0; index < tuples_.size(); ++index) {
      const Tuple &entry = tuples_[index];
      uint64_t hash = tupleHash(entry.node, entry.object);
      size_t mask = slots_.size() - 1;
      size_t slot = hash & mask;
      while (slots_[slot].hash)
        slot = (slot + 1) & mask;
      slots_[slot] = {hash, index};
    }
  }

  std::vector<Tuple> &tuples_;
  std::vector<Slot> slots_;
};

struct SolverStats {
  uint64_t tuples = 0;
  uint64_t valueTuples = 0;
  uint64_t memoryTuples = 0;
  uint64_t workPops = 0;
  uint64_t pendingTuples = 0;
  uint64_t memoryCells = 0;
  uint64_t objectContextsMaterialized = 0;
  uint64_t objectContextValueNodes = 0;
  uint64_t objectContextStackObjects = 0;
  uint64_t objectContextConstraints = 0;
  uint64_t copyEdges = 0;
  uint64_t dynamicCopyEdges = 0;
  uint64_t duplicateCopyEdges = 0;
  uint64_t indirectTargets = 0;
  uint64_t contextualizedIndirectTargets = 0;
  uint64_t deferredIndirectPairs = 0;
  uint64_t affineMemoryNodeTuples = 0;      // tuples added at an affine memory-cell node
  uint64_t affineMemoryDerivedTuples = 0;   // tuples whose predecessor node is an affine cell
  uint64_t affineRegionsCanonicalized = 0;
  uint64_t locationRejectedOffsets = 0;
  uint64_t transferPairs = 0;
  uint64_t transferCells = 0;
  uint64_t dynamicAliasEdges = 0;
  uint64_t saturatedOffsets = 0;
  uint64_t droppedOffsets = 0;
  uint64_t rootDynamicEdges = 0;
  uint64_t unresolvedDynamicEdgesDropped = 0;
  uint64_t stridedEdgesActive = 0;
  uint64_t stridedEdgesDropped = 0;
  uint64_t stridedEdgesOverLimit = 0;
  uint64_t stridedOffsetsAdded = 0;
  uint64_t stridedOffsetArithmeticDropped = 0;
  uint64_t typedFieldApplications = 0;
  uint64_t typedFieldCompatible = 0;
  uint64_t typedFieldUnknown = 0;
  uint64_t typedFieldIncompatible = 0;
  uint64_t typedFieldDropped = 0;
  uint64_t fieldCycleEdges = 0;
  uint64_t fieldCycleEdgesRootDynamic = 0;
  uint64_t fieldCycleEdgesAffine = 0;
  uint64_t fieldCycleEdgesDropped = 0;
  uint64_t affineRegionApplications = 0;
  uint64_t affineRegionsCreated = 0;
  uint64_t affineRegionFallbackDynamic = 0;
  uint64_t affineRegionClips = 0;
  uint64_t affineAliasEdges = 0;
  uint64_t fieldTypeDropSamples = 0;
  bool fieldTypeDropSamplesTruncated = false;
  uint64_t rootsReachingHandler = 0;
  uint64_t copySccComponents = 0;
  uint64_t copySccCollapsedValues = 0;
  uint64_t copySccMaxSize = 0;
  uint64_t liveValues = 0;
  uint64_t liveComponents = 0;
  uint64_t coreValues = 0;
  uint64_t coreComponents = 0;
  uint64_t demandRounds = 0;
  uint64_t demandedStoreSources = 0;
  uint64_t demandedIndirectValues = 0;
  uint64_t demandedMemoryCells = 0;
  uint64_t nullPropagationsDropped = 0;
  uint64_t functionDereferencesDropped = 0;
  uint64_t storeOnlyTuplesDropped = 0;
  bool truncated = false;
  double loadSeconds = 0;
  double solveSeconds = 0;
};

class Solver {
 public:
  Solver(Database &database, FieldDynamicPolicy fieldDynamicPolicy,
         FieldTypePolicy fieldTypePolicy, FieldCyclePolicy fieldCyclePolicy,
         uint64_t maxStridedExpansion,
         OffsetPolicy offsetPolicy, bool useCopyScc,
         bool usePointerSinkSlice, CallFlowMode callFlowMode,
         const std::vector<uint8_t> *forcedValues,
         const std::unordered_set<ObjKey, ObjKeyHash> *initialDemandedCells,
         uint64_t maxTuples,
         DynamicAliasPolicy dynamicAliasPolicy = DynamicAliasPolicy::None,
         bool demandForcedOnly = false,
         AffineCanonPolicy affineCanonPolicy = AffineCanonPolicy::None,
         FieldLocationPolicy fieldLocationPolicy = FieldLocationPolicy::RootWide,
         bool discoveryMode = false, bool affineMemoryCensus = false)
      : db_(database), fieldDynamicPolicy_(fieldDynamicPolicy),
        fieldTypePolicy_(fieldTypePolicy),
        fieldCyclePolicy_(fieldCyclePolicy),
        dynamicAliasPolicy_(dynamicAliasPolicy),
        affineCanonPolicy_(affineCanonPolicy),
        fieldLocationPolicy_(fieldLocationPolicy),
        maxStridedExpansion_(maxStridedExpansion), offsetPolicy_(offsetPolicy),
        callFlowMode_(callFlowMode), maxTuples_(maxTuples),
        usePointerSinkSlice_(usePointerSinkSlice), demandForcedOnly_(demandForcedOnly),
        discoveryMode_(discoveryMode), affineMemoryCensus_(affineMemoryCensus),
        originalValueCount_(static_cast<uint32_t>(database.values.size())), tupleIndex_(tuples_) {
    buildValueLiveness(usePointerSinkSlice, forcedValues);
    buildValueClasses(useCopyScc);
    liveComponents_.assign(valueCount_, false);
    coreComponents_.assign(valueCount_, false);
    for (uint32_t value = 0; value < originalValueCount_; ++value) {
      if (liveValues_[value])
        liveComponents_[valueNode(value)] = true;
      if (coreValues_[value])
        coreComponents_[valueNode(value)] = true;
    }
    stats.liveComponents = std::count(liveComponents_.begin(), liveComponents_.end(), true);
    stats.coreComponents = std::count(coreComponents_.begin(), coreComponents_.end(), true);
    if (!demandForcedOnly_)
      for (const RootSeed &seed : db_.rootSeeds)
        demandedRoots_.insert(seed.dispatchObject);
    if (initialDemandedCells) {
      demandedCells_ = *initialDemandedCells;
      for (ObjKey cell : demandedCells_)
        demandedCellRoots_.insert(cell.root);
    }
    nodeArena_.resetBaseline(componentRepresentatives_, coreComponents_);
    resizeNodes(nodeArena_.size());
    memHeadByRoot_.assign(db_.objects.size(), NONE);
    transferHeadByRoot_.assign(db_.objects.size(), NONE);
  }

  void build() {
    for (const CopyConstraint &constraint : db_.copies) {
      if (!callConstraintEnabled(constraint))
        continue;
      if (!liveValues_[constraint.dst])
        continue;
      addCopyEdge(valueNode(constraint.src), valueNode(constraint.dst), constraint.rule,
                  constraint.source, false);
    }
    for (const FieldConstraint &constraint : db_.fields) {
      if (!liveValues_[constraint.dst])
        continue;
      installFieldEdge(valueNode(constraint.src), valueNode(constraint.dst),
                       constraint.offset, constraint.source, constraint.structType);
    }
    for (const DynamicFieldConstraint &constraint : db_.dynamicFields) {
      if (!liveValues_[constraint.dst])
        continue;
      installDynamicFieldEdge(valueNode(constraint.src), valueNode(constraint.dst),
                              constraint.source, constraint.structType);
    }
    for (const StridedFieldConstraint &constraint : db_.stridedFields) {
      if (!liveValues_[constraint.dst])
        continue;
      installStridedFieldEdge(valueNode(constraint.src), valueNode(constraint.dst),
                              constraint.base, constraint.stride, constraint.count,
                              constraint.source, constraint.structType);
    }
    for (const SimpleConstraint &constraint : db_.loads) {
      if (!liveValues_[constraint.second])
        continue;
      installLoadEdge(valueNode(constraint.first), valueNode(constraint.second),
                      constraint.source);
    }
    for (const SimpleConstraint &constraint : db_.stores)
      installStoreEdge(valueNode(constraint.first), valueNode(constraint.second),
                       constraint.source);
    for (const StoreObjectConstraint &constraint : db_.storeObjects) {
      ObjKey object = field({constraint.root, 0}, constraint.offset,
                            constraint.source);
      if (object.root == NONE)
        continue;
      if (!demanded(object))
        continue;
      uint32_t cell = memoryNode(object);
      addCopyEdge(valueNode(constraint.src), cell, Rule::StoreObject, constraint.source, false);
    }
    for (uint32_t index = 0; index < db_.indirectSites.size(); ++index) {
      const IndirectSite &site = db_.indirectSites[index];
      installIndirectWatch(valueNode(site.calleeValue), index);
    }
    for (const MemoryCopyConstraint &copy : db_.memoryCopies)
      installMemoryCopy(valueNode(copy.dst), valueNode(copy.src), copy.size, copy.source);
    for (const AddressSeed &seed : db_.addressSeeds)
      if (liveValues_[seed.dst])
        addTuple(valueNode(seed.dst), {seed.root, seed.offset}, seed.rule, NONE, seed.source);
    for (const RootSeed &seed : db_.rootSeeds) {
      uint32_t rootTuple = addTuple(valueNode(seed.rootValue), {seed.rootObject, 0},
                                    Rule::ObjectSeed, NONE, seed.source);
      uint32_t installCell = memoryNode({seed.rootObject, INSTALL_OFFSET});
      addTuple(installCell, {seed.dispatchObject, 0}, Rule::Install, rootTuple, seed.source);
    }
  }

  void solve() {
    auto started = std::chrono::steady_clock::now();
    build();
    drainWorklist();
    auto ended = std::chrono::steady_clock::now();
    stats.solveSeconds = std::chrono::duration<double>(ended - started).count();
    stats.tuples = tuples_.size();
    stats.pendingTuples = work_.size() - stats.workPops;
    stats.memoryCells = memoryKeys_.size();
    for (const Tuple &tuple : tuples_)
      if (nodeArena_.isMemory(tuple.node))
        ++stats.memoryTuples;
      else
        ++stats.valueTuples;
    countRootHandlers();
  }

  uint64_t addDemandedStoreSources(std::vector<uint8_t> &forcedValues) const {
    uint64_t added = 0;
    auto demandSource = [&](uint32_t source) {
      if (liveValues_[source] || forcedValues[source])
        return;
      forcedValues[source] = true;
      ++added;
    };
    for (const SimpleConstraint &constraint : db_.stores) {
      uint32_t pointer = valueNode(constraint.first);
      for (uint32_t tuple = tupleHead_[pointer]; tuple != NONE; tuple = tuples_[tuple].next) {
        if (db_.objects.isFunction(tuples_[tuple].object.root))
          continue;
        if (!demanded(tuples_[tuple].object))
          continue;
        demandSource(constraint.second);
        break;
      }
    }
    for (const StoreObjectConstraint &constraint : db_.storeObjects) {
      ObjKey cell{constraint.root, constraint.offset};
      if (demanded(cell))
        demandSource(constraint.src);
    }
    return added;
  }

  uint64_t addDemandedIndirectValues(std::vector<uint8_t> &forcedValues) const {
    uint64_t added = 0;
    auto demandValue = [&](uint32_t value) {
      if (coreValues_[value] || forcedValues[value])
        return;
      forcedValues[value] = true;
      ++added;
    };
    for (const auto &[siteIndex, function] : indirectTargets_) {
      const IndirectSite &site = db_.indirectSites[siteIndex];
      if (!callerEnabled(site.callerFunction))
        continue;
      auto found = db_.functions.find(function);
      if (found == db_.functions.end())
        continue;
      const FunctionInfo &info = found->second;
      for (uint32_t offset = 0; offset < site.actualCount; ++offset) {
        const Actual &actual = db_.indirectActuals[site.actualStart + offset];
        auto formal = std::find_if(info.formals.begin(), info.formals.end(),
                                   [&](const auto &item) { return item.first == actual.index; });
        if (formal != info.formals.end() && coreValues_[formal->second])
          demandValue(actual.value);
      }
      if (site.result != NONE && coreValues_[site.result]) {
        for (uint32_t returned : info.returns)
          demandValue(returned);
      }
    }
    return added;
  }

  uint64_t mergeDemandedCells(
      std::unordered_set<ObjKey, ObjKeyHash> &demandedCells) const {
    uint64_t added = 0;
    for (ObjKey cell : demandedCells_)
      added += demandedCells.insert(cell).second;
    return added;
  }

  void writeHotspots(const fs::path &path, size_t limit = 32) const {
    std::vector<uint64_t> nodeCounts(tupleHead_.size());
    std::vector<uint64_t> rootCounts(db_.objects.size());
    std::vector<uint64_t> pendingNodeCounts(tupleHead_.size());
    std::vector<uint64_t> pendingRootCounts(db_.objects.size());
    std::vector<uint64_t> ruleCounts(static_cast<size_t>(Rule::AffineRegion) + 1);
    for (uint32_t tupleId = 0; tupleId < tuples_.size(); ++tupleId) {
      const Tuple &tuple = tuples_[tupleId];
      ++nodeCounts[tuple.node];
      ++rootCounts[tuple.object.root];
      ++ruleCounts[static_cast<size_t>(tuple.rule)];
      if (tupleId >= stats.workPops) {
        ++pendingNodeCounts[tuple.node];
        ++pendingRootCounts[tuple.object.root];
      }
    }

    auto top = [limit](const std::vector<uint64_t> &counts) {
      using Item = std::pair<uint64_t, uint32_t>;
      std::priority_queue<Item, std::vector<Item>, std::greater<Item>> heap;
      for (uint32_t id = 0; id < counts.size(); ++id) {
        if (!counts[id])
          continue;
        Item item{counts[id], id};
        if (heap.size() < limit) {
          heap.push(item);
        } else if (item > heap.top()) {
          heap.pop();
          heap.push(item);
        }
      }
      std::vector<Item> result;
      while (!heap.empty()) {
        result.push_back(heap.top());
        heap.pop();
      }
      std::sort(result.begin(), result.end(), std::greater<Item>());
      return result;
    };

    std::ofstream out(path);
    out << "#dimension\tcount\tid\tdetail\n";
    for (auto [count, node] : top(nodeCounts))
      out << "node\t" << count << '\t' << node << '\t' << renderNode(node) << '\n';
    for (auto [count, root] : top(rootCounts))
      out << "root\t" << count << '\t' << root << '\t' << db_.objects.name(root) << '\n';
    for (auto [count, node] : top(pendingNodeCounts))
      out << "pending_node\t" << count << '\t' << node << '\t' << renderNode(node) << '\n';
    for (auto [count, root] : top(pendingRootCounts))
      out << "pending_root\t" << count << '\t' << root << '\t' << db_.objects.name(root) << '\n';
    for (size_t rule = 0; rule < ruleCounts.size(); ++rule)
      out << "rule\t" << ruleCounts[rule] << '\t' << rule << '\t'
          << ruleName(static_cast<Rule>(rule)) << '\n';
  }

  void writeHotspotDerivations(const fs::path &path, size_t nodeLimit = 8,
                               size_t tuplesPerNode = 4, size_t depthLimit = 64) const {
    std::vector<uint64_t> nodeCounts(tupleHead_.size());
    std::vector<uint64_t> rootCounts(db_.objects.size());
    for (const Tuple &tuple : tuples_) {
      ++nodeCounts[tuple.node];
      ++rootCounts[tuple.object.root];
    }
    std::vector<uint32_t> nodes;
    for (uint32_t node = 0; node < nodeCounts.size(); ++node)
      if (nodeCounts[node])
        nodes.push_back(node);
    std::sort(nodes.begin(), nodes.end(), [&](uint32_t left, uint32_t right) {
      if (nodeCounts[left] != nodeCounts[right])
        return nodeCounts[left] > nodeCounts[right];
      return left < right;
    });
    if (nodes.size() > nodeLimit)
      nodes.resize(nodeLimit);

    std::ofstream out(path);
    out << "#chain\tstep\thot_node\thot_count\tnode\tobject\trule\tsource\n";
    uint32_t chain = 0;
    for (uint32_t node : nodes) {
      std::vector<uint32_t> candidates;
      for (uint32_t tuple = tupleHead_[node]; tuple != NONE; tuple = tuples_[tuple].next)
        candidates.push_back(tuple);
      std::sort(candidates.begin(), candidates.end(), [&](uint32_t left, uint32_t right) {
        uint32_t leftRoot = tuples_[left].object.root;
        uint32_t rightRoot = tuples_[right].object.root;
        if (rootCounts[leftRoot] != rootCounts[rightRoot])
          return rootCounts[leftRoot] > rootCounts[rightRoot];
        if (leftRoot != rightRoot)
          return leftRoot < rightRoot;
        if (tuples_[left].object.region != tuples_[right].object.region)
          return tuples_[left].object.region < tuples_[right].object.region;
        return tuples_[left].object.offset < tuples_[right].object.offset;
      });
      if (candidates.size() > tuplesPerNode)
        candidates.resize(tuplesPerNode);
      for (uint32_t tupleId : candidates) {
        uint32_t current = tupleId;
        for (size_t depth = 0; current != NONE && depth < depthLimit; ++depth) {
          const Tuple &tuple = tuples_[current];
          out << chain << '\t' << depth << '\t' << renderNode(node) << '\t'
              << nodeCounts[node] << '\t' << renderNode(tuple.node) << '\t'
              << renderObject(tuple.object) << '\t' << ruleName(tuple.rule) << '\t'
              << renderSource(tuple.source) << '\n';
          current = tuple.predecessor;
        }
        ++chain;
      }
    }
  }

  static uint64_t magnitude(int64_t value) {
    if (value >= 0)
      return static_cast<uint64_t>(value);
    return static_cast<uint64_t>(-(value + 1)) + 1;
  }

  static std::optional<int64_t> alignUp(__int128 value, __int128 residue,
                                        int64_t stride) {
    __int128 remainder = (residue - value) % stride;
    if (remainder < 0)
      remainder += stride;
    __int128 aligned = value + remainder;
    if (aligned < std::numeric_limits<int64_t>::min() ||
        aligned > std::numeric_limits<int64_t>::max())
      return std::nullopt;
    return static_cast<int64_t>(aligned);
  }

  static std::optional<int64_t> alignDown(__int128 value, __int128 residue,
                                          int64_t stride) {
    __int128 remainder = (value - residue) % stride;
    if (remainder < 0)
      remainder += stride;
    __int128 aligned = value - remainder;
    if (aligned < std::numeric_limits<int64_t>::min() ||
        aligned > std::numeric_limits<int64_t>::max())
      return std::nullopt;
    return static_cast<int64_t>(aligned);
  }

  ObjKey affineFallback(uint32_t root) {
    ++stats.affineRegionFallbackDynamic;
    return {root, DYN_OFFSET};
  }

  // Lowest legal root-relative byte offset. Under the subobject location policy a known-size
  // top-level object cannot be indexed before its own base, so the floor is 0; otherwise
  // (unknown/incomplete size, or root-wide policy) we keep the conservative -size floor.
  int64_t offsetLowerBound(uint32_t root, int64_t size) const {
    if (fieldLocationPolicy_ == FieldLocationPolicy::Subobject && size > 0)
      return 0;
    return -size;
  }

  ObjKey internAffine(uint32_t root, int64_t base, int64_t stride, int64_t bound) {
    if (stride <= 0 || base > bound)
      return {NONE, 0};
    int64_t censusInputBase = base, censusInputBound = bound;
    // Subsumption canonicalization: widen the region to the maximal progression of its
    // (root, stride, congruence) class over the object's full extent, so every region that
    // is subsumed by, or overlaps at the same congruence as, another collapses to a single
    // ObjKey (the tuple index then dedups them). Sound over-approximation; only widens.
    if (affineCanonPolicy_ == AffineCanonPolicy::Subsumption) {
      int64_t size = db_.objects.size(root);
      if (size > 0) {
        int64_t lower = offsetLowerBound(root, size);
        auto canonBase = alignUp(static_cast<__int128>(lower), base, stride);
        auto canonBound = alignDown(static_cast<__int128>(size) - 1, base, stride);
        if (canonBase && canonBound && *canonBase <= *canonBound &&
            (*canonBase != base || *canonBound != bound)) {
          ++stats.affineRegionsCanonicalized;
          base = *canonBase;
          bound = *canonBound;
        }
      }
    }
    if (base == bound)
      return {root, base};
    __int128 distance = static_cast<__int128>(bound) - base;
    if (distance % stride != 0)
      return affineFallback(root);
    size_t before = db_.affineRegions.size();
    uint32_t region = db_.affineRegions.intern(base, stride, bound);
    stats.affineRegionsCreated += db_.affineRegions.size() != before;
    ObjKey object = ObjKey::affine(root, region);
    usedAffineObjects_.insert(object);
    if (affineMemoryCensus_)
      affineCanonInputs_[object].insert({censusInputBase, censusInputBound});
    return object;
  }

  ObjKey affineCycle(ObjKey object, int64_t deltaBase, int64_t deltaStride,
                     uint64_t deltaCount) {
    ++stats.affineRegionApplications;
    if (object.offset == DYN_OFFSET || object.offset == INSTALL_OFFSET)
      return affineFallback(object.root);
    if (deltaCount == 0)
      return affineFallback(object.root);
    int64_t size = db_.objects.size(object.root);
    if (size <= 0)
      return affineFallback(object.root);

    int64_t inputBase = object.offset;
    int64_t inputBound = object.offset;
    uint64_t inputStride = 0;
    if (object.isAffine()) {
      const AffineRegion &region = db_.affineRegions.get(object.region);
      inputBase = region.base;
      inputBound = region.bound;
      inputStride = static_cast<uint64_t>(region.stride);
    }

    __int128 deltaLastWide = static_cast<__int128>(deltaBase) +
                             static_cast<__int128>(deltaStride) *
                                 static_cast<__int128>(deltaCount - 1);
    if (deltaLastWide < std::numeric_limits<int64_t>::min() ||
        deltaLastWide > std::numeric_limits<int64_t>::max())
      return affineFallback(object.root);
    int64_t deltaLast = static_cast<int64_t>(deltaLastWide);
    int64_t deltaMin = std::min(deltaBase, deltaLast);
    int64_t deltaMax = std::max(deltaBase, deltaLast);
    if (deltaMin == 0 && deltaMax == 0)
      return object;

    uint64_t generatorStride = magnitude(deltaBase);
    if (deltaCount > 1)
      generatorStride = std::gcd(generatorStride, magnitude(deltaStride));
    if (generatorStride == 0)
      return affineFallback(object.root);
    uint64_t combinedStride = inputStride == 0
                                  ? generatorStride
                                  : std::gcd(inputStride, generatorStride);
    if (combinedStride == 0 ||
        combinedStride > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
      return affineFallback(object.root);
    int64_t stride = static_cast<int64_t>(combinedStride);

    int64_t lower = offsetLowerBound(object.root, size);
    int64_t upper = size - 1;
    if (object.isAffine() && generatorStride % inputStride == 0) {
      const AffineRegion &region = db_.affineRegions.get(object.region);
      bool closedLower = deltaMin >= 0 ||
                         static_cast<__int128>(region.base) + deltaMax < lower;
      bool closedUpper = deltaMax <= 0 ||
                         static_cast<__int128>(region.bound) + deltaMin > upper;
      if (closedLower && closedUpper)
        return object;
    }

    __int128 firstMin = static_cast<__int128>(inputBase) + deltaMin;
    __int128 firstMax = static_cast<__int128>(inputBound) + deltaMax;
    __int128 rawMin = deltaMin < 0 ? lower : firstMin;
    __int128 rawMax = deltaMax > 0 ? upper : firstMax;
    rawMin = std::max(rawMin, static_cast<__int128>(lower));
    rawMax = std::min(rawMax, static_cast<__int128>(upper));
    if (rawMin > rawMax)
      return {NONE, 0};

    auto base = alignUp(rawMin, inputBase, stride);
    auto bound = alignDown(rawMax, inputBase, stride);
    if (!base || !bound || *base > *bound)
      return {NONE, 0};
    return internAffine(object.root, *base, stride, *bound);
  }

  ObjKey field(ObjKey object, int64_t offset, uint64_t source) {
    if (object.offset == DYN_OFFSET || object.offset == INSTALL_OFFSET)
      return {object.root, DYN_OFFSET};
    if (object.isAffine()) {
      const AffineRegion &region = db_.affineRegions.get(object.region);
      __int128 base = static_cast<__int128>(region.base) + offset;
      __int128 bound = static_cast<__int128>(region.bound) + offset;
      int64_t size = db_.objects.size(object.root);
      int64_t lower = offsetLowerBound(object.root, size);
      if (size > 0 && (base < static_cast<__int128>(lower) ||
                       bound >= static_cast<__int128>(size))) {
        if (offsetPolicy_ == OffsetPolicy::Dynamic)
          return affineFallback(object.root);
        if (offsetPolicy_ == OffsetPolicy::Drop) {
          __int128 clippedBase = std::max(base, static_cast<__int128>(lower));
          __int128 clippedBound = std::min(
              bound, static_cast<__int128>(size) - 1);
          auto alignedBase = alignUp(clippedBase, base, region.stride);
          auto alignedBound = alignDown(clippedBound, base, region.stride);
          ++stats.droppedOffsets;
          if (!alignedBase || !alignedBound || *alignedBase > *alignedBound)
            return {NONE, 0};
          ++stats.affineRegionClips;
          affineClips_.push_back({object.root, region.base, region.stride,
                                  region.bound, offset, *alignedBase,
                                  *alignedBound, source});
          return internAffine(object.root, *alignedBase, region.stride,
                              *alignedBound);
        }
      }
      if (base < std::numeric_limits<int64_t>::min() ||
          bound > std::numeric_limits<int64_t>::max()) {
        if (offsetPolicy_ == OffsetPolicy::Dynamic)
          return affineFallback(object.root);
        ++stats.droppedOffsets;
        return {NONE, 0};
      }
      int64_t shiftedBase = static_cast<int64_t>(base);
      int64_t shiftedBound = static_cast<int64_t>(bound);
      return internAffine(object.root, shiftedBase, region.stride, shiftedBound);
    }
    __int128 sum = static_cast<__int128>(object.offset) + offset;
    if (sum < std::numeric_limits<int64_t>::min() || sum > std::numeric_limits<int64_t>::max()) {
      if (offsetPolicy_ == OffsetPolicy::Dynamic) {
        ++stats.saturatedOffsets;
        return {object.root, DYN_OFFSET};
      }
      ++stats.droppedOffsets;
      return {NONE, 0};
    }
    int64_t result = static_cast<int64_t>(sum);
    int64_t size = db_.objects.size(object.root);
    int64_t lower = offsetLowerBound(object.root, size);
    if (size > 0 && (result >= size || result < lower)) {
      if (result < lower && lower == 0)
        ++stats.locationRejectedOffsets;
      if (offsetPolicy_ == OffsetPolicy::Dynamic) {
        ++stats.saturatedOffsets;
        return {object.root, DYN_OFFSET};
      }
      if (offsetPolicy_ == OffsetPolicy::Drop) {
        ++stats.droppedOffsets;
        return {NONE, 0};
      }
    }
    int64_t cap = size > 0 ? HARD_OFFSET_CAP : UNKNOWN_OFFSET_CAP;
    if (result < -cap || result > cap) {
      if (offsetPolicy_ == OffsetPolicy::Dynamic) {
        ++stats.saturatedOffsets;
        return {object.root, DYN_OFFSET};
      }
      ++stats.droppedOffsets;
      return {NONE, 0};
    }
    return {object.root, result};
  }

  std::string renderObject(ObjKey object) const {
    std::string out(db_.objects.name(object.root));
    out += '@';
    if (object.isAffine()) {
      const AffineRegion &region = db_.affineRegions.get(object.region);
      out += "AFF(" + std::to_string(region.base) + "," +
             std::to_string(region.stride) + "," +
             std::to_string(region.bound) + ")";
    } else if (object.offset == DYN_OFFSET) {
      out += "DYN";
    } else if (object.offset == INSTALL_OFFSET) {
      out += "INSTALL";
    } else {
      out += std::to_string(object.offset);
    }
    return out;
  }

  std::string renderNode(uint32_t node) const {
    if (nodeArena_.isMemory(node))
      return "MEM:" + renderObject(memoryKeys_[nodeArena_.memoryIndex(node)]);
    uint32_t origin = nodeArena_.origin(node);
    uint32_t context = nodeArena_.context(node);
    if (context == ObjectContexts::BASELINE)
      return db_.renderValue(origin);
    const ObjectContextKey &key = db_.objectContexts.key(context);
    std::string receiver = key.receiverRoot == SHARED_UNKNOWN_ROOT
                               ? "SHARED_UNKNOWN"
                               : std::string(db_.objects.name(key.receiverRoot));
    return "ctxObj:" + receiver + "[" + std::string(db_.objects.symbol(key.callee)) + ":" +
           std::string(db_.values.name(origin)) + "]";
  }

  void writeCopySccMembers(const fs::path &path) const {
    std::ofstream out(path);
    out << "#value\trepresentative\tcomponent_size\n";
    for (uint32_t value = 0; value < originalValueCount_; ++value) {
      uint32_t component = valueNode(value);
      if (componentSizes_[component] <= 1)
        continue;
      out << db_.values.name(value) << '\t'
          << db_.values.name(componentRepresentatives_[component]) << '\t'
          << componentSizes_[component] << '\n';
    }
  }

  void writeCallTransfers(const fs::path &out) const {
    std::ofstream transfers(out / "call_transfer_map.tsv");
    std::ofstream args(out / "call_arg_flows.tsv");
    std::ofstream returns(out / "call_return_flows.tsv");
    transfers << "#transfer_id\tkind\tcallsite\tcaller\tcaller_context\tcallee"
                 "\tcallee_context\tmode\tstatus\texpected_arg_flows"
                 "\temitted_arg_flows\texpected_return_flows"
                 "\temitted_return_flows\treason\tsource\n";
    args << "#transfer_id\tcallsite\tcaller_context\tactual\tcallee"
            "\tcallee_context\tformal\tindex\tsource\n";
    returns << "#transfer_id\tcallsite\tcaller_context\tcallee\tcallee_context"
               "\treturn_value\tresult_value\tsource\n";

    auto contextName = [](uint32_t context) {
      return context == NONE ? std::string("baseline")
                             : "ctx:" + std::to_string(context);
    };
    auto functionName = [&](uint32_t function) {
      return function == NONE ? std::string("-")
                              : std::string(db_.objects.name(function));
    };
    auto emitTransfer = [&](const CallTransfer &transfer) {
      if (transfer.expectedArgs == 0 && transfer.expectedReturns == 0)
        return;
      const bool direct = !transfer.indirect;
      const DirectSite *directSite =
          direct ? &db_.directSites[transfer.siteIndex] : nullptr;
      const IndirectSite *indirectSite =
          direct ? nullptr : &db_.indirectSites[transfer.siteIndex];
      uint32_t callsiteName = direct ? directSite->callsiteName
                                     : indirectSite->callsiteName;
      uint32_t callerFunction = direct ? directSite->callerFunction
                                       : indirectSite->callerFunction;
      std::string transferId = direct ? "direct:" : "indirect:";
      transferId += std::to_string(transfer.siteIndex);
      transferId += ':';
      transferId += contextName(transfer.callerContext);
      transferId += ':';
      transferId += contextName(transfer.calleeContext);
      if (transfer.indirect) {
        transferId += ':';
        transferId += std::to_string(transfer.calleeFunction);
      }

      std::vector<std::string> reasons;
      if (!transfer.flowEnabled)
        reasons.emplace_back("call_flow_disabled");
      if (transfer.args.size() < transfer.expectedArgs)
        reasons.emplace_back("missing_arg_flow:" +
                             std::to_string(transfer.expectedArgs - transfer.args.size()));
      if (transfer.returns.size() < transfer.expectedReturns)
        reasons.emplace_back(
            "missing_return_flow:" +
            std::to_string(transfer.expectedReturns - transfer.returns.size()));
      std::string reason = "-";
      if (!reasons.empty()) {
        reason.clear();
        for (size_t index = 0; index < reasons.size(); ++index) {
          if (index)
            reason += ',';
          reason += reasons[index];
        }
      }
      std::string callerContext = contextName(transfer.callerContext);
      std::string calleeContext = contextName(transfer.calleeContext);
      std::string callee = functionName(transfer.calleeFunction);
      std::string_view callsite = db_.callsiteNames.name(callsiteName);
      transfers << transferId << '\t' << (direct ? "direct" : "indirect") << '\t'
                << callsite << '\t' << functionName(callerFunction) << '\t'
                << callerContext << '\t' << callee << '\t' << calleeContext << '\t'
                << (transfer.contextual ? "contextual" : "context_insensitive") << '\t'
                << (reasons.empty() ? "active" : "unresolved") << '\t'
                << transfer.expectedArgs << '\t' << transfer.args.size() << '\t'
                << transfer.expectedReturns << '\t' << transfer.returns.size() << '\t'
                << reason << '\t' << renderSource(transfer.source) << '\n';
      for (const CallArgRelation &flow : transfer.args)
        args << transferId << '\t' << callsite << '\t' << callerContext << '\t'
             << db_.renderValue(flow.actual) << '\t' << callee << '\t'
             << calleeContext << '\t' << db_.renderValue(flow.formal) << '\t'
             << flow.index << '\t' << renderSource(flow.source) << '\n';
      for (const CallReturnRelation &flow : transfer.returns)
        returns << transferId << '\t' << callsite << '\t' << callerContext << '\t'
                << callee << '\t' << calleeContext << '\t'
                << db_.renderValue(flow.returned) << '\t'
                << db_.renderValue(flow.result) << '\t'
                << renderSource(flow.source) << '\n';
    };

    for (uint32_t siteIndex = 0; siteIndex < db_.directSites.size(); ++siteIndex) {
      const DirectSite &site = db_.directSites[siteIndex];
      if (site.actualCount == 0 && site.result == NONE)
        continue;
      // Selected direct sites are represented by contextual transfers emitted from
      // contextCallTransfers below; their context-insensitive baseline transfer was
      // disabled in callConstraintEnabled, so it must not be reported here.
      if (siteIndex < db_.contextualDirectSites.size() &&
          db_.contextualDirectSites[siteIndex])
        continue;
      bool flowEnabled = callerEnabled(site.callerFunction);
      CallTransfer transfer{false, false, flowEnabled, siteIndex, NONE,
                            site.calleeFunction, NONE, site.actualCount, 0,
                            site.source, {}, {}};
      auto found = db_.functions.find(site.calleeFunction);
      if (found != db_.functions.end()) {
        const FunctionInfo &info = found->second;
        for (uint32_t offset = 0; flowEnabled && offset < site.actualCount; ++offset) {
          const Actual &actual = db_.directActuals[site.actualStart + offset];
          auto formal = std::find_if(
              info.formals.begin(), info.formals.end(),
              [&](const auto &item) { return item.first == actual.index; });
          if (formal != info.formals.end())
            transfer.args.push_back(
                {actual.value, formal->second, actual.index, actual.source});
        }
        if (site.result != NONE) {
          transfer.expectedReturns = info.returns.empty()
                                         ? 1
                                         : static_cast<uint32_t>(info.returns.size());
          if (flowEnabled)
            for (uint32_t returned : info.returns)
              transfer.returns.push_back({returned, site.result, site.source});
        }
      } else if (site.result != NONE) {
        transfer.expectedReturns = 1;
      }
      emitTransfer(transfer);
    }

    std::vector<size_t> contextOrder(db_.contextCallTransfers.size());
    std::iota(contextOrder.begin(), contextOrder.end(), 0);
    std::sort(contextOrder.begin(), contextOrder.end(), [&](size_t left, size_t right) {
      const CallTransfer &a = db_.contextCallTransfers[left];
      const CallTransfer &b = db_.contextCallTransfers[right];
      return std::tie(a.siteIndex, a.callerContext, a.calleeContext) <
             std::tie(b.siteIndex, b.callerContext, b.calleeContext);
    });
    for (size_t index : contextOrder)
      emitTransfer(db_.contextCallTransfers[index]);

    std::vector<size_t> indirectOrder(indirectCallTransfers_.size());
    std::iota(indirectOrder.begin(), indirectOrder.end(), 0);
    std::sort(indirectOrder.begin(), indirectOrder.end(), [&](size_t left, size_t right) {
      const CallTransfer &a = indirectCallTransfers_[left];
      const CallTransfer &b = indirectCallTransfers_[right];
      return std::tie(a.siteIndex, a.callerContext, a.calleeFunction) <
             std::tie(b.siteIndex, b.callerContext, b.calleeFunction);
    });
    for (size_t index : indirectOrder)
      emitTransfer(indirectCallTransfers_[index]);
  }

  // Structural census of affine field-regions per root object, to quantify whether the
  // memory closure is dominated by overlapping/subsumed byte-region proliferation. A region
  // R2 is "subsumed" by R1 when every member of the progression R2 is also a member of R1
  // (R1.stride divides R2.stride, congruent bases, and R2 within R1's range). No object
  // names, struct types, or size thresholds are used.
  // Per affine memory cell: how many pre-canonical regions collapsed into it, how many distinct
  // objects were stored into / loaded from it (the merge cardinality), and sample provenance so
  // the GEP index can be inspected. Requires affineMemoryCensus_ (else the maps are empty).
  void writeAffineMemoryCensus(const fs::path &path, size_t topCells = 4000) const {
    struct Row {
      ObjKey cell;
      uint64_t regionCardinality;
      uint64_t canonFrom;
      uint64_t storeSites;
      uint64_t loadSites;
      uint64_t storeValues;
      uint64_t loadValues;
      uint64_t storeRoots;
      uint64_t memoryTuples;
      std::string provenance;
    };
    std::vector<Row> rows;
    for (uint32_t index = 0; index < memoryKeys_.size(); ++index) {
      ObjKey cell = memoryKeys_[index];
      // Cover ALL memory cells (concrete + affine). distinct_store_roots and memory_tuples come
      // straight from the cell's points-to, so a concrete-memory clique (a shared cell holding
      // thousands of distinct roots -> quadratic) is visible even without store instrumentation.
      uint64_t cardinality = 1;
      if (cell.isAffine()) {
        const AffineRegion &region = db_.affineRegions.get(cell.region);
        cardinality = static_cast<uint64_t>((region.bound - region.base) / region.stride + 1);
      } else if (cell.offset == DYN_OFFSET || cell.offset == INSTALL_OFFSET) {
        continue;  // dynamic/install pseudo-cells are not real array merges
      }
      uint32_t node = memoryNodeIds_[index];
      std::unordered_set<uint32_t> roots;
      uint64_t memoryTuples = 0;
      // Distinct store/load constraint sources come straight from the cell's tuples (each was
      // added by a Store/Load/MemoryCopy copy edge carrying its constraint source), so concrete
      // cells get provenance without any hot-path instrumentation.
      std::set<std::pair<Rule, uint64_t>> tupleSources;
      for (uint32_t tuple = tupleHead_[node]; tuple != NONE; tuple = tuples_[tuple].next) {
        ++memoryTuples;
        roots.insert(tuples_[tuple].object.root);
        if (tupleSources.size() < 6)
          tupleSources.insert({tuples_[tuple].rule, tuples_[tuple].source});
      }
      if (memoryTuples < 2)
        continue;  // only report cells that actually accumulate (keeps the file bounded)
      auto canonIt = affineCanonInputs_.find(cell);
      std::string provenance;
      size_t emitted = 0;
      for (const auto &[rule, source] : tupleSources) {
        if (emitted++ >= 4)
          break;
        provenance += (provenance.empty() ? "" : ";") + std::string(ruleName(rule)) + ":" +
                      renderSource(source);
      }
      auto storeIt = affineStoreInfo_.find(cell);
      auto loadIt = affineLoadInfo_.find(cell);
      rows.push_back(
          {cell, cardinality,
           canonIt == affineCanonInputs_.end() ? 0 : canonIt->second.size(),
           storeIt == affineStoreInfo_.end() ? 0 : storeIt->second.sources.size(),
           loadIt == affineLoadInfo_.end() ? 0 : loadIt->second.sources.size(),
           storeIt == affineStoreInfo_.end() ? 0 : storeIt->second.values.size(),
           loadIt == affineLoadInfo_.end() ? 0 : loadIt->second.values.size(),
           roots.size(), memoryTuples, provenance});
    }
    std::sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
      return a.memoryTuples > b.memoryTuples;
    });
    std::ofstream out(path);
    out << "#cell\tregion_cardinality\tcanonicalized_from_count\tstore_sites\tload_sites\t"
           "distinct_store_values\tdistinct_loaded_values\tdistinct_store_roots\t"
           "memory_tuples\tindex_provenance\n";
    uint64_t totalCells = rows.size();
    uint64_t widenedCells = 0, wideRootCells = 0, wideRootConcrete = 0;
    uint64_t maxStoreRoots = 0, maxConcreteRoots = 0;
    for (const Row &row : rows) {
      if (row.canonFrom > 1)
        ++widenedCells;
      maxStoreRoots = std::max(maxStoreRoots, row.storeRoots);
      if (!row.cell.isAffine())
        maxConcreteRoots = std::max(maxConcreteRoots, row.storeRoots);
      if (row.storeRoots >= 64) {
        ++wideRootCells;
        if (!row.cell.isAffine())
          ++wideRootConcrete;
      }
    }
    for (size_t index = 0; index < rows.size() && index < topCells; ++index) {
      const Row &row = rows[index];
      out << renderObject(row.cell) << '\t' << row.regionCardinality << '\t' << row.canonFrom
          << '\t' << row.storeSites << '\t' << row.loadSites << '\t' << row.storeValues << '\t'
          << row.loadValues << '\t' << row.storeRoots << '\t' << row.memoryTuples << '\t'
          << (row.provenance.empty() ? "-" : row.provenance) << '\n';
    }
    std::cerr << "[affine-memory-census] memory_cells=" << totalCells
              << " widened(canon_from>1)=" << widenedCells
              << " wide_root_cells(>=64)=" << wideRootCells
              << " (concrete=" << wideRootConcrete << ")"
              << " max_store_roots=" << maxStoreRoots
              << " max_concrete_roots=" << maxConcreteRoots
              << " affine_node_tuples=" << stats.affineMemoryNodeTuples
              << " affine_derived_tuples=" << stats.affineMemoryDerivedTuples
              << " total_tuples=" << stats.tuples << "\n";
  }

  void writeAffineRegionCensus(const fs::path &path, size_t topRoots = 300) const {
    std::unordered_map<uint32_t, std::vector<uint32_t>> regionsByRoot;
    for (const Tuple &tuple : tuples_) {
      if (!tuple.object.isAffine())
        continue;
      regionsByRoot[tuple.object.root].push_back(tuple.object.region);
    }
    auto maxMember = [](const AffineRegion &region) -> int64_t {
      if (region.stride <= 0 || region.bound < region.base)
        return region.base;
      return region.base + ((region.bound - region.base) / region.stride) * region.stride;
    };
    auto subsumes = [&](const AffineRegion &a, const AffineRegion &b) {
      // Does progression a contain every member of progression b?
      if (a.stride <= 0 || b.stride <= 0 || b.stride % a.stride != 0)
        return false;
      if ((((b.base - a.base) % a.stride) + a.stride) % a.stride != 0)
        return false;
      return b.base >= a.base && maxMember(b) <= maxMember(a);
    };
    struct Row {
      uint32_t root;
      uint64_t total, subsumed, retained;
      bool exact;
    };
    std::vector<Row> rows;
    uint64_t totalRegions = 0, totalSubsumed = 0, capped = 0;
    constexpr size_t kPairwiseCap = 6000;
    for (auto &[root, regionIds] : regionsByRoot) {
      std::sort(regionIds.begin(), regionIds.end());
      regionIds.erase(std::unique(regionIds.begin(), regionIds.end()), regionIds.end());
      uint64_t total = regionIds.size();
      totalRegions += total;
      uint64_t subsumed = 0;
      bool exact = total <= kPairwiseCap;
      if (exact) {
        for (size_t i = 0; i < regionIds.size(); ++i) {
          const AffineRegion &ri = db_.affineRegions.get(regionIds[i]);
          for (size_t j = 0; j < regionIds.size(); ++j) {
            if (i == j)
              continue;
            const AffineRegion &rj = db_.affineRegions.get(regionIds[j]);
            if (rj == ri ? j < i : subsumes(rj, ri)) {
              ++subsumed;
              break;
            }
          }
        }
        totalSubsumed += subsumed;
      } else {
        ++capped;
      }
      rows.push_back({root, total, subsumed, exact ? total - subsumed : 0, exact});
    }
    std::sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
      if (a.total != b.total)
        return a.total > b.total;
      return a.root < b.root;
    });
    std::ofstream out(path);
    out << "#root\ttotal_regions\tsubsumed_regions\tretained_regions\texact\n";
    out << "#aggregate\t" << totalRegions << '\t' << totalSubsumed << '\t'
        << (totalRegions - totalSubsumed) << "\tcapped_roots=" << capped << '\n';
    for (size_t index = 0; index < rows.size() && index < topRoots; ++index)
      out << db_.objects.name(rows[index].root) << '\t' << rows[index].total << '\t'
          << rows[index].subsumed << '\t' << rows[index].retained << '\t'
          << (rows[index].exact ? 1 : 0) << '\n';
  }

  void writeOutputs(const fs::path &out, bool writeTuples, bool writeDerivations) const {
    fs::create_directories(out);
    if (writeTuples) {
      std::ofstream points(out / "points_to.tsv");
      std::ofstream memory(out / "memory_points_to.tsv");
      points << "#value\tobject\n";
      memory << "#object\ttarget\n";
      for (const Tuple &tuple : tuples_) {
        if (!nodeArena_.isMemory(tuple.node))
          points << renderNode(tuple.node) << '\t' << renderObject(tuple.object) << '\n';
        else
          memory << renderObject(memoryKeys_[nodeArena_.memoryIndex(tuple.node)]) << '\t'
                 << renderObject(tuple.object) << '\n';
      }
    }
    std::ofstream calls(out / "indirect_call_targets.tsv");
    calls << "#callsite\tfunction_object\tfunction\n";
    std::vector<std::pair<uint32_t, uint32_t>> sortedTargets = indirectTargets_;
    std::sort(sortedTargets.begin(), sortedTargets.end());
    for (const auto &[site, function] : sortedTargets)
      calls << db_.callsiteNames.name(db_.indirectSites[site].callsiteName) << '\t'
            << db_.objects.name(function) << '\t' << db_.objects.symbol(function) << '\n';
    writeCallTransfers(out);

    std::ofstream applied(out / "applied_seeds.tsv");
    applied << "#root\troot_object\tdispatch_object\top_key\thandler\tsource\n";
    for (const RootSeed &seed : db_.rootSeeds) {
      bool wrote = false;
      for (const NamedSummary &summary : db_.namedSummaries) {
        if (summary.object != seed.dispatchObject)
          continue;
        applied << db_.rootNames.name(seed.rootName) << '\t' << db_.objects.name(seed.rootObject)
                << '\t' << db_.objects.name(seed.dispatchObject) << '\t'
                << db_.summaryKeys.name(summary.key) << '\t'
                << db_.handlerNames.name(summary.handler) << "\tapi_summary\n";
        wrote = true;
      }
      uint32_t head = memHeadByRoot_[seed.dispatchObject];
      for (uint32_t memoryIndex = head; memoryIndex != NONE; memoryIndex = memoryNextByRoot_[memoryIndex]) {
        ObjKey cell = memoryKeys_[memoryIndex];
        uint32_t node = memoryNodeIds_[memoryIndex];
        for (uint32_t tuple = tupleHead_[node]; tuple != NONE; tuple = tuples_[tuple].next) {
          ObjKey target = tuples_[tuple].object;
          if (target.isAffine() || target.offset != 0 ||
              !db_.objects.isFunction(target.root))
            continue;
          applied << db_.rootNames.name(seed.rootName) << '\t' << db_.objects.name(seed.rootObject)
                  << '\t' << db_.objects.name(seed.dispatchObject) << "\t@";
          if (cell.isAffine()) {
            const AffineRegion &region = db_.affineRegions.get(cell.region);
            applied << "AFF(" << region.base << ',' << region.stride << ','
                    << region.bound << ')';
          } else if (cell.offset == DYN_OFFSET) {
            applied << "DYN";
          } else {
            applied << cell.offset;
          }
          applied << '\t' << db_.objects.symbol(target.root) << "\tSTORE_OBJECT\n";
          wrote = true;
        }
      }
      if (!wrote)
        applied << db_.rootNames.name(seed.rootName) << '\t' << db_.objects.name(seed.rootObject)
                << '\t' << db_.objects.name(seed.dispatchObject) << "\t-\t-\tinstall-only\n";
    }

    std::ofstream derivations(out / "fixpoint_derivations.tsv");
    derivations << "#node\tobject\trule\tpredecessor_node\tpredecessor_object\tsource\n";
    if (writeDerivations) {
      for (const Tuple &tuple : tuples_) {
        derivations << renderNode(tuple.node) << '\t' << renderObject(tuple.object) << '\t'
                    << ruleName(tuple.rule) << '\t';
        if (tuple.predecessor == NONE) {
          derivations << "-\t-\t";
        } else {
          const Tuple &predecessor = tuples_[tuple.predecessor];
          derivations << renderNode(predecessor.node) << '\t'
                      << renderObject(predecessor.object) << '\t';
        }
        derivations << renderSource(tuple.source) << '\n';
      }
    }

    std::ofstream typeDrops(out / "field_type_drops.tsv");
    typeDrops << "#predecessor_node\tpredecessor_object\troot_object\trequired_struct"
                 "\trule\tsource\n";
    for (const FieldTypeDrop &drop : fieldTypeDrops_) {
      const Tuple &predecessor = tuples_[drop.predecessor];
      typeDrops << renderNode(predecessor.node) << '\t'
                << renderObject(predecessor.object) << '\t'
                << db_.objects.name(drop.root) << '\t'
                << db_.objects.structName(drop.structType) << '\t'
                << ruleName(drop.rule) << '\t' << renderSource(drop.source) << '\n';
    }

    std::ofstream fieldCycles(out / "field_cycle_edges.tsv");
    fieldCycles << "#source_node\tdestination_node\tbase\tstride\tcount\trule"
                   "\taction\tsource\n";
    for (const FieldCycleRecord &cycle : fieldCycles_)
      fieldCycles << renderNode(cycle.src) << '\t' << renderNode(cycle.dst) << '\t'
                  << cycle.base << '\t' << cycle.stride << '\t' << cycle.count << '\t'
                  << ruleName(cycle.rule) << '\t'
                  << fieldCyclePolicyName(cycle.action) << '\t'
                  << renderSource(cycle.source) << '\n';

    std::ofstream affineRegions(out / "affine_regions.tsv");
    affineRegions << "#region_id\troot_object\tbase\tstride\tbound\tcount\n";
    std::vector<ObjKey> regions(usedAffineObjects_.begin(), usedAffineObjects_.end());
    std::sort(regions.begin(), regions.end(), [](ObjKey left, ObjKey right) {
      if (left.root != right.root)
        return left.root < right.root;
      return left.region < right.region;
    });
    for (ObjKey object : regions) {
      const AffineRegion &region = db_.affineRegions.get(object.region);
      uint64_t count = static_cast<uint64_t>(
          (static_cast<__int128>(region.bound) - region.base) / region.stride + 1);
      affineRegions << object.region << '\t' << db_.objects.name(object.root) << '\t'
                    << region.base << '\t' << region.stride << '\t'
                    << region.bound << '\t' << count << '\n';
    }

    std::ofstream affineClips(out / "affine_region_clips.tsv");
    affineClips << "#root_object\tinput_base\tstride\tinput_bound\tfield_offset"
                   "\toutput_base\toutput_bound\tsource\tapplications\n";
    std::vector<AffineClipRecord> clips = affineClips_;
    std::sort(clips.begin(), clips.end());
    for (size_t index = 0; index < clips.size();) {
      size_t end = index + 1;
      while (end < clips.size() && clips[end] == clips[index])
        ++end;
      const AffineClipRecord &clip = clips[index];
      affineClips << db_.objects.name(clip.root) << '\t' << clip.inputBase << '\t'
                  << clip.stride << '\t' << clip.inputBound << '\t' << clip.offset
                  << '\t' << clip.outputBase << '\t' << clip.outputBound << '\t'
                  << renderSource(clip.source) << '\t' << end - index << '\n';
      index = end;
    }
  }

  SolverStats stats;

  // All resolved (indirect callsite, target function) pairs discovered this solve, regardless
  // of whether flow was wired. In discovery mode the non-promoted pairs are deferred (no
  // baseline broadcast) but still recorded here, so the frontier driver can accumulate the
  // monotone target set across rounds.
  const std::vector<std::pair<uint32_t, uint32_t>> &indirectTargets() const {
    return indirectTargets_;
  }
  const std::vector<std::pair<uint32_t, uint32_t>> &deferredIndirectPairs() const {
    return deferredIndirectPairs_;
  }

  bool containsValue(uint32_t value, ObjKey object) const {
    return tupleIndex_.find(valueNode(value), object).has_value();
  }

  bool containsAffineValue(uint32_t value, uint32_t root, int64_t base,
                           int64_t stride, int64_t bound) const {
    auto region = db_.affineRegions.find(base, stride, bound);
    return region && containsValue(value, ObjKey::affine(root, *region));
  }

  bool hasValueTuples(uint32_t value) const {
    return value < originalValueCount_ && tupleHead_[valueNode(value)] != NONE;
  }

  // Enumerates the points-to set of a value (used to build actual-set signatures from a
  // context-insensitive baseline). Yields each pointed-to ObjKey once per stored tuple.
  template <typename Fn>
  void forEachValueObject(uint32_t value, Fn &&fn) const {
    if (value >= originalValueCount_)
      return;
    uint32_t node = valueNode(value);
    for (uint32_t tuple = tupleHead_[node]; tuple != NONE; tuple = tuples_[tuple].next)
      fn(tuples_[tuple].object);
  }

  // Detection for selective value-context: the owning functions of any value whose points-to
  // set exceeds `threshold`. On a truncated solve these are exactly the value-merge points that
  // blew up (e.g. a device-model formal holding thousands of device objects). Reported in a
  // deterministic sorted vector so the value-context set grows deterministically across rounds.
  std::vector<uint32_t> valueMergeFunctions(uint64_t threshold) const {
    std::unordered_set<uint32_t> fns;
    for (uint32_t value = 0; value < originalValueCount_; ++value) {
      uint32_t node = valueNode(value);
      uint64_t count = 0;
      for (uint32_t tuple = tupleHead_[node]; tuple != NONE; tuple = tuples_[tuple].next)
        if (++count > threshold)
          break;
      if (count <= threshold)
        continue;
      uint32_t origin =
          (value < db_.contextValueOrigins.size() && db_.contextValueOrigins[value] != NONE)
              ? db_.contextValueOrigins[value]
              : value;
      uint32_t owner = origin < db_.valueOwners.size() ? db_.valueOwners[origin] : NONE;
      if (owner != NONE)
        fns.insert(owner);
    }
    std::vector<uint32_t> sorted(fns.begin(), fns.end());
    std::sort(sorted.begin(), sorted.end());
    return sorted;
  }

  bool containsMemory(ObjKey cell, ObjKey target) const {
    auto found = memoryNodes_.find(cell);
    return found != memoryNodes_.end() && tupleIndex_.find(found->second, target).has_value();
  }

  static bool incrementalInstallerSelftest();
  static bool contextBodyMaterializationSelftest();

 private:
  struct CopyState {
    uint64_t size = 0;
    uint64_t source = 0;
    std::vector<ObjKey> destinations, sources;
  };
  struct ContextStackRange {
    uint32_t start = NONE;
    uint32_t count = 0;
  };

  template <typename Apply>
  void replayNodeTuples(uint32_t node, Apply &&apply) {
    for (uint32_t tuple = tupleHead_[node]; tuple != NONE;) {
      uint32_t next = tuples_[tuple].next;
      apply(tuple);
      tuple = next;
    }
  }

  void applyFieldEdge(uint32_t edgeIndex, uint32_t tupleId) {
    const FieldEdge edge = fields_[edgeIndex];
    const Tuple tuple = tuples_[tupleId];
    if (db_.objects.isFunction(tuple.object.root)) {
      ++stats.functionDereferencesDropped;
      return;
    }
    if (!fieldTypeAllowed(tuple.object.root, edge.structType, tupleId,
                          edge.source, Rule::FieldAddress))
      return;
    ObjKey target;
    Rule rule = Rule::FieldAddress;
    if (edge.cycleRootDynamic) {
      target = {tuple.object.root, DYN_OFFSET};
    } else if (edge.cycleAffine) {
      target = affineCycle(tuple.object, edge.offset, 0, 1);
      rule = Rule::AffineRegion;
    } else {
      target = field(tuple.object, edge.offset, edge.source);
    }
    if (target.root != NONE)
      addTuple(edge.dst, target, rule, tupleId, edge.source);
  }

  void installFieldEdge(uint32_t src, uint32_t dst, int64_t offset,
                        uint64_t source, uint32_t structType) {
    bool cycleRootDynamic = false;
    bool cycleAffine = false;
    if (offset != 0 && isDirectFieldCycle(src, dst)) {
      ++stats.fieldCycleEdges;
      fieldCycles_.push_back({src, dst, offset, 0, 1, source,
                              Rule::FieldAddress, fieldCyclePolicy_});
      if (fieldCyclePolicy_ == FieldCyclePolicy::Drop) {
        ++stats.fieldCycleEdgesDropped;
        return;
      }
      if (fieldCyclePolicy_ == FieldCyclePolicy::RootDynamic) {
        ++stats.fieldCycleEdgesRootDynamic;
        cycleRootDynamic = true;
      }
      if (fieldCyclePolicy_ == FieldCyclePolicy::Affine) {
        ++stats.fieldCycleEdgesAffine;
        cycleAffine = true;
      }
    }
    uint32_t edge = static_cast<uint32_t>(fields_.size());
    fields_.push_back({dst, fieldHead_[src], offset, source, structType,
                       cycleRootDynamic, cycleAffine});
    fieldHead_[src] = edge;
    replayNodeTuples(src, [&](uint32_t tuple) { applyFieldEdge(edge, tuple); });
  }

  void applyDynamicFieldEdge(uint32_t edgeIndex, uint32_t tupleId) {
    const TypedSimpleEdge edge = dynamic_[edgeIndex];
    const Tuple tuple = tuples_[tupleId];
    if (db_.objects.isFunction(tuple.object.root)) {
      ++stats.functionDereferencesDropped;
      return;
    }
    if (!fieldTypeAllowed(tuple.object.root, edge.structType, tupleId,
                          edge.source, Rule::DynamicField))
      return;
    addTuple(edge.value, {tuple.object.root, DYN_OFFSET}, Rule::DynamicField,
             tupleId, edge.source);
  }

  void appendDynamicFieldEdge(uint32_t src, uint32_t dst, uint64_t source,
                              uint32_t structType) {
    uint32_t edge = static_cast<uint32_t>(dynamic_.size());
    dynamic_.push_back({dst, dynamicHead_[src], source, structType});
    dynamicHead_[src] = edge;
    replayNodeTuples(src, [&](uint32_t tuple) { applyDynamicFieldEdge(edge, tuple); });
  }

  void installDynamicFieldEdge(uint32_t src, uint32_t dst, uint64_t source,
                               uint32_t structType) {
    if (fieldDynamicPolicy_ != FieldDynamicPolicy::RootDynamic) {
      ++stats.unresolvedDynamicEdgesDropped;
      return;
    }
    appendDynamicFieldEdge(src, dst, source, structType);
    ++stats.rootDynamicEdges;
  }

  void applyStridedFieldEdge(uint32_t edgeIndex, uint32_t tupleId) {
    const StridedEdge edge = strided_[edgeIndex];
    const Tuple tuple = tuples_[tupleId];
    if (db_.objects.isFunction(tuple.object.root)) {
      ++stats.functionDereferencesDropped;
      return;
    }
    if (!fieldTypeAllowed(tuple.object.root, edge.structType, tupleId,
                          edge.source, Rule::StridedField))
      return;
    if (edge.cycleRootDynamic) {
      addTuple(edge.dst, {tuple.object.root, DYN_OFFSET}, Rule::StridedField,
               tupleId, edge.source);
      return;
    }
    if (edge.cycleAffine) {
      ObjKey target = affineCycle(tuple.object, edge.base, edge.stride, edge.count);
      if (target.root != NONE)
        addTuple(edge.dst, target, Rule::AffineRegion, tupleId, edge.source);
      return;
    }
    for (uint64_t index = 0; index < edge.count; ++index) {
      __int128 offset = static_cast<__int128>(edge.base) +
                        static_cast<__int128>(edge.stride) *
                            static_cast<__int128>(index);
      if (offset < std::numeric_limits<int64_t>::min() ||
          offset > std::numeric_limits<int64_t>::max()) {
        ++stats.stridedOffsetArithmeticDropped;
        continue;
      }
      ObjKey target = field(tuple.object, static_cast<int64_t>(offset), edge.source);
      if (target.root == NONE)
        continue;
      size_t before = tuples_.size();
      addTuple(edge.dst, target, Rule::StridedField, tupleId, edge.source);
      stats.stridedOffsetsAdded += tuples_.size() != before;
    }
  }

  void appendStridedFieldEdge(uint32_t src, uint32_t dst, int64_t base,
                              int64_t stride, uint64_t count, uint64_t source,
                              uint32_t structType, bool cycleRootDynamic,
                              bool cycleAffine) {
    uint32_t edge = static_cast<uint32_t>(strided_.size());
    strided_.push_back({dst, stridedHead_[src], base, stride, count, source,
                        structType, cycleRootDynamic, cycleAffine});
    stridedHead_[src] = edge;
    replayNodeTuples(src, [&](uint32_t tuple) { applyStridedFieldEdge(edge, tuple); });
  }

  void installStridedFieldEdge(uint32_t src, uint32_t dst, int64_t base,
                               int64_t stride, uint64_t count, uint64_t source,
                               uint32_t structType) {
    bool cycleRootDynamic = false;
    bool cycleAffine = false;
    if ((base != 0 || stride != 0) && isDirectFieldCycle(src, dst)) {
      ++stats.fieldCycleEdges;
      fieldCycles_.push_back({src, dst, base, stride, count, source,
                              Rule::StridedField, fieldCyclePolicy_});
      if (fieldCyclePolicy_ == FieldCyclePolicy::Drop) {
        ++stats.fieldCycleEdgesDropped;
        return;
      }
      if (fieldCyclePolicy_ == FieldCyclePolicy::RootDynamic) {
        ++stats.fieldCycleEdgesRootDynamic;
        cycleRootDynamic = true;
      }
      if (fieldCyclePolicy_ == FieldCyclePolicy::Affine) {
        ++stats.fieldCycleEdgesAffine;
        cycleAffine = true;
      }
    }
    if (cycleRootDynamic || cycleAffine) {
      appendStridedFieldEdge(src, dst, base, stride, count, source, structType,
                             cycleRootDynamic, cycleAffine);
      return;
    }
    if (fieldDynamicPolicy_ == FieldDynamicPolicy::RootDynamic) {
      appendDynamicFieldEdge(src, dst, source, structType);
      ++stats.rootDynamicEdges;
      return;
    }
    if (fieldDynamicPolicy_ == FieldDynamicPolicy::Strided) {
      if (count == 0 || count > maxStridedExpansion_) {
        ++stats.stridedEdgesOverLimit;
        return;
      }
      appendStridedFieldEdge(src, dst, base, stride, count, source, structType,
                             false, false);
      ++stats.stridedEdgesActive;
      return;
    }
    ++stats.stridedEdgesDropped;
  }

  void applyLoadEdge(uint32_t edgeIndex, uint32_t tupleId) {
    const SimpleEdge edge = loads_[edgeIndex];
    const Tuple tuple = tuples_[tupleId];
    if (db_.objects.isFunction(tuple.object.root)) {
      ++stats.functionDereferencesDropped;
      return;
    }
    demandedCells_.insert(tuple.object);
    demandedCellRoots_.insert(tuple.object.root);
    uint32_t cell = memoryNode(tuple.object);
    uint32_t memoryIndex = nodeArena_.memoryIndex(cell);
    activateDynamicRead(memoryIndex, edge.source);
    activateAffineRead(memoryIndex, edge.source);
    addCopyEdge(cell, edge.value, Rule::Load, edge.source, true);
    if (affineMemoryCensus_ && tuple.object.isAffine()) {
      auto &info = affineLoadInfo_[tuple.object];
      info.values.insert(edge.value);
      info.sources.insert(edge.source);
    }
  }

  void installLoadEdge(uint32_t pointer, uint32_t result, uint64_t source) {
    uint32_t edge = static_cast<uint32_t>(loads_.size());
    loads_.push_back({result, loadHead_[pointer], source});
    loadHead_[pointer] = edge;
    replayNodeTuples(pointer, [&](uint32_t tuple) { applyLoadEdge(edge, tuple); });
  }

  void applyStoreEdge(uint32_t edgeIndex, uint32_t tupleId) {
    const SimpleEdge edge = stores_[edgeIndex];
    const Tuple tuple = tuples_[tupleId];
    if (db_.objects.isFunction(tuple.object.root)) {
      ++stats.functionDereferencesDropped;
      return;
    }
    if (!demanded(tuple.object))
      return;
    uint32_t cell = memoryNode(tuple.object);
    uint32_t memoryIndex = nodeArena_.memoryIndex(cell);
    activateDynamicWrite(memoryIndex, edge.source);
    activateAffineWrite(memoryIndex, edge.source);
    addCopyEdge(edge.value, cell, Rule::Store, edge.source, true);
    if (affineMemoryCensus_ && tuple.object.isAffine()) {
      auto &info = affineStoreInfo_[tuple.object];
      info.values.insert(edge.value);
      info.sources.insert(edge.source);
    }
  }

  void installStoreEdge(uint32_t pointer, uint32_t value, uint64_t source) {
    uint32_t edge = static_cast<uint32_t>(stores_.size());
    stores_.push_back({value, storeHead_[pointer], source});
    storeHead_[pointer] = edge;
    replayNodeTuples(pointer, [&](uint32_t tuple) { applyStoreEdge(edge, tuple); });
  }

  void applyIndirectWatch(uint32_t watchIndex, uint32_t tupleId) {
    const WatchEdge watch = indirectWatches_[watchIndex];
    const Tuple tuple = tuples_[tupleId];
    if (!tuple.object.isAffine() && tuple.object.offset == 0 &&
        db_.objects.isFunction(tuple.object.root))
      wireIndirect(watch.index, tuple.object.root);
  }

  void installIndirectWatch(uint32_t calleeNode, uint32_t siteIndex) {
    uint32_t watch = static_cast<uint32_t>(indirectWatches_.size());
    indirectWatches_.push_back({siteIndex, indirectHead_[calleeNode]});
    indirectHead_[calleeNode] = watch;
    replayNodeTuples(calleeNode,
                     [&](uint32_t tuple) { applyIndirectWatch(watch, tuple); });
  }

  void applyMemoryCopyWatch(uint32_t stateIndex, uint32_t tupleId,
                            bool destination) {
    const Tuple tuple = tuples_[tupleId];
    if (db_.objects.isFunction(tuple.object.root)) {
      ++stats.functionDereferencesDropped;
      return;
    }
    addCopyEndpoint(stateIndex, tuple.object, destination);
  }

  uint32_t installMemoryCopy(uint32_t dstPointer, uint32_t srcPointer,
                             uint64_t size, uint64_t source) {
    uint32_t state = static_cast<uint32_t>(copyStates_.size());
    copyStates_.push_back({size, source, {}, {}});
    uint32_t dstWatch = static_cast<uint32_t>(memcpyDstWatches_.size());
    memcpyDstWatches_.push_back({state, memcpyDstHead_[dstPointer]});
    memcpyDstHead_[dstPointer] = dstWatch;
    replayNodeTuples(dstPointer, [&](uint32_t tuple) {
      applyMemoryCopyWatch(state, tuple, true);
    });
    uint32_t srcWatch = static_cast<uint32_t>(memcpySrcWatches_.size());
    memcpySrcWatches_.push_back({state, memcpySrcHead_[srcPointer]});
    memcpySrcHead_[srcPointer] = srcWatch;
    replayNodeTuples(srcPointer, [&](uint32_t tuple) {
      applyMemoryCopyWatch(state, tuple, false);
    });
    return state;
  }

  void processTuple(uint32_t tupleId) {
    const Tuple tuple = tuples_[tupleId];
    for (uint32_t edge = copyHead_[tuple.node]; edge != NONE;) {
      const CopyEdge current = copies_[edge];
      edge = current.next;
      addTuple(current.dst, tuple.object, current.rule, tupleId, current.source);
    }
    for (uint32_t edge = fieldHead_[tuple.node]; edge != NONE;) {
      uint32_t next = fields_[edge].next;
      applyFieldEdge(edge, tupleId);
      edge = next;
    }
    for (uint32_t edge = dynamicHead_[tuple.node]; edge != NONE;) {
      uint32_t next = dynamic_[edge].next;
      applyDynamicFieldEdge(edge, tupleId);
      edge = next;
    }
    for (uint32_t edge = stridedHead_[tuple.node]; edge != NONE;) {
      uint32_t next = strided_[edge].next;
      applyStridedFieldEdge(edge, tupleId);
      edge = next;
    }
    for (uint32_t edge = loadHead_[tuple.node]; edge != NONE;) {
      uint32_t next = loads_[edge].next;
      applyLoadEdge(edge, tupleId);
      edge = next;
    }
    for (uint32_t edge = storeHead_[tuple.node]; edge != NONE;) {
      uint32_t next = stores_[edge].next;
      applyStoreEdge(edge, tupleId);
      edge = next;
    }
    for (uint32_t edge = indirectHead_[tuple.node]; edge != NONE;) {
      uint32_t next = indirectWatches_[edge].next;
      applyIndirectWatch(edge, tupleId);
      edge = next;
    }
    for (uint32_t edge = memcpyDstHead_[tuple.node]; edge != NONE;) {
      const WatchEdge watch = memcpyDstWatches_[edge];
      edge = watch.next;
      applyMemoryCopyWatch(watch.index, tupleId, true);
    }
    for (uint32_t edge = memcpySrcHead_[tuple.node]; edge != NONE;) {
      const WatchEdge watch = memcpySrcWatches_[edge];
      edge = watch.next;
      applyMemoryCopyWatch(watch.index, tupleId, false);
    }
  }

  void drainWorklist() {
    while (stats.workPops < work_.size()) {
      if (maxTuples_ && tuples_.size() >= maxTuples_) {
        stats.truncated = true;
        return;
      }
      uint32_t tupleId = work_[stats.workPops++];
      processTuple(tupleId);
    }
  }

  void ensureRootCapacity() {
    if (memHeadByRoot_.size() < db_.objects.size())
      memHeadByRoot_.resize(db_.objects.size(), NONE);
    if (transferHeadByRoot_.size() < db_.objects.size())
      transferHeadByRoot_.resize(db_.objects.size(), NONE);
  }

  void materializeContextStackObjects(uint32_t contextId,
                                      const ObjectFunctionTemplate &functionTemplate) {
    if (contextStackRanges_.size() <= contextId)
      contextStackRanges_.resize(contextId + 1);
    ContextStackRange &range = contextStackRanges_[contextId];
    if (range.start != NONE)
      return;
    range.start = static_cast<uint32_t>(contextStackObjectIds_.size());
    range.count = static_cast<uint32_t>(functionTemplate.stackObjects.size());
    for (uint32_t ordinal = 0; ordinal < functionTemplate.stackObjects.size(); ++ordinal) {
      uint32_t original = functionTemplate.stackObjects[ordinal];
      std::string name = "objctx:" + std::to_string(contextId) + ":" +
                         std::to_string(ordinal);
      uint32_t clone = db_.objects.internLike(name, original);
      if (db_.objectOwners.size() < db_.objects.size())
        db_.objectOwners.resize(db_.objects.size(), NONE);
      db_.objectOwners[clone] = functionTemplate.function;
      contextStackObjectIds_.push_back(clone);
      ++stats.objectContextStackObjects;
    }
    ensureRootCapacity();
  }

  uint32_t contextValueNode(uint32_t contextId, uint32_t value) const {
    return objectContextNodes_.nodeForValue(db_, contextId, value, valueNode(value));
  }

  uint32_t contextObjectRoot(uint32_t contextId, uint32_t root) const {
    if (contextId == ObjectContexts::BASELINE ||
        root >= db_.templateStackObjectOrdinal.size() ||
        root >= db_.objectOwners.size() || contextId >= contextStackRanges_.size() ||
        contextId >= db_.objectContexts.size())
      return root;
    if (db_.objectOwners[root] != db_.objectContexts.key(contextId).callee)
      return root;
    uint32_t ordinal = db_.templateStackObjectOrdinal[root];
    const ContextStackRange &range = contextStackRanges_[contextId];
    if (ordinal == NONE || range.start == NONE || ordinal >= range.count)
      return root;
    return contextStackObjectIds_[range.start + ordinal];
  }

  bool instantiateObjectContext(uint32_t contextId) {
    if (!objectContextNodes_.materialize(db_, contextId, nodeArena_, coreValues_))
      return false;
    resizeNodes(nodeArena_.size());
    const ObjectContextKey &key = db_.objectContexts.key(contextId);
    const ObjectFunctionTemplate *functionTemplate = db_.objectTemplate(key.callee);
    const ObjectContextNodes::Range *range = objectContextNodes_.range(contextId);
    if (!functionTemplate || !range)
      throw std::runtime_error("materialized object context has no function template range");
    materializeContextStackObjects(contextId, *functionTemplate);
    ++stats.objectContextsMaterialized;
    stats.objectContextValueNodes += range->count;

    for (const TemplateCopyEdge &edge : functionTemplate->copyEdges) {
      uint32_t destinationOrigin =
          functionTemplate->componentRepresentatives[edge.dstComponent];
      if (destinationOrigin < liveValues_.size() && !liveValues_[destinationOrigin])
        continue;
      addCopyEdge(range->base + edge.srcComponent, range->base + edge.dstComponent,
                  Rule::Copy, edge.source, true);
      ++stats.objectContextConstraints;
    }
    for (uint32_t index : functionTemplate->fields) {
      const FieldConstraint &constraint = db_.fields[index];
      if (constraint.dst < liveValues_.size() && liveValues_[constraint.dst]) {
        installFieldEdge(contextValueNode(contextId, constraint.src),
                         contextValueNode(contextId, constraint.dst), constraint.offset,
                         constraint.source, constraint.structType);
        ++stats.objectContextConstraints;
      }
    }
    for (uint32_t index : functionTemplate->dynamicFields) {
      const DynamicFieldConstraint &constraint = db_.dynamicFields[index];
      if (constraint.dst < liveValues_.size() && liveValues_[constraint.dst]) {
        installDynamicFieldEdge(contextValueNode(contextId, constraint.src),
                                contextValueNode(contextId, constraint.dst),
                                constraint.source, constraint.structType);
        ++stats.objectContextConstraints;
      }
    }
    for (uint32_t index : functionTemplate->stridedFields) {
      const StridedFieldConstraint &constraint = db_.stridedFields[index];
      if (constraint.dst < liveValues_.size() && liveValues_[constraint.dst]) {
        installStridedFieldEdge(contextValueNode(contextId, constraint.src),
                                contextValueNode(contextId, constraint.dst), constraint.base,
                                constraint.stride, constraint.count, constraint.source,
                                constraint.structType);
        ++stats.objectContextConstraints;
      }
    }
    for (uint32_t index : functionTemplate->loads) {
      const SimpleConstraint &constraint = db_.loads[index];
      if (constraint.second < liveValues_.size() && liveValues_[constraint.second]) {
        installLoadEdge(contextValueNode(contextId, constraint.first),
                        contextValueNode(contextId, constraint.second), constraint.source);
        ++stats.objectContextConstraints;
      }
    }
    for (uint32_t index : functionTemplate->stores) {
      const SimpleConstraint &constraint = db_.stores[index];
      installStoreEdge(contextValueNode(contextId, constraint.first),
                       contextValueNode(contextId, constraint.second), constraint.source);
      ++stats.objectContextConstraints;
    }
    for (uint32_t index : functionTemplate->storeObjects) {
      const StoreObjectConstraint &constraint = db_.storeObjects[index];
      uint32_t root = contextObjectRoot(contextId, constraint.root);
      ObjKey object = field({root, 0}, constraint.offset, constraint.source);
      if (object.root == NONE || !demanded(object))
        continue;
      uint32_t cell = memoryNode(object);
      addCopyEdge(contextValueNode(contextId, constraint.src), cell,
                  Rule::StoreObject, constraint.source, true);
      ++stats.objectContextConstraints;
    }
    for (uint32_t index : functionTemplate->memoryCopies) {
      const MemoryCopyConstraint &constraint = db_.memoryCopies[index];
      installMemoryCopy(contextValueNode(contextId, constraint.dst),
                        contextValueNode(contextId, constraint.src), constraint.size,
                        constraint.source);
      ++stats.objectContextConstraints;
    }
    for (uint32_t index : functionTemplate->addressSeeds) {
      const AddressSeed &seed = db_.addressSeeds[index];
      if (seed.dst < liveValues_.size() && liveValues_[seed.dst]) {
        addTuple(contextValueNode(contextId, seed.dst),
                 {contextObjectRoot(contextId, seed.root), seed.offset}, seed.rule,
                 NONE, seed.source);
        ++stats.objectContextConstraints;
      }
    }
    return true;
  }

  bool isDirectFieldCycle(uint32_t src, uint32_t dst) const {
    if (src == dst)
      return true;
    uint64_t reverse = (static_cast<uint64_t>(dst) << 32) | src;
    return copyEdgeKeys_.count(reverse);
  }

  bool fieldTypeAllowed(uint32_t root, uint32_t structType, uint32_t predecessor,
                        uint64_t source, Rule rule) {
    if (structType == NONE)
      return true;
    ++stats.typedFieldApplications;
    if (!db_.objects.hasCompleteAggregateType(root)) {
      ++stats.typedFieldUnknown;
      return true;
    }
    if (db_.objects.containsStruct(root, structType)) {
      ++stats.typedFieldCompatible;
      return true;
    }
    ++stats.typedFieldIncompatible;
    if (fieldTypePolicy_ == FieldTypePolicy::All)
      return true;
    ++stats.typedFieldDropped;
    constexpr size_t maxSamples = 10000;
    if (fieldTypeDrops_.size() < maxSamples) {
      fieldTypeDrops_.push_back({predecessor, root, structType, source, rule});
      ++stats.fieldTypeDropSamples;
    } else {
      stats.fieldTypeDropSamplesTruncated = true;
    }
    return false;
  }

  uint32_t valueNode(uint32_t value) const { return valueClasses_[value]; }

  bool liveValueNode(uint32_t node) const { return liveComponents_[node]; }

  bool callerEnabled(uint32_t caller) const {
    if (callFlowMode_ == CallFlowMode::Global ||
        callFlowMode_ == CallFlowMode::Callsite)
      return true;
    if (callFlowMode_ == CallFlowMode::None || caller == NONE)
      return false;
    return db_.handlerReachableFunctions.count(caller) != 0;
  }

  bool callConstraintEnabled(const CopyConstraint &constraint) const {
    if (constraint.rule != Rule::CallArgument && constraint.rule != Rule::CallReturn)
      return true;
    // A selected (contextualized) direct callsite replaces its context-insensitive
    // baseline CALL_ARGUMENT/CALL_RETURN with per-context transfers wired by
    // materializeCallsiteContexts. Keeping the baseline copy would re-merge the
    // callee's shared formals/returns across unrelated callers, so disable it here.
    if (constraint.directSite != NONE &&
        constraint.directSite < db_.contextualDirectSites.size() &&
        db_.contextualDirectSites[constraint.directSite])
      return false;
    return callerEnabled(constraint.caller);
  }

  bool demanded(ObjKey cell) const {
    if (!usePointerSinkSlice_)
      return true;
    if (demandedRoots_.count(cell.root) || demandedCells_.count(cell))
      return true;
    if (cell.isAffine())
      return demandedCellRoots_.count(cell.root) != 0;
    if (cell.offset == DYN_OFFSET)
      return demandedCellRoots_.count(cell.root) != 0;
    return demandedCells_.count({cell.root, DYN_OFFSET}) != 0;
  }

  void buildValueLiveness(bool usePointerSinkSlice,
                          const std::vector<uint8_t> *forcedValues) {
    liveValues_.assign(originalValueCount_, !usePointerSinkSlice);
    coreValues_.assign(originalValueCount_, !usePointerSinkSlice);
    if (!usePointerSinkSlice) {
      stats.liveValues = originalValueCount_;
      stats.coreValues = originalValueCount_;
      return;
    }

    std::vector<uint32_t> reverseStart(originalValueCount_ + 1);
    auto countDependency = [&](uint32_t source, uint32_t destination) {
      (void)source;
      ++reverseStart[destination + 1];
    };
    for (const CopyConstraint &constraint : db_.copies) {
      if (!callConstraintEnabled(constraint))
        continue;
      countDependency(constraint.src, constraint.dst);
    }
    for (const FieldConstraint &constraint : db_.fields)
      countDependency(constraint.src, constraint.dst);
    for (const DynamicFieldConstraint &constraint : db_.dynamicFields)
      countDependency(constraint.src, constraint.dst);
    for (const StridedFieldConstraint &constraint : db_.stridedFields)
      countDependency(constraint.src, constraint.dst);
    for (const SimpleConstraint &constraint : db_.loads)
      countDependency(constraint.first, constraint.second);
    for (uint32_t value = 1; value <= originalValueCount_; ++value)
      reverseStart[value] += reverseStart[value - 1];
    std::vector<uint32_t> reverseEdges(reverseStart.back());
    std::vector<uint32_t> cursor = reverseStart;
    auto addDependency = [&](uint32_t source, uint32_t destination) {
      reverseEdges[cursor[destination]++] = source;
    };
    for (const CopyConstraint &constraint : db_.copies) {
      if (!callConstraintEnabled(constraint))
        continue;
      addDependency(constraint.src, constraint.dst);
    }
    for (const FieldConstraint &constraint : db_.fields)
      addDependency(constraint.src, constraint.dst);
    for (const DynamicFieldConstraint &constraint : db_.dynamicFields)
      addDependency(constraint.src, constraint.dst);
    for (const StridedFieldConstraint &constraint : db_.stridedFields)
      addDependency(constraint.src, constraint.dst);
    for (const SimpleConstraint &constraint : db_.loads)
      addDependency(constraint.first, constraint.second);

    auto close = [&](std::vector<uint8_t> &marks, std::vector<uint32_t> &work) {
      for (size_t index = 0; index < work.size(); ++index) {
        uint32_t value = work[index];
        for (uint32_t edge = reverseStart[value]; edge < reverseStart[value + 1]; ++edge) {
          uint32_t source = reverseEdges[edge];
          if (marks[source])
            continue;
          marks[source] = true;
          work.push_back(source);
        }
      }
    };

    std::vector<uint32_t> coreWork;
    auto markCore = [&](uint32_t value) {
      if (coreValues_[value])
        return;
      coreValues_[value] = true;
      coreWork.push_back(value);
    };
    // demandForcedOnly seeds the demand core exclusively from the forced values (the
    // pointer actuals for a signature prepass), so the slice is exactly their backward
    // reachability and nothing else.
    if (!demandForcedOnly_) {
      for (const MemoryCopyConstraint &constraint : db_.memoryCopies) {
        markCore(constraint.dst);
        markCore(constraint.src);
      }
      for (const IndirectSite &site : db_.indirectSites) {
        if ((callFlowMode_ == CallFlowMode::Reachable ||
             callFlowMode_ == CallFlowMode::Callsite) &&
            !callerEnabled(site.callerFunction))
          continue;
        markCore(site.calleeValue);
      }
      for (const RootSeed &seed : db_.rootSeeds)
        markCore(seed.rootValue);
    }
    if (forcedValues) {
      for (uint32_t value = 0; value < forcedValues->size(); ++value)
        if ((*forcedValues)[value])
          markCore(value);
    }
    close(coreValues_, coreWork);

    std::vector<uint8_t> storeValues(originalValueCount_);
    std::vector<uint32_t> storeWork;
    for (const SimpleConstraint &constraint : db_.stores) {
      if (storeValues[constraint.first])
        continue;
      storeValues[constraint.first] = true;
      storeWork.push_back(constraint.first);
    }
    close(storeValues, storeWork);

    uint64_t liveCount = 0;
    for (uint32_t value = 0; value < originalValueCount_; ++value) {
      liveValues_[value] = coreValues_[value] || storeValues[value];
      liveCount += liveValues_[value];
    }
    stats.liveValues = liveCount;
    stats.coreValues = coreWork.size();
  }

  void buildValueClasses(bool useCopyScc) {
    valueClasses_.resize(originalValueCount_);
    if (!useCopyScc) {
      componentRepresentatives_.resize(originalValueCount_);
      componentSizes_.assign(originalValueCount_, 1);
      for (uint32_t value = 0; value < originalValueCount_; ++value) {
        valueClasses_[value] = value;
        componentRepresentatives_[value] = value;
      }
      valueCount_ = originalValueCount_;
      stats.copySccComponents = valueCount_;
      stats.copySccMaxSize = originalValueCount_ ? 1 : 0;
      return;
    }

    std::vector<uint32_t> forwardStart(originalValueCount_ + 1);
    std::vector<uint32_t> reverseStart(originalValueCount_ + 1);
    uint64_t edgeCount = 0;
    for (const CopyConstraint &constraint : db_.copies) {
      if (!callConstraintEnabled(constraint))
        continue;
      if (constraint.src == constraint.dst)
        continue;
      ++forwardStart[constraint.src + 1];
      ++reverseStart[constraint.dst + 1];
      ++edgeCount;
    }
    if (edgeCount > std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("copy graph exceeds 32-bit edge capacity");
    for (uint32_t value = 1; value <= originalValueCount_; ++value) {
      forwardStart[value] += forwardStart[value - 1];
      reverseStart[value] += reverseStart[value - 1];
    }
    std::vector<uint32_t> forwardEdges(edgeCount), reverseEdges(edgeCount);
    std::vector<uint32_t> forwardCursor = forwardStart;
    std::vector<uint32_t> reverseCursor = reverseStart;
    for (const CopyConstraint &constraint : db_.copies) {
      if (!callConstraintEnabled(constraint))
        continue;
      if (constraint.src == constraint.dst)
        continue;
      forwardEdges[forwardCursor[constraint.src]++] = constraint.dst;
      reverseEdges[reverseCursor[constraint.dst]++] = constraint.src;
    }

    struct Frame { uint32_t value, cursor; };
    std::vector<uint8_t> state(originalValueCount_);
    std::vector<uint32_t> order;
    order.reserve(originalValueCount_);
    std::vector<Frame> frames;
    for (uint32_t start = 0; start < originalValueCount_; ++start) {
      if (state[start])
        continue;
      state[start] = 1;
      frames.push_back({start, forwardStart[start]});
      while (!frames.empty()) {
        Frame &frame = frames.back();
        if (frame.cursor < forwardStart[frame.value + 1]) {
          uint32_t next = forwardEdges[frame.cursor++];
          if (!state[next]) {
            state[next] = 1;
            frames.push_back({next, forwardStart[next]});
          }
          continue;
        }
        state[frame.value] = 2;
        order.push_back(frame.value);
        frames.pop_back();
      }
    }

    std::vector<uint32_t> stack;
    for (auto iterator = order.rbegin(); iterator != order.rend(); ++iterator) {
      uint32_t start = *iterator;
      if (valueClasses_[start] != 0)
        continue;
      uint32_t component = static_cast<uint32_t>(componentRepresentatives_.size());
      uint32_t representative = start;
      uint32_t size = 0;
      stack.push_back(start);
      valueClasses_[start] = component + 1;
      while (!stack.empty()) {
        uint32_t value = stack.back();
        stack.pop_back();
        representative = std::min(representative, value);
        ++size;
        for (uint32_t edge = reverseStart[value]; edge < reverseStart[value + 1]; ++edge) {
          uint32_t next = reverseEdges[edge];
          if (valueClasses_[next] != 0)
            continue;
          valueClasses_[next] = component + 1;
          stack.push_back(next);
        }
      }
      componentRepresentatives_.push_back(representative);
      componentSizes_.push_back(size);
      stats.copySccMaxSize = std::max<uint64_t>(stats.copySccMaxSize, size);
    }
    for (uint32_t &component : valueClasses_)
      --component;
    valueCount_ = static_cast<uint32_t>(componentRepresentatives_.size());
    stats.copySccComponents = valueCount_;
    stats.copySccCollapsedValues = originalValueCount_ - valueCount_;
  }

  void resizeNodes(uint32_t count) {
    tupleHead_.resize(count, NONE);
    copyHead_.resize(count, NONE);
    fieldHead_.resize(count, NONE);
    dynamicHead_.resize(count, NONE);
    stridedHead_.resize(count, NONE);
    loadHead_.resize(count, NONE);
    storeHead_.resize(count, NONE);
    indirectHead_.resize(count, NONE);
    memcpyDstHead_.resize(count, NONE);
    memcpySrcHead_.resize(count, NONE);
  }

  uint32_t memoryNode(ObjKey object) {
    auto found = memoryNodes_.find(object);
    if (found != memoryNodes_.end())
      return found->second;
    ensureRootCapacity();
    uint32_t memoryIndex = static_cast<uint32_t>(memoryKeys_.size());
    uint32_t node = nodeArena_.allocateMemory(memoryIndex);
    memoryNodes_[object] = node;
    memoryKeys_.push_back(object);
    memoryNodeIds_.push_back(node);
    memoryNextByRoot_.push_back(memHeadByRoot_[object.root]);
    memHeadByRoot_[object.root] = memoryIndex;
    resizeNodes(nodeArena_.size());
    activateDynamicAliases(memoryIndex);
    activateAffineAliases(memoryIndex);
    activateTransfersForCell(memoryIndex);
    return node;
  }

  void addDynamicAlias(uint32_t source, uint32_t destination, uint64_t provenance) {
    uint64_t before = stats.copyEdges;
    addCopyEdge(source, destination, Rule::MemoryAlias, provenance, true);
    stats.dynamicAliasEdges += stats.copyEdges != before;
  }

  void activateDynamicAliases(uint32_t memoryIndex) {
    if (dynamicAliasPolicy_ == DynamicAliasPolicy::None)
      return;
    ObjKey object = memoryKeys_[memoryIndex];
    if (object.offset == INSTALL_OFFSET)
      return;
    auto dynamic = memoryNodes_.find({object.root, DYN_OFFSET});
    if (dynamic == memoryNodes_.end() || object.offset == DYN_OFFSET)
      return;
    uint32_t dynamicNode = dynamic->second;
    uint32_t node = memoryNodeIds_[memoryIndex];
    if (dynamicReadRoots_.count(object.root))
      addDynamicAlias(node, dynamicNode, dynamicReadSources_[object.root]);
    if (dynamicWriteRoots_.count(object.root))
      addDynamicAlias(dynamicNode, node, dynamicWriteSources_[object.root]);
  }

  void activateDynamicRead(uint32_t memoryIndex, uint64_t source) {
    if (dynamicAliasPolicy_ == DynamicAliasPolicy::None)
      return;
    ObjKey object = memoryKeys_[memoryIndex];
    if (object.offset != DYN_OFFSET)
      return;
    dynamicReadRoots_.insert(object.root);
    dynamicReadSources_.emplace(object.root, source);
    uint32_t dynamicNode = memoryNodeIds_[memoryIndex];
    for (uint32_t peerIndex = memHeadByRoot_[object.root];
         peerIndex != NONE; peerIndex = memoryNextByRoot_[peerIndex]) {
      ObjKey peer = memoryKeys_[peerIndex];
      if (peer.offset == DYN_OFFSET || peer.offset == INSTALL_OFFSET)
        continue;
      addDynamicAlias(memoryNodeIds_[peerIndex], dynamicNode,
                      dynamicReadSources_[object.root]);
    }
  }

  void activateDynamicWrite(uint32_t memoryIndex, uint64_t source) {
    if (dynamicAliasPolicy_ == DynamicAliasPolicy::None)
      return;
    ObjKey object = memoryKeys_[memoryIndex];
    if (object.offset != DYN_OFFSET)
      return;
    dynamicWriteRoots_.insert(object.root);
    dynamicWriteSources_.emplace(object.root, source);
    uint32_t dynamicNode = memoryNodeIds_[memoryIndex];
    for (uint32_t peerIndex = memHeadByRoot_[object.root];
         peerIndex != NONE; peerIndex = memoryNextByRoot_[peerIndex]) {
      ObjKey peer = memoryKeys_[peerIndex];
      if (peer.offset == DYN_OFFSET || peer.offset == INSTALL_OFFSET)
        continue;
      addDynamicAlias(dynamicNode, memoryNodeIds_[peerIndex],
                      dynamicWriteSources_[object.root]);
    }
  }

  bool affineContains(ObjKey object, int64_t offset) const {
    const AffineRegion &region = db_.affineRegions.get(object.region);
    if (offset < region.base || offset > region.bound)
      return false;
    return (static_cast<__int128>(offset) - region.base) % region.stride == 0;
  }

  bool mayAlias(ObjKey left, ObjKey right) const {
    if (left.root != right.root || left.offset == INSTALL_OFFSET ||
        right.offset == INSTALL_OFFSET || left.offset == DYN_OFFSET ||
        right.offset == DYN_OFFSET)
      return false;
    if (left.isAffine() && !right.isAffine())
      return affineContains(left, right.offset);
    if (!left.isAffine() && right.isAffine())
      return affineContains(right, left.offset);
    if (!left.isAffine())
      return left.offset == right.offset;
    const AffineRegion &leftRegion = db_.affineRegions.get(left.region);
    const AffineRegion &rightRegion = db_.affineRegions.get(right.region);
    if (leftRegion.bound < rightRegion.base || rightRegion.bound < leftRegion.base)
      return false;
    int64_t commonStride = std::gcd(leftRegion.stride, rightRegion.stride);
    return (static_cast<__int128>(rightRegion.base) - leftRegion.base) %
               commonStride ==
           0;
  }

  void addAffineAlias(uint32_t source, uint32_t destination, uint64_t provenance) {
    uint64_t before = stats.copyEdges;
    addCopyEdge(source, destination, Rule::MemoryAlias, provenance, true);
    stats.affineAliasEdges += stats.copyEdges != before;
  }

  void activateAffineAliases(uint32_t memoryIndex) {
    ObjKey object = memoryKeys_[memoryIndex];
    if (object.offset == INSTALL_OFFSET)
      return;
    uint32_t node = memoryNodeIds_[memoryIndex];
    auto reads = affineReadCellsByRoot_.find(object.root);
    if (reads != affineReadCellsByRoot_.end()) {
      for (uint32_t regionIndex : reads->second) {
        if (regionIndex == memoryIndex || !mayAlias(object, memoryKeys_[regionIndex]))
          continue;
        addAffineAlias(node, memoryNodeIds_[regionIndex],
                       affineReadSources_[regionIndex]);
      }
    }
    auto writes = affineWriteCellsByRoot_.find(object.root);
    if (writes != affineWriteCellsByRoot_.end()) {
      for (uint32_t regionIndex : writes->second) {
        if (regionIndex == memoryIndex || !mayAlias(object, memoryKeys_[regionIndex]))
          continue;
        addAffineAlias(memoryNodeIds_[regionIndex], node,
                       affineWriteSources_[regionIndex]);
      }
    }
  }

  void activateAffineRead(uint32_t memoryIndex, uint64_t source) {
    ObjKey object = memoryKeys_[memoryIndex];
    if (!object.isAffine() || !affineReadSources_.emplace(memoryIndex, source).second)
      return;
    affineReadCellsByRoot_[object.root].push_back(memoryIndex);
    uint32_t regionNode = memoryNodeIds_[memoryIndex];
    for (uint32_t peerIndex = memHeadByRoot_[object.root];
         peerIndex != NONE; peerIndex = memoryNextByRoot_[peerIndex]) {
      if (peerIndex == memoryIndex || !mayAlias(object, memoryKeys_[peerIndex]))
        continue;
      addAffineAlias(memoryNodeIds_[peerIndex], regionNode, source);
    }
  }

  void activateAffineWrite(uint32_t memoryIndex, uint64_t source) {
    ObjKey object = memoryKeys_[memoryIndex];
    if (!object.isAffine() || !affineWriteSources_.emplace(memoryIndex, source).second)
      return;
    affineWriteCellsByRoot_[object.root].push_back(memoryIndex);
    uint32_t regionNode = memoryNodeIds_[memoryIndex];
    for (uint32_t peerIndex = memHeadByRoot_[object.root];
         peerIndex != NONE; peerIndex = memoryNextByRoot_[peerIndex]) {
      if (peerIndex == memoryIndex || !mayAlias(object, memoryKeys_[peerIndex]))
        continue;
      addAffineAlias(regionNode, memoryNodeIds_[peerIndex], source);
    }
  }

  uint32_t addTuple(uint32_t node, ObjKey object, Rule rule,
                    uint32_t predecessor, uint64_t source) {
    if (db_.objects.isNull(object.root)) {
      ++stats.nullPropagationsDropped;
      return NONE;
    }
    if (usePointerSinkSlice_ && nodeArena_.isValue(node) && !nodeArena_.core(node) &&
        !demanded(object)) {
      ++stats.storeOnlyTuplesDropped;
      return NONE;
    }
    if (auto found = tupleIndex_.find(node, object))
      return *found;
    uint32_t tuple = static_cast<uint32_t>(tuples_.size());
    tuples_.push_back({node, object, tupleHead_[node], predecessor, source, rule});
    tupleHead_[node] = tuple;
    tupleIndex_.insert(tuple);
    work_.push_back(tuple);
    if (affineMemoryCensus_) {
      if (nodeArena_.isMemory(node) &&
          memoryKeys_[nodeArena_.memoryIndex(node)].isAffine())
        ++stats.affineMemoryNodeTuples;
      if (predecessor != NONE) {
        uint32_t predNode = tuples_[predecessor].node;
        if (nodeArena_.isMemory(predNode) &&
            memoryKeys_[nodeArena_.memoryIndex(predNode)].isAffine())
          ++stats.affineMemoryDerivedTuples;
      }
    }
    return tuple;
  }

  void addCopyEdge(uint32_t src, uint32_t dst, Rule rule, uint64_t source, bool dynamic) {
    if (src == dst)
      return;
    uint64_t key = (static_cast<uint64_t>(src) << 32) | dst;
    if (!copyEdgeKeys_.insert(key).second) {
      ++stats.duplicateCopyEdges;
      return;
    }
    copies_.push_back({dst, copyHead_[src], source, rule});
    copyHead_[src] = static_cast<uint32_t>(copies_.size() - 1);
    ++stats.copyEdges;
    if (dynamic)
      ++stats.dynamicCopyEdges;
    for (uint32_t tuple = tupleHead_[src]; tuple != NONE; tuple = tuples_[tuple].next)
      addTuple(dst, tuples_[tuple].object, rule, tuple, source);
  }

  void wireIndirect(uint32_t siteIndex, uint32_t function) {
    uint64_t key = (static_cast<uint64_t>(siteIndex) << 32) | function;
    if (!wired_.insert(key).second)
      return;
    const IndirectSite &site = db_.indirectSites[siteIndex];
    indirectTargets_.push_back({siteIndex, function});
    ++stats.indirectTargets;

    // If this (callsite, target) was promoted to a synthetic contextual direct site, the
    // contextual transfer already carries the actual/formal/return flow; suppress the
    // context-insensitive baseline wiring so the shared target formal is not re-merged
    // across all callsites that reach this target (plan §10.1 item 4).
    if (db_.indirectPairContextualized(site.callsiteName, function)) {
      ++stats.contextualizedIndirectTargets;
      return;
    }

    // Discovery mode (indirect-target frontier bootstrap): a non-promoted pair is recorded as
    // a CallTarget above but its actual/return flow is DEFERRED, not wired. This suppresses the
    // device_release-class shared-formal broadcast that a context-insensitive baseline transfer
    // would produce, keeping each discovery round bounded. The pair enters the frontier and is
    // promoted (contextual transfer) in the next round, where its argument flow may reveal
    // deeper targets. The target set grows monotonically to a fixpoint.
    if (discoveryMode_) {
      ++stats.deferredIndirectPairs;
      deferredIndirectPairs_.push_back({siteIndex, function});
      return;
    }

    bool hasPointerTransfer = site.actualCount != 0 || site.result != NONE;
    if (!hasPointerTransfer)
      return;

    bool useCallFlow = callerEnabled(site.callerFunction);
    CallTransfer transfer{true, false, useCallFlow, siteIndex, site.callerContext,
                          function, NONE, site.actualCount, 0, site.source, {}, {}};
    auto found = db_.functions.find(function);
    if (found == db_.functions.end()) {
      transfer.expectedReturns = site.result == NONE ? 0 : 1;
      indirectCallTransfers_.push_back(std::move(transfer));
      return;
    }
    const FunctionInfo &info = found->second;
    for (uint32_t offset = 0; useCallFlow && offset < site.actualCount; ++offset) {
      const Actual &actual = db_.indirectActuals[site.actualStart + offset];
      auto formal = std::find_if(info.formals.begin(), info.formals.end(),
                                 [&](const auto &item) { return item.first == actual.index; });
      if (formal != info.formals.end()) {
        if (liveValues_[formal->second]) {
          addCopyEdge(valueNode(actual.value), valueNode(formal->second), Rule::CallArgument,
                      actual.source, true);
          transfer.args.push_back(
              {actual.value, formal->second, actual.index, actual.source});
        }
      }
    }
    if (site.result != NONE) {
      transfer.expectedReturns = info.returns.empty()
                                     ? 1
                                     : static_cast<uint32_t>(info.returns.size());
    }
    if (useCallFlow && site.result != NONE && liveValues_[site.result]) {
      for (uint32_t returned : info.returns)
        addCopyEdge(valueNode(returned), valueNode(site.result), Rule::CallReturn,
                    site.source, true);
      for (uint32_t returned : info.returns)
        transfer.returns.push_back({returned, site.result, site.source});
    }
    indirectCallTransfers_.push_back(std::move(transfer));
  }

  void addCopyEndpoint(uint32_t index, ObjKey object, bool destination) {
    CopyState &state = copyStates_[index];
    std::vector<ObjKey> &own = destination ? state.destinations : state.sources;
    std::vector<ObjKey> &other = destination ? state.sources : state.destinations;
    own.push_back(object);
    for (ObjKey peer : other)
      addTransferPair(destination ? object : peer, destination ? peer : object,
                      state.size, state.source);
  }

  void addTransferPair(ObjKey destination, ObjKey source, uint64_t size,
                       uint64_t provenance) {
    uint32_t pair = static_cast<uint32_t>(transferPairs_.size());
    transferPairs_.push_back({destination, source, size, provenance,
                              transferHeadByRoot_[source.root]});
    transferHeadByRoot_[source.root] = pair;
    ++stats.transferPairs;
    for (uint32_t memoryIndex = memHeadByRoot_[source.root]; memoryIndex != NONE;
         memoryIndex = memoryNextByRoot_[memoryIndex])
      activateTransferCell(pair, memoryIndex);
  }

  void activateTransfersForCell(uint32_t memoryIndex) {
    uint32_t root = memoryKeys_[memoryIndex].root;
    for (uint32_t pair = transferHeadByRoot_[root]; pair != NONE;
         pair = transferPairs_[pair].nextByRoot)
      activateTransferCell(pair, memoryIndex);
  }

  void activateTransferCell(uint32_t pairIndex, uint32_t memoryIndex) {
    const TransferPair pair = transferPairs_[pairIndex];
    ObjKey cell = memoryKeys_[memoryIndex];
    ObjKey destination;
    if (cell.isAffine() || pair.src.isAffine() || cell.offset == DYN_OFFSET ||
        pair.src.offset == DYN_OFFSET) {
      destination = {pair.dst.root, DYN_OFFSET};
    } else {
      __int128 delta = static_cast<__int128>(cell.offset) - pair.src.offset;
      if (delta < 0 || delta >= pair.size)
        return;
      destination = field(pair.dst, static_cast<int64_t>(delta), pair.source);
      if (destination.root == NONE)
        return;
    }
    uint32_t srcNode = memoryNodeIds_[memoryIndex];
    uint32_t dstNode = memoryNode(destination);
    addCopyEdge(srcNode, dstNode, Rule::MemoryCopy, pair.source, true);
    ++stats.transferCells;
  }

  void countRootHandlers() {
    std::unordered_set<uint32_t> namedObjects;
    for (const NamedSummary &summary : db_.namedSummaries)
      namedObjects.insert(summary.object);
    std::unordered_set<uint32_t> functionObjects;
    for (const Tuple &tuple : tuples_) {
      if (!nodeArena_.isMemory(tuple.node))
        continue;
      ObjKey cell = memoryKeys_[nodeArena_.memoryIndex(tuple.node)];
      if (!tuple.object.isAffine() && tuple.object.offset == 0 &&
          db_.objects.isFunction(tuple.object.root))
        functionObjects.insert(cell.root);
    }
    std::unordered_set<uint32_t> roots;
    for (const RootSeed &seed : db_.rootSeeds)
      if (namedObjects.count(seed.dispatchObject) || functionObjects.count(seed.dispatchObject))
        roots.insert(seed.rootName);
    stats.rootsReachingHandler = roots.size();
  }

  Database &db_;
  FieldDynamicPolicy fieldDynamicPolicy_;
  FieldTypePolicy fieldTypePolicy_;
  FieldCyclePolicy fieldCyclePolicy_;
  DynamicAliasPolicy dynamicAliasPolicy_;
  AffineCanonPolicy affineCanonPolicy_ = AffineCanonPolicy::None;
  FieldLocationPolicy fieldLocationPolicy_ = FieldLocationPolicy::RootWide;
  uint64_t maxStridedExpansion_;
  OffsetPolicy offsetPolicy_;
  CallFlowMode callFlowMode_;
  uint64_t maxTuples_;
  bool usePointerSinkSlice_;
  bool demandForcedOnly_ = false;
  bool discoveryMode_ = false;
  bool affineMemoryCensus_ = false;
  uint32_t originalValueCount_;
  uint32_t valueCount_;
  SolverNodeArena nodeArena_;
  ObjectContextNodes objectContextNodes_;
  std::vector<ContextStackRange> contextStackRanges_;
  std::vector<uint32_t> contextStackObjectIds_;
  std::vector<uint32_t> valueClasses_, componentRepresentatives_, componentSizes_;
  std::vector<uint8_t> liveValues_, liveComponents_, coreValues_, coreComponents_;
  std::vector<uint32_t> tupleHead_, copyHead_, fieldHead_, dynamicHead_, stridedHead_;
  std::vector<uint32_t> loadHead_, storeHead_;
  std::vector<uint32_t> indirectHead_, memcpyDstHead_, memcpySrcHead_;
  std::vector<CopyEdge> copies_;
  std::vector<FieldEdge> fields_;
  std::vector<StridedEdge> strided_;
  std::vector<TypedSimpleEdge> dynamic_;
  std::vector<SimpleEdge> loads_, stores_;
  std::vector<WatchEdge> indirectWatches_, memcpyDstWatches_, memcpySrcWatches_;
  std::vector<CopyState> copyStates_;
  std::unordered_map<ObjKey, uint32_t, ObjKeyHash> memoryNodes_;
  std::vector<ObjKey> memoryKeys_;
  std::vector<uint32_t> memoryNodeIds_;
  std::vector<uint32_t> memoryNextByRoot_, memHeadByRoot_;
  std::vector<TransferPair> transferPairs_;
  std::vector<uint32_t> transferHeadByRoot_;
  std::vector<Tuple> tuples_;
  std::vector<FieldTypeDrop> fieldTypeDrops_;
  std::vector<FieldCycleRecord> fieldCycles_;
  std::vector<AffineClipRecord> affineClips_;
  TupleIndex tupleIndex_;
  std::vector<uint32_t> work_;
  std::unordered_set<uint64_t> wired_;
  std::unordered_set<uint64_t> copyEdgeKeys_;
  std::vector<std::pair<uint32_t, uint32_t>> indirectTargets_;
  std::vector<std::pair<uint32_t, uint32_t>> deferredIndirectPairs_;
  std::vector<CallTransfer> indirectCallTransfers_;
  std::unordered_set<ObjKey, ObjKeyHash> demandedCells_;
  std::unordered_set<uint32_t> demandedCellRoots_, demandedRoots_;
  std::unordered_set<uint32_t> dynamicReadRoots_, dynamicWriteRoots_;
  std::unordered_map<uint32_t, uint64_t> dynamicReadSources_, dynamicWriteSources_;
  std::unordered_map<uint32_t, std::vector<uint32_t>> affineReadCellsByRoot_;
  std::unordered_map<uint32_t, std::vector<uint32_t>> affineWriteCellsByRoot_;
  std::unordered_map<uint32_t, uint64_t> affineReadSources_, affineWriteSources_;
  std::unordered_set<ObjKey, ObjKeyHash> usedAffineObjects_;

  // Affine-memory census (gated by affineMemoryCensus_). Per affine cell: the pre-canonical
  // (base,bound) regions that collapsed into it, and the stored/loaded value nodes + source
  // constraints. Answers whether the value merge lives inside one abstract affine cell (and
  // whether subsumption over-widened distinct regions into it) vs a call-context merge.
  struct AffineCellEdges {
    std::unordered_set<uint32_t> values;
    std::unordered_set<uint64_t> sources;
  };
  std::unordered_map<ObjKey, std::set<std::pair<int64_t, int64_t>>, ObjKeyHash>
      affineCanonInputs_;
  std::unordered_map<ObjKey, AffineCellEdges, ObjKeyHash> affineStoreInfo_, affineLoadInfo_;
};

bool Solver::incrementalInstallerSelftest() {
  constexpr uint64_t source = 1;
  Database database(true);
  auto value = [&](const char *name) { return database.value(name); };
  uint32_t rootA = database.objects.intern("selftest:late:root_a", 64, ObjectKind::Other);
  uint32_t rootB = database.objects.intern("selftest:late:root_b", 64, ObjectKind::Other);
  uint32_t copySrc = database.objects.intern("selftest:late:copy_src", 64, ObjectKind::Other);
  uint32_t copyDst = database.objects.intern("selftest:late:copy_dst", 64, ObjectKind::Other);
  uint32_t payloadA = database.objects.intern("selftest:late:payload_a", 8, ObjectKind::Other);
  uint32_t payloadB = database.objects.intern("selftest:late:payload_b", 8, ObjectKind::Other);
  uint32_t targetA = database.objects.intern(
      "sym:object:function:selftest_late_target_a", 0, ObjectKind::Function,
      "selftest_late_target_a");
  uint32_t targetB = database.objects.intern(
      "sym:object:function:selftest_late_target_b", 0, ObjectKind::Function,
      "selftest_late_target_b");

  uint32_t base = value("selftest:late:base");
  uint32_t fieldResult = value("selftest:late:field_result");
  uint32_t dynamicResult = value("selftest:late:dynamic_result");
  uint32_t loadResult = value("selftest:late:load_result");
  uint32_t storePointer = value("selftest:late:store_pointer");
  uint32_t storeValue = value("selftest:late:store_value");
  uint32_t copyDstPointer = value("selftest:late:copy_dst_pointer");
  uint32_t copySrcPointer = value("selftest:late:copy_src_pointer");
  uint32_t calleeValue = value("selftest:late:callee");
  uint32_t actual = value("selftest:late:actual");
  uint32_t formalA = value("selftest:late:formal_a");
  uint32_t formalB = value("selftest:late:formal_b");
  database.functions[targetA].formals.push_back({0, formalA});
  database.functions[targetB].formals.push_back({0, formalB});

  Solver solver(database, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                FieldCyclePolicy::Iterate, 64, OffsetPolicy::Dynamic, true, false,
                CallFlowMode::Global, nullptr, nullptr, 0);
  solver.build();

  auto seed = [&](uint32_t target, ObjKey object) {
    solver.addTuple(solver.valueNode(target), object, Rule::AddressOf, NONE, source);
  };
  seed(base, {rootA, 0});
  seed(storePointer, {rootA, 16});
  seed(storeValue, {payloadB, 0});
  seed(copyDstPointer, {copyDst, 0});
  seed(copySrcPointer, {copySrc, 0});
  seed(calleeValue, {targetA, 0});
  seed(actual, {payloadB, 0});
  solver.addTuple(solver.memoryNode({rootA, 8}), {payloadA, 0},
                  Rule::StoreObject, NONE, source);
  solver.addTuple(solver.memoryNode({copySrc, 0}), {payloadA, 0},
                  Rule::StoreObject, NONE, source);

  solver.installFieldEdge(solver.valueNode(base), solver.valueNode(fieldResult),
                          8, source, NONE);
  solver.installDynamicFieldEdge(solver.valueNode(base),
                                 solver.valueNode(dynamicResult), source, NONE);
  solver.installLoadEdge(solver.valueNode(fieldResult), solver.valueNode(loadResult), source);
  solver.installStoreEdge(solver.valueNode(storePointer), solver.valueNode(storeValue), source);
  solver.installMemoryCopy(solver.valueNode(copyDstPointer),
                           solver.valueNode(copySrcPointer), 8, source);

  uint32_t actualStart = static_cast<uint32_t>(database.indirectActuals.size());
  database.indirectActuals.push_back({0, actual, source});
  uint32_t site = static_cast<uint32_t>(database.indirectSites.size());
  database.indirectSites.push_back({database.callsiteNames.intern("selftest:late:indirect"),
                                    NONE, NONE, calleeValue, actualStart, 1, NONE, source});
  solver.installIndirectWatch(solver.valueNode(calleeValue), site);

  seed(base, {rootB, 0});
  seed(storePointer, {rootB, 16});
  seed(calleeValue, {targetB, 0});
  solver.addTuple(solver.memoryNode({rootB, 8}), {payloadB, 0},
                  Rule::StoreObject, NONE, source);
  solver.drainWorklist();

  bool fieldReplay = solver.containsValue(fieldResult, {rootA, 8});
  bool fieldFuture = solver.containsValue(fieldResult, {rootB, 8});
  bool dynamicReplay = solver.containsValue(dynamicResult, {rootA, DYN_OFFSET});
  bool loadReplay = solver.containsValue(loadResult, {payloadA, 0});
  bool loadFuture = solver.containsValue(loadResult, {payloadB, 0});
  bool storeReplay = solver.containsMemory({rootA, 16}, {payloadB, 0});
  bool storeFuture = solver.containsMemory({rootB, 16}, {payloadB, 0});
  bool memcpyReplay = solver.containsMemory({copyDst, 0}, {payloadA, 0});
  bool indirectReplay = solver.containsValue(formalA, {payloadB, 0});
  bool indirectFuture = solver.containsValue(formalB, {payloadB, 0});

  Database stridedDatabase(true);
  uint32_t stridedRoot =
      stridedDatabase.objects.intern("selftest:late:strided_root", 64, ObjectKind::Other);
  uint32_t stridedBase = stridedDatabase.value("selftest:late:strided_base");
  uint32_t stridedResult = stridedDatabase.value("selftest:late:strided_result");
  Solver stridedSolver(stridedDatabase, FieldDynamicPolicy::Strided, FieldTypePolicy::All,
                       FieldCyclePolicy::Iterate, 64, OffsetPolicy::Dynamic, true, false,
                       CallFlowMode::Global, nullptr, nullptr, 0);
  stridedSolver.build();
  stridedSolver.addTuple(stridedSolver.valueNode(stridedBase), {stridedRoot, 0},
                         Rule::AddressOf, NONE, source);
  stridedSolver.installStridedFieldEdge(stridedSolver.valueNode(stridedBase),
                                        stridedSolver.valueNode(stridedResult), 8, 8, 3,
                                        source, NONE);
  stridedSolver.drainWorklist();
  bool stridedReplay = stridedSolver.containsValue(stridedResult, {stridedRoot, 8}) &&
                       stridedSolver.containsValue(stridedResult, {stridedRoot, 16}) &&
                       stridedSolver.containsValue(stridedResult, {stridedRoot, 24});

  return fieldReplay && fieldFuture && dynamicReplay && loadReplay && loadFuture &&
         storeReplay && storeFuture && memcpyReplay && indirectReplay && indirectFuture &&
         stridedReplay;
}

bool Solver::contextBodyMaterializationSelftest() {
  constexpr uint64_t source = 1;
  Database database(true);
  uint32_t function = database.objects.intern(
      "sym:object:function:selftest_context_body", 0, ObjectKind::Function,
      "selftest_context_body");
  uint32_t directTarget = database.objects.intern(
      "sym:object:function:selftest_context_body_target", 0, ObjectKind::Function,
      "selftest_context_body_target");
  auto ownedValue = [&](const char *name) {
    uint32_t value = database.value(name);
    database.valueOwners[value] = function;
    return value;
  };
  uint32_t formal = ownedValue("selftest:ctxbody:formal");
  uint32_t copied = ownedValue("selftest:ctxbody:copied");
  uint32_t fieldPointer = ownedValue("selftest:ctxbody:field_pointer");
  uint32_t dynamicPointer = ownedValue("selftest:ctxbody:dynamic_pointer");
  uint32_t stridedPointer = ownedValue("selftest:ctxbody:strided_pointer");
  uint32_t loaded = ownedValue("selftest:ctxbody:loaded");
  uint32_t stackSrcPointer = ownedValue("selftest:ctxbody:stack_src_pointer");
  uint32_t stackDstPointer = ownedValue("selftest:ctxbody:stack_dst_pointer");
  uint32_t payloadPointer = ownedValue("selftest:ctxbody:payload_pointer");
  uint32_t indirectCallee = ownedValue("selftest:ctxbody:indirect_callee");
  database.functions[function].formals.push_back({0, formal});
  uint32_t foreignFormal = database.value("selftest:ctxbody:foreign_formal");
  uint32_t foreignField = database.value("selftest:ctxbody:foreign_field");
  database.valueOwners[foreignFormal] = directTarget;
  database.valueOwners[foreignField] = directTarget;
  database.functions[directTarget].formals.push_back({0, foreignFormal});

  uint32_t stackSrc =
      database.objects.intern("selftest:ctxbody:stack_src", 32, ObjectKind::Stack);
  uint32_t stackDst =
      database.objects.intern("selftest:ctxbody:stack_dst", 32, ObjectKind::Stack);
  uint32_t payload =
      database.objects.intern("selftest:ctxbody:payload", 8, ObjectKind::Other);
  uint32_t foreignStack =
      database.objects.intern("selftest:ctxbody:foreign_stack", 16, ObjectKind::Stack);
  database.objectOwners.resize(database.objects.size(), NONE);
  database.objectOwners[stackSrc] = function;
  database.objectOwners[stackDst] = function;
  database.objectOwners[foreignStack] = directTarget;

  database.addressSeeds.push_back({stackSrcPointer, stackSrc, 0, source, Rule::AddressOf});
  database.addressSeeds.push_back({stackDstPointer, stackDst, 0, source, Rule::AddressOf});
  database.addressSeeds.push_back({payloadPointer, payload, 0, source, Rule::AddressOf});
  database.copies.push_back({formal, copied, source, Rule::Copy});
  database.fields.push_back({copied, fieldPointer, 8, source, NONE});
  database.fields.push_back({foreignFormal, foreignField, 8, source, NONE});
  database.dynamicFields.push_back({formal, dynamicPointer, source, NONE});
  database.stridedFields.push_back({formal, stridedPointer, 16, 8, 2, source, NONE});
  database.loads.push_back({fieldPointer, loaded, source});
  database.stores.push_back({fieldPointer, stackSrcPointer, source});
  database.storeObjects.push_back({stackSrc, payloadPointer, 8, source});
  database.memoryCopies.push_back({stackDstPointer, stackSrcPointer, 16, source});
  database.directSites.push_back(
      {database.callsiteNames.intern("selftest:ctxbody:direct"), function, directTarget,
       0, 0, NONE, source});
  database.indirectSites.push_back(
      {database.callsiteNames.intern("selftest:ctxbody:indirect"), function, NONE,
       indirectCallee, 0, 0, NONE, source});
  database.computeReceiverFormals();
  database.computeObjectSensitivityTemplates();
  const ObjectFunctionTemplate *functionTemplate = database.objectTemplate(function);
  bool completeIndex = functionTemplate && functionTemplate->addressSeeds.size() == 3 &&
                       functionTemplate->copyEdges.size() == 1 &&
                       functionTemplate->fields.size() == 1 &&
                       functionTemplate->dynamicFields.size() == 1 &&
                       functionTemplate->stridedFields.size() == 1 &&
                       functionTemplate->loads.size() == 1 &&
                       functionTemplate->stores.size() == 1 &&
                       functionTemplate->storeObjects.size() == 1 &&
                       functionTemplate->memoryCopies.size() == 1 &&
                       functionTemplate->directSites.size() == 1 &&
                       functionTemplate->indirectSites.size() == 1 &&
                       functionTemplate->stackObjects.size() == 2;
  if (!completeIndex)
    return false;

  Solver solver(database, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                FieldCyclePolicy::Iterate, 64, OffsetPolicy::Dynamic, true, false,
                CallFlowMode::Global, nullptr, nullptr, 0);
  solver.build();
  uint32_t receiverA =
      database.objects.intern("selftest:ctxbody:receiver_a", 64, ObjectKind::Other);
  uint32_t receiverB =
      database.objects.intern("selftest:ctxbody:receiver_b", 64, ObjectKind::Other);
  uint32_t contextA = database.objectContexts.ensure(function, 0, receiverA);
  uint32_t contextB = database.objectContexts.ensure(function, 0, receiverB);
  bool createdA = solver.instantiateObjectContext(contextA);
  bool createdB = solver.instantiateObjectContext(contextB);
  bool idempotent = !solver.instantiateObjectContext(contextA);
  if (!createdA || !createdB || !idempotent)
    return false;

  uint32_t formalA = solver.contextValueNode(contextA, formal);
  uint32_t formalB = solver.contextValueNode(contextB, formal);
  solver.addTuple(formalA, {receiverA, 0}, Rule::CallArgument, NONE, source);
  solver.addTuple(formalB, {receiverB, 0}, Rule::CallArgument, NONE, source);
  solver.drainWorklist();

  uint32_t stackSrcA = solver.contextObjectRoot(contextA, stackSrc);
  uint32_t stackSrcB = solver.contextObjectRoot(contextB, stackSrc);
  uint32_t stackDstA = solver.contextObjectRoot(contextA, stackDst);
  uint32_t stackDstB = solver.contextObjectRoot(contextB, stackDst);
  uint32_t loadedA = solver.contextValueNode(contextA, loaded);
  uint32_t loadedB = solver.contextValueNode(contextB, loaded);
  uint32_t dynamicA = solver.contextValueNode(contextA, dynamicPointer);
  uint32_t dynamicB = solver.contextValueNode(contextB, dynamicPointer);
  uint32_t stridedA = solver.contextValueNode(contextA, stridedPointer);
  uint32_t stridedB = solver.contextValueNode(contextB, stridedPointer);
  auto containsNode = [&](uint32_t node, ObjKey object) {
    return solver.tupleIndex_.find(node, object).has_value();
  };

  bool stackIsolation = stackSrcA != stackSrcB && stackDstA != stackDstB &&
                        stackSrcA != stackSrc && stackSrcB != stackSrc &&
                        stackDstA != stackDst && stackDstB != stackDst &&
                        solver.contextObjectRoot(contextA, foreignStack) == foreignStack &&
                        solver.contextObjectRoot(contextB, foreignStack) == foreignStack;
  bool receiverStoreIsolation =
      solver.containsMemory({receiverA, 8}, {stackSrcA, 0}) &&
      solver.containsMemory({receiverB, 8}, {stackSrcB, 0}) &&
      !solver.containsMemory({receiverA, 8}, {stackSrcB, 0}) &&
      !solver.containsMemory({receiverB, 8}, {stackSrcA, 0});
  bool loadIsolation = containsNode(loadedA, {stackSrcA, 0}) &&
                       containsNode(loadedB, {stackSrcB, 0}) &&
                       !containsNode(loadedA, {stackSrcB, 0}) &&
                       !containsNode(loadedB, {stackSrcA, 0});
  bool storeObjectMapped = solver.containsMemory({stackSrcA, 8}, {payload, 0}) &&
                           solver.containsMemory({stackSrcB, 8}, {payload, 0});
  bool memcpyMapped = solver.containsMemory({stackDstA, 8}, {payload, 0}) &&
                      solver.containsMemory({stackDstB, 8}, {payload, 0});
  bool fieldKindsMapped = containsNode(dynamicA, {receiverA, DYN_OFFSET}) &&
                          containsNode(dynamicB, {receiverB, DYN_OFFSET}) &&
                          containsNode(stridedA, {receiverA, DYN_OFFSET}) &&
                          containsNode(stridedB, {receiverB, DYN_OFFSET});
  bool nodeMetadata = solver.nodeArena_.context(formalA) == contextA &&
                      solver.nodeArena_.context(formalB) == contextB &&
                      solver.nodeArena_.origin(formalA) == formal &&
                      solver.nodeArena_.origin(formalB) == formal;
  bool accounting = solver.stats.objectContextsMaterialized == 2 &&
                    solver.stats.objectContextStackObjects == 4 &&
                    solver.stats.objectContextValueNodes > 0 &&
                    solver.stats.objectContextConstraints > 0;
  return stackIsolation && receiverStoreIsolation && loadIsolation && storeObjectMapped &&
         memcpyMapped && fieldKindsMapped && nodeMetadata && accounting;
}

// Value-context signature accounting. A context is keyed by the context-insensitive
// points-to signature of a callsite's pointer actuals, so callsites with the same abstract
// input share one clone (this collapses "same device state replicated across thousands of
// callsites"). A per-callee budget bounds the number of distinct signatures; excess
// signatures fold into one deterministic overflow context whose formal is the union of the
// overflowed inputs (sound over-approximation, no call edge is lost).
struct SignatureCensus {
  uint64_t originalSites = 0;       // pointer-flow direct sites given a signature
  uint64_t uniqueSignatures = 0;    // distinct (function, signature) contexts created
  uint64_t equivalenceMerged = 0;   // sites that reused an existing signature context
  uint64_t overflowFunctions = 0;   // callees that exceeded the budget
  uint64_t overflowMerged = 0;      // sites routed into an overflow context
  uint64_t contextsCreated = 0;     // uniqueSignatures + overflowFunctions
};

// A callsite's actual-set signature: the exact, sorted points-to object set of each pointer
// formal's actual. Equality is by full object set (not a hash) so two callsites merge only
// when their abstract inputs are truly identical; the hash is only for bucketing.
struct ActualSignature {
  std::vector<std::pair<uint32_t, std::vector<ObjKey>>> perFormal;
  bool operator==(const ActualSignature &other) const {
    return perFormal == other.perFormal;
  }
};
struct ActualSignatureHash {
  size_t operator()(const ActualSignature &signature) const {
    uint64_t hash = 1469598103934665603ULL;
    for (const auto &[index, objects] : signature.perFormal) {
      hash = mix64(hash ^ mix64(index + 1));
      for (const ObjKey &object : objects)
        hash = mix64(hash ^ mix64(object.root) ^
                     mix64(static_cast<uint64_t>(object.region) + 0x9e3779b9ULL) ^
                     mix64(static_cast<uint64_t>(object.offset)));
    }
    return static_cast<size_t>(hash);
  }
};

// Builds a callsite's actual-set signature from a solved baseline: the exact sorted points-to
// object set of each pointer formal's actual. Shared by the global signature model and the
// selective value-context blend.
ActualSignature buildActualSignature(const Database &db, const DirectSite &site,
                                     const Solver &ci) {
  ActualSignature signature;
  auto found = db.functions.find(site.calleeFunction);
  if (found == db.functions.end())
    return signature;
  for (const auto &[index, formal] : found->second.formals) {
    (void)formal;
    uint32_t actualValue = NONE;
    for (uint32_t offset = 0; offset < site.actualCount; ++offset) {
      const Actual &actual = db.directActuals[site.actualStart + offset];
      if (actual.index == index) {
        actualValue = actual.value;
        break;
      }
    }
    if (actualValue == NONE)
      continue;
    std::vector<ObjKey> objects;
    ci.forEachValueObject(actualValue, [&](ObjKey object) { objects.push_back(object); });
    std::sort(objects.begin(), objects.end(), [](const ObjKey &a, const ObjKey &b) {
      if (a.root != b.root) return a.root < b.root;
      if (a.region != b.region) return a.region < b.region;
      return a.offset < b.offset;
    });
    objects.erase(std::unique(objects.begin(), objects.end()), objects.end());
    signature.perFormal.emplace_back(index, std::move(objects));
  }
  return signature;
}

// Computes a per-direct-site global signature-context id from a solved (and required to be
// converged) context-insensitive baseline. Deterministic: sites are processed in index
// order, so the first `budget` distinct signatures per callee win their own context and the
// rest overflow. Returns a vector indexed by direct site (NONE for sites without pointer
// flow). Equality uses the full object set (exact), not just a hash.
std::vector<uint32_t> computeSignatureContexts(const Database &db, const Solver &ci,
                                               uint32_t budget,
                                               SignatureCensus &census) {
  std::vector<uint32_t> signatureOf(db.directSites.size(), NONE);
  struct FnState {
    std::unordered_map<ActualSignature, uint32_t, ActualSignatureHash> bySignature;
    uint32_t overflowId = NONE;
  };
  std::unordered_map<uint32_t, FnState> perFunction;
  uint32_t nextId = 0;

  auto buildSignature = [&](const DirectSite &site) {
    return buildActualSignature(db, site, ci);
  };

  for (uint32_t siteIndex = 0; siteIndex < db.directSites.size(); ++siteIndex) {
    const DirectSite &site = db.directSites[siteIndex];
    if (!db.directSiteHasPointerFlow(site))
      continue;
    ++census.originalSites;
    ActualSignature signature = buildSignature(site);
    FnState &state = perFunction[site.calleeFunction];
    if (auto it = state.bySignature.find(signature); it != state.bySignature.end()) {
      signatureOf[siteIndex] = it->second;
      ++census.equivalenceMerged;
      continue;
    }
    if (state.bySignature.size() < budget) {
      uint32_t id = nextId++;
      state.bySignature.emplace(std::move(signature), id);
      signatureOf[siteIndex] = id;
      ++census.uniqueSignatures;
    } else {
      if (state.overflowId == NONE) {
        state.overflowId = nextId++;
        ++census.overflowFunctions;
      }
      signatureOf[siteIndex] = state.overflowId;
      ++census.overflowMerged;
    }
  }
  census.contextsCreated = census.uniqueSignatures + census.overflowFunctions;
  return signatureOf;
}

struct BootstrapCensus {
  uint64_t sites = 0;
  uint64_t dedicatedContexts = 0;
  uint64_t overflowFunctions = 0;
  uint64_t overflowSites = 0;
};

// Phase 0 bounded callsite bootstrap: no CI prepass. Per callee, the first `budget` static
// pointer-flow sites (in index order) each get a dedicated context; the rest fold into one
// deterministic per-callee overflow context (union of inputs). Because the resulting
// contexts disable the callee's baseline call transfer, no context-insensitive shared-return
// broadcast is produced, so the Phase-0 solve is bounded and can reach a fixpoint.
std::vector<uint32_t> computeBootstrapContexts(const Database &db, uint32_t budget,
                                               BootstrapCensus &census,
                                               std::vector<uint8_t> *overflowSiteMask = nullptr) {
  std::vector<uint32_t> bootstrapOf(db.directSites.size(), NONE);
  if (overflowSiteMask)
    overflowSiteMask->assign(db.directSites.size(), 0);
  struct FnState {
    uint32_t dedicated = 0;
    uint32_t overflowId = NONE;
  };
  std::unordered_map<uint32_t, FnState> perFunction;
  uint32_t nextId = 0;
  for (uint32_t siteIndex = 0; siteIndex < db.directSites.size(); ++siteIndex) {
    const DirectSite &site = db.directSites[siteIndex];
    if (!db.directSiteHasPointerFlow(site))
      continue;
    ++census.sites;
    FnState &state = perFunction[site.calleeFunction];
    if (state.dedicated < budget) {
      bootstrapOf[siteIndex] = nextId++;
      ++state.dedicated;
      ++census.dedicatedContexts;
    } else {
      if (state.overflowId == NONE) {
        state.overflowId = nextId++;
        ++census.overflowFunctions;
      }
      bootstrapOf[siteIndex] = state.overflowId;
      if (overflowSiteMask)
        (*overflowSiteMask)[siteIndex] = 1;
      ++census.overflowSites;
    }
  }
  return bootstrapOf;
}

// Selective value-context blend. Sites whose callee is in `valueContextFns` are keyed by the
// exact points-to signature of their pointer actuals (bounded to `budget` distinct signatures
// per callee, rest overflow) computed from the prior solve `ci`; every other pointer-flow site
// keeps its bootstrap context. Value-context callee sites are removed from `overflowMask` (they
// carry split flow, not deferred flow). This is the "lazy/selective value-context": only the
// detected value-merge subtree pays the object-set-sensitivity cost, so a mega-fan-in utility
// stays cheap while a device-model chain gets separated by receiver object set. The signature
// ids occupy a disjoint high range so they never collide with bootstrap ids.
std::vector<uint32_t> computeBlendedContexts(const Database &db, const Solver &ci,
                                             const std::unordered_set<uint32_t> &valueContextFns,
                                             uint32_t budget,
                                             std::vector<uint8_t> &overflowMask,
                                             BootstrapCensus &bootCensus,
                                             SignatureCensus &sigCensus) {
  std::vector<uint32_t> contextOf =
      computeBootstrapContexts(db, budget, bootCensus, &overflowMask);
  uint32_t nextId = 0;
  for (uint32_t id : contextOf)
    if (id != NONE)
      nextId = std::max(nextId, id + 1);
  struct FnState {
    std::unordered_map<ActualSignature, uint32_t, ActualSignatureHash> bySignature;
    uint32_t overflowId = NONE;
  };
  std::unordered_map<uint32_t, FnState> perFunction;
  for (uint32_t siteIndex = 0; siteIndex < db.directSites.size(); ++siteIndex) {
    const DirectSite &site = db.directSites[siteIndex];
    if (!db.directSiteHasPointerFlow(site) || !valueContextFns.count(site.calleeFunction))
      continue;
    // This site's callee is value-contexted: replace its bootstrap context with a signature
    // context and un-defer it (it now carries split flow).
    if (siteIndex < overflowMask.size())
      overflowMask[siteIndex] = 0;
    ++sigCensus.originalSites;
    ActualSignature signature = buildActualSignature(db, site, ci);
    FnState &state = perFunction[site.calleeFunction];
    if (auto it = state.bySignature.find(signature); it != state.bySignature.end()) {
      contextOf[siteIndex] = it->second;
      ++sigCensus.equivalenceMerged;
      continue;
    }
    if (state.bySignature.size() < budget) {
      uint32_t id = nextId++;
      state.bySignature.emplace(std::move(signature), id);
      contextOf[siteIndex] = id;
      ++sigCensus.uniqueSignatures;
    } else {
      if (state.overflowId == NONE) {
        state.overflowId = nextId++;
        ++sigCensus.overflowFunctions;
      }
      contextOf[siteIndex] = state.overflowId;
      ++sigCensus.overflowMerged;
    }
  }
  sigCensus.contextsCreated = sigCensus.uniqueSignatures + sigCensus.overflowFunctions;
  return contextOf;
}

// Phase 1: from a converged Phase-0 solve, read each context's contextual formal points-to
// and derive an exact signature; bootstrap contexts of the same callee with identical formal
// signatures merge, so the final Pass uses semantic value-context ids rather than the
// arbitrary first-B bootstrap split. Overflow contexts keep their union (no unproven split).
std::vector<uint32_t> computeSignaturesFromBootstrap(
    const Database &db, const Solver &phase0, const std::vector<uint32_t> &bootstrapOf,
    SignatureCensus &census) {
  // For each context, build the (function, per-formal sorted Pt) signature.
  struct FormalSig {
    std::vector<std::pair<uint32_t, std::vector<ObjKey>>> perFormal;
    bool operator==(const FormalSig &other) const { return perFormal == other.perFormal; }
  };
  struct FormalSigHash {
    size_t operator()(const FormalSig &s) const {
      uint64_t hash = 1469598103934665603ULL;
      for (const auto &[index, objects] : s.perFormal) {
        hash = mix64(hash ^ mix64(index + 1));
        for (const ObjKey &object : objects)
          hash = mix64(hash ^ mix64(object.root) ^
                       mix64(static_cast<uint64_t>(object.region) + 0x9e3779b9ULL) ^
                       mix64(static_cast<uint64_t>(object.offset)));
      }
      return static_cast<size_t>(hash);
    }
  };
  // context id -> merged signature id.
  std::vector<uint32_t> contextMerged(db.contextInfo.size(), NONE);
  struct FnState {
    std::unordered_map<FormalSig, uint32_t, FormalSigHash> bySignature;
  };
  std::unordered_map<uint32_t, FnState> perFunction;
  uint32_t nextId = 0;
  for (uint32_t contextId = 0; contextId < db.contextInfo.size(); ++contextId) {
    const Database::ContextInfo &info = db.contextInfo[contextId];
    auto function = db.functions.find(info.function);
    FormalSig signature;
    if (function != db.functions.end()) {
      // Map each of this context's clones back to the baseline value it represents, then
      // read the clone whose origin is a formal. The callee's formal list gives a stable,
      // per-function canonical ordering, so signatures of the same callee compare directly.
      std::unordered_map<uint32_t, uint32_t> cloneByOrigin;
      for (uint32_t clone = info.baseValue;
           clone < info.baseValue + info.valueCount; ++clone) {
        uint32_t origin = clone < db.contextValueOrigins.size()
                              ? db.contextValueOrigins[clone]
                              : NONE;
        if (origin != NONE)
          cloneByOrigin.emplace(origin, clone);
      }
      for (const auto &[index, formal] : function->second.formals) {
        auto found = cloneByOrigin.find(formal);
        if (found == cloneByOrigin.end())
          continue;
        std::vector<ObjKey> objects;
        phase0.forEachValueObject(found->second,
                                  [&](ObjKey object) { objects.push_back(object); });
        std::sort(objects.begin(), objects.end(), [](const ObjKey &a, const ObjKey &b) {
          if (a.root != b.root) return a.root < b.root;
          if (a.region != b.region) return a.region < b.region;
          return a.offset < b.offset;
        });
        objects.erase(std::unique(objects.begin(), objects.end()), objects.end());
        signature.perFormal.emplace_back(index, std::move(objects));
      }
    }
    FnState &state = perFunction[info.function];
    if (auto it = state.bySignature.find(signature); it != state.bySignature.end()) {
      contextMerged[contextId] = it->second;
      ++census.equivalenceMerged;
    } else {
      uint32_t id = nextId++;
      state.bySignature.emplace(std::move(signature), id);
      contextMerged[contextId] = id;
      ++census.uniqueSignatures;
    }
  }
  // Map each site through its Phase-0 context to the merged signature id.
  std::vector<uint32_t> signatureOf(db.directSites.size(), NONE);
  for (uint32_t siteIndex = 0; siteIndex < db.directSites.size(); ++siteIndex) {
    if (bootstrapOf[siteIndex] == NONE)
      continue;
    ++census.originalSites;
    uint32_t contextId = siteIndex < db.siteContextId.size()
                             ? db.siteContextId[siteIndex]
                             : NONE;
    if (contextId != NONE && contextId < contextMerged.size())
      signatureOf[siteIndex] = contextMerged[contextId];
  }
  census.contextsCreated = census.uniqueSignatures;
  return signatureOf;
}

struct Options {
  fs::path sh = "run/seed_horizon";
  fs::path out = "run/seed_horizon/pointsto/global";
  std::string batch = "all";
  bool keepUnknown = true;
  FieldDynamicPolicy fieldDynamicPolicy = FieldDynamicPolicy::RootDynamic;
  FieldTypePolicy fieldTypePolicy = FieldTypePolicy::All;
  FieldLocationPolicy fieldLocationPolicy = FieldLocationPolicy::RootWide;
  FieldCyclePolicy fieldCyclePolicy = FieldCyclePolicy::Iterate;
  DynamicAliasPolicy dynamicAliasPolicy = DynamicAliasPolicy::None;
  AffineCanonPolicy affineCanonPolicy = AffineCanonPolicy::None;
  uint64_t maxStridedExpansion = 256;
  OffsetPolicy offsetPolicy = OffsetPolicy::Dynamic;
  bool useCopyScc = true;
  bool usePointerSinkSlice = false;
  CallFlowMode callFlowMode = CallFlowMode::Global;
  ContextScope contextScope = ContextScope::Handler;
  ContextModel contextModel = ContextModel::CallString;
  uint32_t contextBudget = 64;
  ContextObjectMode contextObjectMode = ContextObjectMode::Shared;
  uint32_t contextDepth = 1;
  ContextValueSlice contextValueSlice = ContextValueSlice::All;
  uint32_t contextRefineMinContexts = 0;
  uint32_t contextRefineDepth = 1;
  ContextRefinePropagation contextRefinePropagation =
      ContextRefinePropagation::Linear;
  fs::path contextSites;
  fs::path indirectTargets;
  uint64_t maxContexts = 2000000;
  bool writeTuples = true;
  bool writeDerivations = true;
  bool writeCallsiteActivity = false;
  bool selftest = false;
  bool contextCensusOnly = false;
  bool indirectBootstrap = false;
  bool contextMergeCensus = false;
  bool affineMemoryCensus = false;
  bool valueContextRefine = false;
  uint64_t valueContextThreshold = 256;
  uint32_t valueContextMaxIters = 12;
  uint32_t indirectBootstrapMaxRounds = 64;
  uint64_t maxTuples = 0;
};

Options parseOptions(int argc, char **argv) {
  Options options;
  for (int index = 1; index < argc; ++index) {
    std::string argument = argv[index];
    auto value = [&](const char *name) {
      if (index + 1 >= argc)
        throw std::runtime_error(std::string("missing value for ") + name);
      return std::string(argv[++index]);
    };
    if (argument == "--sh") options.sh = value("--sh");
    else if (argument == "--out") options.out = value("--out");
    else if (argument == "--batch") options.batch = value("--batch");
    else if (argument == "--unknown") options.keepUnknown = value("--unknown") != "drop";
    else if (argument == "--field-dynamic") {
      std::string mode = value("--field-dynamic");
      if (mode == "root_dyn")
        options.fieldDynamicPolicy = FieldDynamicPolicy::RootDynamic;
      else if (mode == "drop")
        options.fieldDynamicPolicy = FieldDynamicPolicy::Drop;
      else if (mode == "strided")
        options.fieldDynamicPolicy = FieldDynamicPolicy::Strided;
      else
        throw std::runtime_error("invalid --field-dynamic mode: " + mode);
    }
    else if (argument == "--field-type") {
      std::string mode = value("--field-type");
      if (mode == "all")
        options.fieldTypePolicy = FieldTypePolicy::All;
      else if (mode == "compatible")
        options.fieldTypePolicy = FieldTypePolicy::Compatible;
      else
        throw std::runtime_error("invalid --field-type mode: " + mode);
    }
    else if (argument == "--field-location") {
      std::string mode = value("--field-location");
      if (mode == "root-wide")
        options.fieldLocationPolicy = FieldLocationPolicy::RootWide;
      else if (mode == "subobject")
        options.fieldLocationPolicy = FieldLocationPolicy::Subobject;
      else
        throw std::runtime_error("invalid --field-location mode: " + mode);
    }
    else if (argument == "--field-cycle") {
      std::string mode = value("--field-cycle");
      if (mode == "iterate")
        options.fieldCyclePolicy = FieldCyclePolicy::Iterate;
      else if (mode == "root_dyn")
        options.fieldCyclePolicy = FieldCyclePolicy::RootDynamic;
      else if (mode == "affine")
        options.fieldCyclePolicy = FieldCyclePolicy::Affine;
      else if (mode == "drop")
        options.fieldCyclePolicy = FieldCyclePolicy::Drop;
      else
        throw std::runtime_error("invalid --field-cycle mode: " + mode);
    }
    else if (argument == "--dynamic-alias") {
      std::string mode = value("--dynamic-alias");
      if (mode == "none")
        options.dynamicAliasPolicy = DynamicAliasPolicy::None;
      else if (mode == "root")
        options.dynamicAliasPolicy = DynamicAliasPolicy::Root;
      else
        throw std::runtime_error("invalid --dynamic-alias mode: " + mode);
    }
    else if (argument == "--affine-canon") {
      std::string mode = value("--affine-canon");
      if (mode == "none")
        options.affineCanonPolicy = AffineCanonPolicy::None;
      else if (mode == "subsumption")
        options.affineCanonPolicy = AffineCanonPolicy::Subsumption;
      else
        throw std::runtime_error("invalid --affine-canon mode: " + mode);
    }
    else if (argument == "--max-strided-expansion")
      options.maxStridedExpansion = parseU64(value("--max-strided-expansion"));
    else if (argument == "--no-saturate") options.offsetPolicy = OffsetPolicy::Exact;
    else if (argument == "--offset-overflow") {
      std::string mode = value("--offset-overflow");
      if (mode == "dynamic")
        options.offsetPolicy = OffsetPolicy::Dynamic;
      else if (mode == "drop")
        options.offsetPolicy = OffsetPolicy::Drop;
      else if (mode == "exact")
        options.offsetPolicy = OffsetPolicy::Exact;
      else
        throw std::runtime_error("invalid --offset-overflow mode: " + mode);
    }
    else if (argument == "--copy-scc") options.useCopyScc = value("--copy-scc") != "off";
    else if (argument == "--value-slice")
      options.usePointerSinkSlice = value("--value-slice") != "all";
    else if (argument == "--call-flow") {
      std::string mode = value("--call-flow");
      if (mode == "none")
        options.callFlowMode = CallFlowMode::None;
      else if (mode == "reachable")
        options.callFlowMode = CallFlowMode::Reachable;
      else if (mode == "callsite")
        options.callFlowMode = CallFlowMode::Callsite;
      else if (mode == "global")
        options.callFlowMode = CallFlowMode::Global;
      else
        throw std::runtime_error("invalid --call-flow mode: " + mode);
    }
    else if (argument == "--context-scope") {
      std::string mode = value("--context-scope");
      if (mode == "handler")
        options.contextScope = ContextScope::Handler;
      else if (mode == "global")
        options.contextScope = ContextScope::Global;
      else
        throw std::runtime_error("invalid --context-scope mode: " + mode);
    }
    else if (argument == "--context-model") {
      std::string mode = value("--context-model");
      if (mode == "callstring")
        options.contextModel = ContextModel::CallString;
      else if (mode == "signature")
        options.contextModel = ContextModel::Signature;
      else
        throw std::runtime_error("invalid --context-model mode: " + mode);
    }
    else if (argument == "--context-budget")
      options.contextBudget = static_cast<uint32_t>(std::stoul(value("--context-budget")));
    else if (argument == "--context-objects") {
      std::string mode = value("--context-objects");
      if (mode == "shared")
        options.contextObjectMode = ContextObjectMode::Shared;
      else if (mode == "stack")
        options.contextObjectMode = ContextObjectMode::Stack;
      else
        throw std::runtime_error("invalid --context-objects mode: " + mode);
    }
    else if (argument == "--context-depth")
      options.contextDepth = static_cast<uint32_t>(std::stoul(value("--context-depth")));
    else if (argument == "--context-value-slice") {
      std::string mode = value("--context-value-slice");
      if (mode == "all")
        options.contextValueSlice = ContextValueSlice::All;
      else if (mode == "interface")
        options.contextValueSlice = ContextValueSlice::Interface;
      else if (mode == "escape")
        options.contextValueSlice = ContextValueSlice::Escape;
      else
        throw std::runtime_error("invalid --context-value-slice mode: " + mode);
    }
    else if (argument == "--context-refine-min-contexts")
      options.contextRefineMinContexts = static_cast<uint32_t>(
          std::stoul(value("--context-refine-min-contexts")));
    else if (argument == "--context-refine-depth")
      options.contextRefineDepth = static_cast<uint32_t>(
          std::stoul(value("--context-refine-depth")));
    else if (argument == "--context-refine-propagation") {
      std::string mode = value("--context-refine-propagation");
      if (mode == "linear")
        options.contextRefinePropagation = ContextRefinePropagation::Linear;
      else if (mode == "all")
        options.contextRefinePropagation = ContextRefinePropagation::All;
      else
        throw std::runtime_error("invalid --context-refine-propagation mode: " + mode);
    }
    else if (argument == "--context-sites")
      options.contextSites = value("--context-sites");
    else if (argument == "--indirect-targets")
      options.indirectTargets = value("--indirect-targets");
    else if (argument == "--max-contexts")
      options.maxContexts = std::stoull(value("--max-contexts"));
    else if (argument == "--no-tuples") options.writeTuples = false;
    else if (argument == "--no-derivations") options.writeDerivations = false;
    else if (argument == "--write-callsite-activity")
      options.writeCallsiteActivity = true;
    else if (argument == "--selftest") options.selftest = true;
    else if (argument == "--context-census-only") options.contextCensusOnly = true;
    else if (argument == "--indirect-bootstrap") options.indirectBootstrap = true;
    else if (argument == "--context-merge-census") options.contextMergeCensus = true;
    else if (argument == "--affine-memory-census") options.affineMemoryCensus = true;
    else if (argument == "--value-context-refine") options.valueContextRefine = true;
    else if (argument == "--value-context-threshold")
      options.valueContextThreshold = std::stoull(value("--value-context-threshold"));
    else if (argument == "--value-context-max-iters")
      options.valueContextMaxIters =
          static_cast<uint32_t>(std::stoul(value("--value-context-max-iters")));
    else if (argument == "--indirect-bootstrap-max-rounds")
      options.indirectBootstrapMaxRounds =
          static_cast<uint32_t>(std::stoul(value("--indirect-bootstrap-max-rounds")));
    else if (argument == "--max-tuples") options.maxTuples = std::stoull(value("--max-tuples"));
    else if (argument == "--help") {
      std::cout << "pointsto_global [--sh DIR] [--out DIR] [--batch all|B1,B2] "
                   "[--unknown opaque|drop] [--field-dynamic root_dyn|drop|strided] "
                   "[--field-type all|compatible] "
                   "[--field-location root-wide|subobject] "
                   "[--field-cycle iterate|root_dyn|affine|drop] "
                   "[--dynamic-alias none|root] "
                   "[--affine-canon none|subsumption] "
                   "[--max-strided-expansion N] "
                   "[--offset-overflow dynamic|drop|exact] "
                   "[--copy-scc on|off] [--value-slice all|pointer-sinks] "
                   "[--call-flow global|reachable|callsite|none] "
                   "[--context-scope handler|global] "
                   "[--context-model callstring|signature] "
                   "[--context-budget N] "
                   "[--context-objects shared|stack] "
                   "[--context-depth 1..4] "
                   "[--context-value-slice all|interface|escape] "
                   "[--context-refine-min-contexts N] "
                   "[--context-refine-depth N] "
                   "[--context-refine-propagation linear|all] "
                   "[--context-sites FILE] "
                   "[--indirect-targets FILE] "
                   "[--max-contexts N] "
                   "[--max-tuples N] [--no-tuples] "
                   "[--no-derivations] [--write-callsite-activity] "
                   "[--context-census-only] [--selftest]\n";
      std::exit(0);
    } else {
      throw std::runtime_error("unknown option: " + argument);
    }
  }
  if (options.maxStridedExpansion == 0)
    throw std::runtime_error("--max-strided-expansion must be positive");
  return options;
}

// A discovery round is the fixpoint only if it fully converged (no residual pending tuples, not
// truncated) AND found no new targets AND deferred no flow. Truncation or pending>0 forbids
// completion even when new_targets==0. Crucially, a non-zero deferred_direct_transfers also
// forbids completion: the direct overflow deferral drops flow with no promotion/recovery (an
// under-approximation), so as long as any such transfer is dropped the target set is not proven
// complete. This reaches zero only when selective context refinement replaces the deferral.
inline bool indirectBootstrapComplete(uint64_t newTargets, uint64_t deferredPairs,
                                      uint64_t deferredDirectTransfers,
                                      uint64_t pendingTuples, bool truncated) {
  return newTargets == 0 && deferredPairs == 0 && deferredDirectTransfers == 0 &&
         pendingTuples == 0 && !truncated;
}

int runSelftest() {
  Database database(true);
  uint32_t table = database.objects.intern("sym:object:global:selftest_table", 256,
                                           ObjectKind::Other, "-", true,
                                           "selftest_table,selftest_embedded");
  uint32_t source = database.objects.intern("sym:object:global:selftest_source", 64,
                                            ObjectKind::Other, "-", true,
                                            "selftest_source");
  uint32_t destination = database.objects.intern("sym:object:global:selftest_destination", 64,
                                                 ObjectKind::Other);
  uint32_t argument = database.objects.intern("sym:object:global:selftest_argument", 8,
                                              ObjectKind::Other);
  uint32_t returned = database.objects.intern("sym:object:global:selftest_return", 8,
                                              ObjectKind::Other);
  uint32_t function = database.objects.intern("sym:object:function:selftest_handler", 0,
                                              ObjectKind::Function, "selftest_handler");
  uint32_t affineStoreFunction = database.objects.intern(
      "sym:object:function:selftest_affine_store_handler", 0,
      ObjectKind::Function, "selftest_affine_store_handler");
  uint32_t rootObject = database.objects.intern("seed:object:selftest_root", 0,
                                                ObjectKind::Synthetic);
  auto value = [&](const char *name) { return database.value(name); };
  uint32_t vTable = value("selftest:value:table");
  uint32_t vSource = value("selftest:value:source");
  uint32_t vDestination = value("selftest:value:destination");
  uint32_t vFunction = value("selftest:value:function");
  uint32_t vAffineStoreFunction = value("selftest:value:affine_store_function");
  uint32_t vArgument = value("selftest:value:argument");
  uint32_t vReturned = value("selftest:value:returned");
  uint32_t field80 = value("selftest:value:field80");
  uint32_t parent = value("selftest:value:parent");
  uint32_t outOfBounds = value("selftest:value:out_of_bounds");
  uint32_t strided = value("selftest:value:strided");
  uint32_t stridedNegative = value("selftest:value:strided_negative");
  uint32_t stridedOverLimit = value("selftest:value:strided_over_limit");
  uint32_t unresolvedDynamic = value("selftest:value:unresolved_dynamic");
  uint32_t typedMatch = value("selftest:value:typed_match");
  uint32_t typedMismatch = value("selftest:value:typed_mismatch");
  uint32_t typedUnknown = value("selftest:value:typed_unknown");
  uint32_t cyclePhi = value("selftest:value:cycle_phi");
  uint32_t cycleNext = value("selftest:value:cycle_next");
  uint32_t stridedCyclePhi = value("selftest:value:strided_cycle_phi");
  uint32_t stridedCycleNext = value("selftest:value:strided_cycle_next");
  uint32_t dynamicPointer = value("selftest:value:dynamic_pointer");
  uint32_t dynamicLoaded = value("selftest:value:dynamic_loaded");
  uint32_t concretePointer = value("selftest:value:concrete_pointer");
  uint32_t concreteLoaded = value("selftest:value:concrete_loaded");
  uint32_t affineShifted = value("selftest:value:affine_shifted");
  uint32_t affineClipped = value("selftest:value:affine_clipped");
  uint32_t affineShiftedLoaded = value("selftest:value:affine_shifted_loaded");
  uint32_t affineLoaded = value("selftest:value:affine_loaded");
  uint32_t affineOutsidePointer = value("selftest:value:affine_outside_pointer");
  uint32_t affineOutsideLoaded = value("selftest:value:affine_outside_loaded");
  uint32_t callee = value("selftest:value:callee");
  uint32_t formal = value("selftest:value:formal");
  uint32_t result = value("selftest:value:result");
  uint64_t synthetic = sourceRef(SourceTable::Synthetic, 1);
  uint32_t tableStruct = database.objects.internStruct("selftest_table");
  database.addressSeeds = {
      {vTable, table, 0, synthetic, Rule::AddressOf},
      {vSource, source, 0, synthetic, Rule::AddressOf},
      {vDestination, destination, 0, synthetic, Rule::AddressOf},
      {vFunction, function, 0, synthetic, Rule::AddressOf},
      {vAffineStoreFunction, affineStoreFunction, 0, synthetic, Rule::AddressOf},
      {vArgument, argument, 0, synthetic, Rule::AddressOf},
      {vReturned, returned, 0, synthetic, Rule::AddressOf},
      {cyclePhi, source, 0, synthetic, Rule::AddressOf},
      {stridedCyclePhi, source, 0, synthetic, Rule::AddressOf},
      {dynamicPointer, source, DYN_OFFSET, synthetic, Rule::AddressOf},
      {concretePointer, source, 24, synthetic, Rule::AddressOf},
      {affineOutsidePointer, source, 20, synthetic, Rule::AddressOf},
  };
  database.copies = {
      {cycleNext, cyclePhi, synthetic, Rule::Copy},
      {stridedCycleNext, stridedCyclePhi, synthetic, Rule::Copy},
  };
  database.fields = {
      {vTable, field80, 80, synthetic},
      {field80, parent, -80, synthetic},
      {vTable, outOfBounds, 512, synthetic},
      {vTable, typedMatch, 0, synthetic, tableStruct},
      {vSource, typedMismatch, 0, synthetic, tableStruct},
      {vArgument, typedUnknown, 0, synthetic, tableStruct},
      {cyclePhi, cycleNext, 8, synthetic},
      {cycleNext, affineShifted, 4, synthetic},
      {cycleNext, affineClipped, 24, synthetic},
  };
  database.stridedFields = {
      {vTable, strided, 8, 16, 4, synthetic},
      {vTable, stridedNegative, 56, -16, 4, synthetic},
      {vTable, stridedOverLimit, 0, 8, 5, synthetic},
      {stridedCyclePhi, stridedCycleNext, 8, 8, 4, synthetic},
  };
  database.dynamicFields = {{vTable, unresolvedDynamic, synthetic}};
  database.storeObjects = {
      {table, vFunction, 80, synthetic},
      {source, vFunction, 16, synthetic},
  };
  database.loads = {{field80, callee, synthetic}};
  database.loads.push_back({dynamicPointer, dynamicLoaded, synthetic});
  database.loads.push_back({concretePointer, concreteLoaded, synthetic});
  database.loads.push_back({cycleNext, affineLoaded, synthetic});
  database.loads.push_back({affineShifted, affineShiftedLoaded, synthetic});
  database.loads.push_back({affineOutsidePointer, affineOutsideLoaded, synthetic});
  database.stores.push_back({dynamicPointer, vFunction, synthetic});
  database.stores.push_back({cycleNext, vAffineStoreFunction, synthetic});
  database.memoryCopies = {{vDestination, vSource, 32, synthetic}};
  database.functions[function].formals.push_back({0, formal});
  database.functions[function].returns.push_back(vReturned);
  database.indirectActuals.push_back({0, vArgument, synthetic});
  uint32_t callsite = database.callsiteNames.intern("selftest:callsite");
  database.indirectSites.push_back(
      {callsite, function, NONE, callee, 0, 1, result, synthetic});
  uint32_t rootName = database.rootNames.intern("resource:selftest");
  uint32_t rootValue = value("seed:value:root:resource:selftest");
  database.rootSeeds.push_back({rootName, rootValue, rootObject, table, synthetic});
  database.namedSummaries.push_back({table, database.summaryKeys.intern("ioctl"),
                                     database.handlerNames.intern("selftest_handler"), synthetic});

  Solver solver(database, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
                CallFlowMode::Global, nullptr, nullptr, 0);
  solver.solve();
  Solver dropOffsetSolver(database, FieldDynamicPolicy::RootDynamic,
                          FieldTypePolicy::All, FieldCyclePolicy::Iterate, 256,
                          OffsetPolicy::Drop, true, false,
                          CallFlowMode::Global, nullptr, nullptr, 0);
  dropOffsetSolver.solve();
  Solver exactOffsetSolver(database, FieldDynamicPolicy::RootDynamic,
                           FieldTypePolicy::All, FieldCyclePolicy::Iterate, 256,
                           OffsetPolicy::Exact, true, false,
                           CallFlowMode::Global, nullptr, nullptr, 0);
  exactOffsetSolver.solve();
  Solver stridedSolver(database, FieldDynamicPolicy::Strided, FieldTypePolicy::All,
                       FieldCyclePolicy::Iterate, 4, OffsetPolicy::Exact, true, false,
                       CallFlowMode::Global, nullptr, nullptr, 0);
  stridedSolver.solve();
  Solver compatibleTypeSolver(database, FieldDynamicPolicy::RootDynamic,
                              FieldTypePolicy::Compatible, FieldCyclePolicy::Iterate, 256,
                              OffsetPolicy::Dynamic, true, false,
                              CallFlowMode::Global, nullptr, nullptr, 0);
  compatibleTypeSolver.solve();
  Solver dropCycleSolver(database, FieldDynamicPolicy::RootDynamic,
                         FieldTypePolicy::All, FieldCyclePolicy::Drop, 256,
                         OffsetPolicy::Drop, true, false, CallFlowMode::Global,
                         nullptr, nullptr, 0);
  dropCycleSolver.solve();
  Solver rootDynamicCycleSolver(database, FieldDynamicPolicy::Strided,
                                FieldTypePolicy::All,
                                FieldCyclePolicy::RootDynamic, 256,
                                OffsetPolicy::Exact, true, false,
                                CallFlowMode::Global, nullptr, nullptr, 0);
  rootDynamicCycleSolver.solve();
  Solver dynamicAliasSolver(database, FieldDynamicPolicy::RootDynamic,
                            FieldTypePolicy::All, FieldCyclePolicy::Iterate, 256,
                            OffsetPolicy::Dynamic, true, false,
                            CallFlowMode::Global, nullptr, nullptr, 0,
                            DynamicAliasPolicy::Root);
  dynamicAliasSolver.solve();
  Solver affineCycleSolver(database, FieldDynamicPolicy::Strided,
                           FieldTypePolicy::All, FieldCyclePolicy::Affine, 4,
                           OffsetPolicy::Drop, true, false,
                           CallFlowMode::Global, nullptr, nullptr, 0);
  affineCycleSolver.solve();

  Database affineMathDatabase(true);
  uint32_t affineMathObject = affineMathDatabase.objects.intern(
      "sym:object:global:selftest_affine_math", 64, ObjectKind::Other);
  auto affineMathValue = [&](const char *name) { return affineMathDatabase.value(name); };
  uint32_t negativePhi = affineMathValue("selftest:affine:negative_phi");
  uint32_t negativeNext = affineMathValue("selftest:affine:negative_next");
  uint32_t mixedPhi = affineMathValue("selftest:affine:mixed_phi");
  uint32_t mixedNext = affineMathValue("selftest:affine:mixed_next");
  affineMathDatabase.addressSeeds = {
      {negativePhi, affineMathObject, 56, synthetic, Rule::AddressOf},
      {mixedPhi, affineMathObject, 0, synthetic, Rule::AddressOf},
  };
  affineMathDatabase.copies = {
      {negativeNext, negativePhi, synthetic, Rule::Copy},
      {mixedNext, mixedPhi, synthetic, Rule::Copy},
  };
  affineMathDatabase.fields = {
      {negativePhi, negativeNext, -8, synthetic},
  };
  affineMathDatabase.stridedFields = {
      {mixedPhi, mixedNext, -8, 8, 3, synthetic},
  };
  Solver affineMathSolver(affineMathDatabase, FieldDynamicPolicy::Strided,
                          FieldTypePolicy::All, FieldCyclePolicy::Affine, 8,
                          OffsetPolicy::Drop, true, false,
                          CallFlowMode::Global, nullptr, nullptr, 0);
  affineMathSolver.solve();

  Database contextDatabase(true);
  uint32_t contextCaller = contextDatabase.objects.intern(
      "sym:object:function:selftest_context_caller", 0, ObjectKind::Function,
      "selftest_context_caller");
  uint32_t contextCallee = contextDatabase.objects.intern(
      "sym:object:function:selftest_context_callee", 0, ObjectKind::Function,
      "selftest_context_callee");
  uint32_t contextObjectA = contextDatabase.objects.intern(
      "sym:object:global:selftest_context_a", 8, ObjectKind::Other);
  uint32_t contextObjectB = contextDatabase.objects.intern(
      "sym:object:global:selftest_context_b", 8, ObjectKind::Other);
  auto ownedValue = [&](const char *name, uint32_t owner) {
    uint32_t id = contextDatabase.value(name);
    contextDatabase.valueOwners[id] = owner;
    return id;
  };
  uint32_t contextActualA = ownedValue("selftest:context:actual_a", contextCaller);
  uint32_t contextActualB = ownedValue("selftest:context:actual_b", contextCaller);
  uint32_t contextFormal = ownedValue("selftest:context:formal", contextCallee);
  contextDatabase.addressSeeds = {
      {contextActualA, contextObjectA, 0, synthetic, Rule::AddressOf},
      {contextActualB, contextObjectB, 0, synthetic, Rule::AddressOf},
  };
  contextDatabase.functions[contextCallee].formals.push_back({0, contextFormal});
  contextDatabase.directActuals = {
      {0, contextActualA, synthetic},
      {0, contextActualB, synthetic},
  };
  uint32_t contextSiteA = contextDatabase.callsiteNames.intern("selftest:context:site_a");
  uint32_t contextSiteB = contextDatabase.callsiteNames.intern("selftest:context:site_b");
  contextDatabase.directSites = {
      {contextSiteA, contextCaller, contextCallee, 0, 1, NONE, synthetic},
      {contextSiteB, contextCaller, contextCallee, 1, 1, NONE, synthetic},
  };
  contextDatabase.wireStaticCall(
      contextCaller, contextCallee,
      std::vector<Actual>{contextDatabase.directActuals[0]}, NONE, synthetic, 0);
  contextDatabase.wireStaticCall(
      contextCaller, contextCallee,
      std::vector<Actual>{contextDatabase.directActuals[1]}, NONE, synthetic, 1);
  contextDatabase.handlerRootFunctions.insert(contextCaller);
  contextDatabase.handlerReachableFunctions.insert(contextCaller);
  contextDatabase.handlerReachableFunctions.insert(contextCallee);
  uint32_t contextStack = contextDatabase.objects.intern(
      "selftest:context:stack", 8, ObjectKind::Stack);
  if (contextDatabase.objectOwners.size() < contextDatabase.objects.size())
    contextDatabase.objectOwners.resize(contextDatabase.objects.size(), NONE);
  contextDatabase.objectOwners[contextStack] = contextCallee;
  uint32_t contextStackPointer = ownedValue("selftest:context:stack_pointer", contextCallee);
  uint32_t contextLoaded = ownedValue("selftest:context:loaded", contextCallee);
  contextDatabase.addressSeeds.push_back(
      {contextStackPointer, contextStack, 0, synthetic, Rule::AddressOf});
  contextDatabase.stores.push_back({contextStackPointer, contextFormal, synthetic});
  contextDatabase.loads.push_back({contextStackPointer, contextLoaded, synthetic});
  uint32_t contextOriginalValueCount = static_cast<uint32_t>(contextDatabase.values.size());
  contextDatabase.materializeCallsiteContexts(
      ContextScope::Handler, ContextObjectMode::Stack, 1,
      ContextValueSlice::Interface, 0, 1,
      ContextRefinePropagation::Linear, nullptr, 1000);
  std::unordered_set<uint32_t> contextualFormals;
  for (const CopyConstraint &constraint : contextDatabase.copies)
    if (constraint.rule == Rule::CallArgument &&
        constraint.dst >= contextOriginalValueCount)
      contextualFormals.insert(constraint.dst);
  Solver contextSolver(contextDatabase, FieldDynamicPolicy::RootDynamic,
                       FieldTypePolicy::All, FieldCyclePolicy::Iterate, 256,
                       OffsetPolicy::Dynamic, true, false,
                       CallFlowMode::Callsite, nullptr, nullptr, 0);
  contextSolver.solve();
  bool contextsIsolated = contextualFormals.size() == 2;
  for (uint32_t formalValue : contextualFormals) {
    bool hasA = contextSolver.containsValue(formalValue, {contextObjectA, 0});
    bool hasB = contextSolver.containsValue(formalValue, {contextObjectB, 0});
    contextsIsolated = contextsIsolated && (hasA != hasB);
  }
  // Both callsites are selected, so their baseline CALL_ARGUMENT is disabled and the
  // shared baseline formal must stay inactive; the flow lives only in the per-site
  // contextual clones asserted by contextsIsolated above.
  bool baselineContextInactive =
      !contextSolver.containsValue(contextFormal, {contextObjectA, 0}) &&
      !contextSolver.containsValue(contextFormal, {contextObjectB, 0});
  std::unordered_set<uint32_t> contextualLoads;
  for (const SimpleConstraint &constraint : contextDatabase.loads)
    if (constraint.second >= contextOriginalValueCount)
      contextualLoads.insert(constraint.second);
  bool stackContextsIsolated = contextualLoads.size() == 2;
  for (uint32_t loadedValue : contextualLoads) {
    bool hasA = contextSolver.containsValue(loadedValue, {contextObjectA, 0});
    bool hasB = contextSolver.containsValue(loadedValue, {contextObjectB, 0});
    stackContextsIsolated = stackContextsIsolated && (hasA != hasB);
  }
  // The helper's stack load derives from the baseline formal, which is inactive for a
  // selected site, so the baseline load result must be inactive as well.
  bool baselineStackInactive =
      !contextSolver.containsValue(contextLoaded, {contextObjectA, 0}) &&
      !contextSolver.containsValue(contextLoaded, {contextObjectB, 0});

  struct NestedContextResult {
    bool merged;
    bool isolated;
    bool baselineInactive;
    bool refinementAccounting;
  };
  auto runNestedContext = [&](uint32_t refineMinContexts) {
    Database nested(true);
    uint32_t outer = nested.objects.intern(
        "sym:object:function:selftest_nested_outer", 0, ObjectKind::Function,
        "selftest_nested_outer");
    uint32_t middle = nested.objects.intern(
        "sym:object:function:selftest_nested_middle", 0, ObjectKind::Function,
        "selftest_nested_middle");
    uint32_t bridge = nested.objects.intern(
        "sym:object:function:selftest_nested_bridge", 0, ObjectKind::Function,
        "selftest_nested_bridge");
    uint32_t leaf = nested.objects.intern(
        "sym:object:function:selftest_nested_leaf", 0, ObjectKind::Function,
        "selftest_nested_leaf");
    uint32_t objectA = nested.objects.intern(
        "sym:object:global:selftest_nested_a", 8, ObjectKind::Other);
    uint32_t objectB = nested.objects.intern(
        "sym:object:global:selftest_nested_b", 8, ObjectKind::Other);
    auto nestedValue = [&](const char *name, uint32_t owner) {
      uint32_t id = nested.value(name);
      nested.valueOwners[id] = owner;
      return id;
    };
    uint32_t actualA = nestedValue("selftest:nested:actual_a", outer);
    uint32_t actualB = nestedValue("selftest:nested:actual_b", outer);
    uint32_t middleFormal = nestedValue("selftest:nested:middle_formal", middle);
    uint32_t bridgeFormal = nestedValue("selftest:nested:bridge_formal", bridge);
    uint32_t leafFormal = nestedValue("selftest:nested:leaf_formal", leaf);
    nested.addressSeeds = {
        {actualA, objectA, 0, synthetic, Rule::AddressOf},
        {actualB, objectB, 0, synthetic, Rule::AddressOf},
    };
    nested.functions[middle].formals.push_back({0, middleFormal});
    nested.functions[bridge].formals.push_back({0, bridgeFormal});
    nested.functions[leaf].formals.push_back({0, leafFormal});
    nested.directActuals = {
        {0, actualA, synthetic},
        {0, actualB, synthetic},
        {0, middleFormal, synthetic},
        {0, bridgeFormal, synthetic},
    };
    uint32_t outerSiteA = nested.callsiteNames.intern("selftest:nested:outer_a");
    uint32_t outerSiteB = nested.callsiteNames.intern("selftest:nested:outer_b");
    uint32_t middleSite = nested.callsiteNames.intern("selftest:nested:middle_bridge");
    uint32_t bridgeSite = nested.callsiteNames.intern("selftest:nested:bridge_leaf");
    nested.directSites = {
        {outerSiteA, outer, middle, 0, 1, NONE, synthetic},
        {outerSiteB, outer, middle, 1, 1, NONE, synthetic},
        {middleSite, middle, bridge, 2, 1, NONE, synthetic},
        {bridgeSite, bridge, leaf, 3, 1, NONE, synthetic},
    };
    nested.wireStaticCall(
        outer, middle, std::vector<Actual>{nested.directActuals[0]}, NONE, synthetic, 0);
    nested.wireStaticCall(
        outer, middle, std::vector<Actual>{nested.directActuals[1]}, NONE, synthetic, 1);
    nested.wireStaticCall(
        middle, bridge, std::vector<Actual>{nested.directActuals[2]}, NONE, synthetic, 2);
    nested.wireStaticCall(
        bridge, leaf, std::vector<Actual>{nested.directActuals[3]}, NONE, synthetic, 3);
    nested.handlerRootFunctions.insert(outer);
    nested.handlerReachableFunctions.insert(outer);
    nested.handlerReachableFunctions.insert(middle);
    nested.handlerReachableFunctions.insert(bridge);
    nested.handlerReachableFunctions.insert(leaf);
    nested.materializeCallsiteContexts(ContextScope::Handler,
                                       ContextObjectMode::Shared, 1,
                                       ContextValueSlice::Interface,
                                       refineMinContexts, 2,
                                       ContextRefinePropagation::Linear, nullptr, 1000);
    Solver nestedSolver(nested, FieldDynamicPolicy::RootDynamic,
                        FieldTypePolicy::All, FieldCyclePolicy::Iterate, 256,
                        OffsetPolicy::Dynamic, true, false,
                        CallFlowMode::Callsite, nullptr, nullptr, 0);
    nestedSolver.solve();

    std::unordered_set<uint32_t> leafFormals;
    for (const CopyConstraint &constraint : nested.copies) {
      if (constraint.rule != Rule::CallArgument)
        continue;
      uint32_t origin = constraint.dst < nested.contextValueOrigins.size()
                            ? nested.contextValueOrigins[constraint.dst]
                            : NONE;
      if (origin == leafFormal)
        leafFormals.insert(constraint.dst);
    }
    bool merged = leafFormals.size() == 1;
    bool isolated = leafFormals.size() == 2;
    for (uint32_t formal : leafFormals) {
      bool hasA = nestedSolver.containsValue(formal, {objectA, 0});
      bool hasB = nestedSolver.containsValue(formal, {objectB, 0});
      merged = merged && hasA && hasB;
      isolated = isolated && (hasA != hasB);
    }
    bool accounting = nested.counts.refinedContextFunctions == 1 &&
                      nested.counts.refinedContextConeFunctions == 2 &&
                      nested.counts.refinedContextTransitions == 4;
    // The bridge->leaf site is selected, so the leaf's baseline formal is disabled
    // and must not receive either object through the context-insensitive path.
    bool baselineInactive =
        !nestedSolver.containsValue(leafFormal, {objectA, 0}) &&
        !nestedSolver.containsValue(leafFormal, {objectB, 0});
    return NestedContextResult{merged, isolated, baselineInactive, accounting};
  };
  NestedContextResult nestedK1 = runNestedContext(0);
  NestedContextResult nestedAdaptive = runNestedContext(2);

  Database globalCallsiteDatabase(true);
  uint32_t globalCaller = globalCallsiteDatabase.objects.intern(
      "sym:object:function:selftest_global_caller", 0, ObjectKind::Function,
      "selftest_global_caller");
  uint32_t globalDirectCallee = globalCallsiteDatabase.objects.intern(
      "sym:object:function:selftest_global_direct_callee", 0, ObjectKind::Function,
      "selftest_global_direct_callee");
  uint32_t globalIndirectCallee = globalCallsiteDatabase.objects.intern(
      "sym:object:function:selftest_global_indirect_callee", 0, ObjectKind::Function,
      "selftest_global_indirect_callee");
  uint32_t globalObjectA = globalCallsiteDatabase.objects.intern(
      "sym:object:global:selftest_global_a", 8, ObjectKind::Other);
  uint32_t globalObjectB = globalCallsiteDatabase.objects.intern(
      "sym:object:global:selftest_global_b", 8, ObjectKind::Other);
  auto globalValue = [&](const char *name, uint32_t owner) {
    uint32_t id = globalCallsiteDatabase.value(name);
    globalCallsiteDatabase.valueOwners[id] = owner;
    return id;
  };
  uint32_t globalDirectActual = globalValue("selftest:global:direct_actual", globalCaller);
  uint32_t globalDirectFormal = globalValue(
      "selftest:global:direct_formal", globalDirectCallee);
  uint32_t globalIndirectActual = globalValue(
      "selftest:global:indirect_actual", globalCaller);
  uint32_t globalIndirectFormal = globalValue(
      "selftest:global:indirect_formal", globalIndirectCallee);
  uint32_t globalCalleeValue = globalValue("selftest:global:callee", globalCaller);
  globalCallsiteDatabase.addressSeeds = {
      {globalDirectActual, globalObjectA, 0, synthetic, Rule::AddressOf},
      {globalIndirectActual, globalObjectB, 0, synthetic, Rule::AddressOf},
      {globalCalleeValue, globalIndirectCallee, 0, synthetic, Rule::AddressOf},
  };
  globalCallsiteDatabase.functions[globalDirectCallee].formals.push_back(
      {0, globalDirectFormal});
  globalCallsiteDatabase.functions[globalIndirectCallee].formals.push_back(
      {0, globalIndirectFormal});
  globalCallsiteDatabase.directActuals = {{0, globalDirectActual, synthetic}};
  uint32_t globalDirectSite = globalCallsiteDatabase.callsiteNames.intern(
      "selftest:global:direct_site");
  globalCallsiteDatabase.directSites = {
      {globalDirectSite, globalCaller, globalDirectCallee, 0, 1, NONE, synthetic},
  };
  globalCallsiteDatabase.wireStaticCall(
      globalCaller, globalDirectCallee, globalCallsiteDatabase.directActuals,
      NONE, synthetic, 0);
  globalCallsiteDatabase.indirectActuals = {{0, globalIndirectActual, synthetic}};
  uint32_t globalIndirectSite = globalCallsiteDatabase.callsiteNames.intern(
      "selftest:global:indirect_site");
  globalCallsiteDatabase.indirectSites.push_back(
      {globalIndirectSite, globalCaller, NONE, globalCalleeValue, 0, 1, NONE,
       synthetic});
  globalCallsiteDatabase.materializeCallsiteContexts(
      ContextScope::Global, ContextObjectMode::Shared, 1,
      ContextValueSlice::Interface, 0, 1,
      ContextRefinePropagation::Linear, nullptr, 1000);
  Solver globalCallsiteSolver(
      globalCallsiteDatabase, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
      FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
      CallFlowMode::Callsite, nullptr, nullptr, 0);
  globalCallsiteSolver.solve();

  // Global scope selects the out-of-cone direct site, so its baseline formal is disabled
  // while the baseline caller still reaches the callee through the contextual formal clone.
  auto contextualFormalHasObject = [](const Database &db, const Solver &solver,
                                      uint32_t originFormal, ObjKey object) {
    for (const CopyConstraint &constraint : db.copies) {
      if (constraint.rule != Rule::CallArgument)
        continue;
      uint32_t origin = constraint.dst < db.contextValueOrigins.size()
                            ? db.contextValueOrigins[constraint.dst]
                            : NONE;
      if (origin == originFormal && solver.containsValue(constraint.dst, object))
        return true;
    }
    return false;
  };
  auto functionHasContextualFormal = [](const Database &db, uint32_t originFormal) {
    for (const CopyConstraint &constraint : db.copies) {
      if (constraint.rule != Rule::CallArgument)
        continue;
      uint32_t origin = constraint.dst < db.contextValueOrigins.size()
                            ? db.contextValueOrigins[constraint.dst]
                            : NONE;
      if (origin == originFormal)
        return true;
    }
    return false;
  };
  bool globalDirectBaselineInactive =
      !globalCallsiteSolver.containsValue(globalDirectFormal, {globalObjectA, 0});
  bool globalDirectContextual = contextualFormalHasObject(
      globalCallsiteDatabase, globalCallsiteSolver, globalDirectFormal,
      {globalObjectA, 0});

  // A database with one selected and one unselected direct site: the unselected site keeps
  // its context-insensitive baseline flow, while the selected site is contextualized and
  // leaves its baseline formal inactive. This exercises the mixed callsite semantics.
  Database mixedDatabase(true);
  uint32_t mixedCaller = mixedDatabase.objects.intern(
      "sym:object:function:selftest_mixed_caller", 0, ObjectKind::Function,
      "selftest_mixed_caller");
  uint32_t mixedSelCallee = mixedDatabase.objects.intern(
      "sym:object:function:selftest_mixed_selected_callee", 0, ObjectKind::Function,
      "selftest_mixed_selected_callee");
  uint32_t mixedUnselCallee = mixedDatabase.objects.intern(
      "sym:object:function:selftest_mixed_unselected_callee", 0, ObjectKind::Function,
      "selftest_mixed_unselected_callee");
  uint32_t mixedObjectSel = mixedDatabase.objects.intern(
      "sym:object:global:selftest_mixed_selected", 8, ObjectKind::Other);
  uint32_t mixedObjectUnsel = mixedDatabase.objects.intern(
      "sym:object:global:selftest_mixed_unselected", 8, ObjectKind::Other);
  auto mixedValue = [&](const char *name, uint32_t owner) {
    uint32_t id = mixedDatabase.value(name);
    mixedDatabase.valueOwners[id] = owner;
    return id;
  };
  uint32_t mixedActualSel = mixedValue("selftest:mixed:actual_selected", mixedCaller);
  uint32_t mixedActualUnsel = mixedValue("selftest:mixed:actual_unselected", mixedCaller);
  uint32_t mixedFormalSel = mixedValue("selftest:mixed:formal_selected", mixedSelCallee);
  uint32_t mixedFormalUnsel =
      mixedValue("selftest:mixed:formal_unselected", mixedUnselCallee);
  mixedDatabase.addressSeeds = {
      {mixedActualSel, mixedObjectSel, 0, synthetic, Rule::AddressOf},
      {mixedActualUnsel, mixedObjectUnsel, 0, synthetic, Rule::AddressOf},
  };
  mixedDatabase.functions[mixedSelCallee].formals.push_back({0, mixedFormalSel});
  mixedDatabase.functions[mixedUnselCallee].formals.push_back({0, mixedFormalUnsel});
  mixedDatabase.directActuals = {
      {0, mixedActualSel, synthetic},
      {0, mixedActualUnsel, synthetic},
  };
  uint32_t mixedSelSite = mixedDatabase.callsiteNames.intern("selftest:mixed:selected_site");
  uint32_t mixedUnselSite =
      mixedDatabase.callsiteNames.intern("selftest:mixed:unselected_site");
  mixedDatabase.directSites = {
      {mixedSelSite, mixedCaller, mixedSelCallee, 0, 1, NONE, synthetic},
      {mixedUnselSite, mixedCaller, mixedUnselCallee, 1, 1, NONE, synthetic},
  };
  mixedDatabase.wireStaticCall(
      mixedCaller, mixedSelCallee,
      std::vector<Actual>{mixedDatabase.directActuals[0]}, NONE, synthetic, 0);
  mixedDatabase.wireStaticCall(
      mixedCaller, mixedUnselCallee,
      std::vector<Actual>{mixedDatabase.directActuals[1]}, NONE, synthetic, 1);
  mixedDatabase.handlerRootFunctions.insert(mixedCaller);
  mixedDatabase.handlerReachableFunctions.insert(mixedCaller);
  mixedDatabase.handlerReachableFunctions.insert(mixedSelCallee);
  mixedDatabase.handlerReachableFunctions.insert(mixedUnselCallee);
  std::vector<uint8_t> mixedEnabledSites = {1, 0};
  mixedDatabase.materializeCallsiteContexts(
      ContextScope::Handler, ContextObjectMode::Shared, 1,
      ContextValueSlice::Interface, 0, 1, ContextRefinePropagation::Linear,
      &mixedEnabledSites, 1000);
  Solver mixedSolver(mixedDatabase, FieldDynamicPolicy::RootDynamic,
                     FieldTypePolicy::All, FieldCyclePolicy::Iterate, 256,
                     OffsetPolicy::Dynamic, true, false,
                     CallFlowMode::Callsite, nullptr, nullptr, 0);
  mixedSolver.solve();
  bool mixedSelectedBaselineInactive =
      !mixedSolver.containsValue(mixedFormalSel, {mixedObjectSel, 0});
  bool mixedSelectedContextual = contextualFormalHasObject(
      mixedDatabase, mixedSolver, mixedFormalSel, {mixedObjectSel, 0});
  bool mixedUnselectedBaselineActive =
      mixedSolver.containsValue(mixedFormalUnsel, {mixedObjectUnsel, 0});
  bool mixedUnselectedNoClone =
      !functionHasContextualFormal(mixedDatabase, mixedFormalUnsel);
  bool mixedAccounting =
      mixedDatabase.counts.contextEligibleDirectSites == 1 &&
      mixedDatabase.counts.contextSkippedDirectSites == 1;

  // --- Signature (value-context) model tests -------------------------------------------
  // Runs a context-insensitive baseline, derives per-site signatures, materializes
  // signature-keyed contexts, then solves. Returns the census; the database is left with
  // contexts materialized so callers can inspect the resulting clones.
  auto solveSignature = [&](Database &db, uint32_t budget, SignatureCensus &census) {
    Solver ci(db, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
              FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
              CallFlowMode::Global, nullptr, nullptr, 0);
    ci.solve();
    std::vector<uint32_t> sigOf = computeSignatureContexts(db, ci, budget, census);
    db.materializeCallsiteContexts(ContextScope::Global, ContextObjectMode::Shared, 1,
                                   ContextValueSlice::Interface, 0, 1,
                                   ContextRefinePropagation::Linear, nullptr, 10000, &sigOf);
  };
  auto formalClones = [&](const Database &db, uint32_t originFormal) {
    std::unordered_set<uint32_t> clones;
    for (const CopyConstraint &c : db.copies)
      if (c.rule == Rule::CallArgument && c.dst < db.contextValueOrigins.size() &&
          db.contextValueOrigins[c.dst] == originFormal)
        clones.insert(c.dst);
    return clones;
  };
  auto buildSharedTarget = [&](Database &db, uint32_t &caller, uint32_t &target,
                               uint32_t &formal, const std::string &tag) {
    caller = db.objects.intern("sym:object:function:" + tag + "_caller", 0,
                               ObjectKind::Function, tag + "_caller");
    target = db.objects.intern("sym:object:function:" + tag + "_target", 0,
                               ObjectKind::Function, tag + "_target");
    formal = db.value("selftest:" + tag + ":formal");
    db.valueOwners[formal] = target;
    db.functions[target].formals.push_back({0, formal});
    db.handlerReachableFunctions.insert(caller);
    db.handlerReachableFunctions.insert(target);
  };
  auto addSharedSite = [&](Database &db, uint32_t caller, uint32_t target,
                           const std::string &name, uint32_t object) {
    uint32_t actual = db.value("selftest:" + name + ":actual");
    db.valueOwners[actual] = caller;
    db.addressSeeds.push_back({actual, object, 0, synthetic, Rule::AddressOf});
    uint32_t start = static_cast<uint32_t>(db.directActuals.size());
    db.directActuals.push_back({0, actual, synthetic});
    uint32_t siteIndex = static_cast<uint32_t>(db.directSites.size());
    db.directSites.push_back({db.callsiteNames.intern("selftest:" + name), caller, target,
                              start, 1, NONE, synthetic});
    db.wireStaticCall(caller, target, {db.directActuals[start]}, NONE, synthetic, siteIndex);
    return siteIndex;
  };

  // Test 1: two callsites with identical actual signatures share one context.
  Database sigMerge(true);
  uint32_t smCaller, smTarget, smFormal;
  buildSharedTarget(sigMerge, smCaller, smTarget, smFormal, "sig_merge");
  uint32_t smObjA = sigMerge.objects.intern("sym:object:global:sig_merge_a", 8, ObjectKind::Other);
  addSharedSite(sigMerge, smCaller, smTarget, "sig_merge_x", smObjA);
  addSharedSite(sigMerge, smCaller, smTarget, "sig_merge_y", smObjA);
  SignatureCensus smCensus;
  solveSignature(sigMerge, 64, smCensus);
  Solver smSolver(sigMerge, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                  FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
                  CallFlowMode::Callsite, nullptr, nullptr, 0);
  smSolver.solve();
  auto smClones = formalClones(sigMerge, smFormal);
  bool signatureSameMerged = smClones.size() == 1 && smCensus.equivalenceMerged == 1 &&
                             smCensus.uniqueSignatures == 1;
  for (uint32_t clone : smClones)
    signatureSameMerged = signatureSameMerged && smSolver.containsValue(clone, {smObjA, 0});

  // Test 2: two callsites with different actual signatures get isolated contexts.
  Database sigSplit(true);
  uint32_t ssCaller, ssTarget, ssFormal;
  buildSharedTarget(sigSplit, ssCaller, ssTarget, ssFormal, "sig_split");
  uint32_t ssObjA = sigSplit.objects.intern("sym:object:global:sig_split_a", 8, ObjectKind::Other);
  uint32_t ssObjB = sigSplit.objects.intern("sym:object:global:sig_split_b", 8, ObjectKind::Other);
  addSharedSite(sigSplit, ssCaller, ssTarget, "sig_split_x", ssObjA);
  addSharedSite(sigSplit, ssCaller, ssTarget, "sig_split_y", ssObjB);
  SignatureCensus ssCensus;
  solveSignature(sigSplit, 64, ssCensus);
  Solver ssSolver(sigSplit, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                  FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
                  CallFlowMode::Callsite, nullptr, nullptr, 0);
  ssSolver.solve();
  auto ssClones = formalClones(sigSplit, ssFormal);
  bool signatureDiffIsolated = ssClones.size() == 2 && ssCensus.uniqueSignatures == 2 &&
                               ssCensus.equivalenceMerged == 0;
  for (uint32_t clone : ssClones) {
    bool hasA = ssSolver.containsValue(clone, {ssObjA, 0});
    bool hasB = ssSolver.containsValue(clone, {ssObjB, 0});
    signatureDiffIsolated = signatureDiffIsolated && (hasA != hasB);
  }

  // Test 3: with budget 1, extra signatures fold into one overflow context whose formal
  // is the union of the overflowed inputs (no flow lost).
  Database sigOverflow(true);
  uint32_t soCaller, soTarget, soFormal;
  buildSharedTarget(sigOverflow, soCaller, soTarget, soFormal, "sig_of");
  uint32_t soObjA = sigOverflow.objects.intern("sym:object:global:sig_of_a", 8, ObjectKind::Other);
  uint32_t soObjB = sigOverflow.objects.intern("sym:object:global:sig_of_b", 8, ObjectKind::Other);
  uint32_t soObjC = sigOverflow.objects.intern("sym:object:global:sig_of_c", 8, ObjectKind::Other);
  addSharedSite(sigOverflow, soCaller, soTarget, "sig_of_x", soObjA);
  addSharedSite(sigOverflow, soCaller, soTarget, "sig_of_y", soObjB);
  addSharedSite(sigOverflow, soCaller, soTarget, "sig_of_z", soObjC);
  SignatureCensus soCensus;
  solveSignature(sigOverflow, 1, soCensus);
  Solver soSolver(sigOverflow, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                  FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
                  CallFlowMode::Callsite, nullptr, nullptr, 0);
  soSolver.solve();
  auto soClones = formalClones(sigOverflow, soFormal);
  bool overflowUnion = soClones.size() == 2 && soCensus.uniqueSignatures == 1 &&
                       soCensus.overflowFunctions == 1 && soCensus.overflowMerged == 2;
  bool overflowHasUnion = false;
  for (uint32_t clone : soClones) {
    if (soSolver.containsValue(clone, {soObjB, 0}) &&
        soSolver.containsValue(clone, {soObjC, 0}))
      overflowHasUnion = true;
  }
  overflowUnion = overflowUnion && overflowHasUnion;

  // Test 4: a direct site and a synthetic (indirect-promoted) site to the same target with
  // the same signature share one context (direct/indirect use the same context key).
  Database sigDi(true);
  uint32_t diCaller, diTarget, diFormal;
  buildSharedTarget(sigDi, diCaller, diTarget, diFormal, "sig_di");
  uint32_t diObjA = sigDi.objects.intern("sym:object:global:sig_di_a", 8, ObjectKind::Other);
  addSharedSite(sigDi, diCaller, diTarget, "sig_di_direct", diObjA);
  sigDi.syntheticDirectSiteStart = static_cast<uint32_t>(sigDi.directSites.size());
  addSharedSite(sigDi, diCaller, diTarget, "sig_di_indirect", diObjA);
  SignatureCensus diCensus;
  solveSignature(sigDi, 64, diCensus);
  Solver diSolver(sigDi, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                  FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
                  CallFlowMode::Callsite, nullptr, nullptr, 0);
  diSolver.solve();
  auto diClones = formalClones(sigDi, diFormal);
  bool directIndirectShared = diClones.size() == 1 && diCensus.equivalenceMerged == 1;
  for (uint32_t clone : diClones)
    directIndirectShared = directIndirectShared && diSolver.containsValue(clone, {diObjA, 0});

  // --- Location-sensitive subobject policy tests ---------------------------------------
  Database locDb(true);
  uint32_t locRoot = locDb.objects.intern("sym:object:global:selftest_loc_root", 64,
                                           ObjectKind::Other);
  uint32_t locUnknown = locDb.objects.intern("sym:object:global:selftest_loc_unknown", 0,
                                             ObjectKind::Unknown);
  auto locValue = [&](const char *name) { return locDb.value(name); };
  uint32_t locBase = locValue("selftest:loc:base");        // -> locRoot@0
  uint32_t locMember = locValue("selftest:loc:member");    // -> locRoot@16 (a member)
  uint32_t locBackToBase = locValue("selftest:loc:back");  // member - 16 -> locRoot@0
  uint32_t locNegative = locValue("selftest:loc:neg");     // base - 8 -> locRoot@-8 (illegal)
  uint32_t locField16 = locValue("selftest:loc:f16");      // base + 16 -> locRoot@16
  uint32_t locField32 = locValue("selftest:loc:f32");      // base + 32 -> locRoot@32
  uint32_t locUnknownBase = locValue("selftest:loc:unk");  // -> locUnknown@0
  uint32_t locUnknownNeg = locValue("selftest:loc:unk_neg");  // unk - 8 -> locUnknown@-8
  locDb.addressSeeds = {
      {locBase, locRoot, 0, synthetic, Rule::AddressOf},
      {locMember, locRoot, 16, synthetic, Rule::AddressOf},
      {locUnknownBase, locUnknown, 0, synthetic, Rule::AddressOf},
  };
  locDb.fields = {
      {locBase, locNegative, -8, synthetic, NONE},
      {locBase, locField16, 16, synthetic, NONE},
      {locBase, locField32, 32, synthetic, NONE},
      {locMember, locBackToBase, -16, synthetic, NONE},
      {locUnknownBase, locUnknownNeg, -8, synthetic, NONE},
  };
  auto makeLocationSolver = [&](FieldLocationPolicy policy) {
    return Solver(locDb, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                  FieldCyclePolicy::Iterate, 256, OffsetPolicy::Drop, true, false,
                  CallFlowMode::Global, nullptr, nullptr, 0, DynamicAliasPolicy::None,
                  false, AffineCanonPolicy::None, policy);
  };
  Solver locSub = makeLocationSolver(FieldLocationPolicy::Subobject);
  locSub.solve();
  Solver locWide = makeLocationSolver(FieldLocationPolicy::RootWide);
  locWide.solve();
  bool locRejectsNegative = !locSub.containsValue(locNegative, {locRoot, -8}) &&
                            locSub.stats.locationRejectedOffsets >= 1;
  bool locWideKeepsNegative = locWide.containsValue(locNegative, {locRoot, -8});
  bool locContainerOfToBase = locSub.containsValue(locBackToBase, {locRoot, 0});
  bool locDistinctMembers = locSub.containsValue(locField16, {locRoot, 16}) &&
                            locSub.containsValue(locField32, {locRoot, 32}) &&
                            !locSub.containsValue(locField16, {locRoot, 32});
  bool locUnknownPreserved = locSub.containsValue(locUnknownNeg, {locUnknown, -8});

  // --- Two-phase bootstrap + exact-signature tests -------------------------------------
  // Merge/isolate fixture: three callsites into one target, two with identical objects.
  Database bootMerge(true);
  uint32_t bmCaller, bmTarget, bmFormal;
  buildSharedTarget(bootMerge, bmCaller, bmTarget, bmFormal, "boot_merge");
  uint32_t bmObjA = bootMerge.objects.intern("sym:object:global:boot_a", 8, ObjectKind::Other);
  uint32_t bmObjB = bootMerge.objects.intern("sym:object:global:boot_b", 8, ObjectKind::Other);
  uint32_t bmSiteX = addSharedSite(bootMerge, bmCaller, bmTarget, "boot_x", bmObjA);
  uint32_t bmSiteY = addSharedSite(bootMerge, bmCaller, bmTarget, "boot_y", bmObjA);
  uint32_t bmSiteZ = addSharedSite(bootMerge, bmCaller, bmTarget, "boot_z", bmObjB);
  BootstrapCensus bmBootCensus;
  std::vector<uint32_t> bmBootstrapOf =
      computeBootstrapContexts(bootMerge, 64, bmBootCensus);
  bootMerge.materializeCallsiteContexts(ContextScope::Global, ContextObjectMode::Shared, 1,
                                        ContextValueSlice::Interface, 0, 1,
                                        ContextRefinePropagation::Linear, nullptr, 10000,
                                        &bmBootstrapOf);
  Solver bmPhase0(bootMerge, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                  FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
                  CallFlowMode::Callsite, nullptr, nullptr, 0);
  bmPhase0.solve();
  SignatureCensus bmSigCensus;
  std::vector<uint32_t> bmSigOf =
      computeSignaturesFromBootstrap(bootMerge, bmPhase0, bmBootstrapOf, bmSigCensus);
  bool bootstrapNoPrepass = bmBootCensus.sites == 3 && bmBootCensus.dedicatedContexts == 3;
  bool bootstrapPhase0Converged =
      !bmPhase0.stats.truncated && bmPhase0.stats.pendingTuples == 0;
  bool bootstrapNoBaselineBroadcast =
      !bmPhase0.containsValue(bmFormal, {bmObjA, 0}) &&
      !bmPhase0.containsValue(bmFormal, {bmObjB, 0});
  bool bootstrapSameFormalMerges = bmSigOf[bmSiteX] != NONE &&
                                   bmSigOf[bmSiteX] == bmSigOf[bmSiteY] &&
                                   bmSigCensus.equivalenceMerged >= 1;
  bool bootstrapDiffFormalIsolates = bmSigOf[bmSiteZ] != NONE &&
                                     bmSigOf[bmSiteZ] != bmSigOf[bmSiteX];

  // Overflow fixture: budget 1, three distinct objects; the two overflow sites share a
  // context whose formal is the union of their inputs.
  Database bootOf(true);
  uint32_t boCaller, boTarget, boFormal;
  buildSharedTarget(bootOf, boCaller, boTarget, boFormal, "boot_of");
  uint32_t boObjA = bootOf.objects.intern("sym:object:global:boot_of_a", 8, ObjectKind::Other);
  uint32_t boObjB = bootOf.objects.intern("sym:object:global:boot_of_b", 8, ObjectKind::Other);
  uint32_t boObjC = bootOf.objects.intern("sym:object:global:boot_of_c", 8, ObjectKind::Other);
  addSharedSite(bootOf, boCaller, boTarget, "boot_of_x", boObjA);
  addSharedSite(bootOf, boCaller, boTarget, "boot_of_y", boObjB);
  addSharedSite(bootOf, boCaller, boTarget, "boot_of_z", boObjC);
  BootstrapCensus boBootCensus;
  std::vector<uint32_t> boBootstrapOf = computeBootstrapContexts(bootOf, 1, boBootCensus);
  bootOf.materializeCallsiteContexts(ContextScope::Global, ContextObjectMode::Shared, 1,
                                     ContextValueSlice::Interface, 0, 1,
                                     ContextRefinePropagation::Linear, nullptr, 10000,
                                     &boBootstrapOf);
  Solver boPhase0(bootOf, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                  FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
                  CallFlowMode::Callsite, nullptr, nullptr, 0);
  boPhase0.solve();
  bool bootstrapOverflowUnion =
      boBootCensus.overflowFunctions == 1 && boBootCensus.overflowSites == 2;
  bool overflowFormalHasUnion = false;
  for (uint32_t clone : formalClones(bootOf, boFormal))
    if (boPhase0.containsValue(clone, {boObjB, 0}) &&
        boPhase0.containsValue(clone, {boObjC, 0}))
      overflowFormalHasUnion = true;
  bootstrapOverflowUnion = bootstrapOverflowUnion && overflowFormalHasUnion;

  // Determinism: the bootstrap mapping is a pure deterministic function of the inputs.
  Database bootDet(true);
  uint32_t bdCaller, bdTarget, bdFormal;
  buildSharedTarget(bootDet, bdCaller, bdTarget, bdFormal, "boot_det");
  uint32_t bdObj = bootDet.objects.intern("sym:object:global:boot_det_a", 8, ObjectKind::Other);
  addSharedSite(bootDet, bdCaller, bdTarget, "boot_det_x", bdObj);
  addSharedSite(bootDet, bdCaller, bdTarget, "boot_det_y", bdObj);
  BootstrapCensus bdA, bdB;
  std::vector<uint32_t> bdMapA = computeBootstrapContexts(bootDet, 64, bdA);
  std::vector<uint32_t> bdMapB = computeBootstrapContexts(bootDet, 64, bdB);
  bool bootstrapDeterministic = bdMapA == bdMapB && bdA.sites == bdB.sites &&
                                bdA.dedicatedContexts == bdB.dedicatedContexts;

  // --- Indirect-target frontier bootstrap (discovery mode) tests -----------------------
  // In discovery mode every resolved (indirect callsite, target) pair is recorded, but flow is
  // wired only for PROMOTED pairs; non-promoted pairs are DEFERRED (no baseline broadcast).
  // The frontier driver promotes the deferred pairs next round, deepening to a monotone
  // fixpoint. These fixtures exercise a single discovery round and manual round-to-round
  // promotion, mirroring the driver exactly.
  auto runDiscovery = [&](Database &db) {
    BootstrapCensus bc;
    std::vector<uint32_t> bootOf = computeBootstrapContexts(db, 64, bc);
    db.materializeCallsiteContexts(ContextScope::Global, ContextObjectMode::Shared, 1,
                                   ContextValueSlice::Interface, 0, 1,
                                   ContextRefinePropagation::Linear, nullptr, 10000, &bootOf);
    auto discoverySolver = std::make_unique<Solver>(
        db, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All, FieldCyclePolicy::Iterate,
        256, OffsetPolicy::Dynamic, true, false, CallFlowMode::Callsite, nullptr, nullptr, 0,
        DynamicAliasPolicy::None, false, AffineCanonPolicy::None,
        FieldLocationPolicy::RootWide, /*discoveryMode=*/true);
    discoverySolver->solve();
    return discoverySolver;
  };
  auto collectDiscovered = [&](const Database &db, const Solver &s) {
    std::set<std::pair<std::string, std::string>> out;
    for (const auto &[si, fn] : s.indirectTargets())
      out.insert({std::string(db.callsiteNames.name(db.indirectSites[si].callsiteName)),
                  std::string(db.objects.name(fn))});
    return out;
  };
  // One caller with one indirect site whose callee value is &target, passing &objA as the
  // pointer actual matching target's formal index 0.
  auto buildDiscoveryFixture = [&](Database &db, uint32_t &target, uint32_t &formal,
                                   uint32_t &objA, std::string &siteStr,
                                   std::string &targetStr) {
    uint32_t caller = db.objects.intern("sym:object:function:disc_caller", 0,
                                        ObjectKind::Function, "disc_caller");
    targetStr = "sym:object:function:disc_target";
    target = db.objects.intern(targetStr, 0, ObjectKind::Function, "disc_target");
    formal = db.value("selftest:disc:formal");
    db.valueOwners[formal] = target;
    db.functions[target].formals.push_back({0, formal});
    db.handlerReachableFunctions.insert(caller);
    db.handlerReachableFunctions.insert(target);
    objA = db.objects.intern("sym:object:global:disc_objA", 8, ObjectKind::Other);
    uint32_t actual = db.value("selftest:disc:actual");
    db.valueOwners[actual] = caller;
    db.addressSeeds.push_back({actual, objA, 0, synthetic, Rule::AddressOf});
    uint32_t calleeValue = db.value("selftest:disc:calleeValue");
    db.valueOwners[calleeValue] = caller;
    db.addressSeeds.push_back({calleeValue, target, 0, synthetic, Rule::AddressOf});
    siteStr = "selftest:disc:site";
    uint32_t callsiteName = db.callsiteNames.intern(siteStr);
    uint32_t start = static_cast<uint32_t>(db.indirectActuals.size());
    db.indirectActuals.push_back({0, actual, synthetic});
    db.indirectSites.push_back(
        {callsiteName, caller, NONE, calleeValue, start, 1, NONE, synthetic});
  };

  // Test A: a non-promoted pair is recorded as a target but its actual is NOT broadcast to the
  // shared formal (deferred), and it is counted as deferred.
  Database discDefer(true);
  uint32_t ddTarget, ddFormal, ddObjA;
  std::string ddSite, ddTargetStr;
  buildDiscoveryFixture(discDefer, ddTarget, ddFormal, ddObjA, ddSite, ddTargetStr);
  auto discDeferSolver = runDiscovery(discDefer);
  bool discDeferRecordsTarget = false;
  for (const auto &[si, fn] : discDeferSolver->indirectTargets())
    if (fn == ddTarget) discDeferRecordsTarget = true;
  bool discDeferNoBroadcast =
      discDeferRecordsTarget && discDeferSolver->stats.deferredIndirectPairs == 1 &&
      !discDeferSolver->containsValue(ddFormal, {ddObjA, 0});

  // Test B: once the pair is promoted, the contextual actual/return flow takes effect (the
  // formal clone receives &objA) and the pair is no longer deferred.
  Database discProm(true);
  uint32_t dpTarget, dpFormal, dpObjA;
  std::string dpSite, dpTargetStr;
  buildDiscoveryFixture(discProm, dpTarget, dpFormal, dpObjA, dpSite, dpTargetStr);
  discProm.promoteIndirectPairs({{dpSite, dpTargetStr}});
  auto discPromSolver = runDiscovery(discProm);
  bool discPromContextualFlow = false;
  for (uint32_t clone : formalClones(discProm, dpFormal))
    if (discPromSolver->containsValue(clone, {dpObjA, 0}))
      discPromContextualFlow = true;
  bool discPromoteContextual =
      discPromContextualFlow && discPromSolver->stats.deferredIndirectPairs == 0 &&
      discPromSolver->stats.contextualizedIndirectTargets >= 1;

  // Nested fixture: site1 (in caller) -> outerTarget, passing &innerTarget as a function
  // pointer; site2 (inside outerTarget) dispatches through the received formal. innerTarget is
  // reachable only after site1 is promoted so the formal actually carries &innerTarget.
  auto buildNestedFixture = [&](Database &db, uint32_t &innerTarget, std::string &site1Str,
                                std::string &outerStr) {
    uint32_t caller = db.objects.intern("sym:object:function:nest_caller", 0,
                                        ObjectKind::Function, "nest_caller");
    outerStr = "sym:object:function:nest_outer";
    uint32_t outerTarget = db.objects.intern(outerStr, 0, ObjectKind::Function, "nest_outer");
    innerTarget = db.objects.intern("sym:object:function:nest_inner", 0,
                                    ObjectKind::Function, "nest_inner");
    uint32_t outerFormal = db.value("selftest:nest:outerFormal");
    db.valueOwners[outerFormal] = outerTarget;
    db.functions[outerTarget].formals.push_back({0, outerFormal});
    db.handlerReachableFunctions.insert(caller);
    db.handlerReachableFunctions.insert(outerTarget);
    db.handlerReachableFunctions.insert(innerTarget);
    uint32_t cv1 = db.value("selftest:nest:cv1");
    db.valueOwners[cv1] = caller;
    db.addressSeeds.push_back({cv1, outerTarget, 0, synthetic, Rule::AddressOf});
    uint32_t innerPtr = db.value("selftest:nest:innerPtr");
    db.valueOwners[innerPtr] = caller;
    db.addressSeeds.push_back({innerPtr, innerTarget, 0, synthetic, Rule::AddressOf});
    site1Str = "selftest:nest:site1";
    uint32_t site1Name = db.callsiteNames.intern(site1Str);
    uint32_t s1 = static_cast<uint32_t>(db.indirectActuals.size());
    db.indirectActuals.push_back({0, innerPtr, synthetic});
    db.indirectSites.push_back({site1Name, caller, NONE, cv1, s1, 1, NONE, synthetic});
    uint32_t site2Name = db.callsiteNames.intern("selftest:nest:site2");
    uint32_t s2 = static_cast<uint32_t>(db.indirectActuals.size());
    db.indirectSites.push_back(
        {site2Name, outerTarget, NONE, outerFormal, s2, 0, NONE, synthetic});
  };
  // Round 1: nothing promoted -> only outer discovered, inner not yet.
  Database nestR1(true);
  uint32_t n1Inner;
  std::string n1Site1, n1Outer;
  buildNestedFixture(nestR1, n1Inner, n1Site1, n1Outer);
  auto nestSolver1 = runDiscovery(nestR1);
  auto nestDisc1 = collectDiscovered(nestR1, *nestSolver1);
  std::string n1InnerStr = std::string(nestR1.objects.name(n1Inner));
  bool nestedInnerAbsentR1 = true;
  for (const auto &pr : nestDisc1)
    if (pr.second == n1InnerStr) nestedInnerAbsentR1 = false;
  bool nestedOuterFoundR1 = nestDisc1.count({n1Site1, n1Outer}) == 1;
  // Round 2: promote round-1 discoveries -> outer's formal carries &inner -> inner discovered.
  Database nestR2(true);
  uint32_t n2Inner;
  std::string n2Site1, n2Outer;
  buildNestedFixture(nestR2, n2Inner, n2Site1, n2Outer);
  std::vector<std::pair<std::string, std::string>> nestPromote(nestDisc1.begin(),
                                                               nestDisc1.end());
  nestR2.promoteIndirectPairs(nestPromote);
  auto nestSolver2 = runDiscovery(nestR2);
  auto nestDisc2 = collectDiscovered(nestR2, *nestSolver2);
  std::string n2InnerStr = std::string(nestR2.objects.name(n2Inner));
  bool nestedInnerFoundR2 = false;
  for (const auto &pr : nestDisc2)
    if (pr.second == n2InnerStr) nestedInnerFoundR2 = true;
  bool nestedDiscovery = nestedOuterFoundR1 && nestedInnerAbsentR1 && nestedInnerFoundR2;
  // Monotonic: round-2 discovered set strictly contains round-1's.
  bool nestedMonotonic = std::includes(nestDisc2.begin(), nestDisc2.end(),
                                       nestDisc1.begin(), nestDisc1.end()) &&
                         nestDisc2.size() > nestDisc1.size();

  // Test: the discovery pass is a deterministic function of its inputs.
  Database discDetA(true), discDetB(true);
  uint32_t xA, yA, zA, xB, yB, zB;
  std::string sA, tA, sB, tB;
  buildDiscoveryFixture(discDetA, xA, yA, zA, sA, tA);
  buildDiscoveryFixture(discDetB, xB, yB, zB, sB, tB);
  auto detSolverA = runDiscovery(discDetA);
  auto detSolverB = runDiscovery(discDetB);
  bool discDeterministic = collectDiscovered(discDetA, *detSolverA) ==
                           collectDiscovered(discDetB, *detSolverB);

  // Test: an overflow direct context is deferred in discovery mode — the dedicated (first
  // budget) callsite's actual reaches its contextual formal, but the overflow callsite's actual
  // is neither broadcast to the baseline formal nor merged into an overflow formal.
  Database discOf(true);
  uint32_t doCaller, doTarget, doFormal;
  buildSharedTarget(discOf, doCaller, doTarget, doFormal, "disc_of");
  uint32_t doObjDed =
      discOf.objects.intern("sym:object:global:disc_of_ded", 8, ObjectKind::Other);
  uint32_t doObjOvf =
      discOf.objects.intern("sym:object:global:disc_of_ovf", 8, ObjectKind::Other);
  addSharedSite(discOf, doCaller, doTarget, "disc_of_ded", doObjDed);  // budget 1 -> dedicated
  addSharedSite(discOf, doCaller, doTarget, "disc_of_ovf", doObjOvf);  // -> overflow (deferred)
  BootstrapCensus doCensus;
  std::vector<uint8_t> doOverflow;
  std::vector<uint32_t> doBootOf =
      computeBootstrapContexts(discOf, 1, doCensus, &doOverflow);
  discOf.materializeCallsiteContexts(ContextScope::Global, ContextObjectMode::Shared, 1,
                                     ContextValueSlice::Interface, 0, 1,
                                     ContextRefinePropagation::Linear, nullptr, 10000,
                                     &doBootOf, &doOverflow);
  Solver doSolver(discOf, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
                  FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
                  CallFlowMode::Callsite, nullptr, nullptr, 0);
  doSolver.solve();
  bool doDedicatedFlows = false, doOverflowDeferred = true;
  for (uint32_t clone : formalClones(discOf, doFormal)) {
    if (doSolver.containsValue(clone, {doObjDed, 0})) doDedicatedFlows = true;
    if (doSolver.containsValue(clone, {doObjOvf, 0})) doOverflowDeferred = false;
  }
  bool doBaselineInactive = !doSolver.containsValue(doFormal, {doObjDed, 0}) &&
                            !doSolver.containsValue(doFormal, {doObjOvf, 0});
  bool discoveryOverflowDeferral = doDedicatedFlows && doOverflowDeferred &&
                                   doBaselineInactive && doCensus.overflowSites == 1;

  // Test: the completion predicate rejects truncated rounds and rounds with residual pending
  // tuples even when no new targets appeared, and rejects any round with new/deferred pairs.
  bool discCompletionGuard =
      indirectBootstrapComplete(0, 0, 0, 0, false) &&   // converged, nothing deferred -> complete
      !indirectBootstrapComplete(0, 0, 0, 5, false) &&  // pending>0 -> not complete
      !indirectBootstrapComplete(0, 0, 0, 0, true) &&   // truncated -> not complete
      !indirectBootstrapComplete(3, 3, 0, 0, false) &&  // new targets -> not complete
      !indirectBootstrapComplete(0, 0, 7, 0, false);    // deferred direct transfers -> not complete

  // --- Selective value-context blend tests --------------------------------------------
  // Two callsites to one target passing DISTINCT object sets. Value-contexting the target keys
  // them by their actual object-set signature (split); detection flags a formal holding many
  // objects; with an empty value-context set the blend falls back to bootstrap.
  Database vcDb(true);
  uint32_t vcCaller, vcTarget, vcFormal;
  buildSharedTarget(vcDb, vcCaller, vcTarget, vcFormal, "vc");
  uint32_t vcObjA = vcDb.objects.intern("sym:object:global:vc_a", 8, ObjectKind::Other);
  uint32_t vcObjB = vcDb.objects.intern("sym:object:global:vc_b", 8, ObjectKind::Other);
  uint32_t vcSiteA = addSharedSite(vcDb, vcCaller, vcTarget, "vc_a", vcObjA);
  uint32_t vcSiteB = addSharedSite(vcDb, vcCaller, vcTarget, "vc_b", vcObjB);
  Solver vcCi(vcDb, FieldDynamicPolicy::RootDynamic, FieldTypePolicy::All,
              FieldCyclePolicy::Iterate, 256, OffsetPolicy::Dynamic, true, false,
              CallFlowMode::Global, nullptr, nullptr, 0);
  vcCi.solve();
  std::unordered_set<uint32_t> vcSet{vcTarget};
  std::vector<uint8_t> vcMask;
  BootstrapCensus vcBoot;
  SignatureCensus vcSig;
  std::vector<uint32_t> vcBlend =
      computeBlendedContexts(vcDb, vcCi, vcSet, 64, vcMask, vcBoot, vcSig);
  bool vcSplits = vcBlend[vcSiteA] != NONE && vcBlend[vcSiteB] != NONE &&
                  vcBlend[vcSiteA] != vcBlend[vcSiteB] && vcSig.uniqueSignatures == 2 &&
                  vcMask[vcSiteA] == 0 && vcMask[vcSiteB] == 0;
  std::vector<uint8_t> vcMask0;
  BootstrapCensus vcBoot0;
  SignatureCensus vcSig0;
  std::vector<uint32_t> vcBlend0 =
      computeBlendedContexts(vcDb, vcCi, {}, 64, vcMask0, vcBoot0, vcSig0);
  bool vcBootstrapWhenOff = vcSig0.uniqueSignatures == 0 && vcBoot0.sites == 2 &&
                            vcBlend0[vcSiteA] != NONE && vcBlend0[vcSiteB] != NONE;
  auto vcMergeFns = vcCi.valueMergeFunctions(1);  // vcTarget's formal holds {objA,objB} in CI
  bool vcDetects =
      std::find(vcMergeFns.begin(), vcMergeFns.end(), vcTarget) != vcMergeFns.end() &&
      vcCi.valueMergeFunctions(5).empty();  // threshold above the set size finds nothing

  // --- P1 object-sensitivity: receiver-formal selection (design §3) -----------------------
  auto osFn = [&](Database &db, const std::string &sym) {
    return db.objects.intern("sym:object:function:" + sym, 0, ObjectKind::Function, sym);
  };
  auto osOwned = [&](Database &db, uint32_t owner, const std::string &name) {
    uint32_t v = db.value(name);
    db.valueOwners[v] = owner;
    return v;
  };
  // (A) A formal dereferenced locally (its value is a field base) is a receiver.
  Database osLocal(true);
  uint32_t olF = osFn(osLocal, "os_local");
  uint32_t olFormal = osOwned(osLocal, olF, "selftest:os_local:formal");
  uint32_t olField = osOwned(osLocal, olF, "selftest:os_local:field");
  osLocal.functions[olF].formals.push_back({0, olFormal});
  osLocal.fields.push_back({olFormal, olField, 8, synthetic, NONE});
  osLocal.computeReceiverFormals();
  bool osLocalReceiver = olF < osLocal.receiverFormalIndex.size() &&
                         osLocal.receiverArity[olF] == 1 &&
                         osLocal.receiverFormalIndex[olF] == 0;

  // (B) A pointer-forwarding wrapper (no local deref; forwards its arg into a receiver formal)
  //     is itself a receiver — the inter-procedural backward fixpoint (the case that would
  //     otherwise re-merge a deep chain).
  Database osWrap(true);
  uint32_t owH = osFn(osWrap, "os_wrap_h");
  uint32_t owG = osFn(osWrap, "os_wrap_g");
  uint32_t owHFormal = osOwned(osWrap, owH, "selftest:os_wrap:h_formal");
  uint32_t owHField = osOwned(osWrap, owH, "selftest:os_wrap:h_field");
  uint32_t owGFormal = osOwned(osWrap, owG, "selftest:os_wrap:g_formal");
  osWrap.functions[owH].formals.push_back({0, owHFormal});
  osWrap.functions[owG].formals.push_back({0, owGFormal});
  osWrap.fields.push_back({owHFormal, owHField, 8, synthetic, NONE});  // h dereferences its arg
  uint32_t owStart = static_cast<uint32_t>(osWrap.directActuals.size());
  osWrap.directActuals.push_back({0, owGFormal, synthetic});           // g forwards its arg to h
  osWrap.directSites.push_back({osWrap.callsiteNames.intern("selftest:os_wrap:site"), owG, owH,
                                owStart, 1, NONE, synthetic});
  osWrap.computeReceiverFormals();
  bool osWrapForwards = owG < osWrap.receiverFormalIndex.size() &&
                        osWrap.receiverArity[owG] == 1 &&
                        osWrap.receiverFormalIndex[owG] == 0 && osWrap.receiverArity[owH] == 1;

  // (C) A pure value transformer (formal only copied, never dereferenced or forwarded) is not a
  //     receiver.
  Database osPass(true);
  uint32_t opF = osFn(osPass, "os_pass");
  uint32_t opFormal = osOwned(osPass, opF, "selftest:os_pass:formal");
  uint32_t opCopy = osOwned(osPass, opF, "selftest:os_pass:copy");
  osPass.functions[opF].formals.push_back({0, opFormal});
  osPass.copies.push_back({opFormal, opCopy, synthetic, Rule::Copy});
  osPass.computeReceiverFormals();
  bool osPassNoReceiver = opF >= osPass.receiverArity.size() || osPass.receiverArity[opF] == 0;

  // (D) Two dereferenced formals -> multi-receiver: arity 2, unique gate NONE (keeps bootstrap).
  Database osMulti(true);
  uint32_t omF = osFn(osMulti, "os_multi");
  uint32_t omA = osOwned(osMulti, omF, "selftest:os_multi:a");
  uint32_t omB = osOwned(osMulti, omF, "selftest:os_multi:b");
  uint32_t omAField = osOwned(osMulti, omF, "selftest:os_multi:a_field");
  uint32_t omBField = osOwned(osMulti, omF, "selftest:os_multi:b_field");
  osMulti.functions[omF].formals.push_back({0, omA});
  osMulti.functions[omF].formals.push_back({1, omB});
  osMulti.fields.push_back({omA, omAField, 8, synthetic, NONE});
  osMulti.fields.push_back({omB, omBField, 8, synthetic, NONE});
  osMulti.computeReceiverFormals();
  bool osMultiNotUnique = omF < osMulti.receiverArity.size() && osMulti.receiverArity[omF] == 2 &&
                          osMulti.receiverFormalIndex[omF] == NONE;

  // (E) ObjectContext interner identity (design §2): global reuse per (callee,formal,root);
  //     distinct roots, the explicit-unknown union, and the baseline are all distinct ids.
  ObjectContexts oc;
  uint32_t ocF = 100, ocG = 200, ocR1 = 10, ocR2 = 11;
  uint32_t oc_f_r1 = oc.ensure(ocF, 0, ocR1);
  bool ocReuse = oc.ensure(ocF, 0, ocR1) == oc_f_r1;                 // same key -> same id
  bool ocDistinctRoot = oc.ensure(ocF, 0, ocR2) != oc_f_r1;          // different root -> different
  bool ocDistinctFormal = oc.ensure(ocF, 1, ocR1) != oc_f_r1;        // different formal -> different
  bool ocDistinctCallee = oc.ensure(ocG, 0, ocR1) != oc_f_r1;        // different callee -> different
  uint32_t oc_unknown = oc.ensure(ocF, 0, SHARED_UNKNOWN_ROOT);
  bool ocUnknownDistinct = oc_unknown != oc_f_r1 && oc_unknown != ObjectContexts::BASELINE &&
                           oc.isSharedUnknown(oc_unknown) && !oc.isSharedUnknown(oc_f_r1) &&
                           oc.isBaseline(ObjectContexts::BASELINE) && oc_f_r1 != 0;
  bool ocInterner = ocReuse && ocDistinctRoot && ocDistinctFormal && ocDistinctCallee &&
                    ocUnknownDistinct;

  // (F) Per-function template SCC: only same-owner ordinary COPY edges participate. A local
  // cycle collapses, while same-owner call edges and an ordinary cross-owner edge cannot join
  // components. Stack objects receive stable function-local template ordinals.
  Database otDb(true);
  uint32_t otF = osFn(otDb, "os_template_f");
  uint32_t otOther = osFn(otDb, "os_template_other");
  uint32_t otFormal = osOwned(otDb, otF, "selftest:os_template:formal");
  uint32_t otField = osOwned(otDb, otF, "selftest:os_template:field");
  uint32_t otCycleA = osOwned(otDb, otF, "selftest:os_template:cycle_a");
  uint32_t otCycleB = osOwned(otDb, otF, "selftest:os_template:cycle_b");
  uint32_t otTail = osOwned(otDb, otF, "selftest:os_template:tail");
  uint32_t otCallOnly = osOwned(otDb, otF, "selftest:os_template:call_only");
  uint32_t otForeign = osOwned(otDb, otOther, "selftest:os_template:foreign");
  otDb.functions[otF].formals.push_back({0, otFormal});
  otDb.fields.push_back({otFormal, otField, 8, synthetic, NONE});
  otDb.copies.push_back({otFormal, otCycleA, synthetic, Rule::Copy});
  otDb.copies.push_back({otCycleA, otCycleB, synthetic, Rule::Copy});
  otDb.copies.push_back({otCycleB, otCycleA, synthetic, Rule::Copy});
  otDb.copies.push_back({otCycleB, otTail, synthetic, Rule::Copy});
  otDb.copies.push_back({otTail, otCallOnly, synthetic, Rule::CallArgument});
  otDb.copies.push_back({otCallOnly, otTail, synthetic, Rule::CallReturn});
  otDb.copies.push_back({otTail, otForeign, synthetic, Rule::Copy});
  uint32_t otStack = otDb.objects.intern("selftest:os_template:stack", 16, ObjectKind::Stack);
  otDb.objectOwners.resize(otDb.objects.size(), NONE);
  otDb.objectOwners[otStack] = otF;
  otDb.computeReceiverFormals();
  otDb.computeObjectSensitivityTemplates();
  const ObjectFunctionTemplate *otTemplate = otDb.objectTemplate(otF);
  bool otCycleCollapsed = otTemplate &&
                          otDb.objectTemplateComponent(otCycleA) ==
                              otDb.objectTemplateComponent(otCycleB);
  bool otCallsExcluded = otTemplate &&
                         otDb.objectTemplateComponent(otTail) !=
                             otDb.objectTemplateComponent(otCallOnly);
  bool otCrossOwnerExcluded = otDb.objectTemplateComponent(otForeign) == NONE;
  bool otTemplateShape = otTemplate && otTemplate->componentRepresentatives.size() == 5 &&
                         otTemplate->copyEdges.size() == 2 &&
                         otTemplate->stackObjects.size() == 1 &&
                         otTemplate->stackObjects[0] == otStack &&
                         otDb.templateStackObjectOrdinal[otStack] == 0;

  // (G) Eager synthetic isolation fixture. The same two static forwarding callsites carry two
  // receiver roots through outer -> middle -> leaf. Each root uses globally-reused object
  // contexts, and a small copy fixpoint over the materialized template graph must keep the two
  // roots disjoint at every leaf node. No full-kernel or truncated baseline result is consulted.
  Database oiDb(true);
  uint32_t oiOuter = osFn(oiDb, "os_isolation_outer");
  uint32_t oiMiddle = osFn(oiDb, "os_isolation_middle");
  uint32_t oiLeaf = osFn(oiDb, "os_isolation_leaf");
  uint32_t oiOuterFormal = osOwned(oiDb, oiOuter, "selftest:os_iso:outer_formal");
  uint32_t oiOuterA = osOwned(oiDb, oiOuter, "selftest:os_iso:outer_a");
  uint32_t oiOuterB = osOwned(oiDb, oiOuter, "selftest:os_iso:outer_b");
  uint32_t oiMiddleFormal = osOwned(oiDb, oiMiddle, "selftest:os_iso:middle_formal");
  uint32_t oiMiddleA = osOwned(oiDb, oiMiddle, "selftest:os_iso:middle_a");
  uint32_t oiMiddleB = osOwned(oiDb, oiMiddle, "selftest:os_iso:middle_b");
  uint32_t oiLeafFormal = osOwned(oiDb, oiLeaf, "selftest:os_iso:leaf_formal");
  uint32_t oiLeafA = osOwned(oiDb, oiLeaf, "selftest:os_iso:leaf_a");
  uint32_t oiLeafB = osOwned(oiDb, oiLeaf, "selftest:os_iso:leaf_b");
  uint32_t oiLeafField = osOwned(oiDb, oiLeaf, "selftest:os_iso:leaf_field");
  uint32_t oiShared = oiDb.value("selftest:os_iso:shared_global_value");
  oiDb.functions[oiOuter].formals.push_back({0, oiOuterFormal});
  oiDb.functions[oiMiddle].formals.push_back({0, oiMiddleFormal});
  oiDb.functions[oiLeaf].formals.push_back({0, oiLeafFormal});
  oiDb.copies.push_back({oiOuterFormal, oiOuterA, synthetic, Rule::Copy});
  oiDb.copies.push_back({oiOuterA, oiOuterB, synthetic, Rule::Copy});
  oiDb.copies.push_back({oiMiddleFormal, oiMiddleA, synthetic, Rule::Copy});
  oiDb.copies.push_back({oiMiddleA, oiMiddleB, synthetic, Rule::Copy});
  oiDb.copies.push_back({oiLeafFormal, oiLeafA, synthetic, Rule::Copy});
  oiDb.copies.push_back({oiLeafA, oiLeafB, synthetic, Rule::Copy});
  oiDb.fields.push_back({oiLeafB, oiLeafField, 8, synthetic, NONE});
  auto addIsolationSite = [&](uint32_t caller, uint32_t callee, uint32_t actual,
                              const char *name) {
    uint32_t start = static_cast<uint32_t>(oiDb.directActuals.size());
    oiDb.directActuals.push_back({0, actual, synthetic});
    oiDb.directSites.push_back(
        {oiDb.callsiteNames.intern(name), caller, callee, start, 1, NONE, synthetic});
  };
  addIsolationSite(oiOuter, oiMiddle, oiOuterB, "selftest:os_iso:outer_middle");
  addIsolationSite(oiMiddle, oiLeaf, oiMiddleB, "selftest:os_iso:middle_leaf");
  oiDb.computeReceiverFormals();
  oiDb.computeObjectSensitivityTemplates();
  uint32_t oiRootA = oiDb.objects.intern("selftest:os_iso:root_a", 64, ObjectKind::Other);
  uint32_t oiRootB = oiDb.objects.intern("selftest:os_iso:root_b", 64, ObjectKind::Other);
  auto isolationContext = [&](uint32_t function, uint32_t root) {
    return oiDb.objectContexts.ensure(function, oiDb.receiverFormalIndex[function], root);
  };
  uint32_t oiOuterAContext = isolationContext(oiOuter, oiRootA);
  uint32_t oiOuterBContext = isolationContext(oiOuter, oiRootB);
  uint32_t oiMiddleAContext = isolationContext(oiMiddle, oiRootA);
  uint32_t oiMiddleBContext = isolationContext(oiMiddle, oiRootB);
  uint32_t oiLeafAContext = isolationContext(oiLeaf, oiRootA);
  uint32_t oiLeafBContext = isolationContext(oiLeaf, oiRootB);
  std::vector<uint32_t> oiBaselineOrigins(oiDb.values.size());
  std::iota(oiBaselineOrigins.begin(), oiBaselineOrigins.end(), 0);
  std::vector<uint8_t> oiCoreValues(oiDb.values.size(), 1);
  SolverNodeArena oiArena;
  oiArena.resetBaseline(oiBaselineOrigins, oiCoreValues);
  ObjectContextNodes oiNodes;
  for (uint32_t context : {oiOuterAContext, oiOuterBContext, oiMiddleAContext,
                           oiMiddleBContext, oiLeafAContext, oiLeafBContext})
    oiNodes.materialize(oiDb, context, oiArena, oiCoreValues);
  auto oiNode = [&](uint32_t context, uint32_t valueId) {
    return oiNodes.nodeForValue(oiDb, context, valueId, valueId);
  };
  std::vector<std::vector<uint32_t>> oiAdjacency(oiArena.size());
  for (const MaterializedTemplateCopyEdge &edge : oiNodes.copyEdges())
    oiAdjacency[edge.src].push_back(edge.dst);
  auto addContextCall = [&](uint32_t callerContext, uint32_t actual,
                            uint32_t calleeContext, uint32_t formal) {
    oiAdjacency[oiNode(callerContext, actual)].push_back(oiNode(calleeContext, formal));
  };
  addContextCall(oiOuterAContext, oiOuterB, oiMiddleAContext, oiMiddleFormal);
  addContextCall(oiOuterBContext, oiOuterB, oiMiddleBContext, oiMiddleFormal);
  addContextCall(oiMiddleAContext, oiMiddleB, oiLeafAContext, oiLeafFormal);
  addContextCall(oiMiddleBContext, oiMiddleB, oiLeafBContext, oiLeafFormal);
  std::vector<std::unordered_set<uint32_t>> oiPoints(oiArena.size());
  std::queue<std::pair<uint32_t, uint32_t>> oiWork;
  auto oiSeed = [&](uint32_t node, uint32_t root) {
    if (oiPoints[node].insert(root).second)
      oiWork.push({node, root});
  };
  oiSeed(oiNode(oiOuterAContext, oiOuterFormal), oiRootA);
  oiSeed(oiNode(oiOuterBContext, oiOuterFormal), oiRootB);
  while (!oiWork.empty()) {
    auto [node, root] = oiWork.front();
    oiWork.pop();
    for (uint32_t destination : oiAdjacency[node])
      if (oiPoints[destination].insert(root).second)
        oiWork.push({destination, root});
  }
  uint32_t oiLeafANode = oiNode(oiLeafAContext, oiLeafB);
  uint32_t oiLeafBNode = oiNode(oiLeafBContext, oiLeafB);
  bool oiDeepIsolation = oiLeafANode != oiLeafBNode &&
                         oiPoints[oiLeafANode] == std::unordered_set<uint32_t>{oiRootA} &&
                         oiPoints[oiLeafBNode] == std::unordered_set<uint32_t>{oiRootB};
  bool oiNodeContexts = oiArena.context(oiLeafANode) == oiLeafAContext &&
                        oiArena.context(oiLeafBNode) == oiLeafBContext &&
                        oiArena.origin(oiLeafANode) != NONE &&
                        oiArena.origin(oiLeafBNode) != NONE;
  bool oiSharedBaseline = oiNode(oiLeafAContext, oiShared) == oiShared &&
                          oiNode(oiLeafBContext, oiShared) == oiShared &&
                          oiArena.context(oiShared) == ObjectContexts::BASELINE;

  // (H) P2 unified node arena: memory and context nodes may be allocated in either order.
  // Identity is metadata-driven; no valueCount_ threshold or valueCount_+memory_index
  // arithmetic is allowed to classify them.
  SolverNodeArena p2Arena;
  p2Arena.resetBaseline({100, 101}, {1, 0});
  uint32_t p2Memory0 = p2Arena.allocateMemory(0);
  uint32_t p2ContextBase = p2Arena.allocateContextBlock(7, {200, 201}, {0, 1});
  uint32_t p2Memory1 = p2Arena.allocateMemory(1);
  bool p2NodeArenaInterleaves =
      p2Memory0 == 2 && p2ContextBase == 3 && p2Memory1 == 5 &&
      p2Arena.kind(0) == SolverNodeKind::BaselineValue && p2Arena.core(0) &&
      !p2Arena.core(1) && p2Arena.isMemory(p2Memory0) &&
      p2Arena.memoryIndex(p2Memory0) == 0 && p2Arena.isValue(p2ContextBase) &&
      p2Arena.kind(p2ContextBase) == SolverNodeKind::ContextValue &&
      p2Arena.context(p2ContextBase) == 7 && p2Arena.origin(p2ContextBase) == 200 &&
      !p2Arena.core(p2ContextBase) && p2Arena.core(p2ContextBase + 1) &&
      p2Arena.isMemory(p2Memory1) && p2Arena.memoryIndex(p2Memory1) == 1;
  bool p2IncrementalReplay = Solver::incrementalInstallerSelftest();
  bool p2ContextBody = Solver::contextBodyMaterializationSelftest();

  struct Check { const char *name; bool passed; };
  std::vector<Check> checks = {
      {"receiver: local dereference selects formal", osLocalReceiver},
      {"receiver: forwarding wrapper is a receiver", osWrapForwards},
      {"receiver: value transformer is not a receiver", osPassNoReceiver},
      {"receiver: two dereferenced formals are not unique", osMultiNotUnique},
      {"object-context interner identity", ocInterner},
      {"object template collapses local copy SCC", otCycleCollapsed},
      {"object template excludes call copies", otCallsExcluded},
      {"object template excludes cross-owner copies", otCrossOwnerExcluded},
      {"object template records components and stack objects", otTemplateShape},
      {"object-context nodes isolate deep forwarding roots", oiDeepIsolation},
      {"object-context nodes retain context and origin", oiNodeContexts},
      {"object-context nodes preserve shared baseline values", oiSharedBaseline},
      {"solver node arena supports memory/context interleaving", p2NodeArenaInterleaves},
      {"incremental installers replay old and accept new tuples", p2IncrementalReplay},
      {"object context materializes complete isolated body", p2ContextBody},
      {"value-context blend splits distinct object sets", vcSplits},
      {"value-context blend falls back to bootstrap when empty", vcBootstrapWhenOff},
      {"value-merge detection flags wide formals", vcDetects},
      {"discovery records target without broadcast", discDeferNoBroadcast},
      {"discovery promotes to contextual flow", discPromoteContextual},
      {"discovery nested target found next round", nestedDiscovery},
      {"discovery target set monotonic", nestedMonotonic},
      {"discovery fixpoint deterministic", discDeterministic},
      {"discovery overflow context deferred", discoveryOverflowDeferral},
      {"discovery completion guard", discCompletionGuard},
      {"field load resolves function", solver.containsValue(callee, {function, 0})},
      {"negative offset returns parent", solver.containsValue(parent, {table, 0})},
      {"overflow dynamic stays root-local",
       solver.containsValue(outOfBounds, {table, DYN_OFFSET})},
      {"overflow drop removes tuple",
       !dropOffsetSolver.containsValue(outOfBounds, {table, DYN_OFFSET}) &&
           dropOffsetSolver.stats.droppedOffsets >= 1},
      {"overflow exact preserves signed offset",
       exactOffsetSolver.containsValue(outOfBounds, {table, 512})},
      {"strided GEP expands finite offsets",
       stridedSolver.containsValue(strided, {table, 8}) &&
           stridedSolver.containsValue(strided, {table, 24}) &&
           stridedSolver.containsValue(strided, {table, 40}) &&
           stridedSolver.containsValue(strided, {table, 56}) &&
           !stridedSolver.containsValue(strided, {table, DYN_OFFSET})},
      {"negative-stride GEP expands finite offsets",
       stridedSolver.containsValue(stridedNegative, {table, 56}) &&
           stridedSolver.containsValue(stridedNegative, {table, 40}) &&
           stridedSolver.containsValue(stridedNegative, {table, 24}) &&
           stridedSolver.containsValue(stridedNegative, {table, 8})},
      {"strided expansion limit does not fall back to dynamic",
       !stridedSolver.containsValue(stridedOverLimit, {table, DYN_OFFSET}) &&
           !stridedSolver.containsValue(stridedOverLimit, {table, 0}) &&
           stridedSolver.stats.stridedEdgesOverLimit == 1},
      {"unresolved dynamic is explicit in strided mode",
       !stridedSolver.containsValue(unresolvedDynamic, {table, DYN_OFFSET}) &&
           stridedSolver.stats.unresolvedDynamicEdgesDropped == 1},
      {"field type all preserves incompatible candidate",
       solver.containsValue(typedMismatch, {source, 0})},
      {"field type compatible preserves matching aggregate",
       compatibleTypeSolver.containsValue(typedMatch, {table, 0})},
      {"field type compatible rejects proven mismatch",
       !compatibleTypeSolver.containsValue(typedMismatch, {source, 0})},
      {"field type compatible preserves unknown evidence",
       compatibleTypeSolver.containsValue(typedUnknown, {argument, 0})},
      {"field type compatibility accounting is explicit",
       compatibleTypeSolver.stats.typedFieldApplications >= 3 &&
           compatibleTypeSolver.stats.typedFieldCompatible >= 1 &&
           compatibleTypeSolver.stats.typedFieldIncompatible >= 1 &&
           compatibleTypeSolver.stats.typedFieldUnknown >= 1 &&
           compatibleTypeSolver.stats.typedFieldDropped >= 1},
      {"field cycle iterate preserves recurrence",
       solver.containsValue(cycleNext, {source, 8}) &&
           solver.stats.fieldCycleEdges == 2 &&
           solver.stats.fieldCycleEdgesDropped == 0},
      {"field cycle drop is explicit",
       !dropCycleSolver.containsValue(cycleNext, {source, 8}) &&
           dropCycleSolver.stats.fieldCycleEdges == 2 &&
           dropCycleSolver.stats.fieldCycleEdgesDropped == 2},
      {"field cycle root dynamic is root-local",
       rootDynamicCycleSolver.containsValue(cycleNext, {source, DYN_OFFSET}) &&
           !rootDynamicCycleSolver.containsValue(cycleNext, {source, 8}) &&
           rootDynamicCycleSolver.containsValue(stridedCycleNext,
                                                {source, DYN_OFFSET}) &&
           !rootDynamicCycleSolver.containsValue(stridedCycleNext, {source, 8}) &&
           rootDynamicCycleSolver.stats.fieldCycleEdges == 2 &&
           rootDynamicCycleSolver.stats.fieldCycleEdgesRootDynamic == 2 &&
           rootDynamicCycleSolver.stats.fieldCycleEdgesDropped == 0},
      {"dynamic read aliases concrete cell",
       dynamicAliasSolver.containsValue(dynamicLoaded, {function, 0})},
      {"dynamic write aliases concrete cell",
       dynamicAliasSolver.containsValue(concreteLoaded, {function, 0})},
      {"dynamic alias accounting is explicit",
       dynamicAliasSolver.stats.dynamicAliasEdges >= 2},
      {"affine field cycle forms one bounded region",
       affineCycleSolver.containsAffineValue(cycleNext, source, 8, 8, 56) &&
           !affineCycleSolver.containsValue(cycleNext, {source, 8}) &&
           affineCycleSolver.stats.fieldCycleEdges == 2 &&
           affineCycleSolver.stats.fieldCycleEdgesAffine == 2 &&
           affineCycleSolver.stats.affineRegionFallbackDynamic == 0},
      {"affine strided cycle uses the same closure",
       affineCycleSolver.containsAffineValue(stridedCycleNext, source, 8, 8, 56)},
      {"constant field shifts affine region",
       affineCycleSolver.containsAffineValue(affineShifted, source, 12, 8, 60)},
      {"affine field shift clips only out-of-range members",
       affineCycleSolver.containsAffineValue(affineClipped, source, 32, 8, 56) &&
           !affineCycleSolver.containsValue(affineClipped,
                                             {source, DYN_OFFSET}) &&
           affineCycleSolver.stats.affineRegionClips >= 1},
      {"affine load reads overlapping concrete cell",
       affineCycleSolver.containsValue(affineLoaded, {function, 0})},
      {"affine store writes overlapping concrete cell",
       affineCycleSolver.containsValue(concreteLoaded, {affineStoreFunction, 0})},
      {"affine alias excludes non-member offset",
       !affineCycleSolver.containsValue(affineOutsideLoaded,
                                        {affineStoreFunction, 0}) &&
           affineCycleSolver.stats.affineAliasEdges >= 2},
      {"affine region congruence excludes shifted progression",
       !affineCycleSolver.containsValue(affineShiftedLoaded,
                                        {affineStoreFunction, 0})},
      {"negative affine cycle closes toward lower bound",
       affineMathSolver.containsAffineValue(negativeNext, affineMathObject,
                                            -64, 8, 48)},
      {"mixed affine generators close both directions",
       affineMathSolver.containsAffineValue(mixedNext, affineMathObject,
                                            -64, 8, 56)},
      {"indirect actual reaches formal", solver.containsValue(formal, {argument, 0})},
      {"indirect return reaches result", solver.containsValue(result, {returned, 0})},
      {"aggregate copy preserves field", solver.containsMemory({destination, 16}, {function, 0})},
      {"indirect target activated", solver.stats.indirectTargets == 1},
      {"root seed reaches handler", solver.stats.rootsReachingHandler == 1},
      {"callsite contexts isolate helper formals", contextsIsolated},
      {"callsite contexts isolate helper stack objects", stackContextsIsolated},
      {"selected callsite leaves baseline formal inactive", baselineContextInactive},
      {"selected callsite leaves baseline helper stack inactive", baselineStackInactive},
      {"K=1 merges only in its contextual helper node",
       nestedK1.merged && nestedK1.baselineInactive},
      {"adaptive context persists through the helper chain",
       nestedAdaptive.isolated && nestedAdaptive.baselineInactive &&
           nestedAdaptive.refinementAccounting},
      {"global scope routes baseline caller into contextual callee",
       globalDirectContextual && globalDirectBaselineInactive},
      {"callsite mode activates indirect flow outside handler cone",
       globalCallsiteSolver.containsValue(globalIndirectFormal, {globalObjectB, 0}) &&
           globalCallsiteSolver.stats.indirectTargets == 1},
      {"unselected callsite retains baseline flow",
       mixedUnselectedBaselineActive && mixedUnselectedNoClone},
      {"selected callsite in mixed database isolates via contextual clone",
       mixedSelectedBaselineInactive && mixedSelectedContextual},
      {"mixed callsite selection accounting is explicit", mixedAccounting},
      {"signature model merges identical actual signatures", signatureSameMerged},
      {"signature model isolates distinct actual signatures", signatureDiffIsolated},
      {"signature overflow preserves flow as a union", overflowUnion},
      {"signature model shares direct and indirect callsites", directIndirectShared},
      {"location subobject rejects illegal negative offset",
       locRejectsNegative && locWideKeepsNegative},
      {"location subobject allows container_of back to base", locContainerOfToBase},
      {"location subobject keeps distinct nested member positions", locDistinctMembers},
      {"location subobject preserves unknown layout", locUnknownPreserved},
      {"bootstrap needs no CI prepass", bootstrapNoPrepass},
      {"bootstrap phase 0 converges without broadcast",
       bootstrapPhase0Converged && bootstrapNoBaselineBroadcast},
      {"bootstrap overflow preserves all inputs as a union", bootstrapOverflowUnion},
      {"phase 1 merges identical phase-0 formal sets", bootstrapSameFormalMerges},
      {"phase 1 isolates distinct phase-0 formal sets", bootstrapDiffFormalIsolates},
      {"bootstrap mapping is deterministic", bootstrapDeterministic},
  };
  int failures = 0;
  for (const Check &check : checks) {
    std::cout << '[' << (check.passed ? "PASS" : "FAIL") << "] " << check.name << '\n';
    failures += !check.passed;
  }
  return failures ? 1 : 0;
}

struct DirectSiteActivityStats {
  uint64_t pointerFlowSites = 0;
  uint64_t activeSites = 0;
  uint64_t activeActualSites = 0;
  uint64_t activeReturnSites = 0;
};

DirectSiteActivityStats writeDirectSiteActivity(const fs::path &path,
                                                 const Database &database,
                                                 const Solver &solver,
                                                 const std::vector<uint8_t> *previouslyActive) {
  DirectSiteActivityStats stats;
  std::vector<uint8_t> activeOrigins(database.values.size());
  for (uint32_t valueId = 0; valueId < database.values.size(); ++valueId) {
    if (!solver.hasValueTuples(valueId))
      continue;
    uint32_t origin = valueId < database.contextValueOrigins.size() &&
                              database.contextValueOrigins[valueId] != NONE
                          ? database.contextValueOrigins[valueId]
                          : valueId;
    if (origin < activeOrigins.size())
      activeOrigins[origin] = 1;
  }
  std::ofstream out(path);
  out << "#site_index\tcallsite\tcaller\tcallee\tpointer_actuals"
         "\tactive_actuals\tactive_return\tcontextual\tactive\n";
  for (uint32_t siteIndex = 0; siteIndex < database.directSites.size(); ++siteIndex) {
    const DirectSite &site = database.directSites[siteIndex];
    if (!database.handlerReachableFunctions.count(site.callerFunction) ||
        !database.handlerReachableFunctions.count(site.calleeFunction) ||
        !database.directSiteHasPointerFlow(site))
      continue;
    ++stats.pointerFlowSites;
    auto found = database.functions.find(site.calleeFunction);
    if (found == database.functions.end())
      continue;
    const FunctionInfo &info = found->second;
    uint32_t pointerActuals = 0;
    uint32_t activeActuals = 0;
    for (uint32_t offset = 0; offset < site.actualCount; ++offset) {
      const Actual &actual = database.directActuals[site.actualStart + offset];
      bool pointerFormal = std::any_of(
          info.formals.begin(), info.formals.end(),
          [&](const auto &formal) { return formal.first == actual.index; });
      if (!pointerFormal)
        continue;
      ++pointerActuals;
      activeActuals += actual.value < activeOrigins.size() && activeOrigins[actual.value];
    }
    bool activeReturn = false;
    if (site.result != NONE) {
      for (uint32_t returned : info.returns)
        activeReturn = activeReturn ||
                       (returned < activeOrigins.size() && activeOrigins[returned]);
    }
    bool active = activeActuals != 0 || activeReturn;
    if (previouslyActive && siteIndex < previouslyActive->size())
      active = active || (*previouslyActive)[siteIndex];
    stats.activeSites += active;
    stats.activeActualSites += activeActuals != 0;
    stats.activeReturnSites += activeReturn;
    out << siteIndex << '\t' << database.callsiteNames.name(site.callsiteName) << '\t'
        << database.objects.symbol(site.callerFunction) << '\t'
        << database.objects.symbol(site.calleeFunction) << '\t' << pointerActuals << '\t'
        << activeActuals << '\t' << activeReturn << '\t'
        << (siteIndex < database.contextualDirectSites.size() &&
            database.contextualDirectSites[siteIndex])
        << '\t' << active << '\n';
  }
  return stats;
}

std::vector<uint8_t> loadDirectSiteActivity(const fs::path &path,
                                            size_t directSiteCount) {
  std::ifstream input(path);
  if (!input)
    throw std::runtime_error("cannot open context site file: " + path.string());
  std::vector<uint8_t> enabled(directSiteCount);
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty() || line[0] == '#')
      continue;
    auto columns = splitTabs(line);
    uint32_t siteIndex = parseU32(columns[0], NONE);
    bool active = columns.size() == 1 || parseU32(columns.back(), 0) != 0;
    if (active && siteIndex < enabled.size())
      enabled[siteIndex] = 1;
  }
  return enabled;
}

void writeStats(const fs::path &path, const Options &options, const Database &db,
                const SolverStats &stats) {
  std::ofstream out(path);
  out << "{\n";
  out << "  \"batch\": \"" << jsonEscape(options.batch) << "\",\n";
  out << "  \"policy\": {\"unknown\": \"" << (options.keepUnknown ? "opaque" : "drop")
      << "\", \"field_dynamic\": \""
      << fieldDynamicPolicyName(options.fieldDynamicPolicy)
      << "\", \"field_type\": \""
      << fieldTypePolicyName(options.fieldTypePolicy)
      << "\", \"field_location\": \""
      << fieldLocationPolicyName(options.fieldLocationPolicy)
      << "\", \"field_cycle\": \""
      << fieldCyclePolicyName(options.fieldCyclePolicy)
      << "\", \"max_strided_expansion\": " << options.maxStridedExpansion
      << ", \"dynamic_alias\": \""
      << dynamicAliasPolicyName(options.dynamicAliasPolicy)
      << "\", \"affine_canon\": \""
      << affineCanonPolicyName(options.affineCanonPolicy)
      << "\", \"offset_overflow\": \""
      << offsetPolicyName(options.offsetPolicy) << "\""
      << ", \"copy_scc\": " << (options.useCopyScc ? "true" : "false")
      << ", \"value_slice\": \""
      << (options.usePointerSinkSlice ? "pointer-sinks" : "all")
      << "\", \"call_flow\": \"" << callFlowName(options.callFlowMode)
      << "\", \"context_scope\": \""
      << contextScopeName(options.contextScope)
      << "\", \"context_model\": \""
      << contextModelName(options.contextModel)
      << "\", \"context_budget\": " << options.contextBudget
      << ", \"context_objects\": \""
      << contextObjectName(options.contextObjectMode)
      << "\", \"context_depth\": " << options.contextDepth
      << ", \"context_value_slice\": \""
      << contextValueSliceName(options.contextValueSlice) << "\""
      << ", \"context_refine_min_contexts\": "
      << options.contextRefineMinContexts
      << ", \"context_refine_depth\": " << options.contextRefineDepth
      << ", \"context_refine_propagation\": \""
      << contextRefinePropagationName(options.contextRefinePropagation) << "\""
      << ", \"context_sites\": \""
      << jsonEscape(options.contextSites.empty() ? "all" : options.contextSites.string())
      << "\""
      << ", \"indirect_targets\": \""
      << jsonEscape(options.indirectTargets.empty() ? "-" : options.indirectTargets.string())
      << "\""
      << ", \"max_contexts\": " << options.maxContexts
      << "},\n";
  out << "  \"input\": {\n";
  out << "    \"object_schema_version\": " << db.objectSchemaVersion() << ",\n";
  out << "    \"objects\": " << db.counts.objectRows << ",\n";
  out << "    \"point_rows\": " << db.counts.pointRows << ",\n";
  out << "    \"dynamic_field_rows\": " << db.counts.dynamicFields << ",\n";
  out << "    \"strided_field_rows\": " << db.counts.stridedFields << ",\n";
  out << "    \"memory_rows\": " << db.counts.memoryRows << ",\n";
  out << "    \"call_rows\": " << db.counts.callRows << ",\n";
  out << "    \"direct_calls\": " << db.counts.directCalls << ",\n";
  out << "    \"indirect_calls\": " << db.counts.indirectCalls << ",\n";
  out << "    \"receiver_functions\": " << db.counts.receiverFunctions << ",\n";
  out << "    \"unique_receiver_functions\": "
      << db.counts.uniqueReceiverFunctions << ",\n";
  out << "    \"multi_receiver_functions\": "
      << db.counts.multiReceiverFunctions << ",\n";
  out << "    \"object_template_functions\": "
      << db.counts.objectTemplateFunctions << ",\n";
  out << "    \"object_template_values\": " << db.counts.objectTemplateValues << ",\n";
  out << "    \"object_template_components\": "
      << db.counts.objectTemplateComponents << ",\n";
  out << "    \"object_template_copy_edges\": "
      << db.counts.objectTemplateCopyEdges << ",\n";
  out << "    \"object_template_stack_objects\": "
      << db.counts.objectTemplateStackObjects << ",\n";
  out << "    \"object_template_address_seeds\": "
      << db.counts.objectTemplateAddressSeeds << ",\n";
  out << "    \"object_template_fields\": " << db.counts.objectTemplateFields << ",\n";
  out << "    \"object_template_dynamic_fields\": "
      << db.counts.objectTemplateDynamicFields << ",\n";
  out << "    \"object_template_strided_fields\": "
      << db.counts.objectTemplateStridedFields << ",\n";
  out << "    \"object_template_loads\": " << db.counts.objectTemplateLoads << ",\n";
  out << "    \"object_template_stores\": " << db.counts.objectTemplateStores << ",\n";
  out << "    \"object_template_store_objects\": "
      << db.counts.objectTemplateStoreObjects << ",\n";
  out << "    \"object_template_memory_copies\": "
      << db.counts.objectTemplateMemoryCopies << ",\n";
  out << "    \"object_template_direct_sites\": "
      << db.counts.objectTemplateDirectSites << ",\n";
  out << "    \"object_template_indirect_sites\": "
      << db.counts.objectTemplateIndirectSites << ",\n";
  out << "    \"memory_copies\": " << db.counts.memoryCopies << ",\n";
  out << "    \"seed_rows\": " << db.counts.seedRows << ",\n";
  out << "    \"seed_relations\": " << db.counts.seedRelations << ",\n";
  out << "    \"dispatch_summaries\": " << db.counts.dispatchSummaries << ",\n";
  out << "    \"cmd_summaries\": " << db.counts.cmdSummaries << ",\n";
  out << "    \"handler_root_functions\": " << db.counts.handlerRootFunctions << ",\n";
  out << "    \"handler_reachable_functions\": "
      << db.counts.handlerReachableFunctions << ",\n";
  out << "    \"handler_reachable_direct_sites\": "
      << db.counts.handlerReachableDirectSites << ",\n";
  out << "    \"context_eligible_direct_sites\": "
      << db.counts.contextEligibleDirectSites << ",\n";
  out << "    \"context_skipped_direct_sites\": "
      << db.counts.contextSkippedDirectSites << ",\n";
  out << "    \"context_irrelevant_direct_sites\": "
      << db.counts.contextIrrelevantDirectSites << ",\n";
  out << "    \"projected_callsite_values\": " << db.counts.projectedCallsiteValues << ",\n";
  out << "    \"projected_callsite_objects\": "
      << db.counts.projectedCallsiteObjects << ",\n";
  out << "    \"projected_callsite_invocations\": "
      << db.counts.projectedCallsiteInvocations << ",\n";
  out << "    \"projected_callsite_constraints\": "
      << db.counts.projectedCallsiteConstraints << ",\n";
  out << "    \"context_sensitive_values\": "
      << db.counts.contextSensitiveValues << ",\n";
  out << "    \"context_sensitive_memory_functions\": "
      << db.counts.contextSensitiveMemoryFunctions << ",\n";
  out << "    \"materialized_contexts\": " << db.counts.materializedContexts << ",\n";
  out << "    \"materialized_values\": " << db.counts.materializedValues << ",\n";
  out << "    \"materialized_objects\": " << db.counts.materializedObjects << ",\n";
  out << "    \"materialized_constraints\": "
      << db.counts.materializedConstraints << ",\n";
  out << "    \"refined_context_functions\": "
      << db.counts.refinedContextFunctions << ",\n";
  out << "    \"refined_context_cone_functions\": "
      << db.counts.refinedContextConeFunctions << ",\n";
  out << "    \"refined_context_transitions\": "
      << db.counts.refinedContextTransitions << ",\n";
  out << "    \"baseline_caller_transitions\": "
      << db.counts.baselineCallerTransitions << ",\n";
  out << "    \"baseline_dead_caller_sites\": "
      << db.counts.baselineDeadCallerSites << ",\n";
  out << "    \"resolved_indirect_sites\": "
      << db.counts.resolvedIndirectSites << ",\n";
  out << "    \"resolved_indirect_pairs\": "
      << db.counts.resolvedIndirectPairs << ",\n";
  out << "    \"signature_original_sites\": "
      << db.counts.signatureOriginalSites << ",\n";
  out << "    \"signature_unique\": " << db.counts.signatureUnique << ",\n";
  out << "    \"signature_equivalence_merged\": "
      << db.counts.signatureEquivalenceMerged << ",\n";
  out << "    \"signature_overflow_functions\": "
      << db.counts.signatureOverflowFunctions << ",\n";
  out << "    \"signature_overflow_merged\": "
      << db.counts.signatureOverflowMerged << ",\n";
  out << "    \"unresolved_objects\": " << db.counts.unresolvedObjects << ",\n";
  out << "    \"unresolved_functions\": " << db.counts.unresolvedFunctions << "\n";
  out << "  },\n";
  out << "  \"solver\": {\n";
  out << "    \"tuples\": " << stats.tuples << ",\n";
  out << "    \"value_tuples\": " << stats.valueTuples << ",\n";
  out << "    \"memory_tuples\": " << stats.memoryTuples << ",\n";
  out << "    \"memory_cells\": " << stats.memoryCells << ",\n";
  out << "    \"object_contexts_materialized\": "
      << stats.objectContextsMaterialized << ",\n";
  out << "    \"object_context_value_nodes\": "
      << stats.objectContextValueNodes << ",\n";
  out << "    \"object_context_stack_objects\": "
      << stats.objectContextStackObjects << ",\n";
  out << "    \"object_context_constraints\": "
      << stats.objectContextConstraints << ",\n";
  out << "    \"work_pops\": " << stats.workPops << ",\n";
  out << "    \"pending_tuples\": " << stats.pendingTuples << ",\n";
  out << "    \"copy_edges\": " << stats.copyEdges << ",\n";
  out << "    \"dynamic_copy_edges\": " << stats.dynamicCopyEdges << ",\n";
  out << "    \"dynamic_alias_edges\": " << stats.dynamicAliasEdges << ",\n";
  out << "    \"duplicate_copy_edges\": " << stats.duplicateCopyEdges << ",\n";
  out << "    \"indirect_targets\": " << stats.indirectTargets << ",\n";
  out << "    \"contextualized_indirect_targets\": "
      << stats.contextualizedIndirectTargets << ",\n";
  out << "    \"affine_regions_canonicalized\": "
      << stats.affineRegionsCanonicalized << ",\n";
  out << "    \"location_rejected_offsets\": "
      << stats.locationRejectedOffsets << ",\n";
  out << "    \"transfer_pairs\": " << stats.transferPairs << ",\n";
  out << "    \"transfer_cells\": " << stats.transferCells << ",\n";
  out << "    \"saturated_offsets\": " << stats.saturatedOffsets << ",\n";
  out << "    \"dropped_offsets\": " << stats.droppedOffsets << ",\n";
  out << "    \"root_dynamic_edges\": " << stats.rootDynamicEdges << ",\n";
  out << "    \"unresolved_dynamic_edges_dropped\": "
      << stats.unresolvedDynamicEdgesDropped << ",\n";
  out << "    \"strided_edges_active\": " << stats.stridedEdgesActive << ",\n";
  out << "    \"strided_edges_dropped\": " << stats.stridedEdgesDropped << ",\n";
  out << "    \"strided_edges_over_limit\": " << stats.stridedEdgesOverLimit << ",\n";
  out << "    \"strided_offsets_added\": " << stats.stridedOffsetsAdded << ",\n";
  out << "    \"strided_offset_arithmetic_dropped\": "
      << stats.stridedOffsetArithmeticDropped << ",\n";
  out << "    \"typed_field_applications\": " << stats.typedFieldApplications << ",\n";
  out << "    \"typed_field_compatible\": " << stats.typedFieldCompatible << ",\n";
  out << "    \"typed_field_unknown\": " << stats.typedFieldUnknown << ",\n";
  out << "    \"typed_field_incompatible\": " << stats.typedFieldIncompatible << ",\n";
  out << "    \"typed_field_dropped\": " << stats.typedFieldDropped << ",\n";
  out << "    \"field_cycle_edges\": " << stats.fieldCycleEdges << ",\n";
  out << "    \"field_cycle_edges_root_dynamic\": "
      << stats.fieldCycleEdgesRootDynamic << ",\n";
  out << "    \"field_cycle_edges_affine\": "
      << stats.fieldCycleEdgesAffine << ",\n";
  out << "    \"field_cycle_edges_dropped\": " << stats.fieldCycleEdgesDropped << ",\n";
  out << "    \"affine_region_applications\": "
      << stats.affineRegionApplications << ",\n";
  out << "    \"affine_regions_created\": " << stats.affineRegionsCreated << ",\n";
  out << "    \"affine_region_fallback_dynamic\": "
      << stats.affineRegionFallbackDynamic << ",\n";
  out << "    \"affine_region_clips\": " << stats.affineRegionClips << ",\n";
  out << "    \"affine_alias_edges\": " << stats.affineAliasEdges << ",\n";
  out << "    \"field_type_drop_samples\": " << stats.fieldTypeDropSamples << ",\n";
  out << "    \"field_type_drop_samples_truncated\": "
      << (stats.fieldTypeDropSamplesTruncated ? "true" : "false") << ",\n";
  out << "    \"roots_reaching_handler\": " << stats.rootsReachingHandler << ",\n";
  out << "    \"copy_scc_components\": " << stats.copySccComponents << ",\n";
  out << "    \"copy_scc_collapsed_values\": " << stats.copySccCollapsedValues << ",\n";
  out << "    \"copy_scc_max_size\": " << stats.copySccMaxSize << ",\n";
  out << "    \"live_values\": " << stats.liveValues << ",\n";
  out << "    \"live_components\": " << stats.liveComponents << ",\n";
  out << "    \"core_values\": " << stats.coreValues << ",\n";
  out << "    \"core_components\": " << stats.coreComponents << ",\n";
  out << "    \"demand_rounds\": " << stats.demandRounds << ",\n";
  out << "    \"demanded_store_sources\": " << stats.demandedStoreSources << ",\n";
  out << "    \"demanded_indirect_values\": " << stats.demandedIndirectValues << ",\n";
  out << "    \"demanded_memory_cells\": " << stats.demandedMemoryCells << ",\n";
  out << "    \"null_propagations_dropped\": " << stats.nullPropagationsDropped << ",\n";
  out << "    \"function_dereferences_dropped\": "
      << stats.functionDereferencesDropped << ",\n";
  out << "    \"store_only_tuples_dropped\": " << stats.storeOnlyTuplesDropped << ",\n";
  out << "    \"truncated\": " << (stats.truncated ? "true" : "false") << ",\n";
  out << "    \"load_seconds\": " << stats.loadSeconds << ",\n";
  out << "    \"solve_seconds\": " << stats.solveSeconds << "\n";
  out << "  }\n";
  out << "}\n";
}

// Loads a fresh Database from the configured inputs. Used once per phase so the two-phase
// signature flow can materialize independent context sets without rolling back clones.
std::unique_ptr<Database> loadDatabase(const Options &options,
                                       bool promoteIndirect = true) {
  auto database = std::make_unique<Database>(options.keepUnknown);
  database->setBatchFilter(options.batch);
  database->loadObjects(options.sh / "objects.tsv");
  if (options.fieldTypePolicy == FieldTypePolicy::Compatible &&
      database->objectSchemaVersion() < 3)
    throw std::runtime_error(
        "--field-type compatible requires schema v3 objects.tsv with contained_structs");
  database->loadPoints(options.sh / "points_to_constraints.tsv");
  database->loadMemory(options.sh / "memory_constraints.tsv");
  database->loadFunctionInterfaces(options.sh / "call_constraints.tsv");
  database->loadCalls(options.sh / "call_constraints.tsv");
  database->computeReceiverFormals();  // P1 object-sensitivity: static receiver selection
  database->computeObjectSensitivityTemplates();
  std::cerr << "[receiver] functions=" << database->counts.receiverFunctions
            << " unique_receiver=" << database->counts.uniqueReceiverFunctions
            << " multi_receiver=" << database->counts.multiReceiverFunctions << "\n";
  std::cerr << "[object-template] functions=" << database->counts.objectTemplateFunctions
            << " values=" << database->counts.objectTemplateValues
            << " components=" << database->counts.objectTemplateComponents
            << " copy_edges=" << database->counts.objectTemplateCopyEdges
            << " stack_objects=" << database->counts.objectTemplateStackObjects
            << " body_constraints="
            << database->counts.objectTemplateAddressSeeds +
                   database->counts.objectTemplateFields +
                   database->counts.objectTemplateDynamicFields +
                   database->counts.objectTemplateStridedFields +
                   database->counts.objectTemplateLoads +
                   database->counts.objectTemplateStores +
                   database->counts.objectTemplateStoreObjects +
                   database->counts.objectTemplateMemoryCopies
            << " call_templates="
            << database->counts.objectTemplateDirectSites +
                   database->counts.objectTemplateIndirectSites
            << "\n";
  if (promoteIndirect && !options.indirectTargets.empty())
    database->loadResolvedIndirectTargets(options.indirectTargets);
  database->loadRegistrationSeeds(options.sh / "registration_seeds.tsv");
  database->loadApiSummaries(options.sh / "api_summaries.tsv");
  database->computeHandlerReachability();
  return database;
}

// Runs the demand-driven solve loop to a fixpoint and returns the final solver.
std::unique_ptr<Solver> runSolveLoop(Database &database, const Options &options,
                                     double loadSeconds, const char *tag,
                                     bool discoveryMode = false,
                                     bool affineMemoryCensus = false) {
  std::vector<uint8_t> forcedValues(options.usePointerSinkSlice ? database.values.size() : 0);
  std::unordered_set<ObjKey, ObjKeyHash> demandedCells;
  std::unique_ptr<Solver> solver;
  uint64_t demandRounds = 0, demandedStoreSources = 0, demandedIndirectValues = 0;
  while (true) {
    solver = std::make_unique<Solver>(
        database, options.fieldDynamicPolicy, options.fieldTypePolicy,
        options.fieldCyclePolicy, options.maxStridedExpansion, options.offsetPolicy,
        options.useCopyScc, options.usePointerSinkSlice, options.callFlowMode,
        options.usePointerSinkSlice ? &forcedValues : nullptr,
        options.usePointerSinkSlice ? &demandedCells : nullptr, options.maxTuples,
        options.dynamicAliasPolicy, /*demandForcedOnly=*/false, options.affineCanonPolicy,
        options.fieldLocationPolicy, discoveryMode, affineMemoryCensus);
    ++demandRounds;
    std::cerr << "[" << tag << "] start round=" << demandRounds << "\n";
    solver->solve();
    solver->stats.loadSeconds = loadSeconds;
    solver->stats.demandRounds = demandRounds;
    solver->stats.demandedStoreSources = demandedStoreSources;
    solver->stats.demandedIndirectValues = demandedIndirectValues;
    solver->stats.demandedMemoryCells = demandedCells.size();
    std::cerr << "[" << tag << "] tuples=" << solver->stats.tuples
              << " indirect_targets=" << solver->stats.indirectTargets
              << " truncated=" << solver->stats.truncated
              << " pending=" << solver->stats.pendingTuples
              << " seconds=" << solver->stats.solveSeconds << "\n";
    if (solver->stats.truncated || !options.usePointerSinkSlice)
      break;
    uint64_t addedCells = solver->mergeDemandedCells(demandedCells);
    uint64_t addedSources = solver->addDemandedStoreSources(forcedValues);
    uint64_t addedIndirect = solver->addDemandedIndirectValues(forcedValues);
    demandedStoreSources += addedSources;
    demandedIndirectValues += addedIndirect;
    solver->stats.demandedStoreSources = demandedStoreSources;
    solver->stats.demandedIndirectValues = demandedIndirectValues;
    solver->stats.demandedMemoryCells = demandedCells.size();
    if (!addedCells && !addedSources && !addedIndirect)
      break;
    if (demandRounds >= 32) {
      solver->stats.truncated = true;
      break;
    }
  }
  return solver;
}

// Monotonic indirect-target frontier bootstrap. Each round loads a fresh database, promotes the
// accumulated (callsite, target) set as synthetic contextual direct sites, and solves in
// DISCOVERY mode: promoted pairs carry contextual actual/return flow, while every newly
// resolved non-promoted (callsite, target) pair is recorded but its flow is DEFERRED (no
// baseline broadcast), keeping the round bounded. The deferred pairs form the frontier;
// unioning them into the promoted set and repeating deepens one call level per round. Flow is
// only ever added (contextual), so the target set grows monotonically to a fixpoint. No CI
// prepass and no direct-callsite activity file are consumed — bootstrap contexts bypass the
// escape/activity filters — so there is no circular dependency. Each round MUST fully converge
// (pending=0, truncated=false) or its target set is rejected as untrustworthy.
int runIndirectBootstrap(const Options &options) {
  fs::create_directories(options.out);
  std::ofstream census(options.out / "indirect_target_bootstrap.tsv");
  census << "#round\tpromoted_in\ttargets_seen\tnew_targets\tdeferred_pairs\t"
            "deferred_direct_sites\tdeferred_direct_transfers\tvalue_context_fns\ttuples\t"
            "pending\ttruncated\n";

  // The monotone target set, keyed by string identities (callsite name, function-object name)
  // so it stays stable across the fresh per-round databases whose interned ids differ.
  std::set<std::pair<std::string, std::string>> promoted;
  std::map<std::pair<std::string, std::string>, std::string> symbolOf;
  if (!options.indirectTargets.empty()) {
    std::ifstream seed(options.indirectTargets);
    std::string line;
    while (std::getline(seed, line)) {
      if (line.empty() || line[0] == '#')
        continue;
      auto columns = splitTabs(line);
      if (columns.size() < 2)
        continue;
      std::pair<std::string, std::string> key{std::string(columns[0]),
                                              std::string(columns[1])};
      symbolOf[key] = columns.size() > 2 ? std::string(columns[2]) : std::string("-");
      promoted.insert(std::move(key));
    }
    std::cerr << "[indirect-bootstrap] seeded promoted=" << promoted.size()
              << " source=" << options.indirectTargets << "\n";
  }

  // Persistent, monotonically growing set of value-context functions (by NAME so it survives the
  // fresh per-round databases). Populated by the inner refinement loop when a round would
  // otherwise truncate on a value-merge (the device-model chain class).
  std::set<std::string> valueContextNames;

  uint32_t round = 0;
  while (true) {
    ++round;
    std::cerr << "[indirect-bootstrap] round=" << round
              << " promote=" << promoted.size()
              << " value_context_fns=" << valueContextNames.size() << "\n";
    std::vector<std::pair<std::string, std::string>> promotedVec(promoted.begin(),
                                                                 promoted.end());

    // Inner value-context refinement loop. Iteration 0 keys direct calls by bootstrap contexts
    // (mega-fan-in overflow deferred). On truncation, the value-merge functions (formals holding
    // > threshold objects) AND their pointer-flow callers are added to the value-context set, and
    // the round is retried on a fresh database with those callees keyed by receiver object-set
    // signature (computeBlendedContexts). The set grows UPSTREAM along the value-flow until the
    // merge separates where objects are still distinct, or growth stalls. Only one database is
    // held at a time: the next iteration's per-site context assignment is computed from the
    // current database+solver (site indices are stable across identical loads) and applied to the
    // next fresh load, so the prior database is freed before the next solve.
    std::unique_ptr<Database> databasePtr;
    std::unique_ptr<Solver> solver;
    std::vector<uint32_t> pendingContextOf;  // computed from prev iter; applied to this one
    std::vector<uint8_t> pendingMask;
    std::vector<uint8_t> overflowSiteMask;  // the mask that materialized the final database
    uint64_t valueContextContexts = 0;
    for (uint32_t iter = 0;; ++iter) {
      auto db = loadDatabase(options, /*promoteIndirect=*/false);
      db->promoteIndirectPairs(promotedVec);
      BootstrapCensus bootCensus;
      std::vector<uint8_t> mask;
      std::vector<uint32_t> ctxOf;
      if (iter == 0 || pendingContextOf.empty()) {
        ctxOf = computeBootstrapContexts(*db, options.contextBudget, bootCensus, &mask);
      } else {
        ctxOf = std::move(pendingContextOf);
        mask = std::move(pendingMask);
      }
      db->materializeCallsiteContexts(
          options.contextScope, options.contextObjectMode, options.contextDepth,
          options.contextValueSlice, options.contextRefineMinContexts,
          options.contextRefineDepth, options.contextRefinePropagation,
          /*enabledDirectSites=*/nullptr, options.maxContexts, &ctxOf,
          /*deferFlowSites=*/&mask);
      auto s = runSolveLoop(*db, options, 0.0, "indirect-bootstrap", /*discoveryMode=*/true);
      bool converged = !s->stats.truncated && s->stats.pendingTuples == 0;
      if (converged || !options.valueContextRefine ||
          iter >= options.valueContextMaxIters) {
        overflowSiteMask = std::move(mask);
        databasePtr = std::move(db);
        solver = std::move(s);
        break;
      }
      // Grow the value-context set from this (truncated) solve: value-merge callees plus their
      // pointer-flow callers (walk upstream toward where the objects are still distinct).
      std::set<std::string> grown = valueContextNames;
      std::unordered_set<uint32_t> targetIds;
      for (uint32_t fn : s->valueMergeFunctions(options.valueContextThreshold)) {
        targetIds.insert(fn);
        grown.insert(std::string(db->objects.name(fn)));
      }
      for (const auto &n : valueContextNames)
        if (auto o = db->objects.find(n))
          targetIds.insert(*o);
      for (const DirectSite &site : db->directSites)
        if (site.callerFunction != NONE && targetIds.count(site.calleeFunction) &&
            db->directSiteHasPointerFlow(site))
          grown.insert(std::string(db->objects.name(site.callerFunction)));
      if (grown.size() == valueContextNames.size()) {  // growth stalled: cannot refine further
        overflowSiteMask = std::move(mask);
        databasePtr = std::move(db);
        solver = std::move(s);
        break;
      }
      valueContextNames = std::move(grown);
      // Compute the next iteration's per-site context assignment from THIS db+solver, then free
      // them (single database held at a time).
      std::unordered_set<uint32_t> vcIds;
      for (const auto &n : valueContextNames)
        if (auto o = db->objects.find(n))
          vcIds.insert(*o);
      BootstrapCensus nextBoot;
      SignatureCensus nextSig;
      pendingContextOf = computeBlendedContexts(*db, *s, vcIds, options.contextBudget,
                                                pendingMask, nextBoot, nextSig);
      valueContextContexts = nextSig.uniqueSignatures;
      std::cerr << "[indirect-bootstrap] round=" << round << " vc-refine iter=" << iter
                << " tuples=" << s->stats.tuples << " pending=" << s->stats.pendingTuples
                << " value_context_fns=" << valueContextNames.size()
                << " value_context_contexts=" << valueContextContexts << "\n";
    }
    Database &database = *databasePtr;

    uint64_t promotedIn = promoted.size();
    std::set<std::pair<std::string, std::string>> discovered;
    for (const auto &[siteIndex, function] : solver->indirectTargets()) {
      std::pair<std::string, std::string> key{
          std::string(database.callsiteNames.name(
              database.indirectSites[siteIndex].callsiteName)),
          std::string(database.objects.name(function))};
      if (discovered.count(key) == 0)
        symbolOf[key] = std::string(database.objects.symbol(function));
      discovered.insert(std::move(key));
    }
    uint64_t targetsSeen = discovered.size();
    uint64_t newTargets = 0;
    for (const auto &key : discovered)
      if (promoted.insert(key).second)
        ++newTargets;

    // Direct overflow deferral is an under-approximation with no recovery (unlike indirect
    // promotion), so it is reported and gated on: deferred_direct_sites = selected overflow
    // sites, deferred_direct_transfers = contextual transfers dropped.
    uint64_t deferredDirectSites = 0;
    for (uint32_t s = 0; s < overflowSiteMask.size(); ++s)
      if (overflowSiteMask[s] && s < database.contextualDirectSites.size() &&
          database.contextualDirectSites[s])
        ++deferredDirectSites;
    uint64_t deferredDirectTransfers = database.counts.deferredDirectTransfers;

    census << round << '\t' << promotedIn << '\t' << targetsSeen << '\t' << newTargets << '\t'
           << solver->stats.deferredIndirectPairs << '\t' << deferredDirectSites << '\t'
           << deferredDirectTransfers << '\t' << valueContextNames.size() << '\t'
           << solver->stats.tuples << '\t' << solver->stats.pendingTuples << '\t'
           << (solver->stats.truncated ? 1 : 0) << '\n';
    census.flush();
    (void)valueContextContexts;
    std::cerr << "[indirect-bootstrap] round=" << round << " targets_seen=" << targetsSeen
              << " new=" << newTargets << " deferred_indirect="
              << solver->stats.deferredIndirectPairs
              << " deferred_direct_sites=" << deferredDirectSites
              << " deferred_direct_transfers=" << deferredDirectTransfers
              << " tuples=" << solver->stats.tuples
              << " pending=" << solver->stats.pendingTuples
              << " truncated=" << solver->stats.truncated << "\n";

    // Each discovery round must fully converge, else its target set is incomplete/untrustworthy.
    if (solver->stats.truncated || solver->stats.pendingTuples != 0) {
      // Diagnostic: dump what exploded so the residual broadcast source is identifiable.
      solver->writeHotspots(options.out / "truncated_hotspots.tsv");
      solver->writeHotspotDerivations(options.out / "truncated_hotspot_derivations.tsv");
      solver->writeAffineRegionCensus(options.out / "truncated_affine_region_census.tsv");
      std::cerr << "[indirect-bootstrap] round " << round
                << " did not converge (pending=" << solver->stats.pendingTuples
                << ", truncated=" << (solver->stats.truncated ? 1 : 0)
                << "); refusing incomplete target set\n";
      return 2;
    }
    // Persist the accumulated target set after each converged round so a later round that fails
    // (or a downstream census run) can consume the last good set without re-deriving it.
    {
      std::ofstream partial(options.out / "indirect_call_targets_partial.tsv");
      partial << "#callsite\tfunction_object\tfunction\n";
      for (const auto &key : promoted) {
        auto sym = symbolOf.find(key);
        partial << key.first << '\t' << key.second << '\t'
                << (sym == symbolOf.end() ? std::string("-") : sym->second) << '\n';
      }
    }

    // Fixpoint: converged with no new targets AND no deferred flow (indirect or direct).
    if (indirectBootstrapComplete(newTargets, solver->stats.deferredIndirectPairs,
                                  deferredDirectTransfers, solver->stats.pendingTuples,
                                  solver->stats.truncated))
      break;
    if (round >= options.indirectBootstrapMaxRounds) {
      std::cerr << "[indirect-bootstrap] exceeded max rounds "
                << options.indirectBootstrapMaxRounds << " without fixpoint\n";
      return 2;
    }
  }

  std::ofstream out(options.out / "indirect_call_targets.tsv");
  out << "#callsite\tfunction_object\tfunction\n";
  for (const auto &key : promoted) {
    auto sym = symbolOf.find(key);
    out << key.first << '\t' << key.second << '\t'
        << (sym == symbolOf.end() ? std::string("-") : sym->second) << '\n';
  }
  std::cerr << "[indirect-bootstrap] fixpoint rounds=" << round
            << " complete_targets=" << promoted.size() << " out="
            << (options.out / "indirect_call_targets.tsv").string() << "\n";
  return 0;
}

// Census-only analysis of the materialized context transition graph. NO solver / NO tuple
// closure. For each callee context it reports how many distinct caller contexts and static sites
// merge into it, then statically simulates keying the context by 1/2/3 levels of parent token
// (K1/K2/K3) to show whether selective deeper context would break the merges. This covers BOTH
// merge classes uniformly: the fan-in overflow (many static sites -> one overflow context, e.g.
// lockdep_init_map) and the chain-collapse (few sites, many caller contexts along a deep chain,
// e.g. the runtime-PM/device chain). Decision input: if K2/K3 collapses max in-degree at only a
// few merge points, selective parent-token refinement is warranted; if high in-degree is
// widespread, a lazier value-context is needed instead of blindly raising K.
void writeContextMergeCensus(const Database &db, const std::vector<uint32_t> &bootstrapOf,
                             const std::vector<uint8_t> &overflowSiteMask,
                             const fs::path &outDir) {
  const auto &trans = db.capturedTransitions;
  const uint32_t numContexts = static_cast<uint32_t>(db.contextInfo.size());
  std::vector<uint32_t> token1(numContexts, NONE);
  std::vector<uint8_t> overflowCtx(numContexts, 0);
  std::vector<uint32_t> incomingCount(numContexts, 0);
  std::vector<std::vector<uint32_t>> callersOf(numContexts), sitesOf(numContexts);
  for (const auto &t : trans) {
    uint32_t site = t[0], caller = t[1], callee = t[2];
    if (callee >= numContexts)
      continue;
    token1[callee] = site < bootstrapOf.size() ? bootstrapOf[site] : NONE;
    if (site < overflowSiteMask.size() && overflowSiteMask[site])
      overflowCtx[callee] = 1;
    ++incomingCount[callee];
    callersOf[callee].push_back(caller);
    sitesOf[callee].push_back(site);
  }
  auto dedup = [](std::vector<uint32_t> &v) {
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
  };
  for (uint32_t c = 0; c < numContexts; ++c) {
    dedup(callersOf[c]);
    dedup(sitesOf[c]);
  }

  struct Agg {
    uint64_t totalContexts = 0, maxIndeg = 0, merged = 0;
  };
  Agg k1, k2, k3;
  std::array<uint64_t, 24> hist{};  // log2 buckets of K1 distinct-caller in-degree

  std::ofstream rows(outDir / "context_merge_census.tsv");
  rows << "#callee\tcallee_context\tincoming_transitions\tdistinct_caller_contexts\t"
          "distinct_static_sites\tdistinct_parent_tokens\tk2_max_indeg\tk3_max_indeg\t"
          "pointer_formals\tbootstrap_overflow\n";

  for (uint32_t c = 0; c < numContexts; ++c) {
    if (callersOf[c].empty())
      continue;  // root / no incoming transition
    uint64_t indeg = callersOf[c].size();
    ++k1.totalContexts;
    k1.maxIndeg = std::max(k1.maxIndeg, indeg);
    if (indeg > 1)
      ++k1.merged;
    uint32_t bucket = 0;
    for (uint64_t v = indeg; v > 1 && bucket + 1 < hist.size(); v >>= 1)
      ++bucket;
    ++hist[bucket];

    // K2: split c's callers by their immediate token (token1 of the caller context).
    std::unordered_map<uint32_t, std::vector<uint32_t>> byParent;
    for (uint32_t p : callersOf[c])
      byParent[p < numContexts ? token1[p] : NONE].push_back(p);
    uint64_t k2maxC = 0, k3maxC = 0;
    for (auto &group : byParent) {
      ++k2.totalContexts;
      uint64_t sz = group.second.size();
      k2.maxIndeg = std::max(k2.maxIndeg, sz);
      if (sz > 1)
        ++k2.merged;
      k2maxC = std::max(k2maxC, sz);
      // K3: split each K2 group further by grandparent token (token1 of the caller's callers).
      std::unordered_map<uint32_t, uint64_t> byGrand;
      for (uint32_t p : group.second) {
        if (p >= numContexts || callersOf[p].empty()) {
          ++byGrand[NONE];
          continue;
        }
        std::unordered_set<uint32_t> grandTokens;
        for (uint32_t q : callersOf[p])
          grandTokens.insert(q < numContexts ? token1[q] : NONE);
        for (uint32_t gt : grandTokens)
          ++byGrand[gt];
      }
      for (auto &g3 : byGrand) {
        ++k3.totalContexts;
        k3.maxIndeg = std::max(k3.maxIndeg, g3.second);
        if (g3.second > 1)
          ++k3.merged;
        k3maxC = std::max(k3maxC, g3.second);
      }
    }

    if (indeg > 1) {  // only emit merge points to keep the file bounded
      uint32_t fn = db.contextInfo[c].function;
      uint32_t formals = 0;
      auto fit = db.functions.find(fn);
      if (fit != db.functions.end())
        formals = static_cast<uint32_t>(fit->second.formals.size());
      rows << db.objects.name(fn) << '\t' << c << '\t' << incomingCount[c] << '\t' << indeg
           << '\t' << sitesOf[c].size() << '\t' << byParent.size() << '\t' << k2maxC << '\t'
           << k3maxC << '\t' << formals << '\t' << (overflowCtx[c] ? 1 : 0) << '\n';
    }
  }

  std::ofstream summary(outDir / "context_merge_summary.tsv");
  summary << "#model\ttotal_contexts\tmax_caller_context_in_degree\tmerged_contexts\n";
  summary << "K1\t" << k1.totalContexts << '\t' << k1.maxIndeg << '\t' << k1.merged << '\n';
  summary << "K2\t" << k2.totalContexts << '\t' << k2.maxIndeg << '\t' << k2.merged << '\n';
  summary << "K3\t" << k3.totalContexts << '\t' << k3.maxIndeg << '\t' << k3.merged << '\n';
  summary << "#in_degree_histogram (K1 distinct caller contexts, log2 buckets)\n";
  summary << "#bucket\tlower_bound\tcontexts\n";
  for (uint32_t b = 0; b < hist.size(); ++b)
    if (hist[b])
      summary << b << '\t' << (uint64_t(1) << b) << '\t' << hist[b] << '\n';
  std::cerr << "[merge-census] contexts=" << k1.totalContexts
            << " K1_max_indeg=" << k1.maxIndeg << " merged=" << k1.merged
            << " | K2_max_indeg=" << k2.maxIndeg << " contexts=" << k2.totalContexts
            << " | K3_max_indeg=" << k3.maxIndeg << " contexts=" << k3.totalContexts << "\n";
}

// Driver for --context-merge-census: materialize the bootstrap context graph (optionally with
// promoted indirect targets) and write the merge census. No solver runs.
int runContextMergeCensus(const Options &options) {
  fs::create_directories(options.out);
  std::cerr << "[merge-census] load database\n";
  auto databasePtr = loadDatabase(options, /*promoteIndirect=*/true);
  Database &database = *databasePtr;
  std::cerr << "[merge-census] promoted_indirect_pairs="
            << database.counts.resolvedIndirectPairs << "\n";
  BootstrapCensus bootstrapCensus;
  std::vector<uint8_t> overflowSiteMask;
  std::vector<uint32_t> bootstrapOf = computeBootstrapContexts(
      database, options.contextBudget, bootstrapCensus, &overflowSiteMask);
  database.captureTransitions_ = true;
  database.materializeCallsiteContexts(
      options.contextScope, options.contextObjectMode, options.contextDepth,
      options.contextValueSlice, options.contextRefineMinContexts, options.contextRefineDepth,
      options.contextRefinePropagation, /*enabledDirectSites=*/nullptr, options.maxContexts,
      &bootstrapOf, /*deferFlowSites=*/&overflowSiteMask);
  std::cerr << "[merge-census] contexts=" << database.counts.materializedContexts
            << " transitions=" << database.capturedTransitions.size()
            << " bootstrap_overflow_sites=" << bootstrapCensus.overflowSites << "\n";
  writeContextMergeCensus(database, bootstrapOf, overflowSiteMask, options.out);
  return 0;
}

// Driver for --affine-memory-census: reproduces a discovery round (promote --indirect-targets,
// bootstrap contexts with overflow deferral) and solves with affine-memory instrumentation on,
// then dumps the affine memory census (+ region census + hotspots). Run twice with different
// --affine-canon to compare whether subsumption widened distinct regions into a shared cell.
int runAffineMemoryCensus(const Options &options) {
  fs::create_directories(options.out);
  std::cerr << "[affine-memory-census] load database\n";
  auto databasePtr = loadDatabase(options, /*promoteIndirect=*/true);
  Database &database = *databasePtr;
  std::cerr << "[affine-memory-census] promoted_indirect_pairs="
            << database.counts.resolvedIndirectPairs
            << " affine_canon=" << affineCanonPolicyName(options.affineCanonPolicy) << "\n";
  BootstrapCensus bootstrapCensus;
  std::vector<uint8_t> overflowSiteMask;
  std::vector<uint32_t> bootstrapOf = computeBootstrapContexts(
      database, options.contextBudget, bootstrapCensus, &overflowSiteMask);
  database.materializeCallsiteContexts(
      options.contextScope, options.contextObjectMode, options.contextDepth,
      options.contextValueSlice, options.contextRefineMinContexts, options.contextRefineDepth,
      options.contextRefinePropagation, /*enabledDirectSites=*/nullptr, options.maxContexts,
      &bootstrapOf, /*deferFlowSites=*/&overflowSiteMask);
  std::unique_ptr<Solver> solver = runSolveLoop(database, options, 0.0, "affine-memory-census",
                                                /*discoveryMode=*/true,
                                                /*affineMemoryCensus=*/true);
  std::cerr << "[affine-memory-census] tuples=" << solver->stats.tuples
            << " truncated=" << solver->stats.truncated
            << " pending=" << solver->stats.pendingTuples << "\n";
  solver->writeAffineMemoryCensus(options.out / "affine_memory_census.tsv");
  solver->writeAffineRegionCensus(options.out / "affine_region_census.tsv");
  solver->writeHotspots(options.out / "hotspots.tsv");
  solver->writeHotspotDerivations(options.out / "hotspot_derivations.tsv");
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  try {
    Options options = parseOptions(argc, argv);
    if (options.selftest)
      return runSelftest();
    if (options.contextMergeCensus)
      return runContextMergeCensus(options);
    if (options.affineMemoryCensus)
      return runAffineMemoryCensus(options);
    if (options.indirectBootstrap)
      return runIndirectBootstrap(options);
    auto loadStart = std::chrono::steady_clock::now();
    std::cerr << "[load] database\n";
    auto databasePtr = loadDatabase(options);
    Database &database = *databasePtr;
    if (!options.indirectTargets.empty())
      std::cerr << "[indirect] promoted_sites="
                << database.counts.resolvedIndirectSites
                << " pairs=" << database.counts.resolvedIndirectPairs
                << " source=" << options.indirectTargets << "\n";
    fs::create_directories(options.out);
    database.writeCallsiteContextCensus(options.out / "callsite_context_census.tsv");
    database.writeObjectTemplateCensus(options.out / "object_template_census.tsv");
    std::vector<uint8_t> enabledContextSites;
    const std::vector<uint8_t> *enabledContextSitesPtr = nullptr;
    if (!options.contextSites.empty()) {
      enabledContextSites = loadDirectSiteActivity(options.contextSites,
                                                   database.directSites.size());
      enabledContextSitesPtr = &enabledContextSites;
      std::cerr << "[context] enabled_sites="
                << std::count(enabledContextSites.begin(), enabledContextSites.end(), 1)
                << " source=" << options.contextSites << "\n";
    }
    std::vector<uint32_t> signatureOf;
    const std::vector<uint32_t> *signatureOfPtr = nullptr;
    BootstrapCensus bootstrapCensus;
    SignatureCensus signatureCensus;
    uint64_t bootstrapTuples = 0;
    bool usedBootstrap = false;
    if (options.callFlowMode == CallFlowMode::Callsite &&
        options.contextModel == ContextModel::Signature &&
        !options.contextCensusOnly) {
      // Phase 0: bounded callsite bootstrap on a SEPARATE database (no CI prepass). All
      // selected sites disable their baseline call transfer, so no strstr-class CI broadcast
      // is produced and the Phase-0 solve is bounded. It must converge before signatures are
      // derived from its context-sensitive formal points-to.
      std::cerr << "[phase0] load bootstrap database\n";
      auto phase0Ptr = loadDatabase(options);
      Database &phase0 = *phase0Ptr;
      std::vector<uint32_t> bootstrapOf =
          computeBootstrapContexts(phase0, options.contextBudget, bootstrapCensus);
      std::cerr << "[phase0] bootstrap sites=" << bootstrapCensus.sites
                << " dedicated=" << bootstrapCensus.dedicatedContexts
                << " overflow_fns=" << bootstrapCensus.overflowFunctions
                << " overflow_sites=" << bootstrapCensus.overflowSites << "\n";
      phase0.materializeCallsiteContexts(
          options.contextScope, options.contextObjectMode, options.contextDepth,
          options.contextValueSlice, options.contextRefineMinContexts,
          options.contextRefineDepth, options.contextRefinePropagation,
          enabledContextSitesPtr, options.maxContexts, &bootstrapOf);
      std::unique_ptr<Solver> phase0Solver = runSolveLoop(phase0, options, 0.0, "phase0");
      bootstrapTuples = phase0Solver->stats.tuples;
      if (phase0Solver->stats.truncated || phase0Solver->stats.pendingTuples != 0) {
        phase0Solver->writeAffineRegionCensus(options.out / "affine_region_census.tsv");
        throw std::runtime_error(
            "phase-0 bootstrap did not converge (pending=" +
            std::to_string(phase0Solver->stats.pendingTuples) + ", truncated=" +
            std::to_string(phase0Solver->stats.truncated ? 1 : 0) + ")");
      }
      // Phase 1: derive exact signatures from Phase-0's broadcast-free contextual formals.
      signatureOf = computeSignaturesFromBootstrap(phase0, *phase0Solver, bootstrapOf,
                                                   signatureCensus);
      signatureOfPtr = &signatureOf;
      usedBootstrap = true;
      database.counts.signatureOriginalSites = signatureCensus.originalSites;
      database.counts.signatureUnique = signatureCensus.uniqueSignatures;
      database.counts.signatureEquivalenceMerged = signatureCensus.equivalenceMerged;
      std::cerr << "[phase1] exact signatures sites=" << signatureCensus.originalSites
                << " unique=" << signatureCensus.uniqueSignatures
                << " merged=" << signatureCensus.equivalenceMerged << "\n";
    }
    if (options.callFlowMode == CallFlowMode::Callsite && !options.contextCensusOnly) {
      std::cerr << "[context] materialize callsite contexts scope="
                << contextScopeName(options.contextScope)
                << " model=" << contextModelName(options.contextModel) << "\n";
      database.materializeCallsiteContexts(options.contextScope,
                                           options.contextObjectMode,
                                           options.contextDepth,
                                           options.contextValueSlice,
                                           options.contextRefineMinContexts,
                                           options.contextRefineDepth,
                                           options.contextRefinePropagation,
                                           enabledContextSitesPtr,
                                           options.maxContexts,
                                           signatureOfPtr);
      std::cerr << "[context] contexts=" << database.counts.materializedContexts
                << " sensitive_values=" << database.counts.contextSensitiveValues
                << " values=" << database.counts.materializedValues
                << " objects=" << database.counts.materializedObjects
                << " constraints=" << database.counts.materializedConstraints
                << " refined_functions=" << database.counts.refinedContextFunctions
                << " refined_cone_functions="
                << database.counts.refinedContextConeFunctions
                << " refined_transitions=" << database.counts.refinedContextTransitions
                << " baseline_transitions="
                << database.counts.baselineCallerTransitions
                << " baseline_dead_caller_sites="
                << database.counts.baselineDeadCallerSites
                << "\n";
    }
    auto loadEnd = std::chrono::steady_clock::now();
    double loadSeconds = std::chrono::duration<double>(loadEnd - loadStart).count();
    std::cerr << "[load] values=" << database.values.size() << " objects=" << database.objects.size()
              << " direct_calls=" << database.counts.directCalls
              << " indirect_calls=" << database.counts.indirectCalls
              << " seconds=" << loadSeconds << "\n";
    if (options.contextCensusOnly) {
      std::cerr << "[context] roots=" << database.counts.handlerRootFunctions
                << " functions=" << database.counts.handlerReachableFunctions
                << " direct_sites=" << database.counts.handlerReachableDirectSites
                << " projected_values=" << database.counts.projectedCallsiteValues
                << " projected_invocations="
                << database.counts.projectedCallsiteInvocations
                << " projected_constraints="
                << database.counts.projectedCallsiteConstraints << "\n";
      return 0;
    }

    std::unique_ptr<Solver> solver =
        runSolveLoop(database, options, loadSeconds,
                     usedBootstrap ? "phase1" : "solve");
    if (usedBootstrap) {
      std::ofstream censusOut(options.out / "context_signature_census.tsv");
      censusOut << "#metric\tvalue\n"
                << "context_budget\t" << options.contextBudget << '\n'
                << "bootstrap_sites\t" << bootstrapCensus.sites << '\n'
                << "bootstrap_dedicated_contexts\t" << bootstrapCensus.dedicatedContexts
                << '\n'
                << "bootstrap_overflow_functions\t" << bootstrapCensus.overflowFunctions
                << '\n'
                << "bootstrap_overflow_sites\t" << bootstrapCensus.overflowSites << '\n'
                << "bootstrap_tuples\t" << bootstrapTuples << '\n'
                << "bootstrap_pending\t0\n"
                << "bootstrap_truncated\t0\n"
                << "exact_signature_contexts\t" << signatureCensus.uniqueSignatures << '\n'
                << "signature_equivalence_merged\t" << signatureCensus.equivalenceMerged
                << '\n'
                << "final_pending\t" << solver->stats.pendingTuples << '\n'
                << "final_truncated\t" << (solver->stats.truncated ? 1 : 0) << '\n';
    }
    solver->writeOutputs(options.out, options.writeTuples, options.writeDerivations);
    solver->writeCopySccMembers(options.out / "copy_scc_members.tsv");
    solver->writeHotspots(options.out / "fixpoint_hotspots.tsv");
    solver->writeHotspotDerivations(options.out / "hotspot_derivations.tsv");
    solver->writeAffineRegionCensus(options.out / "affine_region_census.tsv");
    if (options.writeCallsiteActivity) {
      DirectSiteActivityStats activity = writeDirectSiteActivity(
          options.out / "direct_callsite_activity.tsv", database, *solver,
          enabledContextSitesPtr);
      std::cerr << "[callsites] pointer_flow=" << activity.pointerFlowSites
                << " active=" << activity.activeSites
                << " active_actual=" << activity.activeActualSites
                << " active_return=" << activity.activeReturnSites << "\n";
    }
    writeStats(options.out / "fixpoint_stats.json", options, database, solver->stats);
    return solver->stats.truncated ? 2 : 0;
  } catch (const std::exception &error) {
    std::cerr << "pointsto_global: " << error.what() << "\n";
    return 1;
  }
}
