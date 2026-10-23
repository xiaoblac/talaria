// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/program/xiuos/xiuos_program_seed.hpp"

#include "util/json.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

namespace refuzz::program::xiuos {

namespace {

struct ApiDescriptor {
    XiuosApiId    id;
    std::uint8_t  argc;
};

// Mirror of tools/xiuos_refuzz/descriptors/common_kernel_sem_mutex.json:
// argc must match the descriptor exactly so seeds round-trip Python ↔ C++.
const std::unordered_map<std::string, ApiDescriptor>& ApiNameTable() {
    static const std::unordered_map<std::string, ApiDescriptor> kTable = {
        {"SEM_CREATE",    {XiuosApiId::SemCreate,    2}},
        {"SEM_DELETE",    {XiuosApiId::SemDelete,    1}},
        {"SEM_OBTAIN",    {XiuosApiId::SemObtain,    2}},
        {"SEM_ABANDON",   {XiuosApiId::SemAbandon,   1}},
        {"SEM_SET_VALUE", {XiuosApiId::SemSetValue,  2}},
        {"MUTEX_CREATE",  {XiuosApiId::MutexCreate,  1}},
        {"MUTEX_DELETE",  {XiuosApiId::MutexDelete,  1}},
        {"MUTEX_OBTAIN",  {XiuosApiId::MutexObtain,  2}},
        {"MUTEX_ABANDON", {XiuosApiId::MutexAbandon, 1}},
        {"MSGQ_CREATE",      {XiuosApiId::MsgqCreate,     3}},
        {"MSGQ_DELETE",      {XiuosApiId::MsgqDelete,     1}},
        {"MSGQ_SEND",        {XiuosApiId::MsgqSend,       2}},
        {"MSGQ_RECV",        {XiuosApiId::MsgqRecv,       2}},
        {"MSGQ_URGENT_SEND", {XiuosApiId::MsgqUrgentSend, 2}},
        {"MSGQ_REINIT",      {XiuosApiId::MsgqReinit,     1}},
        {"EVENT_CREATE",     {XiuosApiId::EventCreate,    2}},
        {"EVENT_DELETE",     {XiuosApiId::EventDelete,    1}},
        {"EVENT_TRIGGER",    {XiuosApiId::EventTrigger,   2}},
        {"EVENT_PROCESS",    {XiuosApiId::EventProcess,   4}},
        {"TIMER_CREATE",     {XiuosApiId::TimerCreate,    3}},
        {"TIMER_DELETE",     {XiuosApiId::TimerDelete,    1}},
        {"TIMER_START_RUN",  {XiuosApiId::TimerStartRun,  1}},
        {"TIMER_QUIT_RUN",   {XiuosApiId::TimerQuitRun,   1}},
        {"TIMER_MODIFY",     {XiuosApiId::TimerModify,    2}},
        {"TIMER_ASSIGN_MEMBER_RUN", {XiuosApiId::TimerAssignMemberRun, 2}},

        {"TASK_SPAWN_BLOCK_SEM",       {XiuosApiId::TaskSpawnBlockSem,      2}},
        {"TASK_SPAWN_BLOCK_EVENT",     {XiuosApiId::TaskSpawnBlockEvent,    2}},
        {"TASK_SPAWN_BLOCK_MSGQ_RECV", {XiuosApiId::TaskSpawnBlockMsgqRecv, 2}},
        {"TASK_TERMINATE",             {XiuosApiId::TaskTerminate,          1}},
        {"TASK_PRIO_SET",              {XiuosApiId::TaskPrioSet,            2}},
        {"TASK_SPAWN_SELF_SUSPEND",    {XiuosApiId::TaskSpawnSelfSuspend,   1}},
        {"TASK_WAKEUP",                {XiuosApiId::TaskWakeup,             1}},
        {"TASK_SPAWN_SELF_DELAY",      {XiuosApiId::TaskSpawnSelfDelay,     2}},
        {"TASK_SPAWN_BLOCK_SEM_TIMEOUT", {XiuosApiId::TaskSpawnBlockSemTimeout, 3}},
        {"TASK_SPAWN_BLOCK_EVENT_TIMEOUT", {XiuosApiId::TaskSpawnBlockEventTimeout, 3}},
        {"TASK_SPAWN_BLOCK_MSGQ_RECV_TIMEOUT", {XiuosApiId::TaskSpawnBlockMsgqRecvTimeout, 3}},
        {"TASK_SPAWN_BLOCK_MUTEX_TIMEOUT", {XiuosApiId::TaskSpawnBlockMutexTimeout, 3}},
        {"TASK_SPAWN_BLOCK_GB_ALLOC", {XiuosApiId::TaskSpawnBlockGbAlloc, 3}},
        {"TASK_SPAWN_BLOCK_MSGQ_SEND_TIMEOUT", {XiuosApiId::TaskSpawnBlockMsgqSendTimeout, 3}},
        {"TASK_GET_PRIO",      {XiuosApiId::TaskGetPrio,      1}},
        {"TASK_SPAWN_BLOCK_MUTEX_HIGH", {XiuosApiId::TaskSpawnBlockMutexHigh, 2}},

        {"WQ_CREATE",          {XiuosApiId::WqCreate,         2}},
        {"WQ_DEINIT",          {XiuosApiId::WqDeinit,         1}},
        {"WQ_SUBMIT",          {XiuosApiId::WqSubmit,         1}},
        {"WQ_SUBMIT_DELAYED",  {XiuosApiId::WqSubmitDelayed,  2}},

        {"DQ_INIT",            {XiuosApiId::DqInit,           2}},
        {"DQ_DEINIT",          {XiuosApiId::DqDeinit,         1}},
        {"DQ_PUSH",            {XiuosApiId::DqPush,           3}},
        {"DQ_POP",             {XiuosApiId::DqPop,            2}},
        {"DQ_PEEK",            {XiuosApiId::DqPeek,           1}},

        {"WAITQ_INIT",         {XiuosApiId::WaitqInit,        1}},
        {"WAITQ_SPAWN_WAIT",   {XiuosApiId::WaitqSpawnWait,   3}},
        {"WAITQ_WAKE",         {XiuosApiId::WaitqWake,        1}},

        {"HEAP_SNAPSHOT",      {XiuosApiId::HeapSnapshot,     0}},
        {"HEAP_INTEGRITY",     {XiuosApiId::HeapIntegrity,    0}},
        {"MALLOC",             {XiuosApiId::Malloc,           2}},
        {"FREE",               {XiuosApiId::Free,             1}},
        {"REALLOC",            {XiuosApiId::Realloc,          2}},
        {"CALLOC",             {XiuosApiId::Calloc,           3}},

        {"GB_CREATE",          {XiuosApiId::GbCreate,         3}},
        {"GB_DELETE",          {XiuosApiId::GbDelete,         1}},
        {"GB_ALLOC",           {XiuosApiId::GbAlloc,          3}},
        {"GB_FREE",            {XiuosApiId::GbFree,           2}},

        {"CA_INIT",            {XiuosApiId::CaInit,           2}},
        {"CA_RELEASE",         {XiuosApiId::CaRelease,        1}},
        {"CA_RESET",           {XiuosApiId::CaReset,          1}},
        {"CA_WRITE",           {XiuosApiId::CaWrite,          3}},
        {"CA_READ",            {XiuosApiId::CaRead,           2}},
        {"CA_GET_DATA_LENGTH", {XiuosApiId::CaGetDataLength,  1}},

        {"AVL_INSERT",         {XiuosApiId::AvlInsert,        2}},
        {"AVL_DELETE",         {XiuosApiId::AvlDelete,        2}},
        {"AVL_MODIFY",         {XiuosApiId::AvlModify,        3}},
        {"AVL_SEARCH",         {XiuosApiId::AvlSearch,        2}},
        {"AVL_COUNT",          {XiuosApiId::AvlCount,         1}},
        {"AVL_CHECK",          {XiuosApiId::AvlCheck,         1}},

        {"CAP_FLAG_SET",       {XiuosApiId::CapFlagSet,       2}},
        {"CAP_FLAG_CHECK",     {XiuosApiId::CapFlagCheck,     2}},
        {"CAP_ADD_TASK",       {XiuosApiId::CapAddTask,       2}},
        {"CAP_ADD_ROOT",       {XiuosApiId::CapAddRoot,       1}},
        {"CAP_ADD_ROOT_SELF",  {XiuosApiId::CapAddRootSelf,   0}},
        {"CAP_REMOVE_TASK",    {XiuosApiId::CapRemoveTask,    1}},
        {"CAP_CHECK_TASK",     {XiuosApiId::CapCheckTask,     2}},
        {"CAP_SET_TASK",       {XiuosApiId::CapSetTask,       2}},

        {"RESOURCE_SNAPSHOT",  {XiuosApiId::ResourceSnapshot, 0}},
        {"TICK_MS_TO_TICK",    {XiuosApiId::TickMsToTick,     1}},
        {"TICK_TO_MS",         {XiuosApiId::TickToMs,         1}},
    };
    return kTable;
}

XiuosSeedResult<XiuosSuiteId> ParseSuite(const std::string& name) {
    if (name == "COMMON_KERNEL") {
        return XiuosSeedResult<XiuosSuiteId>::Ok(XiuosSuiteId::CommonKernel);
    }
    return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                          "XiuosProgramSeed: unknown suite '" + name + "'"};
}

}  // namespace

std::vector<std::uint8_t> XiuosProgramSeed::Encode() const {
    return XiuosEncodeProgram(
        std::span<const XiuosProgramCall>(calls.data(), calls.size()),
        suite_id, /*flags=*/0);
}

XiuosSeedResult<XiuosProgramSeed>
ParseXiuosProgramSeedJson(std::string_view text, std::string_view source_name) {
    nlohmann::json root;
    try {
        root = nlohmann::json::parse(text);
    } catch (const std::exception& exc) {
        return XiuosSeedError{XiuosSeedErrorKind::kParse,
                              std::string(source_name) + ": json::parse: " + exc.what()};
    }

    if (!root.is_object()) {
        return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                              std::string(source_name) +
                              ": top-level JSON must be an object"};
    }
    if (!root.contains("name") || !root["name"].is_string()) {
        return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                              std::string(source_name) +
                              ": missing/non-string field 'name'"};
    }
    if (!root.contains("suite") || !root["suite"].is_string()) {
        return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                              std::string(source_name) +
                              ": missing/non-string field 'suite'"};
    }
    if (!root.contains("calls") || !root["calls"].is_array()) {
        return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                              std::string(source_name) +
                              ": missing/non-array field 'calls'"};
    }

    XiuosProgramSeed seed;
    seed.name = root["name"].get<std::string>();

    auto suite_r = ParseSuite(root["suite"].get<std::string>());
    if (!suite_r.ok()) return suite_r.error();
    seed.suite_id = suite_r.value();

    const auto& api_table = ApiNameTable();
    const auto& calls_arr = root["calls"];
    seed.calls.reserve(calls_arr.size());
    for (std::size_t i = 0; i < calls_arr.size(); ++i) {
        const auto& item = calls_arr[i];
        if (!item.is_object() ||
            !item.contains("api") || !item["api"].is_string()) {
            return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                                  std::string(source_name) + ": calls[" +
                                  std::to_string(i) + "] missing string 'api'"};
        }
        const std::string api_name = item["api"].get<std::string>();
        auto it = api_table.find(api_name);
        if (it == api_table.end()) {
            return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                                  std::string(source_name) + ": calls[" +
                                  std::to_string(i) + "] unknown api '" +
                                  api_name + "'"};
        }
        const auto& desc = it->second;

        XiuosProgramCall call;
        call.api_id = desc.id;
        call.argc   = desc.argc;

        std::vector<std::uint32_t> args_in;
        if (item.contains("args")) {
            if (!item["args"].is_array()) {
                return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                                      std::string(source_name) + ": calls[" +
                                      std::to_string(i) + "].args must be an array"};
            }
            for (const auto& v : item["args"]) {
                if (!v.is_number()) {
                    return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                                          std::string(source_name) + ": calls[" +
                                          std::to_string(i) + "].args must be numbers"};
                }
                args_in.push_back(static_cast<std::uint32_t>(v.get<std::uint64_t>()));
            }
        }
        if (args_in.size() != desc.argc) {
            return XiuosSeedError{XiuosSeedErrorKind::kConfig,
                                  std::string(source_name) + ": calls[" +
                                  std::to_string(i) + "] api=" + api_name +
                                  " expects argc=" + std::to_string(desc.argc) +
                                  ", got " + std::to_string(args_in.size())};
        }
        for (std::size_t a = 0; a < args_in.size() && a < call.args.size(); ++a) {
            call.args[a] = args_in[a];
        }

        if (item.contains("flags") && item["flags"].is_number()) {
            call.flags = static_cast<std::uint16_t>(
                item["flags"].get<std::uint32_t>());
        }
        seed.calls.push_back(call);
    }

    if (root.contains("source_rule") && root["source_rule"].is_string()) {
        seed.source_rule = root["source_rule"].get<std::string>();
    }
    if (root.contains("expected_min_calls") &&
        root["expected_min_calls"].is_number()) {
        seed.expected_min_calls = static_cast<std::uint16_t>(
            root["expected_min_calls"].get<std::uint32_t>());
    }

    return XiuosSeedResult<XiuosProgramSeed>::Ok(std::move(seed));
}

XiuosSeedResult<XiuosProgramSeed>
LoadXiuosProgramSeed(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return XiuosSeedError{XiuosSeedErrorKind::kIo,
                              "XiuosProgramSeed: cannot open " + path.string()};
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    if (in.bad()) {
        return XiuosSeedError{XiuosSeedErrorKind::kIo,
                              "XiuosProgramSeed: read failed " + path.string()};
    }
    return ParseXiuosProgramSeedJson(buf.str(), path.string());
}

std::vector<std::filesystem::path>
DiscoverXiuosProgramSeedFiles(const std::filesystem::path& root) {
    std::vector<std::filesystem::path> out;
    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) return out;

    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(root, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec)) continue;
        const auto& p = entry.path();
        if (p.extension() != ".json") continue;
        if (p.filename() == "manifest.json") continue;
        out.push_back(p);
    }
    std::sort(out.begin(), out.end());
    return out;
}

}  // namespace refuzz::program::xiuos
