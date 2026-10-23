// Deterministic regression coverage for netfilter checkpoint/reset.
// Socket options are intercepted at link time, so this test runs without root
// and without relying on the host kernel's netfilter configuration.

#include "worker/sandbox/device_init/device_init.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace device_init = ::refuzz::worker::sandbox::device_init;

namespace {

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

#define RUN_TEST(fn)                                                      \
    do {                                                                  \
        std::fprintf(stderr, "RUN  %s\n", #fn);                           \
        fn();                                                             \
        std::fprintf(stderr, "OK   %s\n", #fn);                           \
    } while (0)

constexpr std::size_t kTableBytes = 1536;
constexpr std::size_t kBaselineEntryBytes = 64;
constexpr int kIpv4Fd = 9101;
constexpr int kIpv6Fd = 9102;

constexpr int kIptSetReplace = 64;
constexpr int kIptGetInfo = 64;
constexpr int kIptGetEntries = 65;
constexpr int kArptSetReplace = 96;
constexpr int kArptGetInfo = 96;
constexpr int kArptGetEntries = 97;
constexpr int kEbtSetEntries = 128;
constexpr int kEbtGetInfo = 128;
constexpr int kEbtGetEntries = 129;
constexpr int kEbtGetInitInfo = 130;
constexpr int kEbtGetInitEntries = 131;
constexpr unsigned int kBridgeHooks = 6;

struct XtCounters {
    std::uint64_t packets;
    std::uint64_t bytes;
};

struct IptInfo {
    char name[32];
    unsigned int valid_hooks;
    unsigned int hook_entry[5];
    unsigned int underflow[5];
    unsigned int num_entries;
    unsigned int size;
};

struct IptEntries {
    char name[32];
    unsigned int size;
    std::uint64_t entrytable[kTableBytes / sizeof(std::uint64_t)];
};

struct IptReplace {
    char name[32];
    unsigned int valid_hooks;
    unsigned int num_entries;
    unsigned int size;
    unsigned int hook_entry[5];
    unsigned int underflow[5];
    unsigned int num_counters;
    XtCounters* counters;
    std::uint64_t entrytable[kTableBytes / sizeof(std::uint64_t)];
};

struct ArptInfo {
    char name[32];
    unsigned int valid_hooks;
    unsigned int hook_entry[3];
    unsigned int underflow[3];
    unsigned int num_entries;
    unsigned int size;
};

struct ArptEntries {
    char name[32];
    unsigned int size;
    std::uint64_t entrytable[kTableBytes / sizeof(std::uint64_t)];
};

struct ArptReplace {
    char name[32];
    unsigned int valid_hooks;
    unsigned int num_entries;
    unsigned int size;
    unsigned int hook_entry[3];
    unsigned int underflow[3];
    unsigned int num_counters;
    XtCounters* counters;
    std::uint64_t entrytable[kTableBytes / sizeof(std::uint64_t)];
};

struct EbtReplace {
    char name[32];
    unsigned int valid_hooks;
    unsigned int num_entries;
    unsigned int entries_size;
    void* hook_entry[kBridgeHooks];
    unsigned int num_counters;
    void* counters;
    char* entries;
};

struct alignas(alignof(EbtReplace)) EbtEntries {
    unsigned int distinguisher;
    char name[32];
    unsigned int counter_offset;
    int policy;
    unsigned int num_entries;
};

struct IptState {
    IptInfo info{};
    std::array<unsigned char, kTableBytes> entries{};
};

struct ArptState {
    ArptInfo info{};
    std::array<unsigned char, kTableBytes> entries{};
};

struct EbtState {
    EbtReplace info{};
    std::array<unsigned char, kTableBytes> entries{};
};

struct ReplaceCounts {
    unsigned int ipv4 = 0;
    unsigned int ipv6 = 0;
    unsigned int arp = 0;
    unsigned int bridge = 0;

    unsigned int Total() const
    {
        return ipv4 + ipv6 + arp + bridge;
    }
};

constexpr std::array<const char*, 5> kIptNames = {
    "filter", "nat", "mangle", "raw", "security",
};
constexpr std::array<const char*, 3> kEbtNames = {
    "filter", "nat", "broute",
};

std::array<IptState, kIptNames.size()> g_ipv4{};
std::array<IptState, kIptNames.size()> g_ipv6{};
ArptState g_arp{};
std::array<EbtState, kEbtNames.size()> g_bridge{};

std::array<IptState, kIptNames.size()> g_ipv4_baseline{};
std::array<IptState, kIptNames.size()> g_ipv6_baseline{};
ArptState g_arp_baseline{};
std::array<EbtState, kEbtNames.size()> g_bridge_baseline{};

ReplaceCounts g_replace_counts{};
int g_socket_error = 0;
int g_socket_call_count = 0;
int g_fail_socket_call = -1;
int g_fail_socket_errno = EIO;
int g_fail_get_opt = -1;
int g_fail_get_errno = EIO;
int g_fail_set_opt = -1;
int g_fail_set_errno = EIO;
unsigned int g_tun_read_count = 0;
bool g_tun_read_never_blocks = false;

template <typename State, std::size_t N>
State* FindState(std::array<State, N>* states, const char* name)
{
    for (auto& state : *states) {
        if (::strcmp(state.info.name, name) == 0) {
            return &state;
        }
    }
    return nullptr;
}

void FillEntries(std::array<unsigned char, kTableBytes>* entries,
                 unsigned char seed)
{
    for (std::size_t i = 0; i < kBaselineEntryBytes; ++i) {
        (*entries)[i] = static_cast<unsigned char>(seed + i);
    }
}

void ResetFakeKernel()
{
    g_ipv4 = {};
    g_ipv6 = {};
    g_arp = {};
    g_bridge = {};
    g_replace_counts = {};
    g_socket_error = 0;
    g_socket_call_count = 0;
    g_fail_socket_call = -1;
    g_fail_socket_errno = EIO;
    g_fail_get_opt = -1;
    g_fail_get_errno = EIO;
    g_fail_set_opt = -1;
    g_fail_set_errno = EIO;
    g_tun_read_count = 0;
    g_tun_read_never_blocks = false;

    for (std::size_t i = 0; i < kIptNames.size(); ++i) {
        ::strcpy(g_ipv4[i].info.name, kIptNames[i]);
        g_ipv4[i].info.valid_hooks = 1;
        g_ipv4[i].info.num_entries = 1;
        g_ipv4[i].info.size = kBaselineEntryBytes;
        FillEntries(&g_ipv4[i].entries, static_cast<unsigned char>(0x10 + i));

        ::strcpy(g_ipv6[i].info.name, kIptNames[i]);
        g_ipv6[i].info.valid_hooks = 1;
        g_ipv6[i].info.num_entries = 1;
        g_ipv6[i].info.size = kBaselineEntryBytes;
        FillEntries(&g_ipv6[i].entries, static_cast<unsigned char>(0x30 + i));
    }

    ::strcpy(g_arp.info.name, "filter");
    g_arp.info.valid_hooks = 1;
    g_arp.info.num_entries = 1;
    g_arp.info.size = kBaselineEntryBytes;
    FillEntries(&g_arp.entries, 0x50);

    for (std::size_t i = 0; i < kEbtNames.size(); ++i) {
        ::strcpy(g_bridge[i].info.name, kEbtNames[i]);
        g_bridge[i].info.valid_hooks = (1U << 0) | (1U << 2);
        g_bridge[i].info.num_entries = 1;
        g_bridge[i].info.entries_size = kBaselineEntryBytes;
        FillEntries(&g_bridge[i].entries,
                    static_cast<unsigned char>(0x70 + i));
    }

    g_ipv4_baseline = g_ipv4;
    g_ipv6_baseline = g_ipv6;
    g_arp_baseline = g_arp;
    g_bridge_baseline = g_bridge;
}

bool SameIptState(const IptState& left, const IptState& right)
{
    return ::memcmp(&left.info, &right.info, sizeof(left.info)) == 0 &&
           left.entries == right.entries;
}

bool SameArptState(const ArptState& left, const ArptState& right)
{
    return ::memcmp(&left.info, &right.info, sizeof(left.info)) == 0 &&
           left.entries == right.entries;
}

bool SameEbtState(const EbtState& left, const EbtState& right)
{
    EbtReplace left_info = left.info;
    EbtReplace right_info = right.info;
    for (unsigned int i = 0; i < kBridgeHooks; ++i) {
        left_info.hook_entry[i] = nullptr;
        right_info.hook_entry[i] = nullptr;
    }
    left_info.counters = nullptr;
    left_info.entries = nullptr;
    right_info.counters = nullptr;
    right_info.entries = nullptr;
    return ::memcmp(&left_info, &right_info, sizeof(left_info)) == 0 &&
           left.entries == right.entries;
}

std::string ReadFile(const char* path)
{
    std::ifstream input(path);
    CHECK(input.good());
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void TestCheckpointAndRestoreAllFamilies()
{
    ResetFakeKernel();
    CHECK(device_init::CheckpointNetNamespace());
    CHECK(device_init::ResetNetNamespace());
    CHECK(g_replace_counts.Total() == 0);

    g_ipv4[0].entries[3] ^= 0xff;
    g_ipv6[1].info.valid_hooks = 3;
    g_arp.entries[5] ^= 0xff;
    g_bridge[2].entries[7] ^= 0xff;

    CHECK(device_init::ResetNetNamespace());
    CHECK(g_replace_counts.ipv4 == 1);
    CHECK(g_replace_counts.ipv6 == 1);
    CHECK(g_replace_counts.arp == 1);
    CHECK(g_replace_counts.bridge == 1);
    CHECK(SameIptState(g_ipv4[0], g_ipv4_baseline[0]));
    CHECK(SameIptState(g_ipv6[1], g_ipv6_baseline[1]));
    CHECK(SameArptState(g_arp, g_arp_baseline));
    CHECK(SameEbtState(g_bridge[2], g_bridge_baseline[2]));

    const unsigned int replacements = g_replace_counts.Total();
    CHECK(device_init::ResetNetNamespace());
    CHECK(g_replace_counts.Total() == replacements);
}

void TestPartialCheckpointInvalidatesAllTables()
{
    ResetFakeKernel();
    CHECK(device_init::CheckpointNetNamespace());

    g_fail_get_opt = kEbtGetInitEntries;
    CHECK(!device_init::CheckpointNetNamespace());
    g_fail_get_opt = -1;

    g_ipv4[0].entries[0] ^= 0xff;
    g_ipv6[0].entries[0] ^= 0xff;
    g_arp.entries[0] ^= 0xff;
    g_bridge[0].entries[0] ^= 0xff;
    g_replace_counts = {};
    CHECK(device_init::ResetNetNamespace());
    CHECK(g_replace_counts.Total() == 0);
}

void TestUnsupportedFamiliesAreSoftSkipped()
{
    for (const int error_number : {EAFNOSUPPORT, ENOPROTOOPT, ENOENT}) {
        ResetFakeKernel();
        g_socket_error = error_number;
        CHECK(device_init::CheckpointNetNamespace());
        CHECK(device_init::ResetNetNamespace());
        CHECK(g_replace_counts.Total() == 0);
    }
}

void TestMissingTablesAreSoftSkipped()
{
    struct Case {
        int option;
        int error_number;
    };
    for (const Case test_case : {
             Case{kEbtGetInitInfo, EPERM},
             Case{kArptGetInfo, ENOENT},
             Case{kIptGetInfo, ENOPROTOOPT},
         }) {
        ResetFakeKernel();
        g_fail_get_opt = test_case.option;
        g_fail_get_errno = test_case.error_number;
        CHECK(device_init::CheckpointNetNamespace());
        CHECK(device_init::ResetNetNamespace());
    }
}

void TestUnexpectedSocketFailuresPropagate()
{
    for (int socket_call = 1; socket_call <= 4; ++socket_call) {
        ResetFakeKernel();
        g_fail_socket_call = socket_call;
        CHECK(!device_init::CheckpointNetNamespace());
        CHECK(errno == EIO);
    }

    for (int socket_call = 1; socket_call <= 4; ++socket_call) {
        ResetFakeKernel();
        CHECK(device_init::CheckpointNetNamespace());
        g_socket_call_count = 0;
        g_fail_socket_call = socket_call;
        CHECK(!device_init::ResetNetNamespace());
        CHECK(errno == EIO);
    }
}

void TestCheckpointReadFailuresPropagate()
{
    for (const int option : {
             kEbtGetInitInfo, kEbtGetInitEntries,
             kArptGetInfo, kArptGetEntries,
             kIptGetInfo, kIptGetEntries,
         }) {
        ResetFakeKernel();
        g_fail_get_opt = option;
        CHECK(!device_init::CheckpointNetNamespace());
        CHECK(errno == EIO);
    }
}

void TestCheckpointRejectsOversizedTables()
{
    ResetFakeKernel();
    g_bridge[0].info.entries_size = kTableBytes + 1;
    CHECK(!device_init::CheckpointNetNamespace());
    CHECK(errno == E2BIG);

    ResetFakeKernel();
    g_arp.info.size = kTableBytes + 1;
    CHECK(!device_init::CheckpointNetNamespace());
    CHECK(errno == E2BIG);

    ResetFakeKernel();
    g_arp.info.num_entries = 11;
    CHECK(!device_init::CheckpointNetNamespace());
    CHECK(errno == E2BIG);

    ResetFakeKernel();
    g_ipv4[0].info.size = kTableBytes + 1;
    CHECK(!device_init::CheckpointNetNamespace());
    CHECK(errno == E2BIG);

    ResetFakeKernel();
    g_ipv4[0].info.num_entries = 11;
    CHECK(!device_init::CheckpointNetNamespace());
    CHECK(errno == E2BIG);
}

void TestResetSkipsCheckpointedTablesWithoutHooks()
{
    ResetFakeKernel();
    g_ipv4[0].info.valid_hooks = 0;
    g_arp.info.valid_hooks = 0;
    g_bridge[0].info.valid_hooks = 0;
    CHECK(device_init::CheckpointNetNamespace());

    g_ipv4[0].entries[0] ^= 0xff;
    g_arp.entries[0] ^= 0xff;
    g_bridge[0].entries[0] ^= 0xff;
    const unsigned char ipv4_entry = g_ipv4[0].entries[0];
    const unsigned char arp_entry = g_arp.entries[0];
    const unsigned char bridge_entry = g_bridge[0].entries[0];

    CHECK(device_init::ResetNetNamespace());
    CHECK(g_replace_counts.Total() == 0);
    CHECK(g_ipv4[0].entries[0] == ipv4_entry);
    CHECK(g_arp.entries[0] == arp_entry);
    CHECK(g_bridge[0].entries[0] == bridge_entry);
}

void TestEbtablesMetadataChangeIsRestored()
{
    ResetFakeKernel();
    CHECK(device_init::CheckpointNetNamespace());
    g_bridge[0].info.valid_hooks = 1U << 1;

    CHECK(device_init::ResetNetNamespace());
    CHECK(g_replace_counts.bridge == 1);
    CHECK(SameEbtState(g_bridge[0], g_bridge_baseline[0]));
}

void TestResetReadFailuresPropagate()
{
    for (const int option : {
             kEbtGetInfo, kEbtGetEntries,
             kArptGetInfo, kArptGetEntries,
             kIptGetInfo, kIptGetEntries,
         }) {
        ResetFakeKernel();
        CHECK(device_init::CheckpointNetNamespace());
        g_fail_get_opt = option;
        CHECK(!device_init::ResetNetNamespace());
        CHECK(errno == EIO);
    }
}

void TestResetRejectsOversizedCurrentCounterSets()
{
    ResetFakeKernel();
    CHECK(device_init::CheckpointNetNamespace());
    g_arp.info.num_entries = 11;
    CHECK(!device_init::ResetNetNamespace());
    CHECK(errno == E2BIG);

    ResetFakeKernel();
    CHECK(device_init::CheckpointNetNamespace());
    g_ipv4[0].info.num_entries = 11;
    CHECK(!device_init::ResetNetNamespace());
    CHECK(errno == E2BIG);
}

void TestAllRestoreFailuresPropagate()
{
    ResetFakeKernel();
    CHECK(device_init::CheckpointNetNamespace());
    g_bridge[0].entries[0] ^= 0xff;
    g_fail_set_opt = kEbtSetEntries;
    CHECK(!device_init::ResetNetNamespace());
    CHECK(errno == EIO);

    ResetFakeKernel();
    CHECK(device_init::CheckpointNetNamespace());
    g_arp.entries[0] ^= 0xff;
    g_fail_set_opt = kArptSetReplace;
    CHECK(!device_init::ResetNetNamespace());
    CHECK(errno == EIO);

    ResetFakeKernel();
    CHECK(device_init::CheckpointNetNamespace());
    g_ipv4[0].entries[0] ^= 0xff;
    g_fail_set_opt = kIptSetReplace;
    CHECK(!device_init::ResetNetNamespace());
    CHECK(errno == EIO);
}

void TestFlushTunDrainsUntilReadWouldBlock()
{
    ResetFakeKernel();
    device_init::FlushTun();
    CHECK(g_tun_read_count == 3);
}

void TestFlushTunStopsAtSafetyLimit()
{
    ResetFakeKernel();
    g_tun_read_never_blocks = true;
    device_init::FlushTun();
    CHECK(g_tun_read_count == 4096);
}

void TestRuntimeOrderingAndSandboxGates()
{
    const std::string loop = ReadFile(REFUZZ_LOOP_RUNTIME_SOURCE);
    const std::size_t gate = loop.find(
        "sandbox_mode != ::refuzz::worker::SandboxMode::kSetuid");
    const std::size_t checkpoint = loop.find(
        "device_init::CheckpointNetNamespace()");
    const std::size_t checkpoint_guard = loop.find(
        "if (net_namespace_reset_enabled &&", gate);
    const std::size_t ready = loop.find(
        "ReportLoopStartup(&startup_ack_fd, true", checkpoint);
    const std::size_t clear_loop = loop.find("ClearLoopDevice(proc_id)", ready);
    const std::size_t reset = loop.find(
        "device_init::ResetNetNamespace()", clear_loop);
    const std::size_t reset_guard = loop.find(
        "if (net_namespace_reset_enabled &&", checkpoint_guard + 1);
    const std::size_t request_read = loop.find(
        "read(ready_pipe_r, &msg, sizeof(msg))", reset);

    CHECK(gate != std::string::npos);
    CHECK(checkpoint != std::string::npos);
    CHECK(checkpoint_guard != std::string::npos);
    CHECK(ready != std::string::npos);
    CHECK(clear_loop != std::string::npos);
    CHECK(reset != std::string::npos);
    CHECK(reset_guard != std::string::npos);
    CHECK(request_read != std::string::npos);
    CHECK(gate < checkpoint);
    CHECK(checkpoint_guard < checkpoint);
    CHECK(checkpoint < ready);
    CHECK(clear_loop < reset);
    CHECK(clear_loop < reset_guard);
    CHECK(reset_guard < reset);
    CHECK(reset < request_read);

    const std::string snapshot = ReadFile(REFUZZ_SNAPSHOT_ENGINE_SOURCE);
    const std::size_t snapshot_gate = snapshot.find(
        "cfg.sandbox_mode != SandboxMode::kSetuid");
    const std::size_t snapshot_checkpoint = snapshot.find(
        "device_init::CheckpointNetNamespace()");
    const std::size_t snapshot_ready = snapshot.find(
        "task_channel.SetDomainReady(true)", snapshot_checkpoint);
    CHECK(snapshot_gate != std::string::npos);
    CHECK(snapshot_checkpoint != std::string::npos);
    CHECK(snapshot_ready != std::string::npos);
    CHECK(snapshot_gate < snapshot_checkpoint);
    CHECK(snapshot_checkpoint < snapshot_ready);
    CHECK(snapshot.find("device_init::ResetNetNamespace()") ==
          std::string::npos);
}

} // namespace

extern "C" int __real_close(int fd);
extern "C" ssize_t __real_read(int fd, void* data, size_t size);

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    CHECK(type == SOCK_STREAM);
    CHECK(protocol == IPPROTO_TCP);
    ++g_socket_call_count;
    if (g_fail_socket_call == g_socket_call_count) {
        errno = g_fail_socket_errno;
        return -1;
    }
    if (g_socket_error != 0) {
        errno = g_socket_error;
        return -1;
    }
    if (domain == AF_INET) {
        return kIpv4Fd;
    }
    if (domain == AF_INET6) {
        return kIpv6Fd;
    }
    errno = EAFNOSUPPORT;
    return -1;
}

extern "C" int __wrap_close(int fd)
{
    if (fd == kIpv4Fd || fd == kIpv6Fd) {
        return 0;
    }
    return __real_close(fd);
}

extern "C" int __wrap_getsockopt(int fd, int level, int optname,
                                  void* value, socklen_t* value_size)
{
    CHECK(value != nullptr);
    CHECK(value_size != nullptr);
    if (g_fail_get_opt == optname) {
        g_fail_get_opt = -1;
        errno = g_fail_get_errno;
        return -1;
    }

    if (optname == kEbtGetInitInfo || optname == kEbtGetInfo) {
        CHECK(fd == kIpv4Fd);
        CHECK(level == SOL_IP);
        auto* requested = static_cast<EbtReplace*>(value);
        EbtState* state = FindState(&g_bridge, requested->name);
        CHECK(state != nullptr);
        *requested = state->info;
        *value_size = sizeof(*requested);
        return 0;
    }
    if (optname == kEbtGetInitEntries || optname == kEbtGetEntries) {
        CHECK(fd == kIpv4Fd);
        CHECK(level == SOL_IP);
        auto* requested = static_cast<EbtReplace*>(value);
        EbtState* state = FindState(&g_bridge, requested->name);
        CHECK(state != nullptr);
        CHECK(requested->entries != nullptr);
        ::memcpy(requested->entries, state->entries.data(),
                 state->info.entries_size);
        return 0;
    }
    if (optname == kArptGetInfo) {
        CHECK(fd == kIpv4Fd);
        CHECK(level == SOL_IP);
        auto* requested = static_cast<ArptInfo*>(value);
        CHECK(::strcmp(requested->name, g_arp.info.name) == 0);
        *requested = g_arp.info;
        *value_size = sizeof(*requested);
        return 0;
    }
    if (optname == kArptGetEntries) {
        CHECK(fd == kIpv4Fd);
        CHECK(level == SOL_IP);
        auto* requested = static_cast<ArptEntries*>(value);
        CHECK(::strcmp(requested->name, g_arp.info.name) == 0);
        ::memcpy(requested->entrytable, g_arp.entries.data(), g_arp.info.size);
        return 0;
    }
    if (optname == kIptGetInfo) {
        CHECK((fd == kIpv4Fd && level == SOL_IP) ||
              (fd == kIpv6Fd && level == SOL_IPV6));
        auto* requested = static_cast<IptInfo*>(value);
        auto* states = level == SOL_IPV6 ? &g_ipv6 : &g_ipv4;
        IptState* state = FindState(states, requested->name);
        CHECK(state != nullptr);
        *requested = state->info;
        *value_size = sizeof(*requested);
        return 0;
    }
    if (optname == kIptGetEntries) {
        CHECK((fd == kIpv4Fd && level == SOL_IP) ||
              (fd == kIpv6Fd && level == SOL_IPV6));
        auto* requested = static_cast<IptEntries*>(value);
        auto* states = level == SOL_IPV6 ? &g_ipv6 : &g_ipv4;
        IptState* state = FindState(states, requested->name);
        CHECK(state != nullptr);
        ::memcpy(requested->entrytable, state->entries.data(), state->info.size);
        return 0;
    }

    std::fprintf(stderr, "unexpected getsockopt opt=%d level=%d\n",
                 optname, level);
    std::abort();
}

extern "C" int __wrap_setsockopt(int fd, int level, int optname,
                                  const void* value, socklen_t value_size)
{
    CHECK(value != nullptr);
    if (g_fail_set_opt == optname) {
        g_fail_set_opt = -1;
        errno = g_fail_set_errno;
        return -1;
    }
    if (optname == kEbtSetEntries) {
        CHECK(fd == kIpv4Fd);
        CHECK(level == SOL_IP);
        const auto* replacement = static_cast<const EbtReplace*>(value);
        CHECK(value_size == sizeof(*replacement) + replacement->entries_size);
        EbtState* state = FindState(&g_bridge, replacement->name);
        CHECK(state != nullptr);
        unsigned int entry_index = 0;
        for (unsigned int hook = 0; hook < kBridgeHooks; ++hook) {
            if ((replacement->valid_hooks & (1U << hook)) != 0) {
                const void* expected =
                    reinterpret_cast<const EbtEntries*>(replacement->entries) +
                    entry_index;
                CHECK(replacement->hook_entry[hook] == expected);
                ++entry_index;
            } else {
                CHECK(replacement->hook_entry[hook] == nullptr);
            }
        }
        state->info = *replacement;
        for (unsigned int i = 0; i < kBridgeHooks; ++i) {
            state->info.hook_entry[i] = nullptr;
        }
        state->info.num_counters = 0;
        state->info.counters = nullptr;
        state->info.entries = nullptr;
        ::memcpy(state->entries.data(), replacement->entries,
                 replacement->entries_size);
        ++g_replace_counts.bridge;
        return 0;
    }
    if (optname == kArptSetReplace) {
        CHECK(fd == kIpv4Fd);
        CHECK(level == SOL_IP);
        const auto* replacement = static_cast<const ArptReplace*>(value);
        CHECK(value_size ==
              sizeof(*replacement) - sizeof(replacement->entrytable) +
                  replacement->size);
        ArptInfo restored{};
        ::strcpy(restored.name, replacement->name);
        restored.valid_hooks = replacement->valid_hooks;
        restored.num_entries = replacement->num_entries;
        restored.size = replacement->size;
        ::memcpy(restored.hook_entry, replacement->hook_entry,
                 sizeof(restored.hook_entry));
        ::memcpy(restored.underflow, replacement->underflow,
                 sizeof(restored.underflow));
        g_arp.info = restored;
        ::memcpy(g_arp.entries.data(), replacement->entrytable,
                 replacement->size);
        ++g_replace_counts.arp;
        return 0;
    }
    if (optname == kIptSetReplace) {
        CHECK((fd == kIpv4Fd && level == SOL_IP) ||
              (fd == kIpv6Fd && level == SOL_IPV6));
        const auto* replacement = static_cast<const IptReplace*>(value);
        CHECK(value_size ==
              sizeof(*replacement) - sizeof(replacement->entrytable) +
                  replacement->size);
        auto* states = level == SOL_IPV6 ? &g_ipv6 : &g_ipv4;
        IptState* state = FindState(states, replacement->name);
        CHECK(state != nullptr);
        IptInfo restored{};
        ::strcpy(restored.name, replacement->name);
        restored.valid_hooks = replacement->valid_hooks;
        restored.num_entries = replacement->num_entries;
        restored.size = replacement->size;
        ::memcpy(restored.hook_entry, replacement->hook_entry,
                 sizeof(restored.hook_entry));
        ::memcpy(restored.underflow, replacement->underflow,
                 sizeof(restored.underflow));
        state->info = restored;
        ::memcpy(state->entries.data(), replacement->entrytable,
                 replacement->size);
        if (level == SOL_IPV6) {
            ++g_replace_counts.ipv6;
        } else {
            ++g_replace_counts.ipv4;
        }
        return 0;
    }

    std::fprintf(stderr, "unexpected setsockopt opt=%d level=%d\n",
                 optname, level);
    std::abort();
}

extern "C" ssize_t __wrap_read(int fd, void* data, size_t size)
{
    if (fd != 200) {
        return __real_read(fd, data, size);
    }
    CHECK(data != nullptr);
    CHECK(size == 1000);
    ++g_tun_read_count;
    if (g_tun_read_never_blocks) {
        static_cast<char*>(data)[0] = 0;
        return 1;
    }
    if (g_tun_read_count < 3) {
        static_cast<char*>(data)[0] = 0;
        return 1;
    }
    errno = EAGAIN;
    return -1;
}

int main()
{
    RUN_TEST(TestCheckpointAndRestoreAllFamilies);
    RUN_TEST(TestPartialCheckpointInvalidatesAllTables);
    RUN_TEST(TestUnsupportedFamiliesAreSoftSkipped);
    RUN_TEST(TestMissingTablesAreSoftSkipped);
    RUN_TEST(TestUnexpectedSocketFailuresPropagate);
    RUN_TEST(TestCheckpointReadFailuresPropagate);
    RUN_TEST(TestCheckpointRejectsOversizedTables);
    RUN_TEST(TestResetSkipsCheckpointedTablesWithoutHooks);
    RUN_TEST(TestEbtablesMetadataChangeIsRestored);
    RUN_TEST(TestResetReadFailuresPropagate);
    RUN_TEST(TestResetRejectsOversizedCurrentCounterSets);
    RUN_TEST(TestAllRestoreFailuresPropagate);
    RUN_TEST(TestFlushTunDrainsUntilReadWouldBlock);
    RUN_TEST(TestFlushTunStopsAtSafetyLimit);
    RUN_TEST(TestRuntimeOrderingAndSandboxGates);
    return 0;
}
