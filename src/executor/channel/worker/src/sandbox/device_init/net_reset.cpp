// Netfilter namespace checkpoint/reset and TUN queue cleanup.
//
// This mirrors syzkaller's checkpoint_net_namespace/reset_net_namespace pair:
// checkpoint once after sandbox setup, then compare and restore iptables,
// ip6tables, arptables, and ebtables before every program. Besides providing a
// clean per-program network state, the checkpoint getsockopt calls trigger the
// kernel's lazy registration of the corresponding netfilter hooks.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// Linux netfilter userspace headers are not C++ friendly. Keep the small ABI
// subset used by syzkaller local to this translation unit.
#define XT_TABLE_SIZE 1536
#define XT_MAX_ENTRIES 10
#define IPT_BASE_CTL 64
#define IPT_SO_SET_REPLACE (IPT_BASE_CTL)
#define IPT_SO_GET_INFO (IPT_BASE_CTL)
#define IPT_SO_GET_ENTRIES (IPT_BASE_CTL + 1)
#define ARPT_BASE_CTL 96
#define ARPT_SO_SET_REPLACE (ARPT_BASE_CTL)
#define ARPT_SO_GET_INFO (ARPT_BASE_CTL)
#define ARPT_SO_GET_ENTRIES (ARPT_BASE_CTL + 1)
#define EBT_BASE_CTL 128
#define EBT_SO_SET_ENTRIES (EBT_BASE_CTL)
#define EBT_SO_GET_INFO (EBT_BASE_CTL)
#define EBT_SO_GET_ENTRIES (EBT_BASE_CTL + 1)
#define EBT_SO_GET_INIT_INFO (EBT_BASE_CTL + 2)
#define EBT_SO_GET_INIT_ENTRIES (EBT_BASE_CTL + 3)
#define NF_BR_NUMHOOKS 6
#define EBT_TABLE_MAXNAMELEN 32
#define EBT_CHAIN_MAXNAMELEN 32

#ifndef SOL_IPV6
#define SOL_IPV6 41
#endif

namespace {

#define NRLOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] net_reset: " fmt "\n", ##__VA_ARGS__)

struct xt_counters {
    std::uint64_t pcnt;
    std::uint64_t bcnt;
};

struct ipt_getinfo {
    char name[32];
    unsigned int valid_hooks;
    unsigned int hook_entry[5];
    unsigned int underflow[5];
    unsigned int num_entries;
    unsigned int size;
};

struct ipt_get_entries {
    char name[32];
    unsigned int size;
    std::uint64_t entrytable[XT_TABLE_SIZE / sizeof(std::uint64_t)];
};

struct ipt_replace {
    char name[32];
    unsigned int valid_hooks;
    unsigned int num_entries;
    unsigned int size;
    unsigned int hook_entry[5];
    unsigned int underflow[5];
    unsigned int num_counters;
    xt_counters* counters;
    std::uint64_t entrytable[XT_TABLE_SIZE / sizeof(std::uint64_t)];
};

struct ipt_table_desc {
    const char* name;
    ipt_getinfo info;
    ipt_replace replace;
    bool checkpoint_valid;
};

struct arpt_getinfo {
    char name[32];
    unsigned int valid_hooks;
    unsigned int hook_entry[3];
    unsigned int underflow[3];
    unsigned int num_entries;
    unsigned int size;
};

struct arpt_get_entries {
    char name[32];
    unsigned int size;
    std::uint64_t entrytable[XT_TABLE_SIZE / sizeof(std::uint64_t)];
};

struct arpt_replace {
    char name[32];
    unsigned int valid_hooks;
    unsigned int num_entries;
    unsigned int size;
    unsigned int hook_entry[3];
    unsigned int underflow[3];
    unsigned int num_counters;
    xt_counters* counters;
    std::uint64_t entrytable[XT_TABLE_SIZE / sizeof(std::uint64_t)];
};

struct arpt_table_desc {
    const char* name;
    arpt_getinfo info;
    arpt_replace replace;
    bool checkpoint_valid;
};

struct ebt_replace {
    char name[EBT_TABLE_MAXNAMELEN];
    unsigned int valid_hooks;
    unsigned int nentries;
    unsigned int entries_size;
    void* hook_entry[NF_BR_NUMHOOKS];
    unsigned int num_counters;
    void* counters;
    char* entries;
};

struct alignas(alignof(ebt_replace)) ebt_entries {
    unsigned int distinguisher;
    char name[EBT_CHAIN_MAXNAMELEN];
    unsigned int counter_offset;
    int policy;
    unsigned int nentries;
};

struct ebt_table_desc {
    const char* name;
    ebt_replace replace;
    alignas(ebt_entries) char entrytable[XT_TABLE_SIZE];
    bool checkpoint_valid;
};

ipt_table_desc g_ipv4_tables[] = {
    {.name = "filter", .info = {}, .replace = {}, .checkpoint_valid = false},
    {.name = "nat", .info = {}, .replace = {}, .checkpoint_valid = false},
    {.name = "mangle", .info = {}, .replace = {}, .checkpoint_valid = false},
    {.name = "raw", .info = {}, .replace = {}, .checkpoint_valid = false},
    {.name = "security", .info = {}, .replace = {}, .checkpoint_valid = false},
};

ipt_table_desc g_ipv6_tables[] = {
    {.name = "filter", .info = {}, .replace = {}, .checkpoint_valid = false},
    {.name = "nat", .info = {}, .replace = {}, .checkpoint_valid = false},
    {.name = "mangle", .info = {}, .replace = {}, .checkpoint_valid = false},
    {.name = "raw", .info = {}, .replace = {}, .checkpoint_valid = false},
    {.name = "security", .info = {}, .replace = {}, .checkpoint_valid = false},
};

arpt_table_desc g_arpt_tables[] = {
    {.name = "filter", .info = {}, .replace = {}, .checkpoint_valid = false},
};

ebt_table_desc g_ebt_tables[] = {
    {.name = "filter", .replace = {}, .entrytable = {}, .checkpoint_valid = false},
    {.name = "nat", .replace = {}, .entrytable = {}, .checkpoint_valid = false},
    {.name = "broute", .replace = {}, .entrytable = {}, .checkpoint_valid = false},
};

bool IsSoftUnsupportedError(int error_number)
{
    return error_number == EAFNOSUPPORT || error_number == ENOPROTOOPT ||
           error_number == ENOENT;
}

bool IsMissingTableError(int error_number)
{
    return error_number == EPERM || error_number == ENOENT ||
           error_number == ENOPROTOOPT;
}

void InvalidateCheckpoints()
{
    for (auto& table : g_ipv4_tables) {
        table.checkpoint_valid = false;
    }
    for (auto& table : g_ipv6_tables) {
        table.checkpoint_valid = false;
    }
    for (auto& table : g_arpt_tables) {
        table.checkpoint_valid = false;
    }
    for (auto& table : g_ebt_tables) {
        table.checkpoint_valid = false;
    }
}

bool CloseWithFailure(int fd, int error_number)
{
    (void)::close(fd);
    errno = error_number;
    return false;
}

bool CheckpointIptables(ipt_table_desc* tables, std::size_t num_tables,
                        int family, int level, const char* family_name)
{
    const int fd = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        const int error_number = errno;
        if (IsSoftUnsupportedError(error_number)) {
            return true;
        }
        NRLOG("iptable checkpoint %s: socket failed errno=%d (%s)",
              family_name, error_number, ::strerror(error_number));
        errno = error_number;
        return false;
    }

    for (std::size_t i = 0; i < num_tables; ++i) {
        ipt_table_desc* table = &tables[i];
        table->info = {};
        table->replace = {};
        table->checkpoint_valid = false;
        ::strcpy(table->info.name, table->name);
        ::strcpy(table->replace.name, table->name);

        socklen_t optlen = sizeof(table->info);
        if (::getsockopt(fd, level, IPT_SO_GET_INFO,
                         &table->info, &optlen) != 0) {
            const int error_number = errno;
            if (IsMissingTableError(error_number)) {
                continue;
            }
            NRLOG("iptable checkpoint %s/%s: GET_INFO errno=%d (%s)",
                  family_name, table->name, error_number,
                  ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }
        if (table->info.size > sizeof(table->replace.entrytable) ||
            table->info.num_entries > XT_MAX_ENTRIES) {
            NRLOG("iptable checkpoint %s/%s: invalid entries=%u size=%u",
                  family_name, table->name, table->info.num_entries,
                  table->info.size);
            return CloseWithFailure(fd, E2BIG);
        }

        ipt_get_entries entries{};
        ::strcpy(entries.name, table->name);
        entries.size = table->info.size;
        optlen = static_cast<socklen_t>(
            sizeof(entries) - sizeof(entries.entrytable) + table->info.size);
        if (::getsockopt(fd, level, IPT_SO_GET_ENTRIES,
                         &entries, &optlen) != 0) {
            const int error_number = errno;
            NRLOG("iptable checkpoint %s/%s: GET_ENTRIES errno=%d (%s)",
                  family_name, table->name, error_number,
                  ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }

        table->replace.valid_hooks = table->info.valid_hooks;
        table->replace.num_entries = table->info.num_entries;
        table->replace.size = table->info.size;
        ::memcpy(table->replace.hook_entry, table->info.hook_entry,
                 sizeof(table->replace.hook_entry));
        ::memcpy(table->replace.underflow, table->info.underflow,
                 sizeof(table->replace.underflow));
        ::memcpy(table->replace.entrytable, entries.entrytable,
                 table->info.size);
        table->checkpoint_valid = true;
    }

    (void)::close(fd);
    return true;
}

bool ResetIptables(ipt_table_desc* tables, std::size_t num_tables,
                   int family, int level, const char* family_name)
{
    const int fd = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        const int error_number = errno;
        if (IsSoftUnsupportedError(error_number)) {
            return true;
        }
        NRLOG("iptable reset %s: socket failed errno=%d (%s)",
              family_name, error_number, ::strerror(error_number));
        errno = error_number;
        return false;
    }

    for (std::size_t i = 0; i < num_tables; ++i) {
        ipt_table_desc* table = &tables[i];
        if (!table->checkpoint_valid || table->info.valid_hooks == 0) {
            continue;
        }

        ipt_getinfo info{};
        ::strcpy(info.name, table->name);
        socklen_t optlen = sizeof(info);
        if (::getsockopt(fd, level, IPT_SO_GET_INFO, &info, &optlen) != 0) {
            const int error_number = errno;
            NRLOG("iptable reset %s/%s: GET_INFO errno=%d (%s)",
                  family_name, table->name, error_number,
                  ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }

        bool unchanged = false;
        if (::memcmp(&table->info, &info, sizeof(info)) == 0) {
            ipt_get_entries entries{};
            ::strcpy(entries.name, table->name);
            entries.size = table->info.size;
            optlen = static_cast<socklen_t>(
                sizeof(entries) - sizeof(entries.entrytable) + entries.size);
            if (::getsockopt(fd, level, IPT_SO_GET_ENTRIES,
                             &entries, &optlen) != 0) {
                const int error_number = errno;
                NRLOG("iptable reset %s/%s: GET_ENTRIES errno=%d (%s)",
                      family_name, table->name, error_number,
                      ::strerror(error_number));
                return CloseWithFailure(fd, error_number);
            }
            unchanged = ::memcmp(table->replace.entrytable,
                                  entries.entrytable,
                                  table->info.size) == 0;
        }
        if (unchanged) {
            continue;
        }
        if (info.num_entries > XT_MAX_ENTRIES) {
            NRLOG("iptable reset %s/%s: current entries=%u exceeds %d",
                  family_name, table->name, info.num_entries, XT_MAX_ENTRIES);
            return CloseWithFailure(fd, E2BIG);
        }

        xt_counters counters[XT_MAX_ENTRIES]{};
        table->replace.num_counters = info.num_entries;
        table->replace.counters = counters;
        optlen = static_cast<socklen_t>(
            sizeof(table->replace) - sizeof(table->replace.entrytable) +
            table->replace.size);
        if (::setsockopt(fd, level, IPT_SO_SET_REPLACE,
                         &table->replace, optlen) != 0) {
            const int error_number = errno;
            table->replace.counters = nullptr;
            NRLOG("iptable reset %s/%s: SET_REPLACE errno=%d (%s)",
                  family_name, table->name, error_number,
                  ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }
        table->replace.counters = nullptr;
    }

    (void)::close(fd);
    return true;
}

bool CheckpointArptables()
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        const int error_number = errno;
        if (IsSoftUnsupportedError(error_number)) {
            return true;
        }
        NRLOG("arptable checkpoint: socket failed errno=%d (%s)",
              error_number, ::strerror(error_number));
        errno = error_number;
        return false;
    }

    for (auto& table : g_arpt_tables) {
        table.info = {};
        table.replace = {};
        table.checkpoint_valid = false;
        ::strcpy(table.info.name, table.name);
        ::strcpy(table.replace.name, table.name);

        socklen_t optlen = sizeof(table.info);
        if (::getsockopt(fd, SOL_IP, ARPT_SO_GET_INFO,
                         &table.info, &optlen) != 0) {
            const int error_number = errno;
            if (IsMissingTableError(error_number)) {
                continue;
            }
            NRLOG("arptable checkpoint %s: GET_INFO errno=%d (%s)",
                  table.name, error_number, ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }
        if (table.info.size > sizeof(table.replace.entrytable) ||
            table.info.num_entries > XT_MAX_ENTRIES) {
            NRLOG("arptable checkpoint %s: invalid entries=%u size=%u",
                  table.name, table.info.num_entries, table.info.size);
            return CloseWithFailure(fd, E2BIG);
        }

        arpt_get_entries entries{};
        ::strcpy(entries.name, table.name);
        entries.size = table.info.size;
        optlen = static_cast<socklen_t>(
            sizeof(entries) - sizeof(entries.entrytable) + table.info.size);
        if (::getsockopt(fd, SOL_IP, ARPT_SO_GET_ENTRIES,
                         &entries, &optlen) != 0) {
            const int error_number = errno;
            NRLOG("arptable checkpoint %s: GET_ENTRIES errno=%d (%s)",
                  table.name, error_number, ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }

        table.replace.valid_hooks = table.info.valid_hooks;
        table.replace.num_entries = table.info.num_entries;
        table.replace.size = table.info.size;
        ::memcpy(table.replace.hook_entry, table.info.hook_entry,
                 sizeof(table.replace.hook_entry));
        ::memcpy(table.replace.underflow, table.info.underflow,
                 sizeof(table.replace.underflow));
        ::memcpy(table.replace.entrytable, entries.entrytable, table.info.size);
        table.checkpoint_valid = true;
    }

    (void)::close(fd);
    return true;
}

bool ResetArptables()
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        const int error_number = errno;
        if (IsSoftUnsupportedError(error_number)) {
            return true;
        }
        NRLOG("arptable reset: socket failed errno=%d (%s)",
              error_number, ::strerror(error_number));
        errno = error_number;
        return false;
    }

    for (auto& table : g_arpt_tables) {
        if (!table.checkpoint_valid || table.info.valid_hooks == 0) {
            continue;
        }

        arpt_getinfo info{};
        ::strcpy(info.name, table.name);
        socklen_t optlen = sizeof(info);
        if (::getsockopt(fd, SOL_IP, ARPT_SO_GET_INFO,
                         &info, &optlen) != 0) {
            const int error_number = errno;
            NRLOG("arptable reset %s: GET_INFO errno=%d (%s)",
                  table.name, error_number, ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }

        bool unchanged = false;
        if (::memcmp(&table.info, &info, sizeof(info)) == 0) {
            arpt_get_entries entries{};
            ::strcpy(entries.name, table.name);
            entries.size = table.info.size;
            optlen = static_cast<socklen_t>(
                sizeof(entries) - sizeof(entries.entrytable) + entries.size);
            if (::getsockopt(fd, SOL_IP, ARPT_SO_GET_ENTRIES,
                             &entries, &optlen) != 0) {
                const int error_number = errno;
                NRLOG("arptable reset %s: GET_ENTRIES errno=%d (%s)",
                      table.name, error_number, ::strerror(error_number));
                return CloseWithFailure(fd, error_number);
            }
            unchanged = ::memcmp(table.replace.entrytable,
                                  entries.entrytable,
                                  table.info.size) == 0;
        }
        if (unchanged) {
            continue;
        }
        if (info.num_entries > XT_MAX_ENTRIES) {
            NRLOG("arptable reset %s: current entries=%u exceeds %d",
                  table.name, info.num_entries, XT_MAX_ENTRIES);
            return CloseWithFailure(fd, E2BIG);
        }

        xt_counters counters[XT_MAX_ENTRIES]{};
        table.replace.num_counters = info.num_entries;
        table.replace.counters = counters;
        optlen = static_cast<socklen_t>(
            sizeof(table.replace) - sizeof(table.replace.entrytable) +
            table.replace.size);
        if (::setsockopt(fd, SOL_IP, ARPT_SO_SET_REPLACE,
                         &table.replace, optlen) != 0) {
            const int error_number = errno;
            table.replace.counters = nullptr;
            NRLOG("arptable reset %s: SET_REPLACE errno=%d (%s)",
                  table.name, error_number, ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }
        table.replace.counters = nullptr;
    }

    (void)::close(fd);
    return true;
}

bool CheckpointEbtables()
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        const int error_number = errno;
        if (IsSoftUnsupportedError(error_number)) {
            return true;
        }
        NRLOG("ebtable checkpoint: socket failed errno=%d (%s)",
              error_number, ::strerror(error_number));
        errno = error_number;
        return false;
    }

    for (auto& table : g_ebt_tables) {
        table.replace = {};
        ::memset(table.entrytable, 0, sizeof(table.entrytable));
        table.checkpoint_valid = false;
        ::strcpy(table.replace.name, table.name);

        socklen_t optlen = sizeof(table.replace);
        if (::getsockopt(fd, SOL_IP, EBT_SO_GET_INIT_INFO,
                         &table.replace, &optlen) != 0) {
            const int error_number = errno;
            if (IsMissingTableError(error_number)) {
                continue;
            }
            NRLOG("ebtable checkpoint %s: GET_INIT_INFO errno=%d (%s)",
                  table.name, error_number, ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }
        if (table.replace.entries_size > sizeof(table.entrytable)) {
            NRLOG("ebtable checkpoint %s: entries_size=%u exceeds %zu",
                  table.name, table.replace.entries_size,
                  sizeof(table.entrytable));
            return CloseWithFailure(fd, E2BIG);
        }

        table.replace.num_counters = 0;
        table.replace.counters = nullptr;
        table.replace.entries = table.entrytable;
        optlen = static_cast<socklen_t>(
            sizeof(table.replace) + table.replace.entries_size);
        if (::getsockopt(fd, SOL_IP, EBT_SO_GET_INIT_ENTRIES,
                         &table.replace, &optlen) != 0) {
            const int error_number = errno;
            NRLOG("ebtable checkpoint %s: GET_INIT_ENTRIES errno=%d (%s)",
                  table.name, error_number, ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }
        table.checkpoint_valid = true;
    }

    (void)::close(fd);
    return true;
}

bool ResetEbtables()
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        const int error_number = errno;
        if (IsSoftUnsupportedError(error_number)) {
            return true;
        }
        NRLOG("ebtable reset: socket failed errno=%d (%s)",
              error_number, ::strerror(error_number));
        errno = error_number;
        return false;
    }

    for (auto& table : g_ebt_tables) {
        if (!table.checkpoint_valid || table.replace.valid_hooks == 0) {
            continue;
        }

        ebt_replace current{};
        ::strcpy(current.name, table.name);
        socklen_t optlen = sizeof(current);
        if (::getsockopt(fd, SOL_IP, EBT_SO_GET_INFO,
                         &current, &optlen) != 0) {
            const int error_number = errno;
            NRLOG("ebtable reset %s: GET_INFO errno=%d (%s)",
                  table.name, error_number, ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }

        current.num_counters = 0;
        current.counters = nullptr;
        current.entries = nullptr;
        table.replace.num_counters = 0;
        table.replace.counters = nullptr;
        table.replace.entries = nullptr;
        for (unsigned int h = 0; h < NF_BR_NUMHOOKS; ++h) {
            table.replace.hook_entry[h] = nullptr;
        }

        bool unchanged = false;
        if (::memcmp(&table.replace, &current, sizeof(current)) == 0) {
            alignas(ebt_entries) char entries[XT_TABLE_SIZE]{};
            current.entries = entries;
            optlen = static_cast<socklen_t>(
                sizeof(current) + current.entries_size);
            if (::getsockopt(fd, SOL_IP, EBT_SO_GET_ENTRIES,
                             &current, &optlen) != 0) {
                const int error_number = errno;
                NRLOG("ebtable reset %s: GET_ENTRIES errno=%d (%s)",
                      table.name, error_number, ::strerror(error_number));
                return CloseWithFailure(fd, error_number);
            }
            unchanged = ::memcmp(table.entrytable, entries,
                                  current.entries_size) == 0;
        }
        if (unchanged) {
            continue;
        }

        for (unsigned int j = 0, h = 0; h < NF_BR_NUMHOOKS; ++h) {
            if ((table.replace.valid_hooks & (1U << h)) != 0) {
                table.replace.hook_entry[h] =
                    reinterpret_cast<ebt_entries*>(table.entrytable) + j;
                ++j;
            }
        }
        table.replace.entries = table.entrytable;
        optlen = static_cast<socklen_t>(
            sizeof(table.replace) + table.replace.entries_size);
        if (::setsockopt(fd, SOL_IP, EBT_SO_SET_ENTRIES,
                         &table.replace, optlen) != 0) {
            const int error_number = errno;
            NRLOG("ebtable reset %s: SET_ENTRIES errno=%d (%s)",
                  table.name, error_number, ::strerror(error_number));
            return CloseWithFailure(fd, error_number);
        }
    }

    (void)::close(fd);
    return true;
}

constexpr int kTunFd = 200;

} // namespace

namespace refuzz::worker::sandbox::device_init {

bool CheckpointNetNamespace()
{
    // A failed partial checkpoint must never leave older snapshots eligible for
    // restore. The caller tears down the execution domain on false.
    InvalidateCheckpoints();
    if (!CheckpointEbtables() || !CheckpointArptables() ||
        !CheckpointIptables(g_ipv4_tables,
                            sizeof(g_ipv4_tables) / sizeof(g_ipv4_tables[0]),
                            AF_INET, SOL_IP, "ipv4") ||
        !CheckpointIptables(g_ipv6_tables,
                            sizeof(g_ipv6_tables) / sizeof(g_ipv6_tables[0]),
                            AF_INET6, SOL_IPV6, "ipv6")) {
        InvalidateCheckpoints();
        return false;
    }
    return true;
}

bool ResetNetNamespace()
{
    return ResetEbtables() && ResetArptables() &&
           ResetIptables(g_ipv4_tables,
                         sizeof(g_ipv4_tables) / sizeof(g_ipv4_tables[0]),
                         AF_INET, SOL_IP, "ipv4") &&
           ResetIptables(g_ipv6_tables,
                         sizeof(g_ipv6_tables) / sizeof(g_ipv6_tables[0]),
                         AF_INET6, SOL_IPV6, "ipv6");
}

void FlushTun()
{
    char buf[1000];
    int safety = 4096;
    while (safety-- > 0) {
        if (::read(kTunFd, buf, sizeof(buf)) < 0) {
            break;
        }
    }
}

} // namespace refuzz::worker::sandbox::device_init
