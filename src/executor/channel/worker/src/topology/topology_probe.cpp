#include "worker/topology/topology_probe.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

namespace refuzz::worker::topology {

namespace {

void ProbeLog(const char* fmt, ...)
{
    char buf[512];
    va_list args;
    va_start(args, fmt);
    const int n = ::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n > 0) {
        ::refuzz::worker::log::WorkerLog("%s", buf);
    }
}

bool ReadFile(const char* path, std::string* out, int* err)
{
    if (out == nullptr) {
        if (err != nullptr) *err = EINVAL;
        return false;
    }
    out->clear();
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err != nullptr) *err = errno;
        return false;
    }
    char buf[4096];
    while (true) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n > 0) {
            out->append(buf, static_cast<std::size_t>(n));
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        if (err != nullptr) *err = errno;
        ::close(fd);
        return false;
    }
    ::close(fd);
    if (err != nullptr) *err = 0;
    return true;
}

void CopyFieldValue(const std::string& text,
                    const char* key,
                    char* out,
                    std::size_t out_size)
{
    if (out == nullptr || out_size == 0) {
        return;
    }
    out[0] = '-';
    if (out_size > 1) out[1] = '\0';

    const std::size_t key_len = ::strlen(key);
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) {
            eol = text.size();
        }
        if (eol - pos >= key_len &&
            ::memcmp(text.data() + pos, key, key_len) == 0) {
            std::size_t value = pos + key_len;
            while (value < eol &&
                   (text[value] == ' ' || text[value] == '\t')) {
                ++value;
            }
            while (eol > value &&
                   (text[eol - 1] == ' ' || text[eol - 1] == '\t' ||
                    text[eol - 1] == '\r')) {
                --eol;
            }
            const std::size_t len =
                (eol > value) ? (eol - value) : 0;
            const std::size_t copy =
                (len < out_size - 1) ? len : out_size - 1;
            if (copy > 0) {
                ::memcpy(out, text.data() + value, copy);
            }
            out[copy] = '\0';
            return;
        }
        pos = eol + 1;
    }
}

bool ReadStatus(pid_t pid, std::string* status)
{
    char path[64];
    ::snprintf(path, sizeof(path), "/proc/%d/status", static_cast<int>(pid));
    int err = 0;
    return ReadFile(path, status, &err);
}

long ReadLongFile(const char* path, int* err)
{
    std::string text;
    if (!ReadFile(path, &text, err)) {
        return -1;
    }
    return ::strtol(text.c_str(), nullptr, 10);
}

int CountLines(const std::string& text)
{
    if (text.empty()) {
        return 0;
    }
    int lines = 0;
    for (char c : text) {
        if (c == '\n') {
            ++lines;
        }
    }
    if (text.back() != '\n') {
        ++lines;
    }
    return lines;
}

bool ReadProcStatBrief(pid_t pid,
                       char* out_state,
                       int* out_ppid,
                       int* out_pgid,
                       int* out_sid)
{
    if (out_state != nullptr) *out_state = '?';
    if (out_ppid != nullptr) *out_ppid = -1;
    if (out_pgid != nullptr) *out_pgid = -1;
    if (out_sid != nullptr) *out_sid = -1;

    char path[64];
    ::snprintf(path, sizeof(path), "/proc/%d/stat", static_cast<int>(pid));
    int err = 0;
    std::string text;
    if (!ReadFile(path, &text, &err)) {
        return false;
    }
    const char* rp = ::strrchr(text.c_str(), ')');
    if (rp == nullptr) {
        return false;
    }
    char state = '?';
    int ppid = -1;
    int pgid = -1;
    int sid = -1;
    if (::sscanf(rp + 1, " %c %d %d %d", &state, &ppid, &pgid, &sid) != 4) {
        return false;
    }
    if (out_state != nullptr) *out_state = state;
    if (out_ppid != nullptr) *out_ppid = ppid;
    if (out_pgid != nullptr) *out_pgid = pgid;
    if (out_sid != nullptr) *out_sid = sid;
    return true;
}

void EmitStatusLine(const char* role,
                    std::uint32_t worker_id,
                    std::uint64_t executor_id,
                    std::uint32_t dispatch_gen,
                    pid_t pid,
                    const std::string& status,
                    const char* prefix)
{
    char pid_s[64];
    char ppid_s[64];
    char nspid[128];
    char nspgid[128];
    char nssid[128];
    CopyFieldValue(status, "Pid:", pid_s, sizeof(pid_s));
    CopyFieldValue(status, "PPid:", ppid_s, sizeof(ppid_s));
    CopyFieldValue(status, "NSpid:", nspid, sizeof(nspid));
    CopyFieldValue(status, "NSpgid:", nspgid, sizeof(nspgid));
    CopyFieldValue(status, "NSsid:", nssid, sizeof(nssid));

    char state = '?';
    int stat_ppid = -1;
    int stat_pgid = -1;
    int stat_sid = -1;
    (void)ReadProcStatBrief(pid, &state, &stat_ppid, &stat_pgid, &stat_sid);

    ProbeLog("[Worker] [topology-probe] %s role=%s wid=%u exec=%llu gen=%u "
             "Pid=%s PPid=%s NSpid=%s NSpgid=%s NSsid=%s "
             "stat_state=%c stat_ppid=%d stat_pgid=%d stat_sid=%d\n",
             prefix,
             role,
             worker_id,
             static_cast<unsigned long long>(executor_id),
             dispatch_gen,
             pid_s,
             ppid_s,
             nspid,
             nspgid,
             nssid,
             state,
             stat_ppid,
             stat_pgid,
             stat_sid);
}

} // namespace

bool TopologyProbeEnabled()
{
    static const bool enabled = []() {
        const char* env = ::getenv("REFUZZ_TOPOLOGY_PROBE");
        return env != nullptr && env[0] != '\0' && env[0] != '0';
    }();
    return enabled;
}

void EmitTopologyProbeSelf(const char* role,
                           std::uint32_t worker_id,
                           std::uint64_t executor_id,
                           std::uint32_t dispatch_gen)
{
    if (!TopologyProbeEnabled()) {
        return;
    }
    if (role == nullptr) {
        role = "unknown";
    }

    const pid_t pid = ::getpid();
    ProbeLog("[Worker] [topology-probe] self role=%s wid=%u exec=%llu gen=%u "
             "pid=%d ppid=%d pgrp=%d sid=%d getsid=%d\n",
             role,
             worker_id,
             static_cast<unsigned long long>(executor_id),
             dispatch_gen,
             static_cast<int>(pid),
             static_cast<int>(::getppid()),
             static_cast<int>(::getpgrp()),
             static_cast<int>(::getsid(0)),
             static_cast<int>(::getsid(0)));

    std::string status;
    if (ReadStatus(pid, &status)) {
        EmitStatusLine(role, worker_id, executor_id, dispatch_gen,
                       pid, status, "self-status");
    } else {
        ProbeLog("[Worker] [topology-probe] self-status role=%s wid=%u "
                 "exec=%llu gen=%u open_status_errno=%d\n",
                 role,
                 worker_id,
                 static_cast<unsigned long long>(executor_id),
                 dispatch_gen,
                 errno);
    }
}

void EmitCgroupSnapshot(const char* role,
                        std::uint32_t worker_id,
                        std::uint32_t proc_id,
                        std::uint64_t executor_id,
                        std::uint32_t dispatch_gen,
                        int max_procs,
                        bool force)
{
    if (!force && !TopologyProbeEnabled()) {
        return;
    }
    if (role == nullptr) {
        role = "unknown";
    }
    if (max_procs < 0) {
        max_procs = 0;
    }

    char pids_current_path[128];
    char procs_path[128];
    ::snprintf(pids_current_path, sizeof(pids_current_path),
               "/syzcgroup/unified/syz%u/pids.current", proc_id);
    ::snprintf(procs_path, sizeof(procs_path),
               "/syzcgroup/unified/syz%u/cgroup.procs", proc_id);

    int current_errno = 0;
    const long pids_current = ReadLongFile(pids_current_path, &current_errno);

    int procs_errno = 0;
    std::string procs;
    const bool procs_ok = ReadFile(procs_path, &procs, &procs_errno);
    const int procs_lines = procs_ok ? CountLines(procs) : -1;

    ProbeLog("[Worker] [topology-probe] cgroup role=%s wid=%u proc=%u exec=%llu gen=%u "
             "pids.current=%ld current_errno=%d procs_lines=%d procs_errno=%d\n",
             role,
             worker_id,
             proc_id,
             static_cast<unsigned long long>(executor_id),
             dispatch_gen,
             pids_current,
             current_errno,
             procs_lines,
             procs_errno);

    if (!procs_ok) {
        return;
    }

    int emitted = 0;
    std::size_t pos = 0;
    while (pos < procs.size() && emitted < max_procs) {
        std::size_t eol = procs.find('\n', pos);
        if (eol == std::string::npos) {
            eol = procs.size();
        }
        std::string line = procs.substr(pos, eol - pos);
        const long parsed = ::strtol(line.c_str(), nullptr, 10);
        if (parsed > 0) {
            const pid_t proc_pid = static_cast<pid_t>(parsed);
            std::string status;
            if (ReadStatus(proc_pid, &status)) {
                EmitStatusLine(role, worker_id, executor_id, dispatch_gen,
                               proc_pid, status, "cgroup-proc");
            } else {
                char state = '?';
                int ppid = -1;
                int pgid = -1;
                int sid = -1;
                (void)ReadProcStatBrief(proc_pid, &state, &ppid, &pgid, &sid);
                ProbeLog("[Worker] [topology-probe] cgroup-proc role=%s wid=%u "
                         "exec=%llu gen=%u pid=%d state=%c ppid=%d "
                         "pgid=%d sid=%d status=missing\n",
                         role,
                         worker_id,
                         static_cast<unsigned long long>(executor_id),
                         dispatch_gen,
                         static_cast<int>(proc_pid),
                         state,
                         ppid,
                         pgid,
                         sid);
            }
            ++emitted;
        }
        pos = eol + 1;
    }
    if (procs_lines > emitted) {
        ProbeLog("[Worker] [topology-probe] cgroup-truncated role=%s wid=%u "
                 "exec=%llu gen=%u emitted=%d procs_lines=%d\n",
                 role,
                 worker_id,
                 static_cast<unsigned long long>(executor_id),
                 dispatch_gen,
                 emitted,
                 procs_lines);
    }
}

void EmitTopologyProbeCgroup(const char* role,
                             std::uint32_t worker_id,
                             std::uint32_t proc_id,
                             std::uint64_t executor_id,
                             std::uint32_t dispatch_gen,
                             int max_procs)
{
    EmitCgroupSnapshot(role, worker_id, proc_id, executor_id, dispatch_gen,
                       max_procs,
                       false);
}

void EmitTopologyFatalCgroupSnapshot(const char* role,
                                     std::uint32_t worker_id,
                                     std::uint32_t proc_id,
                                     std::uint64_t executor_id,
                                     std::uint32_t dispatch_gen,
                                     int max_procs)
{
    EmitCgroupSnapshot(role, worker_id, proc_id, executor_id, dispatch_gen,
                       max_procs,
                       true);
}

void EmitTopologyProbeProgramFork(const char* role,
                                  std::uint32_t worker_id,
                                  std::uint64_t executor_id,
                                  std::uint32_t dispatch_gen,
                                  pid_t program_pid)
{
    if (!TopologyProbeEnabled()) {
        return;
    }
    if (role == nullptr) {
        role = "program-fork";
    }
    ProbeLog("[Worker] [topology-probe] fork role=%s wid=%u exec=%llu gen=%u "
             "loop_pid=%d program_pid=%d loop_pgrp=%d loop_sid=%d\n",
             role,
             worker_id,
             static_cast<unsigned long long>(executor_id),
             dispatch_gen,
             static_cast<int>(::getpid()),
             static_cast<int>(program_pid),
             static_cast<int>(::getpgrp()),
             static_cast<int>(::getsid(0)));
}

void EmitTopologyProbeCleanupSummary(const char* role,
                                     std::uint32_t worker_id,
                                     std::uint64_t executor_id,
                                     std::uint32_t dispatch_gen,
                                     pid_t program_pid,
                                     bool timed_out,
                                     bool timeout_reaped,
                                     int wait_status,
                                     int reaped_children,
                                     int stopped_children_killed,
                                     int wait_errno)
{
    if (!TopologyProbeEnabled()) {
        return;
    }
    if (role == nullptr) {
        role = "cleanup";
    }
    ProbeLog("[Worker] [topology-probe] cleanup role=%s wid=%u exec=%llu gen=%u "
             "program_pid=%d timed_out=%u timeout_reaped=%u wait_status=0x%x "
             "reaped_children=%d stopped_children_killed=%d wait_errno=%d "
             "loop_pid=%d loop_pgrp=%d loop_sid=%d\n",
             role,
             worker_id,
             static_cast<unsigned long long>(executor_id),
             dispatch_gen,
             static_cast<int>(program_pid),
             timed_out ? 1U : 0U,
             timeout_reaped ? 1U : 0U,
             wait_status,
             reaped_children,
             stopped_children_killed,
             wait_errno,
             static_cast<int>(::getpid()),
             static_cast<int>(::getpgrp()),
             static_cast<int>(::getsid(0)));
}

} // namespace refuzz::worker::topology
