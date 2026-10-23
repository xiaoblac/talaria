// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/control/support/machine_check/machine_check.hpp"

#include "refuzz/control/support/machine_check/probe_program.hpp"  // kProbeMaxCalls
#include "refuzz/control/support/machine_check/probe_runner.hpp"   // BuildProbeTaskFromProg, DecodeProbeCompletion
#include "refuzz/control/support/support_check.hpp"                // ProbeSpec, gather_probes

#include "refuzz/core/channel_contract.hpp"  // Completion / AbnormalCompletion ctx
#include "refuzz/program/syz/prog.hpp"       // Prog (batch assembly)

#include <algorithm>
#include <cerrno>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace refuzz::control::support::machine_check {

namespace cs = ::refuzz::control::support;
namespace cc = ::refuzz::core::channel_contract;

cs::SupportEnv EnvFeaturesToSupportEnv(const ::EnvFeatures& ef, bool sandbox_is_none) {
    cs::SupportEnv env;
    env.sandbox_is_none = sandbox_is_none;
    env.probed          = true;

    // filesystems: split the '\n'-separated buffer.
    std::uint32_t fs_cap = ef.filesystems_len;
    if (fs_cap > ENV_FILESYSTEMS_CAP) fs_cap = ENV_FILESYSTEMS_CAP;
    for (std::uint32_t i = 0; i < fs_cap;) {
        std::uint32_t j = i;
        while (j < fs_cap && ef.filesystems[j] != '\n') ++j;
        if (j > i) env.filesystems.emplace_back(ef.filesystems + i, j - i);
        i = j + 1;
    }

    env.has_raw_gadget = env_features_has_flag(&ef, ENV_FEAT_RAW_GADGET) != 0;
    env.has_kvm        = env_features_has_flag(&ef, ENV_FEAT_KVM) != 0;
    env.kernel_major   = static_cast<int>(ef.kernel_major);
    env.kernel_minor   = static_cast<int>(ef.kernel_minor);
    env.lsm_present    = env_features_has_flag(&ef, ENV_FEAT_LSM_PRESENT) != 0;

    std::uint32_t lsm_cap = ef.lsm_len;
    if (lsm_cap > ENV_LSM_CAP) lsm_cap = ENV_LSM_CAP;
    env.lsms.assign(ef.lsm, lsm_cap);

    return env;
}

namespace {

// The candidate calls to probe: every whitelist-enabled syscall. Each one's
// owning support check decides what probe(s) it needs (cs::gather_probes); the
// generic ENOSYS sweep is just the DefaultCheck. No per-syscall logic here.
std::vector<const syz::SyscallMeta*> CollectCandidates(
    const syz::Target& target, const std::vector<std::uint8_t>& whitelist) {
    std::vector<const syz::SyscallMeta*> out;
    for (const auto& sc : target.syscalls()) {
        if (!sc) continue;
        const std::uint64_t id = sc->id();
        if (id < whitelist.size() && whitelist[id] != 0) out.push_back(sc.get());
    }
    return out;
}

} // namespace

MachineCheckResult RunMachineCheck(
    const syz::Target&                   target,
    const MachineCheckConfig&            cfg,
    ::refuzz::queue::InMemoryTaskQueue&  task_queue,
    ::refuzz::queue::InMemoryEventQueue& event_queue) {
    MachineCheckResult out;

    // Candidate whitelist (pure name-glob); bail early if it's already broken so
    // the caller surfaces the operator error rather than an empty probe run.
    syz::EnabledCalls whitelist =
        syz::compute_enabled_calls(target, cfg.enable, cfg.disable);
    if (!whitelist.ok) {
        out.enabled = std::move(whitelist);
        return out;
    }

    // Gather the probes each candidate's owning support check needs (socket's
    // synthetic socket(af,Vals[0],proto), a canOpen check's openat("/dev/vhci"),
    // a real syscall's bare ENOSYS call, …), deduped by tag — the construction
    // half of every check, owned by the check, never special-cased here.
    const std::vector<const syz::SyscallMeta*> candidates =
        CollectCandidates(target, whitelist.mask);
    std::vector<cs::ProbeSpec> specs = cs::gather_probes(target, candidates);
    out.probe_calls = specs.size();

    // Batch ≤ kProbeMaxCalls pre-built probe calls per program; remember each
    // batch's tags (in order) by executor_id so completions decode position →
    // tag → TrialResults.
    std::unordered_map<std::uint64_t, std::vector<std::string>> batch_tags;
    std::uint64_t next_id = cfg.base_executor_id + 1;  // nonzero
    for (std::size_t i = 0; i < specs.size(); i += kProbeMaxCalls) {
        const std::size_t end = std::min(i + kProbeMaxCalls, specs.size());
        syz::Prog prog;
        prog.set_target(&target);
        std::vector<std::string> tags;
        tags.reserve(end - i);
        for (std::size_t j = i; j < end; ++j) {
            tags.push_back(specs[j].tag);
            prog.add_call(std::move(specs[j].call));
        }
        const std::uint64_t id = next_id++;
        auto task = BuildProbeTaskFromProg(std::move(prog), id, cfg.timeout_ms);
        if (task_queue.Push(std::move(task))) {
            batch_tags.emplace(id, std::move(tags));
            ++out.probe_programs;
        }
    }

    // Collect: drain ChannelEvents until EVERY batch is accounted for. NO overall
    // timeout — the machine-check must fully complete before fuzzing, so we wait
    // for all probes. The running Executor submits the tasks and forwards a
    // terminal event (completion / abnormal — even across channel recovery) per
    // inflight task, so `pending` reaches 0; nothing else drains event_queue in
    // this window. The 200ms Pop is blocking granularity, not a deadline.
    cs::TrialResults trials;
    std::size_t      pending = batch_tags.size();
    while (pending > 0) {
        auto ev = event_queue.Pop(std::chrono::milliseconds(200));
        if (!ev.has_value()) continue;

        const cc::CompletionContext* ctx = nullptr;
        std::vector<std::uint8_t>    output;  // empty for abnormal → calls "unknown"
        if (const cc::Completion* comp = ev->AsCompletion()) {
            ctx    = &comp->ctx;
            output = comp->output;
        } else if (const cc::AbnormalCompletion* ab = ev->AsAbnormal()) {
            ctx = &ab->ctx;
        } else {
            continue;  // fault: not a probe result
        }

        const auto it = batch_tags.find(ctx->executor_id);
        if (it == batch_tags.end()) continue;  // not one of ours

        const std::vector<std::string>&    tags    = it->second;
        const std::vector<ProbeCallResult> results = DecodeProbeCompletion(output, tags.size());
        for (std::size_t k = 0; k < tags.size() && k < results.size(); ++k) {
            trials.by_name[tags[k]] = cs::ProbeOutcome{results[k].executed, results[k].err};
        }
        batch_tags.erase(it);
        --pending;
        ++out.programs_returned;
    }

    // [diagnostic] tally probe execution: how many calls actually ran + ENOSYS.
    for (const auto& [name, o] : trials.by_name) {
        if (o.executed) ++out.probe_executed;
        if (o.executed && o.err == ENOSYS) ++out.probe_enosys;
        if (!o.executed) out.probe_not_executed.push_back(name);  // [diagnostic]
    }
    std::sort(out.probe_not_executed.begin(), out.probe_not_executed.end());

    // Resolve: whitelist ∩ supported(env, trials) ∩ transitive closure, with the
    // disabled report (env/trial + transitive drops, one canonical record type).
    out.enabled = cs::resolve_enabled_calls(
        target, cfg.enable, cfg.disable, cfg.env, trials, &out.disabled);
    return out;
}

} // namespace refuzz::control::support::machine_check
