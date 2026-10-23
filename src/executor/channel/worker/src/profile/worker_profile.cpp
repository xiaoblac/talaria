// Copyright 2026 reFuzz project author -------youngkk.
//
// Generic WorkerProfile runner. Profile factories own family/transport
// assembly; this file owns the common startup order.

#include "worker/profile/worker_profile.hpp"

#include "worker/engine/execution_engine.hpp"
#include "worker/engine/snapshot_engine.hpp"  // [Brick 4a] RunSnapshotEngine
#include "worker/env/env_probe.hpp"           // [machine-check C4.6 ①c] ProbeEnvFeatures
#include "worker/log/log_macros.hpp"
#include "worker/observation/ivshmem_step_event_sink.hpp"
#include "worker/transport/ivshmem_transport.hpp"  // ShmHeader + publish_env_features_v3

#include <memory>
#include <unistd.h>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker {

int RunWorkerProfile(WorkerProfile& profile)
{
    if (profile.adapter == nullptr) {
        LOG("RunWorkerProfile: profile.adapter null");
        return 2;
    }
    auto* daemon_components =
        std::get_if<DaemonOwnedExecutionComponents>(
            &profile.execution_components);
    if (daemon_components != nullptr && !*daemon_components) {
        LOG("RunWorkerProfile: daemon-owned components incomplete");
        return 2;
    }
    if (profile.snapshot && daemon_components == nullptr) {
        LOG("RunWorkerProfile: snapshot profile requires local backend/bus");
        return 2;
    }
    if (profile.topology == nullptr) {
        LOG("RunWorkerProfile: profile.topology null (P1 should assemble in factory)");
        return 2;
    }

    IWorkerTaskChannel& task_channel = profile.adapter->TaskChannel();
    IExecutionDomainRegistry& domain_registry =
        profile.adapter->DomainRegistry();
    IWorkerRegistrar& registrar = profile.adapter->Registrar();

    // ---- adapter.Init ----
    if (profile.adapter->Init() != 0) {
        LOG("profile=%s adapter.Init failed", profile.name.c_str());
        return 1;
    }

    // [machine-check C4.6 ①c] worker-0 publishes per-VM env facts into the
    // ShmHeader right after Init() (shm now mapped) and BEFORE Register(): since
    // Register() publishes daemon ownership before domain startup; the later
    // domain READY guarantees the host — which reads after WaitAllWorkersReady —
    // observes the facts with a SINGLE read (release-on-publish happens-before
    // the ready signal the host
    // acquire-loads), with no polling or timeout. The probe is idempotent
    // file/device reads. Non-ivshmem transports return null and are skipped.
    if (profile.worker_id == 0) {
        if (auto* hdr = static_cast<ShmHeader*>(profile.adapter->TransportShmBase())) {
            ::EnvFeatures ef;
            refuzz::worker::env::ProbeEnvFeatures(&ef);
            publish_env_features_v3(hdr, &ef);
            LOG("profile=%s env_features published: fs_len=%u flags=0x%x "
                "kernel=%u.%u lsm_len=%u",
                profile.name.c_str(), ef.filesystems_len, ef.flags,
                ef.kernel_major, ef.kernel_minor, ef.lsm_len);
        }
    }

    // ---- late sink: IvshmemStepEventSink needs ring pointers after Init ----
    // [no-rtti devirt 2026-05-22] AsIvshmem() 替代 dynamic_cast, 让 worker
    // 编译 with -fno-rtti.
    auto* ivs = profile.adapter->AsIvshmem();
    if (profile.enable_step_events && ivs != nullptr &&
        daemon_components != nullptr) {
        daemon_components->bus->AddSink(
            std::make_unique<IvshmemStepEventSink>(
            ivs->GetStepEventHeader(),
            ivs->GetStepEventSlots(),
            ivs->GetStepEventCapacity(),
            profile.worker_id));
    }

    // ---- Engine config ----
    EngineConfig engine_cfg{};
    engine_cfg.exec_timeout_ms = profile.exec_timeout_ms;
    // [D12 plan §3] watchdog 解耦透传。
    engine_cfg.daemon_watchdog_ms = profile.daemon_watchdog_ms;
    engine_cfg.domain_startup_timeout_ms =
        profile.domain_startup_timeout_ms;
    engine_cfg.recycle_after = profile.recycle_after;
    engine_cfg.worker_id = profile.worker_id;
    engine_cfg.poll_ms = profile.poll_ms;
    engine_cfg.sandbox_mode = profile.sandbox_mode;
    engine_cfg.transport_mapped_bytes = profile.adapter->SandboxMappedBytes();
    engine_cfg.transport_shm_base = profile.adapter->TransportShmBase();
    engine_cfg.transport_shm_size = profile.adapter->TransportShmSize();
    if (!profile.adapter->GetExecutionDomainTransport(
            &engine_cfg.execution_transport)) {
        LOG("profile=%s execution transport unavailable", profile.name.c_str());
        profile.adapter->Cleanup();
        return 1;
    }
    engine_cfg.loop_boot_config = profile.loop_boot_config;
    engine_cfg.loop_boot_config.step_ring_resource_offset =
        engine_cfg.execution_transport.step_ring_offset;
    engine_cfg.loop_boot_config.step_ring_size =
        engine_cfg.execution_transport.step_ring_size;
    engine_cfg.loop_boot_config.step_ring_capacity =
        engine_cfg.execution_transport.step_ring_capacity;
    engine_cfg.executor_path = profile.executor_path;
    engine_cfg.recycle_gate_path = profile.recycle_gate_path;

    // ---- Handshake ----
    if (profile.adapter->Handshake() != 0) {
        LOG("profile=%s adapter.Handshake failed", profile.name.c_str());
        profile.adapter->Cleanup();
        return 1;
    }

    // Publish daemon ownership and start heartbeat before any potentially
    // blocking VM/domain setup. READY remains withheld until the execution
    // domain has completed its own startup.
    if (registrar.Register() != 0) {
        LOG("profile=%s adapter.Register failed", profile.name.c_str());
        profile.adapter->Cleanup();
        return 1;
    }
    if (profile.post_register_setup) {
        profile.post_register_setup();
    }

    // Namespace/mount capability probing can itself block. Keep it after
    // daemon registration so heartbeat remains authoritative during preflight.
    {
        char sbx_err[256] = {0};
        if (!ProbeSandboxMode(profile.sandbox_mode, sbx_err, sizeof(sbx_err))) {
            LOG("sandbox preflight FAILED mode=%s reason=%s",
                SandboxModeName(profile.sandbox_mode), sbx_err);
            profile.adapter->Cleanup();
            return 2;
        }
    }

    LOG("profile=%s started worker_id=%u sandbox=%s sinks=%zu",
        profile.name.c_str(),
        profile.worker_id,
        SandboxModeName(profile.sandbox_mode),
        daemon_components != nullptr
            ? daemon_components->bus->SinkCount() : 0u);

    int engine_rc;
    if (profile.snapshot) {
        // [Brick 4a] Single-process snapshot loop. RunSnapshotEngine does the
        // one-time setup after the common registration path has started
        // heartbeat, then publishes domain READY so the host can take savevm S0.
        // topology is unused in this mode.
        LOG("profile=%s SNAPSHOT mode launch pid=%d", profile.name.c_str(), getpid());
        engine_rc = RunSnapshotEngine(task_channel,
                                      domain_registry,
                                      *daemon_components->backend,
                                      *daemon_components->bus,
                                      engine_cfg);
    } else {
        if (daemon_components != nullptr) {
            ExecutionEngine engine(
                task_channel, domain_registry,
                InheritedDomainComponents{*daemon_components->backend,
                                          *daemon_components->bus},
                std::move(profile.topology), engine_cfg);
            engine_rc = engine.Run();
        } else {
            ExecutionEngine engine(
                task_channel, domain_registry,
                ExecRebuiltDomainComponents{},
                std::move(profile.topology), engine_cfg);
            engine_rc = engine.Run();
        }
    }
    const int adapter_rc = task_channel.ExitCode();

    (void)profile.metric_dump_path;

    profile.adapter->Cleanup();
    return (engine_rc != 0) ? engine_rc : adapter_rc;
}

} // namespace refuzz::worker
