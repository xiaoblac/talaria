cmake_minimum_required(VERSION 3.15)
project(refuzz_worker C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/ivshmem_worker_main.cpp")
    # [Layer-2 §3.3] All worker pluggable parts now live in a static
    # library so out-of-tree tools (the smoke test) can reuse them
    # without duplicating the source list. ivshmem_worker becomes a
    # thin shell over `main` + adapter/engine entry.
    add_library(refuzz_worker_core STATIC
        src/sandbox.cpp
        src/adapter/stdio_adapter.cpp
        src/coverage/kcov_collector.cpp
        # [remote-kcov S1] second /dev/kcov buffer via KCOV_REMOTE_ENABLE
        # (COMMON handle) capturing async/softirq/kthread coverage. Additive
        # to KcovCollector's per-task local KCOV.
        src/coverage/remote_kcov_buffer.cpp
        src/backend/syz_exec_runner.cpp
        src/perf/worker_perf.cpp
        src/engine/domain_supervisor.cpp
        src/engine/execution_engine.cpp
        # [Brick 4a] dedicated single-process snapshot loop (syz snapshot.h model)
        src/engine/snapshot_engine.cpp
        # [v3 P1 DoubleFork plan] engine 拆分:LoopRuntime/ProgramRuntime
        # 跟 ProcessTopology strategy 一起服务 syzkaller-aligned 进程拓扑
        src/engine/loop_runtime.cpp
        src/engine/exec_loop_entry.cpp
        src/engine/fork_server_reaper.cpp
        src/engine/program_runtime.cpp
        src/topology/domain_handle.cpp
        src/topology/reusable_child_topology.cpp
        # [v3 P2] explicit fork-per-N-program strategy (subclass of reusable)
        src/topology/recycle_child_topology.cpp
        # [v3 P3] async child-exit detection: pidfd_open + waitpid fallback,
        # 给 P4 DoubleForkTopology 的 daemon async wait 准备
        src/topology/child_waiter.cpp
        # [D12 ns-runner] disposable layer:daemon → ns-runner(一次性 unshare
        # NEWPID)→ loop_child(PID 1)。替代 D11 的 daemon-内 setns reset 止血,
        # 让 unshare(NEWPID) 永远是新进程的"首次",绕开 kernel copy_pid_ns EINVAL。
        src/topology/ns_runner.cpp
        src/topology/topology_probe.cpp
        # [v3 P4] syzkaller-aligned daemon → loop(PID 1) → program child 两层拓扑
        src/topology/double_fork_topology.cpp
        # [当前版本 sandbox-device-init D1] 完整 sandbox_common_mount_tmpfs:
        # mount_tmpfs (主入口) + VM sysctls + cgroups + gadgetfs + binderfs + fusectl,
        # 在 ApplyNone 末尾按 syzkaller `do_sandbox_none()` 序列调一次性 done。
        src/sandbox/device_init/mount_tmpfs.cpp
        src/sandbox/device_init/sysctls.cpp
        src/sandbox/device_init/cgroups.cpp
        src/sandbox/device_init/gadgetfs.cpp
        src/sandbox/device_init/binderfs.cpp
        src/sandbox/device_init/binfmt_misc.cpp
        src/sandbox/device_init/fusectl.cpp
        # [当前版本 sandbox-device-init D2] netlink foundation primitives
        # (Nlmsg + init/attr/nest/done/send/send_ext/query_family_id/next_msg)。
        # 服务 D3-D7 的 initialize_tun / netdevices / wifi / vhci / devlink_pci。
        src/sandbox/device_init/netlink_helpers.cpp
        # [当前版本 sandbox-device-init D3] cross-D3/D4/D5/D7 共享 netlink builders
        # (device_change / add_addr{,4,6} / add_neigh) + initialize_tun +
        # initialize_netdevices_init。
        # [当前版本 sandbox-device-init D4] netlink_builders 扩展 (add_device/
        # add_veth/add_xfrm/add_hsr/add_linked/add_vlan/add_macvlan/add_geneve/
        # add_ipvlan) + initialize_netdevices + netdevsim + wireguard 子模块。
        src/sandbox/device_init/netlink_builders.cpp
        src/sandbox/device_init/tun.cpp
        # [F4 fix] checkpoint_net_namespace + flush_tun;触发 netns lazy-register
        # 5 张 iptables hook,让 net-inject 类 syscall 的 RX 路径能进 ipt_do_table。
        src/sandbox/device_init/net_reset.cpp
        src/sandbox/device_init/netdevices_init.cpp
        src/sandbox/device_init/netdevices.cpp
        src/sandbox/device_init/netdevsim.cpp
        src/sandbox/device_init/wireguard.cpp
        # [当前版本 sandbox-device-init D5] mac80211_hwsim + nl80211 IBSS setup。
        # 直接给 oracle 解锁 syz_80211_inject_frame / syz_80211_join_ibss
        # 7 个 mismatch。
        src/sandbox/device_init/wifi.cpp
        # [当前版本 sandbox-device-init D6] virtual HCI controller + fake
        # BR/EDR + LE connections。HCI event_thread 走 pthread。
        src/sandbox/device_init/vhci.cpp
        # [当前版本 sandbox-device-init D7] devlink "pci/0000:00:10.0"
        # reload-into-netns + rename ports netpci0/1/...
        src/sandbox/device_init/devlink_pci.cpp
        src/backend/pseudo/pseudo_dispatcher.cpp
        src/backend/pseudo/pseudo_runtime.cpp
        src/backend/pseudo/pseudo_core.cpp
        src/backend/pseudo/pseudo_file.cpp
        src/backend/pseudo/pseudo_fs.cpp
        src/backend/pseudo/pseudo_device.cpp
        src/backend/pseudo/pseudo_net.cpp
        src/backend/pseudo/pseudo_wifi.cpp
        # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
        src/backend/pseudo/usb/usb_helpers.cpp
        src/backend/pseudo/usb/usb_state.cpp
        src/backend/pseudo/usb/usb_dispatcher.cpp
        # [PR-3 2026-05-20] enumeration helpers (device_index parser +
        # lookup_connect_response + configure/set_interface).
        src/backend/pseudo/usb/usb_enumeration.cpp
        src/backend/pseudo/fuse/fuse_dispatcher.cpp
        # [PR-D1] mount-image Tier 3 subdir
        src/backend/pseudo/mount/mount_helpers.cpp
        src/backend/pseudo/mount/mount_state.cpp
        src/backend/pseudo/mount/mount_dispatcher.cpp
        # [PR-D2] KVM Tier 3 subdir (replaces deleted pseudo_kvm.cpp ENOSYS stub)
        src/backend/pseudo/kvm/syzos_guest_amd64.cpp
        src/backend/pseudo/kvm/kvm_helpers.cpp
        src/backend/pseudo/kvm/kvm_state.cpp
        src/backend/pseudo/kvm/kvm_dispatcher.cpp
        src/observation/step_event_writer.cpp
        # [v2 Layer-2 §3.3] syzkaller-equivalent exec wire streaming driver
        src/dispatcher/syscall_or_pseudo.cpp
        src/driver/kernel_wire_driver.cpp
        # [v2 Epic 7 PR-4] threaded path worker thread pool (KCOV per-thread
        # fd / per-thread PseudoRuntimeContext / fault_inject thread-local
        # 的物理基础)。 thread_count=1 时不 spawn,但 .cpp 仍 link 进 lib。
        src/driver/kernel_thread_pool.cpp
        # [v2 Epic 6 §3.14 PR-6-A] worker-side fault-injection helpers
        # (mirror upstream executor/common_linux.h:4749-4778
        # inject_fault / fault_injected via /proc/thread-self/fail-nth)
        src/driver/fault_inject.cpp
        # [v2 R2] ObservationBus + sink 抽象 (KCOV / step event 不再硬编码进 engine)
        src/observation/observation_bus.cpp
        src/observation/kcov_sink.cpp
        src/observation/ivshmem_step_event_sink.cpp
        # [v2 R5] WorkerProfile composition root
        src/profile/worker_profile.cpp
        src/profile/kernel_syz_profile.cpp
        src/profile/kernel_syz_stdio_profile.cpp
        src/profile/kernel_syz_execution_domain.cpp
        # [syscall-support-detection Step C] per-VM env probe (worker-0 only)
        src/env/env_probe.cpp
    )

    target_include_directories(refuzz_worker_core
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/wire/include
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../feedback/include
    )

    set_source_files_properties(
        src/backend/pseudo/kvm/syzos_guest_amd64.cpp
        PROPERTIES
            COMPILE_OPTIONS
                "-Wno-unused-function;-Wno-address-of-packed-member;-Wno-ignored-qualifiers;-Wno-deprecated-volatile;-Wno-unused-parameter;-Wno-missing-field-initializers"
    )

    # [PR-D1] zlib for mount-image image decompression (mount_helpers::DecompressZlibToFd).
    find_package(ZLIB REQUIRED)

    # [dense mount image] zstd: guest-side fast decompress of DENSE mount images
    # (mount_helpers::DecompressZstdToFd) — host transcodes zlib→zstd, guest decompresses
    # ~5-15× faster than zlib inflate (the per-exec dominant cost). No -dev package, so
    # fall back to the runtime soname — libzstd.so.1 ships in the guest rootfs.
    find_library(REFUZZ_ZSTD_LIB NAMES zstd libzstd.so.1
                 PATHS /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu)
    if(NOT REFUZZ_ZSTD_LIB)
        set(REFUZZ_ZSTD_LIB /lib/x86_64-linux-gnu/libzstd.so.1)
    endif()

    target_link_libraries(refuzz_worker_core
        PUBLIC
            pthread
            ZLIB::ZLIB
            ${REFUZZ_ZSTD_LIB}
    )
    # [perf 2026-05-22 reverted] A+B 实测 net -2.4% regression. -fno-exc/rtti
    # 在 ThinLTO 一起跑时 binary layout 变化干扰 fork copy_process. 已 revert.
    # AsIvshmem() helper 保留 (zero-cost, 替代 dynamic_cast). 如未来要再上
    # -fno-rtti, 直接 add target_compile_options PRIVATE 即可 — dynamic_cast
    # 已没了, RTTI 关掉编过.
    if (TARGET refuzz_proto_wire)
        target_link_libraries(refuzz_worker_core PUBLIC refuzz_proto_wire)
    endif()
    if (TARGET refuzz_program)
        target_link_libraries(refuzz_worker_core PUBLIC refuzz_program)
    endif()

    # ivshmem_worker = main + adapter + ivshmem-specific glue + worker_core
    add_executable(ivshmem_worker
        src/ivshmem_attach.cpp
        src/ivshmem_worker_main.cpp
        src/adapter/ivshmem_adapter.cpp
    )

    target_include_directories(ivshmem_worker
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/wire/include
    )

    target_link_libraries(ivshmem_worker
        PRIVATE
            refuzz_worker_core
    )
    # [v2 PR-G — 当前版本]
    # -rdynamic 让 dynamic symbol table 可见,backtrace_symbols_fd 才能解出函数名
    # (否则只显示 binary+offset)。child crash handler 用它输出 stack frame 到 ttyS0,
    # host 侧无需 core dump 也能定位 worker child SIGABRT 的触发点。
    target_link_options(ivshmem_worker PRIVATE "-rdynamic")

    add_executable(refuzz_executor
        src/refuzz_executor_main.cpp
    )
    target_include_directories(refuzz_executor
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/wire/include
    )
    target_link_libraries(refuzz_executor PRIVATE refuzz_worker_core)
    target_link_options(refuzz_executor PRIVATE "-rdynamic")

    # The deployed worker and its exec template form one runtime ABI. Building
    # the worker target must also relink the template against the same core.
    add_dependencies(ivshmem_worker refuzz_executor)
endif()
