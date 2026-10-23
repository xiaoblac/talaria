cmake_minimum_required(VERSION 3.15)
project(refuzz_channel CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

# ── refuzz_channel ──────────────────────────────────────────────────
# 一层聚合 library，源文件按子目录组织。模块导航见 AGENTS.md。
#
#   orchestration/   Channel 编排层（class Channel / IChannel 本体）
#   assembly/        Factory + Builder + Assembler + Catalog（装配链）
#   evidence/        Console + Step-event 证据源
#   control/         IControlPlane 抽象 + IvshmemControlPlane 具体
#   data/            IDataPlane 抽象 + IvshmemDataPlane + DoorbellServer
#   health/          HealthMonitor + Sensor 插件集
#   recovery/        Recovery 顶层 + Executor + FaultTracker + FaultPolicy
#   substrate/       VM 底座全层：ISubstrate 抽象 + infra（ShmInfra/Backbone）+ runtime（Runtime/Pool/VM）
#   worker/          host-side WorkerConfig 契约（target-side binary 在 src/）
add_library(refuzz_channel
    # orchestration：Channel 本体
    orchestration/src/channel.cpp
    orchestration/src/worker_start_sequence.cpp

    # assembly：装配链（Factory / Assembler / Catalog / Builder）
    assembly/src/channel_factory.cpp
    assembly/src/channel_builder.cpp
    assembly/src/channel_catalog.cpp
    assembly/src/qemu_ivshmem_linux_assembler.cpp
    assembly/src/snapshot_assembler.cpp
    assembly/src/qemu_ivshmem_custom_health_assembler.cpp
    assembly/src/qemu_uart_xiuos_assembler.cpp
    assembly/src/ch32_uart_xiuos_assembler.cpp
    assembly/src/sifive_uart_xiuos_assembler.cpp
    assembly/src/mock_assembler.cpp

    # evidence：console + step-event 源
    evidence/src/unix_serial_console_source.cpp

    # control：IControlPlane 具体实现
    control/src/ivshmem_control_plane.cpp
    control/src/xiuos_uart_control_plane.cpp

    # data：IDataPlane 具体实现 + DoorbellServer
    data/src/ivshmem_data_plane.cpp
    data/src/snapshot_data_plane.cpp
    data/src/doorbell_server.cpp
    data/src/xiuos_uart_data_plane.cpp

    # substrate/infra：IvshmemBackbone + ShmInfra + XiUOS UART backbone.
    # XiUOS program-level types + JSON seed loader live in refuzz_program
    # (program/src/xiuos/). XiUOS wire framing is the pure-C codec at
    # proto/wire/include/refuzz/proto_wire/xiuos_uart_codec.h (header-only,
    # shared with the XiUOS guest worker).
    substrate/src/infra/ivshmem_backbone.cpp
    substrate/src/infra/shm_infra.cpp
    substrate/src/infra/xiuos_uart_backbone.cpp

    # health：HealthMonitor + Sensor 插件集
    health/src/health_monitor.cpp
    health/src/heartbeat_sensor.cpp
    health/src/vm_alive_sensor.cpp
    health/src/wedge_relay_sensor.cpp
    health/src/console_sensor.cpp

    # recovery：三层拆分
    recovery/src/recovery.cpp
    recovery/src/recovery_exe.cpp
    recovery/src/fault_tracker.cpp
    recovery/src/fault_policy.cpp

    # substrate/runtime：Runtime 控制器 + Pool + Instance + VM 具体实现
    substrate/src/runtime/runtime.cpp
    substrate/src/runtime/runtime_pool.cpp
    substrate/src/runtime/runtime_instance.cpp
    substrate/src/runtime/vm/arch_map.cpp
    substrate/src/runtime/vm/qemu_args.cpp
    substrate/src/runtime/vm/vm_instance.cpp
    substrate/src/runtime/vm/vm_pool.cpp
    substrate/src/runtime/vm/component/process.cpp
    substrate/src/runtime/vm/component/ssh.cpp
    substrate/src/runtime/xiuos_uart_substrate.cpp
    substrate/src/runtime/ch32_uart_substrate.cpp
)

target_include_directories(refuzz_channel
    PUBLIC
        # orchestration：对外 IChannel + Channel 实现 + ChannelConfig 等
        ${CMAKE_CURRENT_SOURCE_DIR}/orchestration/include
        # assembly：Factory / Builder / Assembler / Catalog
        ${CMAKE_CURRENT_SOURCE_DIR}/assembly/include
        # evidence：console + step-event source 接口与实现
        ${CMAKE_CURRENT_SOURCE_DIR}/evidence/include
        # control / data：plane 抽象 + ivshmem 实现
        ${CMAKE_CURRENT_SOURCE_DIR}/control/include
        ${CMAKE_CURRENT_SOURCE_DIR}/data/include
        # health / recovery
        ${CMAKE_CURRENT_SOURCE_DIR}/health/include
        ${CMAKE_CURRENT_SOURCE_DIR}/recovery/include
        # substrate：ISubstrate 抽象 + SubstratePoolOps 函数表 + infra + runtime 头
        ${CMAKE_CURRENT_SOURCE_DIR}/substrate/include
        # worker：host-side WorkerConfig + worker mode
        ${CMAKE_CURRENT_SOURCE_DIR}/worker/include
)

# 外部头文件依赖
target_include_directories(refuzz_channel
    PUBLIC
        # VM substrate 底层头（types.hpp / util/*.hpp）
        ${CMAKE_CURRENT_SOURCE_DIR}/substrate/src/runtime/vm
        # refuzz/proto_wire/ivshmem_protocol.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/wire/include
        # refuzz/logging/host_logger.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../logging/include
        # runtime include root（runtime config / substrate 共享头）
        ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime/include
        # util/json.hpp（兼容配置解析）
        ${CMAKE_CURRENT_SOURCE_DIR}/../../util
)

target_link_libraries(refuzz_channel
    PUBLIC
        refuzz_core
        # XiUOS UART data-plane decodes RESULT payloads via refuzz_program;
        # keep that dependency public for channel users and tests.
        refuzz_program
        pthread
    PRIVATE
        refuzz_logging
)
