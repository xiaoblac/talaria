# Executor 组件设计

## 1. 文档目的

`executor/` 是 reFuzz 的执行组件。它把上层生成的 `Task` 投递到一个或多个执行后端，管理 VM / worker / 传输通道生命周期，并把执行结果、异常完成和故障现场统一转换成 `ChannelEvent` 交回主循环。

本文以当前 `executor/` 源码为准，说明：

- `executor/` 在整体系统中的职责边界；
- `channel`、`channeldispatcher`、guest-side `worker` 的分层关系；
- 执行请求从 task queue 到 worker，再从 completion 到 event queue 的主流程；
- 启动、关闭、健康检测、恢复和观测的生命周期约束；
- 新增执行后端、健康传感器、submit 策略或 worker 执行后端时的扩展点。

## 2. 设计目标

### 2.1 核心目标

1. 隔离执行后端：上层 fuzzing loop 只依赖 `IChannel` / `ChannelEvent` 合同，不感知 QEMU、ivshmem、doorbell、SSH 或 worker 细节。
2. 保证 task 不丢：`Executor` 对从 task queue 取出的任务执行无限重试；`Channel` 一旦返回 `kAccepted`，就负责把它送达 worker 或在不可服务相位显式产生异常完成。
3. 收敛装配逻辑：具体后端对象只在 `Assembler` 中构造，`Channel` 只持有抽象接口并负责编排时序。
4. 将数据面、控制面、证据面、健康监控和恢复决策拆分为可替换组件，降低新增后端或传输协议时对核心编排代码的影响。
5. 在故障发生时尽早采集现场：console、step-event、inflight task 快照和 generation 信息随 `Fault` 事件一起上报。
6. 以快照、事件、metric、日志四种形式暴露执行侧状态，支持 telemetry 和运行期诊断。

### 2.2 非目标

`executor/` 不负责以下领域：

| 关注点 | 负责组件 | `executor/` 的角色 |
|---|---|---|
| 变异算法 | `mutator/` | 只消费已经序列化的 task payload |
| 种子选择与调度 | `control/` / scheduler 相关模块 | 只按提交策略选择 channel，不决定 fuzzing 策略 |
| 覆盖率判定与反馈策略 | `feedback/` | 只透传 worker 输出里的原始反馈数据 |
| corpus 持久化 | `corpus/` | 无直接写入职责 |
| crash 归档、诊断报告、复现调度 | `crash/` / `control/` | 只产出带现场的 `Fault` 事件 |
| 运行会话总编排 | `control/` | 作为 service 被注册、启动和停止 |

## 3. 总体架构

### 3.1 运行态视图

```text
FuzzerLoop / Control
    │
    │  proto::Task
    ▼
InMemoryTaskQueue
    │
    ▼
channeldispatcher::Executor
    │  ChannelDispatchRequest
    ▼
IChannel
    │
    ▼
channel::Channel
    ├─ ISubstrate        VM / worker 生命周期、SSH、artifact deploy
    ├─ IControlPlane     session、registration、heartbeat、cancel flag
    ├─ IDataPlane        Submit / Poll / Pause / Reset / SnapshotInflight
    ├─ Evidence          console 行流、step-event ring 快照
    ├─ IHealthMonitor    sensor 线程、crash event 聚合、quiesce
    └─ IRecovery         fault policy、recovery 执行、fault tracker
    │
    │  ivshmem / doorbell / shared memory
    ▼
guest ivshmem_worker
    ├─ IvshmemWorkerAdapter
    ├─ ExecutionEngine
    ├─ IExecBackend
    └─ ICoverageCollector
    │
    ▼
ChannelEvent
    │
    ▼
InMemoryEventQueue
    │
    ▼
FuzzerLoop / Feedback / Crash
```

### 3.2 构建态视图

```text
control resolver / assembler
    │
    │  ChannelBuildContext {
    │    ChannelConfig, IChannelBackendProfile, vm_index, vm_workdir
    │  }
    ▼
ChannelCatalog
    │ backend_id
    ▼
IChannelAssembler
    │  ChannelComponents
    ▼
ChannelBuilder
    │  unique_ptr<IChannel>
    ▼
ServiceRegistry
    ├─ ChannelService       Boot / Close channel
    ├─ HealthMonitorService optional service topology node
    └─ channeldispatcher::Executor
```

## 4. 目录职责

| 路径 | 角色 | 主要输出 |
|---|---|---|
| `executor/channel/orchestration/` | `IChannel` 接口与 `Channel` 编排实现 | `Boot`、`Submit`、`DrainEvents`、观测事件 |
| `executor/channel/assembly/` | backend catalog、profile、assembler、builder | `unique_ptr<IChannel>` |
| `executor/channel/substrate/` | VM 底座、QEMU runtime、ivshmem mmap 基础设施 | `ISubstrate`、`ShmInfra` |
| `executor/channel/control/` | worker session、注册、心跳、取消控制面 | `IControlPlane` |
| `executor/channel/data/` | dispatch 数据面与 doorbell server | `IDataPlane` |
| `executor/channel/evidence/` | console 与 step-event 证据源 | crash 现场输入 |
| `executor/channel/health/` | health monitor 与 sensor 插件 | `CrashEvent`、health snapshot |
| `executor/channel/recovery/` | fault policy、fault tracker、recovery executor | `RecoveryAction` 执行结果 |
| `executor/channel/worker/` | guest-side worker binary | `ivshmem_worker` |
| `executor/channeldispatcher/` | 多 channel task 提交和 event 转发 | `Executor` service |

## 5. 关键抽象

### 5.1 `IChannel`

`IChannel` 是执行后端对上层暴露的稳定接口，包含三类能力：

- 生命周期：`Boot()`、`Close()`；
- 数据面：`Submit(request, wait_for_slot)`、`DrainEvents(events, timeout)`；
- 观测面：`AttachObservabilityPublishers(...)`、`ObserveSnapshot()`、`DrainObserveEvents(...)`。

上层只通过 `IChannel` 交互。具体实现可以是当前的 QEMU / ivshmem `Channel`，也可以是 mock、vsock、local process 或其他后端。

### 5.2 `Channel`

`Channel` 是当前主路径的编排实现。它不直接代表某个 wire protocol，而是把已装配好的组件按固定生命周期串起来：

- 启动时按依赖顺序启动 data-plane server、VM、worker、console、registration、health monitor 和 loop thread；
- 运行时由 `loop_thread_` 独占调用 `IControlPlane` / `IDataPlane` 热路径；
- 故障时消费 `IHealthMonitor` 产出的 crash event，并通过 `IRecovery` 决策恢复动作；
- 关闭时停止 loop、recovery thread、health sensor、evidence、substrate、data plane 和 control plane。

`Channel` 的构造函数是 private，只允许 `ChannelBuilder` 从 `ChannelComponents` 构造，确保所有具体组件都来自 `Assembler`。

### 5.3 `ChannelConfig` 与 `IChannelBackendProfile`

配置被拆成两段：

- `ChannelConfig`：后端无关的编排参数，例如 `channel_id`、`n_workers`、`use`、`wait_ready_timeout`、`loop_interval`、`health_check_interval`、`input_queue_capacity`、`pre_reboot_drain`、`deploy_bundle`。
- `IChannelBackendProfile`：后端专属配置包。当前 `QemuIvshmemLinuxProfile` 包含 `InfraConfig`、`RuntimeConfig`、`WorkerConfig`、`TransportConfig`、`HealthMonitorConfig`、`RecoveryConfig`。

`ChannelBuildContext` 是 channel 子系统对外的唯一聚合入口。`control/` 负责填好中性配置、backend profile、`vm_index` 和 `vm_workdir`；`executor/channel` 不感知 `SessionLayout` 的目录推导规则。

### 5.4 `ChannelCatalog` / `IChannelAssembler` / `ChannelBuilder`

新增 backend 的标准路径是：

1. 定义一个实现 `IChannelBackendProfile` 的 profile；
2. 实现一个 `IChannelAssembler`，在 `Assemble(ctx)` 内构造 `ChannelComponents`；
3. 在 `RegisterBuiltinChannels()` 中注册 backend id；
4. 调用方通过 `ChannelCatalog::Build(id, ctx)` 获得 `unique_ptr<IChannel>`。

当前内置 backend：

| backend id | 用途 |
|---|---|
| `qemu_ivshmem_linux` | 生产主路径：QEMU + Linux guest + ivshmem 控制/数据面 |
| `qemu_ivshmem_custom_health_linux` | 复用主路径并额外挂载 `AcceptanceTapSensor` 的扩展验证后端 |
| `mock` | 进程内 mock 组件组合，用于不依赖 VM / SSH / shm 的装配和生命周期路径 |

### 5.5 Substrate / Infra

`ISubstrate` 抽象 VM 底座能力：

- `StartVM`、`StopVM`、`RebootVM`、`IsVMAlive`；
- `CopyFileTo`、`RunCommand`、`DeployArtifacts`；
- `StartAllWorkers`、`StartWorker`、`StopWorker`；
- `DefaultConsoleEndpoint`、`Hints`、`Diagnose`。

当前 `Runtime` 实现 `ISubstrate`，内部使用 QEMU process、SSH endpoint、QMP 配置和 VM workdir。`ShmInfra` / `IvshmemBackbone` 负责 host 侧 ivshmem 文件创建、`mmap`、V2 header 初始化和 typed view 暴露。`ShmInfra` 通过 `shared_ptr<IvshmemBackbone>` 与 control plane、data plane、step-event source 共享 mmap 生命周期。

### 5.6 ControlPlane / DataPlane

`IControlPlane` 负责 session 语义：

- `BeginSession` / `EndSession` / reset；
- worker registration 与 revoke；
- heartbeat 采样；
- cancel flag；
- 向 data plane 导出最小 `SendabilityView` 和 registration hook。

`IDataPlane` 负责 dispatch 语义：

- `StartServer()`：可选启动 host 侧服务端点，例如 doorbell server；
- `Prepare()`：建立 wire、连接 doorbell 或初始化轮询；
- `Submit()`：把请求写入 worker slot；
- `Poll()`：把 wire completion 翻译成语义级 `DispatchOutcome`；
- `Pause()` / `Resume()` / `ResetWorker()` / `ResetAll()` / `SnapshotInflight()`。

两者的边界是：ControlPlane 判断 worker 是否可注册、是否可发送；DataPlane 只执行发送、轮询和重置，不做恢复决策。

### 5.7 Evidence / Health / Recovery

Evidence 层提供 crash 现场输入：

- `IConsoleSource` 按行读取 console / serial；
- `IStepEventSource` 快照 worker step-event ring。

Health 层由 `HealthMonitor` 统一管理 sensor：

- `HeartbeatSensor` 通过 `IControlPlane::SampleHeartbeat()` 检测 worker 卡死；
- `ConsoleSensor` 从 console 行流识别 kernel crash / VM dead；
- `VmAliveSensor` 通过 `ISubstrate::IsVMAlive()` 检查 VM 进程存活；
- 自定义 sensor 可通过 assembler `AddSensor()` 注入。

Recovery 层由 `Recovery` 编排：

- `FaultTracker` 维护故障窗口、计数、active recovery；
- `IFaultPolicy` / `EscalationPolicy` 决定 `RecoveryAction`；
- `RecoveryExe` 使用 `ISubstrate`、`IControlPlane`、`IDataPlane`、`IHealthMonitor` 执行具体动作。

### 5.8 `channeldispatcher::Executor`

`Executor` 是连接 queue 与 channel 的 service：

- 从 `InMemoryTaskQueue` pop `proto::Task`；
- 使用 producer 写入 `proto::Task::executor_id` 构造 `ChannelDispatchRequest`；
- 按 `ISubmitStrategy` 选择 channel 并调用 `IChannel::Submit()`；
- 从所有 channel `DrainEvents()`，把 `Completion`、`AbnormalCompletion`、`Fault` 转发到 `InMemoryEventQueue`；
- 维护 executor metrics 和 submit backoff 统计。

默认 submit 策略是 `RoundRobinStrategy`。它只决定 channel 尝试顺序，不持有 channel 指针，也不调用 `Submit()`。

### 5.9 Guest-side `ivshmem_worker`

`ivshmem_worker` 是 VM 内执行进程，分为四层：

- `IvshmemWorkerAdapter`：attach ivshmem、完成 host_ready / registration 握手、等待 task、写 completion、维护 heartbeat、写 step-event、ring doorbell；
- `ExecutionEngine`：管理持久 worker daemon 与 child 进程，负责 fork、pipe 通知、timeout、cancel、crash 后 respawn；
- `IExecBackend`：执行 payload，当前 `SyscallExecBackend` 支持 v1 flat syscall program 和 v2 typed syz program；
- `ICoverageCollector`：采集覆盖率，当前支持 KCOV 或 no-op。

child 进程执行真实 syscall。worker daemon 与 child 分离，避免目标 syscall 造成进程崩溃、超时或 D-state 时直接杀死 worker daemon。

## 6. 关键流程

### 6.1 装配流程

```text
control 构造 ChannelBuildContext
  → ChannelCatalog 按 backend_id 查找 entry
  → IChannelAssembler::Assemble(ctx)
      → 校验 backend profile 类型
      → 构造 ShmInfra / Runtime / CP / DP / Evidence / Health / Recovery
      → 返回 ChannelComponents
  → ChannelBuilder::Build(components)
      → 校验必填组件非空
      → 构造 Channel
  → 返回 unique_ptr<IChannel>
```

QEMU / ivshmem 主路径中，`QemuIvshmemLinuxAssembler` 负责：

1. 初始化 `ShmInfra`；
2. 将 shm 总大小、VM workdir、serial log path 写入 runtime config；
3. 创建 `Runtime` 作为 `ISubstrate`；
4. 创建 `IvshmemControlPlane` 和 `IvshmemDataPlane`；
5. 创建 `UnixSerialConsoleSource` 和 `IvshmemStepEventSource`；
6. 创建 `HealthMonitor` 并挂载 heartbeat、console、VM alive sensor；
7. 派生或透传 `DeployBundle`；
8. 创建 `Recovery`。

### 6.2 Boot 流程

`Channel::Boot()` 的顺序是运行正确性的核心约束：

1. `IDataPlane::StartServer()`：先启动 host 侧服务端点，doorbell 模式下必须早于 VM 启动；
2. `ISubstrate::StartVM(0)`：启动 VM 并等待底座可用；
3. `ISubstrate::DeployArtifacts(0, deploy_bundle)`：部署 worker binary 或其他 artifact；
4. `IConsoleSource::Open(DefaultConsoleEndpoint)`：VM 启动后打开 console；
5. `IDataPlane::Prepare()`：host 侧连接 doorbell / 初始化 poll 资源；
6. `IControlPlane::BeginSession()`；
7. `ISubstrate::StartAllWorkers(0)`；
8. `IControlPlane::WaitAllWorkersReady()`；
9. 初始化 `generation_ = 1`；
10. `IHealthMonitor::BindChannelSignals()` 并 `Start()`；
11. 启动 `loop_thread_`，状态进入 `kRunning`，发布首个 snapshot。

### 6.3 Submit 流程

```text
Executor submit thread
  → Pop proto::Task
  → 构造 ChannelDispatchRequest
  → ISubmitStrategy::BeginCycle() / NextIndex()
  → 逐个 channel Submit(request, 0)
      ├─ kAccepted: 清 pending，统计 submitted，结束
      ├─ kBusy: 保留 pending，进入 backoff
      └─ kUnavailable / kInvalid: 记录 reject，但 task 不丢
  → 等待 event thread 唤醒或 idle_sleep_us 兜底超时
```

`Channel::Submit()` 的语义：

- `executor_id == 0` 或 payload 超过 `ShmInfra::MaxInput()` 返回 `kInvalid`；
- 仅在 `kRunning` / `kDegraded` 接受请求，其他相位返回 `kUnavailable`；
- `input_queue_ + deferred_submissions_` 达到 `input_queue_capacity` 返回 `kBusy`；
- 防止同一 `executor_id` 同时存在于 input、deferred、pending 三阶段；
- 接受后立即返回 `kAccepted`，真正发送由 `loop_thread_` 异步完成。

`Channel` 内部的 `deferred_submissions_` 不再按 slot deadline 淘汰。只要 request 已被 `Channel` 接管，就会一直重试发送，直到送达 worker 或因相位切换 / close / recovery 被显式取消。

### 6.4 Completion 流程

```text
worker child 执行 payload
  → WorkerAdapter 写 CompletionSlot
  → doorbell 或 poll 唤醒 host DataPlane
  → Channel::DrainTransport()
      → IDataPlane::Poll()
      → 匹配 pending_[executor_id]
      → 校验 dispatch_gen / generation
      → 生成 Completion 或 AbnormalCompletion
      → 从 pending_ 和 active_executor_ids_ 移除
      → QueueEvent()
  → Executor event thread DrainEvents()
  → InMemoryEventQueue
```

`Completion` 携带 `CompletionContext` 和 worker 输出；`AbnormalCompletion` 用于 timeout、exec error、worker signaled、cancelled 等非正常但已归属到某个 task 的结果。

### 6.5 Fault 与恢复流程

Health sensor 线程发现异常后，通过 `HealthMonitor` 入队 `CrashEvent` 并唤醒 `Channel::loop_thread_`。loop 线程先收割已有 completion，再进入故障处理：

1. `DrainCrashEvents()` 取出一批 crash event；
2. 将 `CrashKind` / origin 映射为 `ChannelFaultReason`；
3. 调 `IRecovery::ObserveFault()` 获得 `abort_scope`、`recovery_action`、`target_worker_id`；
4. 按策略中止 slot 或 channel 范围内的 inflight task，并产出 `Fault` 事件；
5. 对单 worker 故障，进入 `kDegraded`，revoke 该 worker，隔离 worker，并由 `recovery_thread_` 异步执行 `kRestartSingleWorker`；
6. 对全通道恢复，进入 `kRecovering`，pause data plane、drain、suspend health，再执行 `kRestartAllWorkers` / `kRebootVm` / `kRestartHealthMonitor` 等动作；
7. 恢复成功后 resume health 和 data plane，递增 `generation_`，发布 generation reset 观测事件，状态回到 `kRunning`；
8. 恢复失败时根据策略升级，最终可能进入 `kFailed`。

`Fault` 事件里的 crash scene 包含：

- console / serial 片段；
- step-event 快照；
- 当前 `pending_` 中按提交时间排序的 worker task 状态；
- candidate task window；
- channel id、generation、fault kind、检测时间。

### 6.6 Close 流程

`Channel::Close()` 负责幂等释放：

1. 停止 `loop_thread_`；
2. join 正在运行的 `recovery_thread_`；
3. 清空 input、deferred、active executor id；
4. 停止 health monitor；
5. 关闭 console source，释放 step source；
6. `ISubstrate::Close()` 停 VM / worker；
7. `IDataPlane::Close()`；
8. `IControlPlane::EndSession()`；
9. reset data / control 指针；
10. 状态进入 `kClosed` 并发布 snapshot。

`Executor::StopThreads()` 会停止 submit / event 两个线程，唤醒 submit wait，join 线程，并关闭 event queue。若 submit 线程仍有 pending task，会在 submit loop 退出时把 payload 移回 task 并重新 push 回 task queue。

## 7. 并发与所有权模型

### 7.1 Executor 线程

`channeldispatcher::Executor` 使用两个线程：

- submit thread：独占 `pending_`，从 task queue 取任务并无限重试提交；
- event thread：轮询或阻塞 drain channel events，并转发到 event queue。

两者通过 `wake_cv_` 协作。event thread 每次转发事件后唤醒 submit thread，因为 completion / abnormal / fault 可能释放 channel 容量。

### 7.2 Channel 线程

`Channel` 的并发边界：

- `loop_thread_` 独占 `pending_`、`deferred_submissions_`、`quarantined_workers_`、`next_worker_rr_` 和 CP / DP 热路径；
- `Submit()` 与 `DrainEvents()` 通过 `io_mutex_` 访问 input / output 队列；
- health sensor 线程只通过 `HealthMonitor` 发布 crash event，不直接操作 channel 内部状态；
- `recovery_thread_` 只执行单 worker 恢复动作，通过 `recovery_signal_` 通知 loop 线程收尾；
- observe queue 由 `observe_mu_` 保护；
- stats 由 `stats_mutex_` 或 atomic 保护。

### 7.3 Worker 进程

guest 内部采用 daemon + child 结构：

- worker daemon 负责 ivshmem 协议、heartbeat、registration、doorbell 和结果上报；
- child 进程执行实际 syscall program；
- child crash handler 尽量在退出前把 coverage snapshot 写入 output buffer；
- 超时、cancel、crash 后 daemon respawn child；
- `recycle_after` 到达上限后主动 respawn child，降低长期运行污染。

## 8. 可观测性

### 8.1 数据事件

`Channel::DrainEvents()` 对外只产出三类 `ChannelEvent`：

- `Completion`：正常执行完成；
- `AbnormalCompletion`：task 已归属但执行异常、超时、取消或 worker 信号退出；
- `Fault`：channel / VM / worker 级故障现场，供 crash pipeline 和 control 处理。

### 8.2 观测事件

`Channel::DrainObserveEvents()` 和 observe bus 发布低频状态事件：

- lifecycle changed；
- fault detected；
- recovery started；
- recovery completed；
- generation reset。

这些事件服务 telemetry 和运行期诊断，不替代数据面 `ChannelEvent`。

### 8.3 Snapshot 与 metrics

- `IChannel::ObserveSnapshot()` 当前返回精简 `ChannelSnapshot`：`channel_id`、`generation`、`lifecycle_state`、`boot_ts_us`；
- runtime、health、recovery 细分状态由 `Channel` 本地采集后推送到 `ChannelMetrics`；
- `ExecutorSnapshot` 暴露 pending tasks、channel 数量、已转发事件数、已提交任务数、submit backoff 总时长和 backoff 次数；
- `Executor` 和 `Channel` 均通过 `HostLogger` 打关键边沿日志，避免热路径逐次刷屏。

## 9. 配置与部署约束

### 9.1 中性配置

`ChannelConfig` 的字段由 `control/` 在解析、profile 决议和装配阶段填好。常见约束：

- `n_workers` 必须与 backend profile 中的 worker / infra 数量一致；
- `input_queue_capacity` 通常按 `n_workers` 的小倍数派生；
- `wait_ready_timeout` 是 control plane 等待 worker 注册的中性超时；
- `deploy_bundle` 为空时，QEMU / ivshmem assembler 会从 `WorkerConfig` 派生最小 bundle。

### 9.2 QEMU / ivshmem profile

`QemuIvshmemLinuxProfile` 承载后端专属字段：

- `infra`：shm path、worker 数、step-event ring 容量；
- `runtime`：QEMU binary、kernel、disk、SSH key、workdir、QMP、ivshmem mode 等；
- `worker`：worker binary host path、remote path、启动命令和超时；
- `transport`：doorbell / plain 模式、poll sleep、wait ready poll；
- `health_monitor`：heartbeat、serial watcher、VM liveness sensor 参数；
- `recovery_config`：故障策略和恢复阈值。

Assembler 会把 `ctx.vm_workdir` 写入 runtime instance。VM workdir 必须由上层显式传入；channel 不自行拼 `vm-<index>`。

## 10. 扩展点

### 10.1 新增 channel backend

新增后端时应保持以下文件边界：

1. 新增 `IChannelBackendProfile` 子类；
2. 新增 `IChannelAssembler` 子类；
3. 如需新传输，新增对应 `IControlPlane` / `IDataPlane` / `IConsoleSource` / `IStepEventSource` 实现；
4. 如需新底座，新增 `ISubstrate` 实现；
5. 在 `RegisterBuiltinChannels()` 注册 backend id；
6. 不修改 `Channel` 的核心编排逻辑，除非新增的是所有后端共享的生命周期语义。

### 10.2 新增 health sensor

新增 sensor 只需实现 `IHealthSensor`：

- `Start(HealthPublisher&)` 启动后台采集；
- `Stop()` 停止线程；
- `Poke()` 支持 quiesce；
- 必要时实现 `SyncObservedWorkers()` 或 `RearmSingleWorker()`；
- 通过 assembler 在 `HealthMonitor::Start()` 之前 `AddSensor()`。

Sensor 只能通过 `HealthPublisher` 发布事件，不应直接操作 `Channel`、`Recovery` 或 data plane。

### 10.3 新增 recovery 策略或动作

策略扩展应优先落在 `IFaultPolicy` / `EscalationPolicy`。新增动作需要同步：

- `core::channel_contract::RecoveryAction`；
- `Recovery::BuildExecPlan()`；
- `RecoveryExe` 具体执行；
- `Channel` 对恢复前后 pause、drain、generation、health resume 的编排语义。

### 10.4 新增 submit 策略

新增 submit 策略实现 `ISubmitStrategy` 即可。策略只接收 `ChannelView`，返回 channel index 顺序，并通过 `OnAccepted()` / `OnCycleEnd()` 更新内部状态。策略不得持有 `IChannel*`，不得直接提交任务。

### 10.5 新增 worker 执行后端或传输适配

guest worker 扩展有两条线：

- 新执行后端：实现 `IExecBackend`，由 worker main 或后续 factory 选择；
- 新传输适配：实现 `IWorkerAdapter`，保持 `ExecutionEngine` 不感知具体 wire。

如果新增传输不使用 ivshmem，需要同时提供 host 侧 `IControlPlane` / `IDataPlane` / evidence source 和 guest 侧 adapter。

## 11. 核心不变式

1. `Channel` 只能通过 `Assembler → ChannelBuilder` 构造。
2. `Channel` 持有抽象组件；具体实现构造集中在 assembler。
3. `loop_thread_` 是 CP / DP 热路径的唯一调用线程。
4. `Submit()` 返回 `kAccepted` 后，task 不允许静默丢弃；必须产生 completion、abnormal 或 fault 相关事件。
5. `executor_id` 在 input、deferred、pending 三阶段必须唯一。
6. `generation_` 递增后，旧 generation 的 completion 必须被丢弃或转成异常路径，不得污染新世代。
7. doorbell 模式下 `IDataPlane::StartServer()` 必须先于 `ISubstrate::StartVM()`。
8. 恢复前必须 pause / drain / suspend health；恢复后必须按结果 resume / generation reset / state transition。
9. `ShmInfra` 生命周期由 `shared_ptr<IvshmemBackbone>` 管理，CP / DP / step source 不拥有 mmap 的独占释放权。
10. `HealthMonitor::AddSensor()` 和 `BindChannelSignals()` 只能在 `Start()` 前调用。

## 12. 当前限制与注意事项

- `ISubstrate` 接口保留 `vm_index`，但当前主路径只支持 `vm_index = 0` 的单 VM channel。
- `mock` backend 是轻量组件组合，不应被视为完整 VM / worker 行为模拟。
- `ChannelSnapshot` 当前保持精简；runtime / health / recovery 细节主要通过 metrics 发布。
- `HealthMonitorService` 仅用于 service 拓扑和生命周期可见性，实际 health stop 仍由 `Channel::Close()` 统一完成。
- `ChannelFactory::Create()` 仍是偏 QEMU / ivshmem 的兼容入口；主路径应优先走 `ChannelCatalog`。
- worker threaded execution 会跳过 KCOV，因为 KCOV 是 per-thread 采集模型。
