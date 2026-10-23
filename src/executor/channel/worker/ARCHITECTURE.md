# Worker 架构与适配指南

> Status: ACTIVE
> Last update: 2026-04-28
> Scope: `executor/channel/worker/` 内部的 design + 后续 family 适配 playbook
> 相关文档:
>   - `../../channel/AGENTS.md` — host 端 channel 子系统抽象(IChannel / 4 plane / ISubstrate / Assembler / Catalog)
>   - `../../../docs/syzkaller-parity-review/roadmap.md` — v2 IR 升级路线、Layer-1/1.5/2/3 进度
>   - `../../../docs/channel-redesign/v4.0/` — host channel 抽象的 12 份设计文档
>   - `MEMORY.md` — reFuzz Project Charter

---

## 0. 怎么用这份文档

| 你是谁 / 你要做什么 | 读 |
|---|---|
| 第一次接手 worker,想搞懂"它是怎么跑起来的" | §1 §2 §3 |
| 给 reFuzz 加新 fuzz target family(AFL CLI / DB / 浏览器 / ...) | §1 §2.2 §4 §5(挑自己要实现的轴)§7 |
| 给 host 加新 substrate(本地进程 / TCP / vsock / 远端机器),需要在 worker 这边补对应 adapter | §1 §2.3 §4(Step 1 A 轴) §5.6 §5.7 §7.3 |
| 改某个具体轴 | §5(对应轴) §6 §7 |
| 想理解 R1-R5 改造为什么这么做 / 怎么 ROLLBACK | §8 |
| 想知道"以后还要做啥" | §9 |

---

## 1. 这份文档要解决什么 + 一个关键认识

**核心结论**:worker 不是 monolithic syscall executor,而是一个 **七轴 composition root**。每一轴可独立替换。新 family 不该改 worker core;它该:

1. 在每个轴上选一个已有实现(能复用就复用)。
2. 不能复用就在对应目录下加新 .cpp 实现。
3. 写一个 `MakeXxxProfile` factory 把它们装配起来。
4. `main()` switch 加一行,CMakeLists 加几行。

worker core(Engine 主循环 / fork 策略 / sandbox 顺序 / crash handler 路径)**不应该因为新 family 出现而被改动**。

### 1.1 关键认识:worker 端的 A 轴 ≠ "ivshmem"

reFuzz 的核心抽象资产 **不是 ivshmem**,而是 **host 端 `executor/channel/` 的整套抽象**:`IChannel` + `IControlPlane` + `IDataPlane` + `IHealthMonitor` + `IRecovery` + `ISubstrate` + 证据源接口。详见 `executor/channel/AGENTS.md`。ivshmem + QEMU 只是 host 当前 substrate 的具体实现 —— 通过 `ChannelAssembler` 装配的一种 backend。host 文档明确写:**新 backend = 新 Assembler**,不动 channel 本体。

worker 端的 **A 轴(Transport / Adapter)** 跟 host channel 抽象一一对应:

| host 端 | worker 端(A 轴) |
|---|---|
| `IControlPlane`(task 投递、completion、cancel、ownership) | `IWorkerTaskChannel` + `IExecutionDomainRegistry` facets |
| `IDataPlane`(数据共享 / doorbell) + `ISubstrate`(VM 底座 / 共享内存载体)的实现细节 | 对应 substrate 的 `IXxxTransport` 子接口 |
| 当前唯一具体实现:`IvshmemControlPlane` + `IvshmemDataPlane` + ivshmem-based `Runtime`(QEMU) | 当前唯一具体实现:`IvshmemWorkerAdapter` impl `IvshmemTransport`(R4 引入子接口) |
| 未来 substrate(本地进程 / TCP / vsock / 远端机器):新 Assembler + 新组件 | 未来 substrate 对应的 worker:新 `IXxxTransport : IWorkerAdapter` + 新 `<Xxx>WorkerAdapter` |

所以:
- **A 轴的"换不换"由 host substrate 决定,不由 fuzz target family 决定**。
- 现在所有 family(kernel-syz / 未来 AFL CLI / DB / 浏览器 / ...)在 host 当前 substrate 是 ivshmem 的前提下,**碰巧**worker 端都用 `IvshmemWorkerAdapter` —— 这是 substrate 的偶然性,不是 family 的本质。
- host 哪天加 TCP substrate,所有 family 的 worker 都要换成 TCP-based adapter,**不需要**改 family-specific 的 B/C/D/E 轴。
- worker A 轴和 family B-G 轴正交。

### 1.2 CMake 结构印证这个认识

worker 的 build 形态自 Layer-2 起已按"core 库 + per-substrate 瘦 exec"切开:

```
refuzz_worker_core (STATIC library)
  ├── B-G 六轴所有实现(driver / codec / dispatcher / observation / engine / sandbox / ...)
  ├── pseudo handler 表
  ├── profile factory(MakeKernelSyzProfile + RunWorkerProfile)
  └── PUBLIC include: include/  + ../../proto/wire/include

ivshmem_worker (EXECUTABLE, thin shell)
  ├── src/ivshmem_worker_main.cpp        — args parse → factory → RunWorkerProfile
  ├── src/ivshmem_attach.cpp             — ivshmem PCI 发现 / mmap helper
  └── src/adapter/ivshmem_adapter.cpp    — IvshmemWorkerAdapter (impl IvshmemTransport)
  link: refuzz_worker_core
```

含义:
- B-G 轴的所有代码都在 `refuzz_worker_core` 静态库,不与 substrate 耦合 → 可被任何 substrate exec target 复用,也可被 out-of-tree 工具(例如 smoke test)单独链。
- 每个 substrate 对应一个 thin exec target,只含三类源文件:**main + substrate-specific glue(attach/discovery)+ substrate-specific adapter**。
- host 加新 substrate 时,worker 这边 build 拓展是镜像的:
  ```
  add_executable(<new>_worker
      src/<new>_worker_main.cpp                — 复用 main 模板,改 adapter 选择
      src/<new>_attach.cpp                     — substrate-specific glue
      src/adapter/<new>_adapter.cpp            — IXxxWorkerAdapter (impl I<New>Transport)
  )
  target_link_libraries(<new>_worker PRIVATE refuzz_worker_core)
  ```
  **不动** `refuzz_worker_core`,**不动** B-G 任何文件。

这印证了 §1.1 的论述:A 轴跟 host substrate 配对,B-G 跟 family 配对,两者正交,build 拓扑也正交。

> ⚠️ 旧版本文档曾写"reFuzz channel 模型核心资产是 ivshmem,A 轴几乎不变"——这是错误论述,已删除。正确表述见上。

---

## 2. 七轴模型

### 2.1 总览图

```
host 端 (executor/channel/, 见 channel/AGENTS.md)
┌──────────────────────────────────────────────────────────────────────┐
│  IChannel ──── orchestration                                         │
│      │                                                               │
│      ├── IControlPlane          ◀──── 当前: IvshmemControlPlane      │
│      ├── IDataPlane + Doorbell  ◀──── 当前: IvshmemDataPlane         │
│      ├── IConsoleSource / IStepEventSource(evidence)                 │
│      ├── IHealthMonitor                                              │
│      ├── IRecovery                                                   │
│      └── ISubstrate (VM 底座)   ◀──── 当前: QEMU + ivshmem Runtime   │
│                                                                      │
│  装配链: ChannelCatalog(backend_id) → IChannelAssembler              │
│           → ChannelComponents → ChannelBuilder → IChannel            │
└──────────────────────────────────────────────────────────────────────┘
        │
        │  当前 substrate=ivshmem 时:BAR2 共享内存 + BAR0 doorbell MSI-X
        │  (substrate 换 → 这里换;worker A 轴跟着换)
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│  worker 进程 (本目录, root, 永远不进 sandbox)                         │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  WorkerProfile (composition root, R5)                        │    │
│  │  ┌────────────────────────────────────────────────────────┐  │    │
│  │  │ A. Adapter        IWorkerAdapter (composition root)   │  │    │
│  │  │  (跟 host       + task/registry/registrar facets      │  │    │
│  │  │   substrate     + IXxxTransport (substrate-specific 子) │ │    │
│  │  │   substrate     当前: IvshmemWorkerAdapter 实现两者     │  │    │
│  │  │   配对)                                                │  │    │
│  │  ├────────────────────────────────────────────────────────┤  │    │
│  │  │ B. Driver         IExecBackend (概念上=IDriver)        │  │    │
│  │  │  (family 决定)    e.g. KernelChildDriver / KernelWireDriver│ │   │
│  │  │     ┌──────────────────────────────────────────────┐   │  │    │
│  │  │     │ C. Codec      ICodec (bytes → ProgramView)   │   │  │    │
│  │  │     │ D. Dispatcher IDispatcher (一次 syscall/action)│  │  │    │
│  │  │     └──────────────────────────────────────────────┘   │  │    │
│  │  ├────────────────────────────────────────────────────────┤  │    │
│  │  │ E. Observation    IObservationBus + IObservationSink   │  │    │
│  │  │                   sinks=[KcovSink, IvshmemStepSink, …] │  │    │
│  │  ├────────────────────────────────────────────────────────┤  │    │
│  │  │ F. Detector       ProgramRuntime + crash handler 路径 │  │    │
│  │  │                   (尚无独立接口,见 §9 TODO)           │  │    │
│  │  ├────────────────────────────────────────────────────────┤  │    │
│  │  │ G. Supervisor     DomainSupervisor 状态机              │  │    │
│  │  │                   deadline + Recover + recycle         │  │    │
│  │  └────────────────────────────────────────────────────────┘  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ▼ ForkChild → child 进程跑实际任务(进 sandbox / 执行 / 反馈)        │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.2 B-G 轴对 family 对照表(A 轴单独看 §2.3)

A 轴跟 host substrate 配对,跟 family 正交,**不写在这张表里**。下面 6 列 = B-G 六轴在不同 family 上的实现选择:

| 轴 | kernel-syz(已有) | AFL CLI(3.1) | 中间件(3.2) | 协议(3.3) | DB-SQLite(3.4) | 编译器(3.5) | 浏览器V8(3.6) | PyTorch(3.7) |
|---|---|---|---|---|---|---|---|---|
| B. Driver | KernelChildDriver(syz_exec) / KernelWireDriver(wire) | ForkServerDriver | DaemonClientDriver | PeerConnDriver | InProcDriver | SubprocessDriver(cc1) | SubprocessDriver(d8) | PythonSubprocessDriver |
| C. Codec | SyzExecCodec / WireCodec | AflBytesCodec | RequestStreamCodec | PduSequenceCodec | SqlCodec | SourceFileCodec | JsAstCodec | TensorGraphCodec |
| D. Dispatcher | SyscallOrPseudoDispatcher | — | — | — | SqlStmtDispatcher | — | — | TensorOpDispatcher |
| E. Sinks | KcovSink + IvshmemStepEventSink | AflBitmapSink + ExitCodeSink + AsanReportSink | LibfuzzerCovSink + ResponseDiffSink | LibfuzzerCovSink + 协议 oracle Sink | LibfuzzerCovSink + ResultDigestSink | LibfuzzerCovSink + IceParserSink + CrossOptOracleSink | LibfuzzerCovSink + V8InternalsSink + StderrCaptureSink | LibfuzzerCovSink + NumericDiffSink |
| F. Detector | KernelCrashDetector(panic via signal) | ExitOrAsanDetector | ProcessLossDetector | PeerCrashDetector | AssertOrAsanDetector | IceDetector | RendererCrashDetector + SandboxViolationDetector | CudaIllegalDetector + NumericDivergenceDetector |
| G. Supervisor | DomainSupervisor + exec double-fork | fork-server | DaemonSupervisor(周期 reset) | DaemonSupervisor | InProcSupervisor(setjmp 恢复) | SubprocessSupervisor | SubprocessSupervisor + sandbox | PythonSubprocessSupervisor(周期 reset state) |

**E 列不是单 sink,是 sink 列表**(同一 family 通常 2-3 个 sink 一起用)。

**D 列在某些 family 中"无"**(driver 内部一次性 exec target 时不需要 per-action dispatch),不要硬塞。

**B 列 kernel-syz 有两个 driver**:R1 引入的 `KernelChildDriver` 跑 legacy syz_exec wire(v1 flat / v2 typed);Layer-2 引入的 `KernelWireDriver` 跑 syzkaller-equivalent exec wire(`§3.2` 的 byte-equal 输出)。在 `KernelSyzArgs::driver_kind = kSyzExec | kWire` 切换,profile factory 内部一行 if(见 §3.2)。

### 2.3 A 轴 — 跟 host channel substrate 配对

A 轴的实现选择**不是按 family 而是按 host substrate**:

| host substrate | host 端组件(channel/) | worker 端 A 轴 |
|---|---|---|
| QEMU + ivshmem(当前唯一具体实现) | `IvshmemControlPlane` + `IvshmemDataPlane` + ivshmem-based `Runtime` | `IvshmemWorkerAdapter` impl `IvshmemTransport`(`worker/adapter/ivshmem_adapter.hpp` + `worker/transport/ivshmem_transport.hpp`) |
| 本地进程(假想 / 未实现) | `LocalControlPlane` + `LocalDataPlane`(stdio pipe) + Local `ISubstrate` | 假想 `LocalWorkerAdapter` impl `LocalTransport` |
| TCP / vsock(假想) | 类似 | 类似 |

加新 substrate 的连锁:
1. host 端按 `executor/channel/AGENTS.md` 加 `???Assembler` + 实现新组件 + `ChannelCatalog::Register`。
2. worker 端加对应 `<NewSubstrate>WorkerAdapter` impl `<NewSubstrate>Transport : IWorkerAdapter`。
3. profile factory 不动 — 它只看 `args.transport_substrate`(或类似)选具体 adapter,family-specific 的 B-G 轴不改。

> 当前 worker codebase 里只有 ivshmem 一个具体 adapter,所有 family 在跑起来时都用它。这是"host 当前只有一种 substrate"的连锁,不是"worker 跟 ivshmem 绑死"。

---

## 3. kernel-syz 端到端调用链(参考实现)

读完这一节,你会知道 §4 playbook 每一步对应代码里的什么。文件路径相对 `executor/channel/worker/`。

### 3.1 启动:`main()` 选 profile + driver

`src/ivshmem_worker_main.cpp`(注:二进制名仍叫 `ivshmem_worker` 是历史名,不代表非 ivshmem substrate 不能用。R5 之后 main 已经 family-agnostic):

```cpp
int main(int argc, char** argv) {
    /* 1. 解析 args (worker_id, vm_id, coverage_mode, sandbox_mode, ...) */
    /* 2. install signal handler, init logging, pseudo runtime cleanup */

    /* --profile=NAME 选 family;--driver=syz_exec|wire 选 kernel-syz 内部 driver */
    std::string profile_name = "kernel-syz";
    KernelSyzArgs::DriverKind driver_kind = KernelSyzArgs::DriverKind::kSyzExec;

    /* 3. 选 profile */
    WorkerProfile profile;
    if (profile_name == "kernel-syz") {
        KernelSyzArgs syz_args = /* 从 CLI args 复制,含 driver_kind */;
        profile = MakeKernelSyzProfile(syz_args);
    } else {
        LOG("unknown profile=%s", profile_name.c_str());
        return 2;
    }

    /* 4. 通用入口 */
    return RunWorkerProfile(profile);
}
```

main 不感知 host substrate,也不感知 family 内部。

### 3.2 装配:`MakeKernelSyzProfile`

`src/profile/kernel_syz_profile.cpp`:

```cpp
WorkerProfile MakeKernelSyzProfile(const KernelSyzArgs& args) {
    WorkerProfile p{};
    p.name = "kernel-syz";

    /* A. Adapter — 当前 host substrate=ivshmem,选 IvshmemWorkerAdapter。
     *    host 加新 substrate 时这里 switch on substrate 选 adapter。 */
    p.adapter = std::make_unique<IvshmemWorkerAdapter>(/* IvshmemWorkerAdapter::Config */);

    /* B. Driver — kernel-syz family 支持 syz_exec / wire 两个 driver:
     *    syz_exec: SyzExecCodec + KernelChildDriver(R1 默认,跑 v1 flat / v2 typed)
     *    wire   : WireCodec + KernelWireDriver(Layer-2,跑 syzkaller-equivalent
     *             exec wire,kSyzExecWire kind) */
    if (args.driver_kind == KernelSyzArgs::DriverKind::kWire) {
        p.backend = std::make_unique<KernelWireDriver>(
            std::make_unique<WireCodec>(),
            std::make_unique<SyscallOrPseudoDispatcher>(),
            args.worker_id);
    } else {
        p.backend = std::make_unique<KernelChildDriver>(
            std::make_unique<SyzExecCodec>(),
            std::make_unique<SyscallOrPseudoDispatcher>());
    }

    /* E. ObservationBus + (部分) Sinks。
     *    IvshmemStepEventSink 需要 ring 指针,只能在 adapter.Init() 后挂,
     *    所以放到 RunWorkerProfile 里 late add。 */
    auto bus = std::make_unique<ObservationBus>();
    if (args.coverage_mode == CoverageMode::kKcov) {
        bus->AddSink(std::make_unique<KcovSink>());
    }
    p.bus = std::move(bus);

    p.sandbox_mode = args.sandbox_mode;
    p.exec_timeout_ms = args.exec_timeout_ms;
    /* ... */
    return p;
}
```

factory **只构造,不调 Init/Handshake**。原因见 §7.6。

### 3.3 通用入口:`RunWorkerProfile`

```cpp
int RunWorkerProfile(WorkerProfile& p) {
    p.adapter->Init();                              /* 当前 substrate=ivshmem 时:mmap BAR2/BAR0,attach driver fd */

    /* late sink:此时才有 substrate-specific 的 ring 指针。 */
    auto* ivs = p.adapter->AsIvshmem();
    if (p.enable_step_events && ivs) {
        p.bus->AddSink(std::make_unique<IvshmemStepEventSink>(
            ivs->GetStepEventHeader(), ivs->GetStepEventSlots(),
            ivs->GetStepEventCapacity(), p.worker_id));
    }

    EngineConfig cfg = /* 从 p 和 adapter transport contract 复制 */;
    auto& task_channel = p.adapter->TaskChannel();
    auto& domain_registry = p.adapter->DomainRegistry();
    auto& registrar = p.adapter->Registrar();
    p.adapter->Handshake();
    registrar.Register();                          /* CLAIMED + heartbeat */
    p.post_register_setup();                       /* worker-0 VM setup once */
    ProbeSandboxMode(p.sandbox_mode, ...);          /* heartbeat 已运行 */

    DomainComponentBinding binding = /* explicit inherited-or-exec variant */;
    ExecutionEngine engine(task_channel, domain_registry, std::move(binding),
                           std::move(p.topology), cfg);
    int rc = engine.Run();                         /* startup ACK publishes READY */
    p.adapter->Cleanup();
    return rc;
}
```

### 3.4 主循环:`DomainSupervisor::Run()`

`ExecutionEngine::Run()` 只转发给 `DomainSupervisor::Run()`。daemon 生命周期只有
supervisor 一个决策点；topology 返回观察结果，adapter 返回 transport 状态：

```cpp
Recover(kInitialStartup);                           /* startup retry + ACK */
while (g_running) {
    MaintainReadyDomain();                          /* liveness + periodic recycle */
    auto task = adapter.WaitTask(timeout);
    if (!task) { ObserveAdapterState(); continue; }

    adapter.ResetOutputLen();
    auto handle = topology.Dispatch(task);
    auto result = topology.Collect(handle, phase_deadline, cancel);

    if (DomainFault(result)) {
        recovery = Recover(ReasonFrom(result));     /* stop plan + proc rotation + retry */
    }
    adapter.ReportDone(ClassifyCompletion(result, recovery));
}
```

`GUEST_REG_CLAIMED` 表示 daemon 已注册；`GUEST_REG_READY` 只表示当前 execution domain
已完成 startup ACK 并允许 DataPlane 提交。supervisor 进入
Starting/Stopping/Failed/Stopped 时退回 CLAIMED，进入 Ready/Executing 时发布 READY。
host 对每个 worker 依次执行 CLAIMED -> grant -> READY，再处理下一个 worker，确保含
VM-global device/cgroup 操作的 sandbox/KCOV startup 不并发。host 不再依赖独立 heartbeat
线程，而是采样由 guest_state、proc_epoch、task slot 和 completion 组成的执行状态机进度
令牌；令牌只在实际推进时变化，空闲或一次有界执行期间保持不变是正常语义。
domain stop/start/retry 不调用 adapter cleanup。只有外部
shutdown、transport 终止或 supervisor 进入 `Failed` 后，`RunWorkerProfile` 才 cleanup adapter。
为避免本地自救无限拖延，task watchdog 后只允许一次有独立 startup deadline 的 replacement；
该 replacement 失败即带 task-watchdog reason 进入 `Failed`，由 host 执行 VM 级恢复。

#### 3.4.1 唯一状态机

`DomainState` 只表示 supervisor 内部的 domain 生命周期 phase。`TransitionReason` 仅作为
恢复策略和日志参数沿当前转换传递，不持久化为测试或遥测指标。只有 supervisor 可以推进状态：

| State | 唯一职责 | Deadline 来源 |
|---|---|---|
| `Starting` | `topology.Setup()` 与 loop-ready ACK | `domain_startup_timeout_ms` |
| `Ready` | domain 健康并可接任务；执行 liveness/recycle maintenance | 无 |
| `Executing` | dispatch、collect 和 completion 所在 task phase | `daemon_watchdog_ms`，从 dispatch 前开始 |
| `Stopping` | 执行 supervisor 下发的 stop escalation plan | 四段 stop timeout 共享 absolute deadline |
| `Failed` | 本地预算耗尽且不可恢复，交给 host 重启 daemon | 无 |
| `Stopped` | clean shutdown 完成 | 无 |

`SetDomainReady()` 只在 domain capability 的边沿发布：`Starting/Stopping/Failed/Stopped`
为 not-ready，`Ready/Executing` 为 ready；`Ready <-> Executing` 和空闲 maintenance 不重复写
共享 `guest_state`。

`ProcessTopology::Setup()` 返回结构化 `DomainStartResult`，不再把所有启动结果
压成 `errno + -1`：

```text
ready ACK                         -> Ready
LoopStartupStatus{ready=0,...}    -> Rejected(stage, errno)
pidfd / pipe EOF before ready     -> Exited(exit_status)
attempt absolute deadline expires -> Stalled
```

`Starting` 只创建一个 absolute deadline。fork/exec、pidfd handoff 和 startup
ACK 都消费该 deadline 的剩余时间；negative ACK 是明确失败并立即返回，不等待
deadline。失败后 partial domain ownership 交回 topology，由 supervisor 进入
`Stopping` 并执行唯一 stop escalation 链。

`DomainSupervisor::Recover()` 同样返回结构化 `DomainRecoveryResult`：

```text
Recovered               -> replacement Ready
ReplacementStartFailed  -> ownership 已回收，但 daemon 无可用 domain
OwnershipUnreclaimed    -> stop escalation 失败，禁止重叠启动同 worker
```

terminal recovery 在 wire 边界压缩为两个 `ErrorCode`，不扩展
`CompletionSlot`：`ERR_DOMAIN_REPLACEMENT_START_FAILED` 触发单 worker restart，
`ERR_DOMAIN_OWNERSHIP_UNRECLAIMED` 才允许 host 升级 VM recovery。原始 task 的
timeout/harness 分类仍由 `CompletionStatus` 表达；host 不得再从
`ERR_DOMAIN_WATCHDOG_TIMEOUT` 推断 ownership。

主转移只有以下几条：

```text
Starting -> Ready
              |
              +-- task ----------------> Executing -> Ready
              |                              |
              |                              +-- fault --> Stopping -> Starting -> Ready
              |                                                       +-------> Failed
              +-- periodic recycle -------> Stopping -> Starting -> Ready
              +-- shutdown ----------------> Stopping -> Stopped
```

reason 只有 `InitialStartup / PeriodicRecycle / TaskWatchdog / TaskCancelled /
HarnessFailure / ProcRebind / Shutdown`。策略只在 `RecoveryPolicyFor(reason)` 定义一次。cancel 是 host control intent：需要替换
被中断的 domain，但 stop intent 是 `Cancellation` 且不增加 health streak。task watchdog 是 domain
fault：轮换 proc-id、增加 streak，但 replacement startup 最多一次。

#### 3.4.2 Topology 模块边界

profile 选择独立 topology 策略；supervisor 决定何时调用，topology 负责该策略的进程原语与配置合同：

| Topology | 组件来源 | Program 隔离 | 模块职责 |
|---|---|---|---|
| `ReusableChildTopology` | daemon 构造，fork 继承 | loop 内 inline | legacy/throughput baseline 的长生命周期 child |
| `RecycleChildTopology` | daemon 构造，fork 继承 | loop 内 inline | 独立策略模块；校验 `recycle_after >= 1`，不自行触发 recycle |
| `DoubleForkTopology` | daemon 构造，fork 继承 | per-program fork | legacy 三层 namespace/fork parity 路径 |
| `ExecDoubleForkTopology` | exec 后按 POD boot config 重建 | per-program fork | production 路径；独立 mapping/backend/bus/KCOV/sandbox |

统一合同为 `Setup / Dispatch / Collect / ExecutionDomainExited / Stop`：

- `Setup` 只创建一个 domain；失败返回，不自行 retry。
- `Dispatch/Collect` 只传标量和 `ProgramBufferDescriptor` offset，不携带进程地址。
- `Collect` 只观察并分类，不 stop、respawn、ReportDone 或修改 daemon 状态。
- `Stop` 只机械执行 `DomainStopPlan`，不选择 proc-id、不启动 replacement、不决定 daemon 退出。
- heartbeat、task completion、recovery budget、periodic threshold 和 proc-id lane 始终属于 supervisor/adapter 层。

### 3.5 child 进程:`ChildMain`

```cpp
[[noreturn]] void ChildMain(/* ready_pipe_r, done_pipe_w, area, worker_id,
                                backend, bus, sandbox_mode, ivshmem_bytes */) {
    /* 1. crash handler 全局指针 + 安装 */
    g_engine_child_area = area;
    g_engine_child_completion = &area->completion;
    g_engine_bus = &bus;
    install_engine_child_crash_handlers();

    /* 2. sink 初始化:KcovSink 打开 /dev/kcov,IvshmemStepEventSink 设全局 ring 指针,
          顺便 LOG 触发 WorkerLogFd 把 ttyS0 在 root 下 lazy-open 持有。 */
    bus.InitAll();

    /* 3. pre-allocate scratch (16 MiB on linux/amd64),必须在 sandbox 之前 mmap */
    PreallocateSyzExecScratch();

    /* 4. sandbox apply。
          sizing.coverage_bytes = bus.TotalBufferBytes()
          sizing.scratch_bytes  = kSyzExecScratchBytes
          sizing.ivshmem_bytes  = 当前 substrate-specific size(见 §9 TODO debt) */
    ApplySandbox(sandbox_mode, sizing);

    /* 5. 主循环 */
    while (true) {
        read(ready_pipe_r, &msg);
        executor_id = atomic_load(&task->executor_id);
        ChildExecuteTask(backend, bus, area, msg.input_len, &out_len, mode,
                         worker_id, executor_id);
        write(done_pipe_w, &done);
    }
}

int ChildExecuteTask(IExecBackend& backend, IObservationBus& bus, ...) {
    ObservationContext ctx{worker_id, executor_id, /*call_index*/0,
                           /*completion_status*/0, mode};
    bus.Publish(kTaskStart, ctx);                   /* KcovSink Begin();
                                                        StepSink set executor_id */
    int status = backend.Execute(input, output, ..., mode);
    bus.Publish(kSessionEnd, ctx);                  /* KcovSink End() 收 entries */
    bus.PackAllFeedback(output, output_cap, &final_len);
    return status;
}
```

### 3.6 driver:`KernelChildDriver` vs `KernelWireDriver`

`KernelChildDriver`(R1,跑 SyzExec wire v1/v2):

```cpp
int KernelChildDriver::Execute(input, len, output, cap, &out_len, mode) {
    ProgramView view;
    if (!codec_->Decode(input, len, &view)) return -1;

    switch (view.kind) {
    case ProgramView::Kind::kSyzV1Flat:
        if (mode.intra == kThreaded) return -1;
        return execute_program(input, len, output, cap, &out_len, *dispatcher_);
    case ProgramView::Kind::kSyzV2Typed:
        if (mode.intra == kThreaded)
            return syz_execute_threaded(input, len, output, cap, &out_len, *dispatcher_);
        return syz_execute(input, len, output, cap, &out_len, *dispatcher_);
    case ProgramView::Kind::kSyzExecWire:
        /* Layer-2 wire format 由 KernelWireDriver 处理。
         * 这里若收到 = profile 装错(SyzExecCodec 不该产 wire kind),拒绝执行。 */
        return -1;
    }
    return -1;
}
```

`KernelWireDriver`(Layer-2,跑 syzkaller-equivalent exec wire):
- Codec 是 `WireCodec`,内部调 `program/syz/exec_wire_decode.hpp::decode_exec_wire()` 产 `WireProgram`,通过 `ProgramView::Kind::kSyzExecWire` 把指针交给 driver。
- Driver 在 child 进程内 mmap 一个可写 data 段(size 由 `Target::data_offset()` 决定),处理 `WireCopyin / WireCsum / WireCall / WireCopyout / WireSetProps`。`WireSetProps.fail_nth` 经 Epic 6 §3.14 PR-6-A 通过 `inject_fault` / `fault_injected` helpers 经由 `/proc/thread-self/fail-nth` 透传到 kernel,触发后在 per-call `SyzExecResult.flags` 写入 `kCallFlagFaultInjected` 报回 host。`Async / Rerun` 仍然 reject(Epic 6 §10 N1/N2 永久非目标),返回执行错误。
- `WireCall` 通过 `dispatcher.Dispatch(SyscallMeta::nr, args, argc, &pseudo_ctx)` 跟 R1 复用同一 `SyscallOrPseudoDispatcher`。

两者通过 profile factory 的 `args.driver_kind` 切换;运行时不切换。

---

## 4. 加新 family 的步骤(playbook)

**目标**:你拿到一个新 fuzz target family,想让 reFuzz worker 跑它。

> family 决定 B/C/D/E/F/G 六轴。**A 轴不归你管** — 它跟 host substrate 走;当前 substrate=ivshmem,所有 family 都复用 `IvshmemWorkerAdapter`(§2.3)。

### Step 1. 决定 B-G 轴的具体选择

| 轴 | 复用 vs 新写 | 决策提示 |
|---|---|---|
| B. Driver | 几乎必须新写 | 这是 family 核心:"如何把 input bytes 跑出来" |
| C. Codec | 必须新写 | 除非沿用 syz wire(那就用 `SyzExecCodec` / `WireCodec`) |
| D. Dispatcher | 看 family | "driver 内部是一次性 exec target?" → 不需要;"driver 内部是 for-each-action?" → 需要 |
| E. Sinks | 复用 + 新写混合 | KcovSink 几乎只对 kernel 有用;LibfuzzerCovSink/ExitCodeSink/AsanReportSink 等是泛用件 |
| F. Detector | 通常新写 | "如何判断出问题":kernel=panic via signal;CLI=exit code;DB=assert/ASAN;... |
| G. Supervisor | 看 family | kernel-syz 已由 `DomainSupervisor` 统一管理；其它 family 需要自己的 supervisor strategy，而不是把分支塞回 engine/topology/adapter |

**A 轴**:沿用 host 当前 substrate 对应的 worker adapter — 不是因为 ivshmem,是因为 host 当前实现就只有 ivshmem。host 哪天加新 substrate,所有 profile 同步换。新 family 启动时**不要**为 A 轴写新 adapter。

### Step 2. 定义 args 结构体

参考 `KernelSyzArgs`(`include/worker/profile/worker_profile.hpp`):

```cpp
struct AflCliArgs {
    uint32_t worker_id;
    uint32_t vm_id;
    int peer_id;
    int poll_ms;
    uint32_t exec_timeout_ms;
    SandboxMode sandbox_mode;

    /* family-specific */
    std::string target_binary;
    std::vector<std::string> argv;
    std::string asan_log_dir;
    uint32_t shmem_id;          /* AFL bitmap shared memory id */
};
```

放在 `include/worker/profile/<family>_args.hpp` 或 factory 文件里(尺寸小可以)。

### Step 3. 实现 B-G 轴

约定:
- 接口 declaration 在 `include/worker/<axis>/`,实现在 `src/<axis>/`。
- **不要把 family-specific 类型塞回通用接口的方法签名**(反例见 §7.2)。
- 在 sink 的 `SnapshotForCrash` 里只做 async-signal-safe 操作(见 §6.3)。

新建文件示例(AFL CLI):
```
include/worker/codec/afl_bytes_codec.hpp
include/worker/driver/fork_server_driver.hpp
include/worker/observation/afl_bitmap_sink.hpp
include/worker/observation/exit_code_sink.hpp
include/worker/observation/asan_report_sink.hpp
src/codec/afl_bytes_codec.cpp
src/driver/fork_server_driver.cpp
src/observation/afl_bitmap_sink.cpp
src/observation/exit_code_sink.cpp
src/observation/asan_report_sink.cpp
```

### Step 4. 写 factory

`src/profile/afl_cli_profile.cpp`:

```cpp
#include "worker/profile/worker_profile.hpp"
#include "worker/adapter/ivshmem_adapter.hpp"        /* A 轴: host 当前 substrate=ivshmem */
#include "worker/codec/afl_bytes_codec.hpp"
#include "worker/driver/fork_server_driver.hpp"
#include "worker/observation/afl_bitmap_sink.hpp"
#include "worker/observation/exit_code_sink.hpp"
#include "worker/observation/asan_report_sink.hpp"

namespace refuzz::worker {

WorkerProfile MakeAflCliProfile(const AflCliArgs& args) {
    WorkerProfile p{};
    p.name = "afl-cli";

    /* A. Adapter — 跟 host substrate 走;当前 substrate=ivshmem。
     *    host 换 substrate 时所有 profile factory 同步换,这里不该是 family 决策。 */
    IvshmemWorkerAdapter::Config acfg{};
    acfg.worker_id = args.worker_id;
    /* ... */
    p.adapter = std::make_unique<IvshmemWorkerAdapter>(acfg);

    /* B. Driver — ForkServerDriver(target binary, codec) */
    p.backend = std::make_unique<ForkServerDriver>(
        args.target_binary, args.argv,
        std::make_unique<AflBytesCodec>());

    /* E. Sinks */
    auto bus = std::make_unique<ObservationBus>();
    bus->AddSink(std::make_unique<AflBitmapSink>(args.shmem_id));
    bus->AddSink(std::make_unique<ExitCodeSink>());
    bus->AddSink(std::make_unique<AsanReportSink>(args.asan_log_dir));
    p.bus = std::move(bus);

    p.sandbox_mode = args.sandbox_mode;
    p.exec_timeout_ms = args.exec_timeout_ms;
    p.worker_id = args.worker_id;
    p.poll_ms = args.poll_ms;
    p.enable_step_events = false;       /* AFL family 不用 step ring */
    return p;
}

} // namespace refuzz::worker
```

### Step 5. main 加 switch + CMakeLists 加 .cpp

`src/ivshmem_worker_main.cpp`:

```cpp
if (profile_name == "kernel-syz") {
    KernelSyzArgs syz_args = /* 含 driver_kind */;
    profile = MakeKernelSyzProfile(syz_args);
} else if (profile_name == "afl-cli") {
    profile = MakeAflCliProfile(/* AflCliArgs */);
} else {
    LOG("unknown profile=%s", profile_name.c_str()); return 2;
}
```

`CMakeLists.txt`:
```cmake
src/profile/afl_cli_profile.cpp
src/codec/afl_bytes_codec.cpp
src/driver/fork_server_driver.cpp
src/observation/afl_bitmap_sink.cpp
src/observation/exit_code_sink.cpp
src/observation/asan_report_sink.cpp
```

### Step 6. 跑通 + 验证

最小验证:
1. `cmake --build /workspace/talaria/build-llvm20 --target ivshmem_worker -- -j$(nproc)` 编译过。
2. `./ivshmem_worker --help` 看 `--profile=afl-cli` 已注册。
3. host 端给 reFuzz 配 AFL target,host 投 task,worker 执行 + 回报 feedback。

### Step 7. 哪些事不该做

- **不要把生命周期判断放回 ExecutionEngine/topology/adapter** — kernel-syz 的所有 domain fault 必须进入 `DomainSupervisor::Recover(reason)`；其它 family 应增加 supervisor strategy。
- **不要改 ChildMain 步骤顺序** — §6.2 强约束。
- **不要在通用接口加 family-specific 方法** — §7.2。
- **不要为新 family 写新 A 轴 adapter** — §2.3。host 加 substrate 时所有 family 一起换。
- **不要新加 child 进程全局变量** — §7.7。

---

## 5. 各轴接口契约与不变量

> 给"我要实现一个新 sink/driver/codec/dispatcher/adapter"的工程师看。读懂自己要实现接口的契约,不破坏不变量。

### 5.1 ICodec — `worker/codec/codec.hpp`

```cpp
struct ProgramView {
    enum class Kind : uint8_t {
        kSyzV1Flat   = 0,   // SyscallProgHeader{magic, count} + SyscallOp[count]
        kSyzV2Typed  = 1,   // SYZ_EXEC_MAGIC + version == SYZ_EXEC_VERSION
        kSyzExecWire = 2,   // [Layer-2] syzkaller-equivalent exec wire (varint stream)
    };
    Kind kind = Kind::kSyzV1Flat;
    uint32_t n_calls = 0;
    /* v1: SyscallOp 数组指针 */
    /* v2: SyzExecHeader + 原始 buffer */
    /* wire: codec-owned WireProgram* — 生命周期跟 codec 实例,driver 必须在同一 Execute() 内消费 */
    const refuzz::program::syz::WireProgram* wire = nullptr;
};

class ICodec {
public:
    virtual bool Decode(const uint8_t* input, uint32_t input_len, ProgramView* out) = 0;
    virtual const char* Name() const = 0;
};
```

**契约**:
- 不拷贝 payload。`ProgramView` 内的指针都指向 codec 内部 buffer 或 input;caller 必须保证 input 在 driver 执行期间持续有效。
- 失败返 `false`,不修改 `*out`,不抛异常。
- 必须 stateless,或仅持 thread-local-state。Codec 实例由 fork 继承,可能从 main thread 或 worker thread 调。

**ProgramView 扩展**:加新 family 通常要扩 `ProgramView::Kind` enum + 加对应字段。如果新 family 的程序模型差异巨大,考虑让 ICodec 返回 family-specific 派生 struct(`std::variant` 或 `unique_ptr<IDecodedProgram>`)— 见 §9 TODO "ProgramView 多态化"。

### 5.2 IDispatcher — `worker/dispatcher/dispatcher.hpp`

```cpp
class IDispatcher {
public:
    virtual PseudoResult Dispatch(uint64_t nr, const intptr_t* args, uint32_t argc,
                                  PseudoRuntimeContext* ctx) = 0;
    virtual const char* Name() const = 0;
};
```

**契约**:
- `nr` 语义由 Dispatcher 实现自定义。`SyscallOrPseudoDispatcher` 中 nr = native syscall number 或 pseudo nr。
- 必须 thread-safe — threaded mode 下从多个 worker thread 并发调。
- 失败返 `PseudoResult{ret=-1, err=errno}`,不抛异常。

**注意**:接口 ctx 类型是 `PseudoRuntimeContext*`,这是 R1 阶段对 kernel concept 的耦合。R5+ 计划让 ctx 变 family-generic 或拆分子接口(§9 TODO)。新 family driver 不走 syscall+pseudo 模式时,**不要**强行复用 `IDispatcher`,driver 内部直接处理 dispatch。

### 5.3 IExecBackend(Driver)— `worker/backend/exec_backend.hpp`

```cpp
class IExecBackend {
public:
    virtual int Execute(const uint8_t* input, uint32_t input_len,
                        uint8_t* output, uint32_t output_cap, uint32_t* output_len,
                        ExecMode mode = {}) = 0;
    virtual const char* Name() const = 0;
};
```

> 概念上是 IDriver,R5 没改名 — 见 §9 TODO。

**契约**:
- 返 `0` = "执行完毕,无 driver 错误"。非 `0` = exec error(input 解析失败 / 不支持的 mode / driver 内部异常)。**业务级失败(如某条 syscall 返 -1)不算 driver error**,作为 result 写到 output 里。
- 不要吞掉 `mode.intra == kThreaded`:不支持 threaded 的 driver 直接返 -1。
- output buffer 由 caller 提供,driver 只写 raw results 到 `*output_len`。Sink 后期 append 的 feedback 帧由 ChildExecuteTask 在 driver 返回后通过 `bus.PackAllFeedback` 处理。
- Execute 在 child process 调用,可能从 main thread(serial)或 worker thread(driver 内部 spawn 的 syz_execute_threaded 路径)调。
- driver 内部可缓存 thread-local scratch(例 `AcquireScratch` 用 `thread_local mmap`)。

### 5.4 IObservationSink — `worker/observation/observation_bus.hpp`

```cpp
class IObservationSink {
public:
    virtual bool Init() { return true; }
    virtual void OnEvent(ObservationEvent ev, const ObservationContext& ctx) = 0;
    virtual void PackFeedback(uint8_t* out, uint32_t out_cap, uint32_t* inout_len) = 0;
    virtual uint32_t SnapshotForCrash(uint8_t* out, uint32_t out_cap) const { return 0; }
    virtual size_t BufferBytes() const { return 0; }
    virtual const char* Name() const = 0;
};
```

| 方法 | 调用时机 | 必须 | 不能 |
|---|---|---|---|
| `Init()` | child fork 后,sandbox 前。child 主线程。 | open fd / 必要预 mmap 在这里完成；若 sink 支持 lazy mmap(如 threaded KCOV delayed slots),`BufferBytes()` 必须预留最坏情况 VA | 假设别的 sink 已 Init |
| `OnEvent(kTaskStart \| kSessionEnd)` | child 主线程(serial) 或 driver 主路径 | 控制 sink-internal state,可以分配 | — |
| `OnEvent(kActionBefore \| kActionAfter)` | (R2 未启用,driver 内部直接调全局函数;启用后会从 worker thread 调) | thread-safe + lock-free | 分配 / 取锁 |
| `PackFeedback` | child 主线程,task 完成后 | 写 sink-specific feedback 帧到 out + offset | 假设 KCOV 在 threaded mode 收集了数据(它没有) |
| `SnapshotForCrash` | **async-signal-safe context**,child crash signal handler | 直接 write to out;atomic load 读 sink state | malloc/free/mutex/stdio/std::vector |
| `BufferBytes()` | sandbox sizing 计算,child 主线程 | 返 sink 在 child VA 的最坏情况 mmap 字节数,用于 RLIMIT_AS | — |

**重要**:`SnapshotForCrash` 的 async-signal-safe 是硬约束。`KcovSink::SnapshotForCrash` 是模板:它直接调 `KcovCollector::SnapshotFeedback`,后者只 read mmap area + memcpy + 一次 atomic header write。

### 5.5 IObservationBus

```cpp
class IObservationBus {
public:
    virtual void AddSink(std::unique_ptr<IObservationSink> sink) = 0;
    virtual bool InitAll() = 0;
    virtual void Publish(ObservationEvent ev, const ObservationContext& ctx) = 0;
    virtual void PackAllFeedback(uint8_t* out, uint32_t out_cap, uint32_t* inout_len) = 0;
    virtual uint32_t SnapshotAllForCrash(uint8_t* out, uint32_t out_cap) const = 0;
    virtual size_t TotalBufferBytes() const = 0;
    virtual size_t SinkCount() const = 0;
};
```

**契约**:
- 默认实现 `ObservationBus` 是 lock-free `vector<unique_ptr<sink>>`;sink 顺序 = 添加顺序。
- AddSink 必须在 InitAll 前;**唯一例外**是 `IvshmemStepEventSink` — 需要 `adapter.Init()` 之后才有 ring 指针,所以 RunWorkerProfile 在 adapter.Init 后 fork 前 AddSink。这是当前唯一 late-add 模式。
- 加新 sink **不需要改** Bus / Engine / ChildMain — 改 profile factory。

### 5.6 Adapter Facets

文件边界：`worker/adapter/worker_task_channel.hpp`、
`worker/engine/execution_domain_registry.hpp`、`worker/adapter/worker_registrar.hpp`；
`worker/adapter/worker_adapter.hpp` 只定义 transport composition root。

`IWorkerAdapter` 拥有 transport 初始化、mapping 和 cleanup，并通过
`TaskChannel() / DomainRegistry() / Registrar()` 显式暴露 facet。它不继承
任一 facet，因此不能再把 proc registry、corpus gate 或 task lifecycle
隐式传给 engine。具体 adapter 组合实现这些 facet，engine 只依赖窄接口：

| Facet | 职责 |
|---|---|
| `IWorkerTaskChannel` | `WaitTask / ReportDone / Cancel / output state / transport lifecycle` |
| `IExecutionDomainRegistry` | worker/proc identity、corpus gate |
| `IWorkerRegistrar` | 延迟发布 worker-ready(snapshot 使用) |

**契约**:
- `WaitTask(timeout)`:阻塞 ≤ timeout,无 task 返 nullopt。返 task 时其 buf 由 transport 保活到下一次 WaitTask 之前。
- `ReportDone(result)`:在主线程或 engine 主循环调;**不可在 child 进程调**(child 不持有 transport 状态)。
- task output/crash length 属于 `IWorkerTaskChannel`；execution-domain backing/mapping 仅由 profile runner 从 composition root 读取并固化到 `EngineConfig`。step ring 等 substrate-specific typed 操作放对应 `IXxxTransport` 子接口(当前是 `IvshmemTransport`)。host 加新 substrate 时:
  - 新 substrate 的 substrate-specific 方法放到新 `I<New>Transport : IWorkerAdapter`。
  - 不要塞回 `IWorkerAdapter` — 那会把所有 worker adapter 都污染。

### 5.7 IvshmemTransport — `worker/transport/ivshmem_transport.hpp`

```cpp
class IvshmemTransport : public IWorkerAdapter {
public:
    virtual WorkerDataWindowV3* GetWorkerDataWindow() = 0;
    virtual StepEventRingHeader* GetStepEventHeader() const = 0;
    virtual StepEventSlot* GetStepEventSlots() const = 0;
    virtual uint32_t GetStepEventCapacity() const = 0;
};
```

**定位**:**当前 host substrate (ivshmem) 在 worker-side 的 substrate-specific 接口**。R4 引入。

**契约**:
- 仅在 host substrate=ivshmem 时由 `IvshmemWorkerAdapter` 实现。host 加新 substrate 时新建 `I<New>Transport : IWorkerAdapter`,**不要**让 `IvshmemTransport` 兼任。
- `IvshmemWorkerAdapter` 另行组合实现 task-channel、domain-registry 和 registrar facet；`IvshmemTransport` 本身不承载这些职责。
- profile runner 在 adapter init 后通过 `AsIvshmem()` 取 step ring；DomainSupervisor 不持有该 typed 接口。
- execution-domain backing 和 task buffer geometry 通过 `IWorkerAdapter` 的通用合同提供。

### 5.8 DomainSupervisor(G) 与 ExecutionEngine facade

`DomainSupervisor` 持有 task-channel facet、domain-registry facet、显式 `DomainComponentBinding`、
topology 和 `EngineConfig`。binding 只能是 `InheritedDomainComponents` 或
`ExecRebuiltDomainComponents`，不存在 backend/bus nullable 组合。
`ExecutionEngine` 只保留构造兼容层、`Run()` 转发和 `ChildExecuteTask` helper。

**不变量**:
- phase deadline、stop escalation、startup retry、completion 和 periodic recycle 只在 supervisor。
- topology `Collect()` 不 stop/respawn；`Stop(plan)` 不决定 daemon 退出。
- daemon 侧唯一机械回收链是 `StopDomainHandle(handle, absolute_deadline, plan)`。
  `NsRunnerSupervisor`、`ExecNsRunnerSupervisor` 和 established topology
  共享同一 `DomainHandle`/实现，不得各自维护 SIGKILL/wait/reap 链。
- startup partial cleanup 若在 deadline 内失败，handle ownership 转交 topology，
  再由外层 `Recover(kStartupCleanup)` 处理；局部 supervisor 不得遗失或重开隐式 deadline。
- task channel 不写 daemon 运行标志，只通过 `LifecycleState()` 报告 transport 状态。
- supervisor 不 include backend family 实现；pseudo/mount 诊断停留在 pseudo/loop 模块。
- domain fault 只能走 `Recover(reason)`；正常 task completion 清零连续 recovery 预算。
- host cancel 会替换被中断的 domain，但不计入 domain health streak。

**实践建议**:
- kernel-syz 继续复用当前 DomainSupervisor。
- 不能套该 domain 模型的 family 写独立 supervisor strategy；不要修改 topology 或 adapter 来决定退出。

---

## 6. 生命周期与线程模型

### 6.1 进程拓扑

```
ivshmem_worker (main 进程, root, 永远不进 sandbox)
├── heartbeat_thread (IvshmemWorkerAdapter 启动,持续写 heartbeat)
└── child 进程 (per worker_id, 一次性 fork, 跑实际任务)
    ├── child main thread (ChildMain 主循环, serial mode 下直接 dispatch)
    └── (threaded mode 时) syz_execute_threaded spawn 的 worker threads
```

> 二进制名 `ivshmem_worker` 是历史名,不代表非 ivshmem substrate 不能用。R5 之后 main 已经 family/substrate-agnostic — host 加新 substrate 时把 main 里的 adapter 选择改成按 substrate 派发即可。

**关键不变量**:
- main 进程永远 root。adapter.Init/Handshake/Register 等需要 root(当前 substrate=ivshmem 时打开 PCI driver fd)。
- child 进程根据 sandbox_mode 可能 setuid / unshare ns / 限制 fd / 限制 RLIMIT_AS。**不可逆**。
- heartbeat thread 在 main 进程,fork 之前启动 — child 不继承 thread 但继承 heartbeat 共享内存。
- 一个 worker_id 同时只对应一个 execution domain；crash / timeout / cancel 后统一 `Recover(reason)`。

### 6.2 ChildMain 的强顺序约束

**这个顺序是硬约束 — 别动**。

```
1. install crash handler           ← g_engine_bus / g_engine_child_area / g_engine_child_completion 必须先赋值
2. bus.InitAll()                   ← KcovSink 打开 /dev/kcov; IvshmemStepEventSink 设全局 ring
                                     [LOG 触发 WorkerLogFd() static lazy init: ttyS0 在 root 下 open 持有]
3. PreallocateSyzExecScratch()     ← 16 MiB scratch mmap(linux/amd64),必须在 sandbox 之前
4. ApplySandbox(mode, sizing)      ← RLIMIT_AS = substrate-bytes + bus.TotalBufferBytes() + scratch_bytes
5. while(true) read ready_pipe → ChildExecuteTask → write done_pipe
```

**为什么不能动**:
- Step 1 之前的 fatal signal 让 crash handler 看到空指针 — _exit(128+sig) 但 snapshot 不到 feedback。
- Step 2 之后才能 LOG;LOG 在 sandbox 之前 lazy-open ttyS0,持有 fd 跨 setuid。
- Step 3 之后才能保证 scratch mmap 不被 sandbox 限额 reject。
- Step 4 必须最后:之后所有 mmap/fd open 失败概率大幅升高。

**新 sink 的 Init 里要 mmap / open fd?** → 必须在 step 2 完成,不要拖到 step 5 task 处理时才做。

### 6.3 Crash signal handler — async-signal-safe

```cpp
void engine_child_crash_handler(int sig) {
    if (g_engine_bus && g_engine_child_area && g_engine_child_completion) {
        const uint32_t crash_out_len = g_engine_bus->SnapshotAllForCrash(
            g_engine_child_area->output_pool, MAX_OUTPUT_SIZE);
        g_engine_child_completion->output_len = crash_out_len;
    }
    /* log signal (async-signal-safe write only) */
    _exit(128 + sig);
}
```

**新 sink 实现 SnapshotForCrash 时**:

| 允许 | 禁止 |
|---|---|
| atomic load 读 sink state | malloc / free |
| memcpy 到 out | std::vector 任何方法 |
| 简单算术、位运算 | pthread_mutex_lock |
| `read(2)` 已打开的 fd | printf / fprintf / iostream |
| 已 mmap 区域读取 | new / delete |

完整 async-signal-safe 函数清单见 `man 7 signal-safety`。

### 6.4 Threaded mode

`syz_execute_threaded`(SyzExecCall 数组,无 SYZ_ARG_RESULT 依赖,> 1 calls):
- 主 thread 预解析 + 创建 N worker threads;所有 threads spin on barrier;主 thread 释放 barrier;所有 threads 同时调 `dispatcher.Dispatch(...)`(本地 PseudoRuntimeContext);主 thread join 全部 threads。

worker threads 期间:
- KCOV 不可用(per-thread 限制) — `KcovSink` 在 kTaskStart 看到 mode=threaded 自动跳过 Begin。
- step event ring 写入是 lock-free atomic — `IvshmemStepEventSink` 全局函数被 worker thread 直接调,安全。
- pseudo handler 不应持 worker-process 全局可变状态。

**新 driver 支持 threaded 时**:
- `IDispatcher.Dispatch` 必须 thread-safe。
- driver 自有的 scratch / output buffer 必须 per-thread。
- 新 sink OnEvent(kAction*) 必须 lock-free。

### 6.5 Scratch buffer 固定 VA 布局(FIXED_SCRATCH_LAYOUT)

worker 在 loop_child 起来后 `PreallocateSyzExecScratch()`(§6.2 step 3)分配 16 MiB
scratch buffer。program 文本里的"逻辑地址"(如 `&(0x7f0000000000)`)在 wire
decode 时被翻译成 scratch_base + offset,然后 `mmap(MAP_FIXED, ...)` 真 syscall
落在那里 — 这块布局**直接决定** mmap return value 跟 KCOV 走的 vma 路径。

**两种 layout(`syz_exec_runner.cpp::UseFixedScratchLayout()` 决策)**:

| Layout | scratch_base | 适用场景 |
|---|---|---|
| **Fixed** (default) | `kSyzExecDataOffset = 0x200000000000` + 两侧 guard page | production fuzz / L3 paired oracle / repro |
| Non-fixed | libc 给 (ASLR'd,例如 `0x7Fxxxxxxx000`) | user-side ASAN 套 worker 等冲突场景 |

**为什么 default fixed**(跟 syzkaller executor 同款):
1. **KCOV 稳定**:kernel 处理 syscall 时常 walk `find_vma()` / `vm_area_struct` 链。
   VA 漂 → 不同 rb-tree 节点 → KCOV PC trace 漂。固定 VA → 跨次 run / 跨 worker /
   跨 VM 的 KCOV byte-equal,coverage feedback 不会因"VA 漂了"误判新覆盖。
2. **Crash repro 可比**:KASAN / UBSAN oops 信息打 user 端 VA。固定 VA 让 manager
   端跨 VM dedupe / 跨次 run match 同一个 bug。Repro 路径(payload 喂回 worker)
   再走同样 VA 就能稳定复现。
3. **L3 paired oracle parity**:跟 syzkaller executor 的 mmap return value byte-equal,
   `scripts/layer3_paired_oracle.sh` 的 ret_mismatch / kcov Jaccard 干净可信。

**关键不变量**:
- `kSyzExecDataOffset = 35184372088832ULL = 0x200000000000` 跟 syzkaller upstream
  `linux/amd64.txt` `data_offset` 同步,改一边必须改另一边
  (`program/src/syz/generated/target_linux_amd64_main.gen.cpp:55` 跟
  `executor/.../syz_exec_runner.hpp:28` 互校,Target::finalize 时也有 numeric
  contract 校验)。
- 两侧 4KiB guard page (PROT_NONE) 防越界 — 跨 guard page 触发 SIGSEGV,
  worker crash handler 截到当 OOB bug 上报。
- `MAP_FIXED_NOREPLACE` 失败(地址已被库 / vdso 占)→ AcquireScratch 返 nullptr,
  worker child _exit(2),daemon 看到 harness_fail 重 fork。Production 不该见
  这条 — 该 VA 在 amd64 上不被 glibc 默认 mmap 用。

**显式关 layout**(罕见 — ASAN debug):
```bash
export REFUZZ_FIXED_SCRATCH_LAYOUT=0
# 任何 "0" 之外的值 / unset → fixed (default-on)
```

**跟 §6.2 顺序的关系**:scratch 必须在 sandbox(step 4)之前 mmap,因为 sandbox
设的 RLIMIT_AS 把 16 MiB 算进 child 总额度;sandbox 之后再 mmap 会撞 limit。
固定/非固定 layout 都遵守此约束 — `PreallocateSyzExecScratch()` 站 step 3 不动。

---

## 7. 反模式 / 常见错误

### 7.1 不要在 OnEvent 里分配
未来 per-call 事件(kActionBefore / kActionAfter)启用后从 worker thread 调。

| ❌ | ✅ |
|---|---|
| `vec.push_back(x);` | `atomic counter fetch_add(1);` |
| `str.append(s);` | 写 ring slot(lock-free fetch_add slot index) |
| `new Foo;` | 预分配 buffer + `idx = atomic++` |

### 7.2 不要把 family-specific concept 塞回通用接口

❌ `class IObservationBus { void OnSyscallReturn(int retval, int err); };` — kernel-specific!

✅ 通用 `Publish(ObservationEvent, ObservationContext)` 加 family-agnostic 字段;family-specific state 通过 sink 自身 + driver 内部传递,不上接口。

### 7.3 不要把 ivshmem typed view 泄漏进 supervisor/runtime

ivshmem 是 host 当前 substrate 的实现细节。DomainSupervisor 只能通过
`IWorkerTaskChannel` 和 `IExecutionDomainRegistry` 工作；step ring typed view 只由
IvshmemTransport / IvshmemWorkerAdapter / IvshmemStepEventSink 使用。

新加 transport-agnostic 模块**不要**破坏这个边界 — 否则 host 加新 substrate 时受影响面失控。

### 7.4 不要直接调 `SetStepEventWriter`(全局函数)

R3 起,该全局只应该在 `IvshmemStepEventSink::Init()` 调一次。其他地方调 = bug 风险。新 substrate 且需 step ring → 实现一个新 `<NewSubstrate>StepEventSink` 替代 IvshmemStepEventSink。

### 7.5 `SyscallExecBackend` 是 ROLLBACK 入口,默认路径不要走它

R1 注释里 `SyscallExecBackend::Execute` 的 v2 实现仍功能完整(内部构造 SyscallOrPseudoDispatcher),但 `MakeKernelSyzProfile` 默认装 `KernelChildDriver` / `KernelWireDriver`。SyscallExecBackend 留作 v1 ROLLBACK + 旧测试链接;**不要在新代码里 instantiate**。

### 7.6 不要在 profile factory 里调 adapter.Init

factory 只装配 unique_ptr,**不调 Init/Handshake/Register**。统一由 `RunWorkerProfile` 驱动。原因:`IvshmemStepEventSink` 需要 adapter.Init 之后才能挂(late add),只有 RunWorkerProfile 知道完整 init 顺序。

### 7.7 不要新加 child 进程全局变量

新 sink 之间通信 → 通过 Bus(Publish + Context)。新 driver 内部状态 → driver 类成员。crash handler 数据 → 复用 `g_engine_bus / g_engine_child_area / g_engine_child_completion`。

### 7.8 不要为新 family 写新 A 轴 adapter

A 轴跟 host substrate 配对,不是 family 决策。host 当前只有 ivshmem substrate,所有 family 都用 `IvshmemWorkerAdapter`。host 加新 substrate 时统一换。**反过来:不要为某个 family 单独写 substrate adapter** — 那是错位。

### 7.9 不要把 sandbox 顺序约束打散

§6.2 列的 5 步顺序是硬约束。如果你新 sink 看起来"得在 sandbox 之后才能 init",停下来 — 大概率是设计问题。重新审:这个 sink 在 sandbox 之后真的还能 mmap 出空间吗?如果不能,改成在 sandbox 之前 mmap 好。

---

## 8. ROLLBACK 路径

每处改动都按 `[v1 ... — ROLLBACK: uncomment below, remove v2 below]` + `[v2 — 当前版本]` 成对注释保留。单 R 步反向回退:

| R | 回退步骤 |
|---|---|
| **R5** | 删 `include/worker/profile/`、`src/profile/`,CMake 删 `kernel_syz_profile.cpp` 一行;`ivshmem_worker_main.cpp` 把 v2 大块删掉,uncomment v1 大块;删 `--profile=` / `--driver=` flag 解析 |
| **R4** | 删 `include/worker/transport/`,把 `IvshmemWorkerAdapter` 继承改回 `IWorkerAdapter`;`worker_adapter.hpp` uncomment 三个 substrate-specific 方法;ivshmem_adapter.cpp uncomment 旧 `GetSharedArea()`,删 `GetWorkerArea`;Engine 把 `ivs_transport_` 字段和 dynamic_cast 删,改回 `adapter_.GetSharedArea/GetCrashOutputLen/ResetOutputLen` |
| **R3** | EngineConfig uncomment `step_event_*` 三字段;ChildMain 入参恢复 `step_hdr/slots/capacity`;ChildMain 内 step writer fallback 块 uncomment;`Engine::ForkChild → ChildMain` 调用恢复 v1.5 形式;main 里 `engine_cfg.step_event_*` 透传那段 uncomment |
| **R2** | observation_bus 相关 include 删;Engine ctor / 字段从 `bus_` 改回 `coverage_`;ChildMain / ChildExecuteTask 入参从 `bus` 改回 `coverage`;crash handler 全局 `g_engine_bus` 改回 `g_engine_coverage`;main 里 ObservationBus / sink 块删,unique_ptr<ICoverageCollector> 块 uncomment;CMake 删 observation/{observation_bus,kcov_sink,ivshmem_step_event_sink}.cpp 三行 |
| **R1** | main 里 `KernelChildDriver` 构造 v2 改回 `SyscallExecBackend backend;` v1;CMake 删 codec / dispatcher / driver 三个 .cpp;syz_exec_runner 函数签名 uncomment v1(无 IDispatcher),删 v2;dispatch 调用点 uncomment `ExecuteNrOrPseudo`,删 `dispatcher.Dispatch`;ThreadCallCtx 删 `dispatcher` 字段;syscall_backend.cpp uncomment 整个 anonymous-ns `execute_program` 和 v1 `SyscallExecBackend::Execute`,删 v2 |

每步独立可回退;按 R5→R1 反向 = 完全回到改造前。R 步之间互不依赖逆序。

> Layer-2 引入的 `KernelWireDriver` / `WireCodec` / `kSyzExecWire` 是 R5 之后的进展,不属于 R1-R5 ROLLBACK 范围。回退它们 = 在 profile factory 里把 `args.driver_kind == kWire` 分支删掉,把 wire_codec / kernel_wire_driver 文件移除。

---

## 9. 未来工作(TODO)

| 项 | 优先级 | 触发条件 | 说明 |
|---|---|---|---|
| **通用 `ISupervisor` strategy** | medium | AFL/Daemon family 着陆 | kernel 的 concrete `DomainSupervisor` 已落地；出现第二种真实生命周期后再抽公共 strategy 接口 |
| **`ICrashDetector` 独立接口** | medium | compiler/PyTorch family 着陆 | crash 判定散在 Engine.Run + child crash handler;新 family(ICE / numerical diff)着陆需显式抽象 |
| **`IExecBackend` 重命名 → `IDriver`** | low | 命名 sweep 时 | 概念上已是 driver,R5 没改名(避免一次大改) |
| **Per-call ObservationBus 事件下沉** | low | 多 family 都需 per-call hook 时 | `kActionBefore/After` 目前未启用 — driver 内部直接调 step_event_writer 全局 |
| **`IDispatcher` 解 `PseudoRuntimeContext` 耦合** | low | 非 kernel 但需 per-action dispatch 的 family(SQL / TensorOp)着陆 | R1 妥协;让 ctx 变 opaque void* 或按 family 分裂子接口 |
| **`ProgramView` 多态化** | medium | C 轴 family-specific decoded shape 显著差异 | 当前 ProgramView 三种 kind(syz v1 / v2 / wire);扩到一定数量后改 `std::variant` 或 `unique_ptr<IDecodedProgram>` |
| **Profile 静态注册表** | low | profile 数 ≥ 5 时 | main 里 if/else 太长改成静态注册表 + `--list-profiles` |

---

## 10. 文件层级速查

> CMake 拓扑:`refuzz_worker_core` STATIC 库(B-G 六轴 + pseudo + profile factory)
> + `ivshmem_worker` thin exec(main + ivshmem attach + IvshmemWorkerAdapter)。
> 详见 §1.2;新 substrate 加 thin exec target 即可,不动 core 库。

```
executor/channel/worker/
├── ARCHITECTURE.md                              ← 本文件
├── CMakeLists.txt                               ← refuzz_worker_core (STATIC) + ivshmem_worker (thin EXE)
├── include/
│   ├── refuzz/channel/worker/mode.hpp
│   └── worker/
│       ├── adapter/
│       │   ├── worker_task_channel.hpp          ← task/result/cancel/lifecycle facet
│       │   ├── worker_registrar.hpp             ← worker-ready publication facet
│       │   ├── worker_adapter.hpp               ← transport owner + facet accessors
│       │   └── ivshmem_adapter.hpp              ← IvshmemWorkerAdapter (impl IvshmemTransport)
│       ├── engine/
│       │   ├── domain_supervisor.hpp            ← daemon 状态机 + Recover/deadline/recycle
│       │   ├── execution_domain_registry.hpp    ← owner/proc/corpus-gate facet
│       │   └── execution_engine.hpp             ← facade + ChildExecuteTask
│       ├── topology/
│       │   ├── domain_handle.hpp                ← 唯一 StopDomainHandle + absolute deadline 合同
│       │   ├── ns_runner.hpp                    ← startup owner / detach
│       │   └── process_topology.hpp             ← topology strategy + stop plan
│       ├── transport/
│       │   └── ivshmem_transport.hpp            ← IvshmemTransport (R4: 当前 substrate 的 worker-side 子接口)
│       ├── backend/
│       │   ├── exec_backend.hpp                 ← IExecBackend (Driver interface, 概念上=IDriver)
│       │   ├── syscall_backend.hpp              ← SyscallExecBackend (R1 ROLLBACK 入口)
│       │   ├── syz_exec_runner.hpp              ← syz_execute / execute_program (with IDispatcher&)
│       │   └── pseudo/...                       ← pseudo handler 表(file/fs/net/usb/kvm/...)
│       ├── codec/codec.hpp                      ← ICodec / SyzExecCodec (R1) + ProgramView::kSyzExecWire (Layer-2)
│       ├── codec/wire_codec.hpp                 ← WireCodec (Layer-2,跑 syzkaller-equivalent exec wire)
│       ├── dispatcher/
│       │   ├── dispatcher.hpp                   ← IDispatcher (R1)
│       │   └── syscall_or_pseudo.hpp            ← SyscallOrPseudoDispatcher (R1)
│       ├── driver/
│       │   ├── kernel_child_driver.hpp          ← KernelChildDriver (R1, syz_exec wire v1/v2)
│       │   └── kernel_wire_driver.hpp           ← KernelWireDriver (Layer-2, wire kind)
│       ├── observation/
│       │   ├── observation_bus.hpp              ← IObservationBus / IObservationSink (R2)
│       │   ├── kcov_sink.hpp                    ← KcovSink (R2)
│       │   ├── ivshmem_step_event_sink.hpp      ← IvshmemStepEventSink (R2)
│       │   └── step_event_writer.hpp            ← child 进程内全局 ring 写入(R3 起仅 sink 调)
│       ├── coverage/
│       │   ├── coverage_collector.hpp           ← ICoverageCollector (R2 起包在 KcovSink 内部)
│       │   └── kcov_collector.hpp               ← KcovCollector (KcovSink 内部使用)
│       ├── profile/
│       │   ├── execution_components.hpp          ← daemon-owned/exec-rebuilt 显式 variant
│       │   └── worker_profile.hpp                ← WorkerProfile + KernelSyzArgs + factory + runner
│       ├── exec_mode.hpp                        ← ExecMode { intra=Serial|Threaded, shape=... }
│       ├── sandbox.hpp                          ← ApplySandbox / ProbeSandboxMode / SandboxSizing
│       └── log/log_macros.hpp                   ← WorkerLog / WorkerCrashLogSignalAsyncSafe
└── src/                                         ← 各 .hpp 对应 .cpp
    │
    │  ── thin EXE 'ivshmem_worker' 持有的源 (substrate=ivshmem 时) ──
    ├── ivshmem_worker_main.cpp                  ← main: args parse → factory → RunWorkerProfile (R5);--profile / --driver flag
    ├── ivshmem_attach.cpp                       ← ivshmem PCI 发现 + mmap helper
    ├── adapter/ivshmem_adapter.cpp              ← IvshmemWorkerAdapter (impl IvshmemTransport)
    │
    │  ── STATIC lib 'refuzz_worker_core' 持有的源 (B-G 六轴, substrate-agnostic) ──
    ├── backend/{syscall_backend,syz_exec_runner}.cpp
    ├── backend/pseudo/{pseudo_*,pseudo_dispatcher,pseudo_runtime}.cpp
    ├── codec/{syz_exec_codec,wire_codec}.cpp
    ├── coverage/kcov_collector.cpp
    ├── dispatcher/syscall_or_pseudo.cpp
    ├── driver/{kernel_child_driver,kernel_wire_driver}.cpp
    ├── engine/execution_engine.cpp
    ├── observation/{observation_bus,kcov_sink,ivshmem_step_event_sink,step_event_writer}.cpp
    ├── profile/kernel_syz_profile.cpp
    └── sandbox.cpp
```

---

## 附录 A. 七轴选择 cheat-sheet

填这张表 → 知道每个轴该选已有还是新写:

| 轴 | family-specific 问题 | 选择 |
|---|---|---|
| **A. Adapter** | "host 当前 substrate 是什么?" | 跟 host channel 当前 substrate 配对(当前唯一:`IvshmemWorkerAdapter`)。**不归 family 决策**。host 加新 substrate 时所有 profile factory 同步换 adapter 选择。 |
| **B. Driver** | "怎么把 input bytes 跑出 result + 状态?" | 几乎必新写。看现有 `KernelChildDriver`(syz_exec)和 `KernelWireDriver`(wire)的形状。 |
| **C. Codec** | "input bytes 的格式是什么?" | 几乎必新写。看 `SyzExecCodec` / `WireCodec`。扩 `ProgramView::Kind` enum + 加对应字段。 |
| **D. Dispatcher** | "driver 内部是 for-each-action 还是一次性 exec?" | 一次性 → 不需要;for-each 且 action 像 syscall(数字 nr + intptr_t args) → 复用 `SyscallOrPseudoDispatcher` 风格;for-each 且 action 不是 syscall → 写新 dispatcher,**不要**强行套现有 `IDispatcher`。 |
| **E. Sinks** | "要采集什么 feedback?" | coverage:KcovSink(kernel) / LibfuzzerCovSink(userspace,新写) / AflBitmapSink(AFL,新写)。exit code:ExitCodeSink(新写)。crash log:AsanReportSink / IceParserSink / CoreDumpSink(新写)。stderr:StepEventSink / StderrCaptureSink(新写)。数值差分:NumericDiffSink(新写)。 |
| **F. Detector** | "怎么知道出问题?" | kernel panic via ProgramRuntime/crash handler；exit code:ExitOrAsanDetector(等 ICrashDetector 接口落地,§9 TODO);ICE / 数值发散:专用 detector,driver 内部判定后通过 ObservationBus 报告。 |
| **G. Supervisor** | "child 生命周期怎么管?" | kernel-syz 复用 `DomainSupervisor`;fork-server/long-running/in-process family 各自实现 strategy，但不得让 engine/topology/adapter 决定 daemon 退出。 |

填完表 → 进 §4 playbook 的 Step 2-5。
