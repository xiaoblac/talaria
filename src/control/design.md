# Control 组件设计

## 1. 文档目的

`control/` 是 reFuzz 的控制平面组件。它负责把“用户配置/命令行意图”转换成“可运行的 fuzzing 会话”，并管理这次会话从构建、启动、运行、观测到停止的完整生命周期。

本文以 `control/` 目录下的当前源码为准，重点说明：

- 这个组件为什么存在；
- 它和 `mutator`、`feedback`、`corpus`、`channel`、`crash`、`telemetry` 的边界；
- 当前代码中的分层、关键数据结构、启动/停止路径和扩展点；
- 运行时必须满足的生命周期与所有权约束。

## 2. 设计目标

### 2.1 核心目标

1. 把配置解析、默认值决议、组件装配、运行时编排拆成清晰阶段。
2. 让“选哪个实现”和“怎么把它们接起来”通过 `profile + catalog` 建模，而不是把选择逻辑散落在 `Orchestrator` 里。
3. 让运行态只保留必要的协调逻辑：线程管理、服务生命周期、主循环驱动、观测、持久化、crash/repro 串联。
4. 保持扩展路径稳定：新增 profile、catalog 条目、feedback spec、channel backend 时，尽量只修改对应层。

### 2.2 非目标

`control/` 不实现下列领域本身的算法或数据面：

- 变异算法：由 `mutator/` 提供；
- 调度策略：由 `scheduler/` 提供；
- 覆盖率信号、聚合与反馈：由 `feedback/` 提供；
- 种子存储与入库：由 `corpus/` 提供；
- VM / worker / 传输数据面：由 `channel/`、`executor/` 提供；
- crash 分析、诊断、复现：由 `crash/` 提供；
- 指标采集、投影、仪表盘：由 `telemetry/` 提供。

`control/` 的职责是把这些能力接起来，并定义它们的调用顺序、生命周期和边界条件。

## 3. 总体架构

### 3.1 分层视图

当前 `control/` 采用“前半段决议 + 后半段编排”的结构：

```text
JSON / CLI
   │
   ▼
startup + config_parser
   │   产出 LaunchPlan + OrchestratorConfig + optional ad-hoc feedback spec
   ▼
resolver
   │   产出 ResolvedPlan
   ▼
assembler
   │   产出 AssembledBundle
   ▼
orchestrator
   │   构建运行时对象图并管理服务生命周期
   ▼
FuzzerLoop
   │   持续生成 task、消费 event、驱动 feedback / corpus / crash
   ▼
telemetry / crash / persistence
```

### 3.2 目录职责

| 子目录 | 角色 | 主要输入 | 主要输出 |
|---|---|---|---|
| `config_parser/` | JSON 到 `OrchestratorConfig` 的底层解析 | JSON object | `OrchestratorConfig` |
| `startup/` | 启动前端，合并 JSON 与 CLI | 配置文件 + flag | `LaunchPlan` + `FeedbackEngineSpec` |
| `profile/` | target 级默认值和 target-specific 规则 | profile 名字 | `ProfileDefaults` |
| `resolver/` | 把用户意图决议成可装配计划 | `LaunchPlan` + `ProfileRegistry` + `CatalogSet` | `ResolvedPlan` |
| `assembler/` | 根据决议结果构建核心组件束 | `ResolvedPlan` + catalogs + context | `AssembledBundle` |
| `orchestrator/` | 运行态装配、服务注册、线程与生命周期管理 | `LaunchPlan`/`ResolvedPlan`/`AssembledBundle` | 运行中的 fuzzing 会话 |
| `include/refuzz/control/` + `src/loop/` | 主循环与策略控制接口 | queue、engine handle、corpus | task/event 驱动 |

## 4. 关键抽象

### 4.1 `OrchestratorConfig`

`OrchestratorConfig` 是运行态配置对象，包含：

- target 模式：`execution_mode`、`coverage_mode`、`sanitizer_mode`；
- 目录布局：`work_dir`、`state_dir`、`SessionLayout`；
- channel 两段式配置：
  - `channel_common`：中性配置；
  - `channel_backend`：后端专属 profile，多态 `unique_ptr`；
  - `channel_backend_id`：catalog 里的选择键；
- executor / fuzzer / policy engine / observability / dashboard / logging 配置；
- coverage、corpus、repro 的持久化路径和开关；
- 运行上限：`runtime`、`total_tasks`、`run_limit_mode`。

设计要点：

1. 该对象是 move-only；`channel_backend` 使用 `unique_ptr` 保存后端专属配置。
2. 它描述的是“怎么运行”，不是“选哪个组件实现”；组件选择由 `LaunchPlan` 承载。
3. `SessionLayout` 只负责瞬态目录，跨 run 的持久目录统一挂在 `state_dir` 下。

### 4.2 `LaunchPlan`

`LaunchPlan` 是用户意图的归一化表示，包含：

- profile 名称；
- 各组件选择字段：`mutator_engine`、`scheduler_engine`、`corpus_store`、`corpus_admission`、`feedback_engine`、`channel_backend_id`、`target_toolkit`；
- 一个完整的 `OrchestratorConfig`。

约定：

- 选择字段为空串表示“使用 profile 默认值”；
- `startup` 负责把 JSON/CLI 映射到 `LaunchPlan`；
- `resolver` 负责把空串填成确定值并校验其在 catalog 中存在。

### 4.3 `ProfileDefaults`

`ProfileDefaults` 不再承担工厂角色，而是表达 target 级组合策略：

- `defaults`：该 profile 下推荐的组件 id；
- `configure`：对 `OrchestratorConfig` 注入 target-specific 配置；
- `validate`：在进入装配前做 target-specific 校验；
- `derive_repro_channel_cfg`：派生 repro VM 的 channel 配置和后端 profile。

这让 profile 的职责收敛为“如何组合系统”，而不是“直接生产系统对象”。

### 4.4 `CatalogSet` / `BuiltinCatalogBundle`

- `CatalogSet` 是 9 个领域 catalog 的只读视图；
- `BuiltinCatalogBundle` 是其拥有者聚合，并提供 `RegisterBuiltins()` 和 `View()`。

Resolver 和 Assembler 只依赖 `CatalogSet`，因此不关心 catalog 实例由谁创建，也不依赖静态注册副作用。

### 4.5 `ResolvedPlan`

`ResolvedPlan` 是 Resolver 的输出，语义上保证：

1. 所有组件选择字段都已决议；
2. 所有 id 都已在对应 catalog 中验证存在；
3. `config` 已经过 profile 的 `configure` 与 `validate`；
4. ad-hoc feedback engine（如果存在）已通过内部校验。

`Assembler` 只接受 `ResolvedPlan`，从类型层面阻止“未决议计划直接装配”。

### 4.6 `AssembleContext`

`AssembleContext` 是装配期依赖注入点，用来传入：

- `profile_registry`：供 repro channel 派生查询 profile；
- `coverage_tracker`：供 feedback engine 写 coverage sink；
- `metric_registry`：供 channel metrics 绑定指标。

这些依赖的所有权不归 Assembler，但生命周期必须长于 `AssembledBundle`。

### 4.7 `AssembledBundle`

`AssembledBundle` 是运行时核心对象的所有权集合，典型成员包括：

- `corpus_store`、`feedback_store`、`seed_id_alloc`；
- `target_toolkit`；
- `mutator_manager`、`scheduler_manager`、`feedback_manager`；
- `main_channel`、`repro_channels`；
- `main_channel_metrics`、`repro_channel_metrics`。

它的声明顺序经过刻意设计，目的是让“被 manager/raw pointer 引用的对象”最后析构，避免悬空指针。

## 5. 启动路径

### 5.1 `config_parser`：JSON → `OrchestratorConfig`

`config_parser` 负责读取底层运行配置，并完成几件关键事：

1. 解析 target、executor、fuzzer、telemetry、coverage、persistence、repro 等配置段；
2. 构造当前主路径使用的 `QemuIvshmemLinuxProfile`；
3. 根据 `work_dir` / `state_dir` / retention 策略生成 `SessionLayout`；
4. 对日志、coverage、corpus、repros 的路径做默认值回填；
5. 把 worker 启动命令、超时、coverage/sanitizer 模式映射进 channel backend profile。

当前实现中，`config_parser` 已经包含少量启动期副作用：`MakeSessionLayout()` 会创建会话目录并执行 retention。

### 5.2 `startup`：JSON + CLI → `LaunchPlan`

`startup::ParseLaunchPlan()` 是正式入口前端。它会：

1. 读取 JSON；
2. 调 `ParseConfigFromJson()` 生成 `OrchestratorConfig`；
3. 从 `components` 段提取各组件选择；
4. 从 `feedback_engine_spec` 段提取可选的 ad-hoc feedback engine 定义；
5. 再用 CLI flag 覆盖 plan-level 的组件 id。

当前 CLI 只支持覆盖组件选择，不支持直接覆盖 `OrchestratorConfig` 内的细粒度 knob。

### 5.3 `resolver`：`LaunchPlan` → `ResolvedPlan`

Resolver 的算法顺序是当前架构的核心约束：

1. 按 `plan.profile` 查找 profile；
2. 用 `profile.defaults` 填充空的组件选择字段；
3. 调 `profile.configure(plan.config)` 做 target-specific 注入；
4. 调 `profile.validate(plan.config, err)` 做 target-specific 校验；
5. 检查 `CatalogSet` 是否完整；
6. 对每个组件 id 执行存在性校验；
7. 若存在 ad-hoc feedback spec，则校验 signal/aggregator/dispatcher/engine_id。

其中 ad-hoc feedback engine 的规则是：

- 它的 `engine_id` 不能和已注册命名 engine 冲突；
- `ResolvedPlan.feedback_engine` 仍会显式记录其最终生效 id；
- Assembler 之后统一从 `ResolvedPlan` 读取 active feedback engine 名称。

### 5.4 `assembler`：`ResolvedPlan` → `AssembledBundle`

Assembler 负责把“决议过的选择”装配成实际对象。构建顺序固定为：

1. `CorpusStore`；
2. `HashFeedbackStore` + `SeedIdAllocator`；
3. `TargetToolkit`；
4. `MutatorManager`（把 catalog 中所有 mutator engine 全量装入，再切 active）；
5. `SchedulerManager`（同上）；
6. `FeedbackManager`（命名 engine 或 ad-hoc spec 二选一）；
7. 主 channel；
8. repro channels（按 profile 派生）。

设计原因：

- active engine 切换统一由 manager 负责，`FuzzerLoop` 只拿 handle；
- repro channel 的派生属于 target 级策略，因此留在 `profile` 而不是 `channel`；
- Channel metrics 在装配时绑定，避免运行期再做结构性修改。

## 6. 运行时编排

### 6.1 `Orchestrator::Build()`

`Orchestrator` 是运行态的总编排器，`Build()` 负责搭建完整对象图。主要步骤如下：

1. 创建/注入 `ProfileRegistry`，并显式注册 builtin profiles；
2. 创建 `BuiltinCatalogBundle` 并注册所有 builtin catalogs；
3. 初始化 `HostLogger`；
4. 调 `Resolver::Resolve()` 产出 `ResolvedPlan`；
5. 按 coverage 模式决定是否创建 `CoverageTracker`；
6. 调 `Assembler::Assemble()` 得到 `AssembledBundle`；
7. 创建 `Executor`、task/event queue，并把主 channel/repro channel 接入观测总线；
8. 从持久化目录恢复 coverage hash、corpus seeds、crash repro seeds；
9. 若 corpus 为空，则由 `TargetToolkit::build_seed_payload` 生成初始 seed；
10. 创建 `FuzzerLoop`、`RunStateStore`、`PolicyEngine`、`ObservabilityProjector`、`TerminalDashboard`；
11. 创建 crash 相关对象：`DiagnosticStore`、diagnostic provider、analysis engine、repro queue、repro manager、repro worker；
12. 注册内置服务并执行 `ServiceRegistry::InitAll()`。

### 6.2 ServiceRegistry 拓扑

当前内置服务注册顺序为：

```text
channel service(s)
   └── executor
         └── health_monitor (可选)
               └── repro_worker (可选)
                     └── telemetry
```

其中：

- `executor` 以 borrowed service 的形式注册；
- `telemetry` 的依赖会根据 repro/health 是否存在自动选择；
- 如果出现依赖环，`Build()` 直接失败。

### 6.3 `Orchestrator::Start()`

`Start()` 的职责是让系统进入运行态：

1. 记录 `started_at` 和 `end_at`；
2. 执行 `registry.StartAll()` 启动所有服务；
3. 判断 dashboard 是否能以交互模式运行，必要时回退到周期性日志面板；
4. 启动 `fuzzer_thread`；
5. 如果 dashboard 未激活，则启动 `status_thread` 定期打印 runtime panel；
6. 如果存在 `CoverageTracker`，则启动 `coverage_thread` 定期 `Drain()` / `Persist()`。

### 6.4 `Orchestrator::WaitForCompletion()`

该接口只负责等待 `fuzzer_thread` 退出。退出条件包括：

- 用户/外部请求停止；
- executor 请求停止；
- 达到 `run_limit_mode` 指定的运行上限。

### 6.5 `Orchestrator::Stop()`

`Stop()` 执行优雅关停，流程如下：

1. 置 `stop_requested`；
2. join `fuzzer_thread`；
3. 在宽限时间内继续 drain task/event pipeline；
4. 调 `registry.StopAll()` 停掉服务；
5. 停止 `status_thread` 和 `coverage_thread`；
6. 做最后一次 coverage 持久化与 feedback store 落盘；
7. 输出 run summary 和 repro summary；
8. 关闭 repro channels 和主 channel；
9. 根据是否真正取得 progress 返回退出码：
   - `0`：至少生成了 task，且收到了 terminal event；
   - `1`：没有有效进展。

## 7. `FuzzerLoop` 设计

### 7.1 角色

`FuzzerLoop` 是热路径消费者。它不直接依赖 manager 实例，而只依赖：

- `EngineHandle<IMutatorEngine>`；
- `EngineHandle<ISchedulerEngine>`；
- `EngineHandle<IFeedbackEngine>`；
- `ICorpusStore`；
- `InMemoryTaskQueue` / `InMemoryEventQueue`。

这意味着：

- engine 切换由 manager 在外部完成；
- loop 在每次调用 `handle.Get()` 时拿到当前 active engine；
- loop 只关心“当前谁在工作”，不关心“谁负责切换”。

### 7.2 `RunOnce()` 的主要算法

一次循环主要做四件事：

1. 应用待生效的 corpus admission policy；
2. 如果 task queue 低于 `high_watermark`，则：
   - scheduler 选 seed；
   - mutator 生成 payload；
   - 生成 `proto::Task` 推入 task queue；
3. 从 event queue 弹一个事件；
4. 按事件类型分桶统计，并把事件交给 feedback engine 处理。

feedback engine 通过 `FeedbackActions` 回调与 loop 交互，包括：

- 提交新 seed 到 `CorpusInbox`；
- 标记 interesting seed；
- 通知 scheduler 反馈结果；
- 分配新的 seed id。

### 7.3 事件处理

事件被分成三类：

- `completion`：任务正常终结；
- `abnormal`：任务异常终结；
- `fault`：channel 级系统事件。

重要约束：

- `fault` 不计入 `crash_results`；
- `terminal results = completion + abnormal`，这是 run summary 中速率计算的分母；
- crash dispatch 由 feedback engine 决定是否生成，再交给 `CrashPipelineManager`。

### 7.4 策略切换

`FuzzerLoop` 实现了 `IPolicyControl`：

- `SwitchMutationPolicy()`
- `SwitchSchedulingPolicy()`
- `SwitchCorpusAdmissionPolicy()`

其中 mutation/scheduling policy 的切换通过当前 active engine 的 `SwitchPolicyByName()` 懒生效；corpus admission policy 由 `CorpusManager` 两阶段切换。

### 7.5 快照与指标

`FuzzerLoop` 维护 `FuzzerRuntimeSnapshot`，内容包括：

- `LoopStats`；
- 当前 mutation/scheduling/corpus policy 名；
- unique coverage 数等派生指标。

快照通过 `WatchBus` 发布给 telemetry，指标则通过 `MetricRegistry` 和 `PolicyStatePublisher` 对外暴露。

## 8. 观测、持久化与 crash/repro 串联

### 8.1 观测总线

运行时至少存在以下总线：

- `fuzzer_snapshot_bus`
- `executor_snapshot_bus`
- `channel_snapshot_bus`
- `channel_event_bus`

`ObservabilityProjector` 订阅这些总线，把多源状态投影到 `RunStateStore`；`TerminalDashboard` 再从 `RunStateStore` 渲染。

### 8.2 持久化模型

目录模型分成两类：

- 瞬态目录：`SessionLayout.root` 下的 `logs/`、`diagnostics/`、`vm-N/`、`repro-N/`；
- 持久目录：`state_dir` 下的 `corpus/`、`coverage/`、`repros/`。

启动时：

- 可从 `coverage_persist_path` 恢复 coverage hash；
- 可从 `corpus_persist_dir` 恢复 corpus；
- 可把诊断目录里的 crash repro 当作 seed 回灌。

停止时：

- coverage tracker 持久化到 `coverage_output_dir`；
- feedback store 持久化到 `coverage_persist_path`；
- repro worker 把成功 repro 落到 `repros_persist_dir`。

### 8.3 Crash / Repro 路径

crash 相关对象由 `TargetToolkit` 和 `Orchestrator` 共同拼装：

1. feedback engine 在事件处理中产生 `crash_dispatch`；
2. `CrashPipelineManager` 负责分析与诊断落盘；
3. 若 repro 开启，则把任务推到 `InMemoryReproQueue`；
4. `ReproWorker` 通过 dedicated repro channel 执行复现；
5. 成功 repro 被持久化保存。

`TargetToolkit` 的职责是提供与 target 绑定的一组能力：初始 seed、analysis engine、repro engine、diagnostic provider。

## 9. 生命周期与所有权约束

当前实现有几条非常重要的不变量：

### 9.1 `AssembledBundle` 必须晚于运行时消费者析构

`FuzzerLoop`、crash 子系统、部分 manager 会持有 bundle 内对象的 raw pointer。  
因此 `Orchestrator::Impl` 中必须先声明 bundle 相关成员，再声明运行时消费者，让 bundle 最后析构。

### 9.2 `MetricRegistry` 必须早于 metrics 使用者声明

`ChannelMetrics`、部分 fuzzer metrics 会缓存 registry 内部对象指针，因此 `MetricRegistry` 必须比这些缓存对象活得更久。

### 9.3 channel 在析构前必须显式关闭

`Impl::~Impl()` 和 `Stop()` 都会调用 `CloseChannels()`。原因是 channel 析构期间仍可能向 bus 发布事件；如果 bus 已经先析构，会触发悬空访问。

### 9.4 `ProfileRegistry` 默认显式注入，不依赖静态副作用

当前 `Build()` 在未注入自定义 registry 时，会创建本地 registry 并显式执行 `RegisterBuiltinProfiles()`。  
这比旧式静态初始化更可测试，也更容易在单测里注入 mock profile。

## 10. 扩展点

### 10.1 新增 profile

做法：

1. 在 `control/profile/src/profiles/` 新增 `MakeXxxProfile()`；
2. 在 `RegisterBuiltinProfiles()` 中注册；
3. 提供对应 defaults / configure / validate / derive_repro_channel_cfg。

适用场景：

- 新 target；
- 同一 target 下的新 channel/repro 组合策略；
- target-specific 配置校验。

### 10.2 新增 catalog 条目

如果只是新增某个 mutator / scheduler / feedback / corpus store / target toolkit / channel backend，实现应落在各自领域组件中；`control/` 只需要通过 builtin catalog 注册暴露出来。

### 10.3 自定义 feedback engine

当前支持两种方式：

1. 命名 engine：先注册到 `FeedbackEngineCatalog`；
2. ad-hoc engine：通过 JSON 的 `feedback_engine_spec` 临时拼出未注册 engine。

第二种方式特别适合交互式前端或实验阶段的组合式 feedback。

### 10.4 测试注入

`Orchestrator::Build()` 支持传入外部 `ProfileRegistry*`，便于单测注入 mock profile，而不必依赖全局单例。

## 11. 当前实现的已知限制

1. `config_parser` 当前主路径仍硬编码构造 `QemuIvshmemLinuxProfile`；如果要支持更多 backend，需要把 backend profile 创建逻辑进一步做成可分派结构。
2. `control/include/refuzz/control/stages/` 和 `src/concept_verify.cpp` 当前只是 concept/stub 验证，并未接入实际主循环；真实运行路径是 `FuzzerLoop`。
3. `corpus_admission` 已进入 `LaunchPlan` / `ResolvedPlan` / snapshot 语义，但初始选择尚未在 `Assembler`/`Orchestrator` 中完整落入装配路径，当前主要通过运行期策略切换生效。
4. `Assembler` 虽然整体按纯函数设计，但 channel `Build()` 过程中仍可能触发底层 backend 的实现细节 IO。

## 12. 维护建议

后续修改 `control/` 时，建议优先遵守以下原则：

1. 用户意图的新增字段，优先进入 `LaunchPlan`，再决定是否需要落到 `ResolvedPlan`；
2. “默认值/target-specific 规则”优先放 `profile`，不要重新塞回 `Orchestrator`；
3. “对象创建顺序”和“对象运行顺序”分开考虑：前者归 `Assembler`，后者归 `Orchestrator`；
4. 所有权关系优先通过 `AssembledBundle`/`Impl` 体现，不要在运行时对象间无约束地散发裸指针；
5. 若新增运行时线程，必须同时定义其启动时机、停止信号、join 点和与 `Stop()` 的交互关系。

---

如果只看一条主线，可以把 `control/` 理解为：

> `startup` 负责“读懂用户”，`resolver` 负责“做出决议”，`assembler` 负责“搭好骨架”，`orchestrator` 负责“把系统跑起来并安全停下来”，`FuzzerLoop` 负责“持续推动 fuzzing 前进”。
