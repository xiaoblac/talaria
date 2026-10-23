# Telemetry 组件设计

> **范围**:本文描述 `telemetry/` 模块**当前**(post `fuzz_phase_started_us` 落地)的事实结构与已实现功能。
> 不包含历史迁移路线 / 过期 v1 设计 / 未来扩展计划。
> 一切以源码为准,所有引用形如 `file:line`。

---

## 1. 模块定位

`telemetry/` 是 reFuzz 的**只读观测平面**。它在系统中只做两件事:

1. **收**:从 `MetricRegistry`(metric 主事实源)和 `BroadcastBus<ChannelObserveEvent>`(channel 离散事件)抽取运行态。
2. **算+发**:把抽到的样本投影成 `RuntimeSnapshot` / `RunSummary` / `RuntimeEvent`,推给 dashboard、JSON sink、coverage 文件。

**不做**:
- 不发布原始 metric(发布方在 `core/src/metrics/*` 五个 `XxxMetrics::Bind`)
- 不执行 task / 不管 channel 恢复 / 不做反馈算法 / 不存权威指标值
- 不提供网络 exporter
- 不管会话总生命周期(`control/orchestrator` 编排 `IService`)
- **唯一的执行面跨界**:`PolicyEngine` 经 `IPolicyControl` 触发策略切换(详见 §4.7)

---

## 2. 总体架构

### 2.1 数据流图

```
┌───────────────────────────────────────────────────────────┐
│ 上游(组件→registry,在 core/src/metrics/*)                  │
│   FuzzerMetrics    ExecutorMetrics    ChannelMetrics       │
│   PolicyStatePublisher                                     │
│      │                │                  │                 │
│      └──── Counter::Inc / Gauge::Set ────┘                 │
└──────────────┬─────────────────────────────────────────────┘
               ▼
        MetricRegistry  ◀── ChannelObserveEvent BroadcastBus
               │                          │
               └──────────┬───────────────┘
                          ▼
              ObservabilityProjector  (后台线程, pull 1Hz)
                ├─ DrainInputs (channel events → RuntimeEvent)
                ├─ PolicyEngine.Evaluate() (含 IPolicyControl 切换)
                ├─ CollectPrefix(fuzzer./executor./channel./perf.)
                ├─ ComputeRunSummary(samples, ...)        ── 纯函数
                ├─ store.UpdateMetricSamples(...)
                ├─ store.UpdateRunSummary(summary)        ◀ 顺序约束
                └─ store.UpdateSnapshot(RuntimeSnapshot)
                          │
                          ▼
                    RunStateStore  (中央只读视图缓存, mutex 保护)
              snapshot │ events deque(1024) │ samples │ run_summary
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
TerminalDashboard   RunStateRenderer  RunSummaryJsonSink
(后台 TTY 线程)     (无状态格式化)    (Stop 时单次写 logs/run_summary.json)

[独立路径]
ICoverageSink ─→ CoverageTracker ─→ Drain/Persist ─→ logs/coverage_hashes.{bin,txt,json}
```

### 2.2 数据视图三层

`RunStateStore` 同时持有三种粒度,对应不同消费者:

| 层 | 类型 | 内容 | 谁读 |
|---|---|---|---|
| 小 snapshot | `RuntimeSnapshot` | `ts_us` / `policy_phase` / `policy_switch_count` | dashboard 顶端、PolicyMonitor 调试 |
| metric samples | `SampleMap = map<(name,labels), Sample>` | 全量 fuzzer./executor./channel./perf. 样本 | renderer、JsonSink |
| run summary | `RunSummary` | schema 投影后的字段表(generated/exec_fuzz_s/...)| JsonSink |
| 离散事件 | `deque<RuntimeEvent>` 长度上限 1024 | channel 生命周期变更、fault、recovery | dashboard 尾部、log 面板 |

---

## 3. 目录布局

```
telemetry/
├── design.md                            # 本文
├── include/refuzz/telemetry/
│   ├── telemetry_service.hpp            # IService 适配壳
│   ├── observation/
│   │   ├── observability_projector.hpp  # 后台 pull 线程
│   │   ├── run_state_store.hpp          # 中央视图
│   │   ├── run_state_renderer.hpp       # 无状态格式化
│   │   ├── terminal_dashboard.hpp       # TTY 后台线程
│   │   ├── run_summary.hpp              # SummaryField 表 / 数据对象
│   │   ├── run_summary_computer.hpp     # 纯函数 ComputeRunSummary
│   │   └── run_summary_json_sink.hpp    # 单次落盘
│   ├── coverage/coverage_tracker.hpp    # ICoverageSink 实现
│   └── policy/
│       ├── policy_engine.hpp            # SystemPhase 状态机 + 切策略
│       └── policy_monitor.hpp           # 旧停滞检测器(未接主路径)
└── src/                                 # 各 .cpp 实现一一对应
```

---

## 4. 关键抽象

### 4.1 `TelemetryService`
`telemetry/include/refuzz/telemetry/telemetry_service.hpp`

`IService` 适配壳,只协调启停 projector + dashboard。本身不持业务状态,组件所有权在 `Orchestrator`。

| 方法 | 行为 |
|---|---|
| `Init()` | 空实现 |
| `Start()` | `projector_->Start()` → `dashboard_->Start()`,设 `running_=true` |
| `Stop()` | `dashboard_->Stop()` → `projector_->Stop()`,设 `running_=false` |
| `IsRunning()` | 读 `running_` |

启停顺序非对称是有意为之(详见 §6.2 / §6.3)。

### 4.2 `RunStateStore`
`telemetry/include/refuzz/telemetry/observation/run_state_store.hpp`

单 `std::mutex mu_` 保护四类数据 + 可选 debug event log。所有读返回值拷贝,不暴露内部引用。

| API | 用途 |
|---|---|
| `UpdateSnapshot(RuntimeSnapshot)` | Projector 每 tick 写 |
| `UpdateMetricSamples(vector<Sample>)` | Projector 每 tick 写,**必须先于** `UpdateRunSummary` |
| `UpdateRunSummary(RunSummary)` | Projector 每 tick 写 |
| `PushEvent(RuntimeEvent)` | Projector 翻译 channel event 时写,deque 超 1024 自动丢最旧 |
| `LatestSnapshot/MetricSamples/RecentEvents/LatestRunSummary()` | 任意线程读 |
| `EnableDebugEventLog(path)` | 开 append 文件镜像 |
| `ObserveExecRate(ts_us, terminal)` | [v2 G5 follow-up-2] Projector 每 tick 写 windowed exec/sec(LibAFL `afl_exec_sec` 等价);内部 forward 到 `RateWindowTracker exec_rate_tracker_` |
| `WindowedExecsPerSec()` | Renderer / RunSummary 读 EWMA 平滑后的 5s windowed rate |

#### 4.2.1 `RateWindowTracker`(嵌入 RunStateStore)

`telemetry/include/refuzz/telemetry/observation/rate_window_tracker.hpp`
`telemetry/src/observation/rate_window_tracker.cpp`

LibAFL `afl_exec_sec` feature 等价(参 `crates/libafl/src/monitors/stats/mod.rs:255`)。

- **数据结构**:`std::deque<{ts_us, value}>`,自带独立 mutex(跟 store `mu_` 解耦避免嵌套锁)
- **算法**:
  - Observe 时 push,prune 5s 之外的老 sample(保留至少 1 个让 LastValue 始终有值)
  - `raw = (last.value - first.value) / dt_secs`
  - `smoothed = α * raw + (1-α) * smoothed_prev`(EWMA,α=0.3 默认;首次有效 raw 时 `smoothed = raw`,跳 EWMA bootstrap)
- **防御**:single sample / dt=0 / non-monotonic counter → raw=0,smoothed 沿用前值(避免 dashboard 闪烁)
- **跟 `execs_per_sec` 累计平均关系**:并存不替代。windowed 反映"当前/末段"速率(LibAFL afl_exec_sec mode);累计平均反映"全局回顾"(LibAFL default mode)。Dashboard live 推荐 windowed,summary 历史推荐 avg。

接入位置:
- 写:`ObservabilityProjector::ComputeAndStoreSummary()` 每 tick 算完 `terminal = completion + abnormal` 后调 `store.ObserveExecRate(now_us, terminal)`,然后把 `WindowedExecsPerSec()` 注入 `summary.fields` 末尾(field name `execs_per_sec_windowed`,详 040 §6.1 schema 表)
- 读:`RenderRuntimePanel` 加一行 `exec/s windowed=A.AA (5s) avg=B.BB`(`avg` 从 LatestRunSummary 拿 `execs_per_sec`,跟 windowed 并显)
- 单测:`tests/rate_window_tracker_test.cpp`(6 case:empty / single / raw / EWMA 收敛 / window prune / non-monotonic 防御)

### 4.3 `ObservabilityProjector`
`telemetry/include/refuzz/telemetry/observation/observability_projector.hpp`
`telemetry/src/observation/observability_projector.cpp`

后台 pull 线程,**Telemetry 唯一从 registry 拉数据的地方**。

**ctor**:
```cpp
ObservabilityProjector(
  RunStateStore& store,
  ChannelEventSubscription channel_event_sub,
  ObservabilityConfig config = {pull_interval=1000ms, enable_summary_invariants=true},
  PolicyEngine* policy_engine = nullptr,
  MetricRegistry* registry = nullptr,
  steady_clock::time_point session_start_steady = {},
  system_clock::time_point session_start_wall = {});
```

**主循环 `ProjectLoop`** (`observability_projector.cpp:219-244`),每 `pull_interval` 跑一遍:
1. `DrainInputs()` —— 抽 channel events,翻译为 `RuntimeEvent` 投 `store`;若 bus 覆盖到旧事件,补一条 `subject="channel_event_gap"` 的 gap event(detail=`dropped=N`)
2. `policy_engine_->Evaluate()` —— 读 registry,DeterminePhase,必要时调 `IPolicyControl` 切策略
3. `CollectAllPrefixes()` —— 顺序扫 `fuzzer.` / `executor.` / `channel.` / `perf.` 四个前缀
4. `ComputeRunSummary(samples, ...)` —— 纯函数投影
5. `store.UpdateMetricSamples(samples)` → `store.UpdateRunSummary(summary)` → `store.UpdateSnapshot(RuntimeSnapshot)`
6. `wait_cv_.wait_for(pull_interval)` —— 可被 `Stop()` 唤醒

**Stop 路径**:置 `running_=false` → cv 唤醒 → `join` → 同步再跑一次 `ComputeAndStoreSummary(is_final=true)`,确保 final summary 落到 store。

**ChannelObserveEvent 翻译表** (`EmitObserveEvent`, `observability_projector.cpp:111-182`):

| Source kind | RuntimeEvent.Kind | subject | from_state | to_state |
|---|---|---|---|---|
| kLifecycleChanged | kChannelStateChange | "channel_lifecycle" | 旧 lifecycle 名 | 新 lifecycle 名 |
| kFaultDetected | kFault | "channel_fault" | fault_kind | fault_reason |
| kRecoveryStarted | kRecoveryBegin | (channel) | fault_reason | recovery_action |
| kRecoveryCompleted | kRecoveryComplete | (channel) | — | "success" / "failed" |
| kGenerationReset | kChannelStateChange | "channel_generation" | 旧 generation | 新 generation |

### 4.4 RunSummary 三件套

**`RunSummary` 数据对象** (`run_summary.hpp:60-69`):
```cpp
struct RunSummary {
  vector<pair<string, SummaryValue>> fields;   // schema 顺序,key 稳定
  RunSummaryInvariants invariants;             // status + failures
  steady_clock::time_point snapshot_ts;
  system_clock::time_point session_start_wall, snapshot_wall;
  bool is_final;
};
```
`SummaryValue` 是 `kInt|kDouble` 的 tagged union(`run_summary.hpp:18-30`)。

**`RunSummarySchema()`** (`run_summary.cpp:99-313`) — 全项目唯一字段表,**硬编码 vector**,顺序 = 计算顺序(派生字段必须在依赖之后)。

40+ 字段,按段分组:

| 段 | 字段示例 | 来源 |
|---|---|---|
| Fuzzer counters | `generated` / `completion` / `abnormal` / `crash` / `timeout` / `coverage_empty` / `malformed_feedback` ... | `fuzzer.generated_tasks` / `fuzzer.results{kind=...}` |
| Coverage / corpus | `new_cov` / `cov_unique` / `corpus_growth` / `corpus` / `corpus_save_error` | `fuzzer.cov.*` / `fuzzer.corpus.*` |
| Policy switches | `policy_sw_mut` / `policy_sw_sched` / `policy_sw_corpus` | `fuzzer.policy_switch{kind=...}` |
| Inbox drops | `inbox_drop` / `crash_inbox_drop` | `fuzzer.inbox_drop{queue=...}` |
| Executor | `events_forwarded` / `tasks_submitted` / `backoff_wait_s` / `backoff_episodes` / `slot_count` | `executor.*` |
| **派生**(顺序敏感) | `terminal` = completion + abnormal | 依赖前面 |
| | `elapsed_ms` / `exec_s` | now − session_start |
| | `fuzz_started_us` | `fuzzer.fuzz_phase_started_us` (FuzzerLoop 首次 produce 时一次性 Set) |
| | `elapsed_fuzz_ms` / `exec_fuzz_s` | `elapsed_ms − fuzz_started_us/1000`,fuzz 未起步则 0 |
| | `submit_rate_net` | `tasks_submitted / max(1, exec_fuzz_s − backoff_wait_s)` |
| | `per_slot_rate` | `submit_rate_net / slot_count` |
| | `execs_per_sec` | `terminal / max(1, exec_fuzz_s)` |
| | `new_cov_rate` | `new_cov / max(1, exec_fuzz_s)` |
| | `coverage_empty_rate` / `timeout_rate` | × `terminal`(事件比率,不是时间率) |

**两套时间口径**(重要):
- `elapsed_ms` / `exec_s` — 从 `session_start`(orchestrator 在 FuzzerLoop 构造前 lock)起的总 wall time,**包含** Build 末段 / Start / executor 启动 / 等首个 task 的时间
- `elapsed_fuzz_ms` / `exec_fuzz_s` — 从 FuzzerLoop **首次 producer 成功投出 task** 起算,对照 syzkaller `exectime` 口径
- 所有速率字段(`execs_per_sec` / `new_cov_rate` / `submit_rate_net`)分母**用 `exec_fuzz_s`**;fuzz 未起步时分子也是 0,自然得 0

**`RunSummaryInvariants`** (`run_summary.hpp:46-56`):
| Status | 何时 |
|---|---|
| kPending | 过程 tick(`is_final=false`) |
| kOk | `is_final=true` 且全部校验通过 |
| kViolated | `is_final=true` 且 `failures` 非空 |
| kDisabled | `enable_summary_invariants=false` |
| kSkipped | `registry==nullptr` 或 samples 为空 |

**`ComputeRunSummary`** (`run_summary_computer.hpp:20-27`) — 纯函数,无副作用,易单测。

**`RunSummaryJsonSink`** (`run_summary_json_sink.hpp:27-43`):
- 构造期接 `(RunSummaryJsonSinkConfig{logs_dir, filename="run_summary.json"}, const RunStateStore&)`
- 只有 `WriteFinal()` 一个写出口,**Orchestrator 在 Stop 路径调一次**(`orchestrator.cpp:892`),无周期写
- 流程:读 `store.LatestRunSummary()` → 渲染 JSON → 写 `<file>.tmp` → 原子 rename → 返回 `JsonWriteStatus`(kOk/kInvariantFailed/kIoError/kSkipped)
- JSON 顶层:`session_start_ts`(ISO-8601 UTC) / `snapshot_ts` / `is_final` / `fields`(对象) / `invariants`(status + failures 数组)

### 4.5 `RunStateRenderer`
`telemetry/include/refuzz/telemetry/observation/run_state_renderer.hpp`

无状态格式化层,只吃 `RuntimeSnapshot` + `SampleMap` + `RecentEvents`,不直接访问任何 producer。

约定:
- fuzzer/executor/channel 信息**全部从 metric samples 读**
- `fuzzer.current_policy{kind,name}` 作为 one-hot gauge 反查当前策略名
- `channel.lifecycle_state{channel_id,state}` 作为 one-hot gauge 反查 channel lifecycle
- channel 行按 `channel_id` 排序
- 提供 `RenderRuntimePanel(const RunStateStore&)` 便捷重载,内部先取 store 三件再调底层 formatter

### 4.6 `TerminalDashboard`
`telemetry/include/refuzz/telemetry/observation/terminal_dashboard.hpp`

后台 TTY 渲染线程。

**激活条件**:`isatty(fd)` && `TERM != "dumb"`。优先打开 `/dev/tty`,失败回退到 config 中的 fd;两者都不行 `Start()` 返回 `false`,Orchestrator 改走 fallback log 面板。

**循环**:每 `refresh_interval` 从 store 读快照 → 调 `RenderRuntimePanel` → 按终端尺寸裁剪 → ANSI 清屏 → 写 fd。

可选支持 alternate screen + 隐藏光标;`Stop()` 负责恢复终端态。

### 4.7 `PolicyEngine`
`telemetry/include/refuzz/telemetry/policy/policy_engine.hpp`
`telemetry/src/policy/policy_engine.cpp`

**唯一的执行面跨界**。位于 telemetry 但通过 `IPolicyControl` 真切策略;架构上更像 control,wiring 历史保留在 telemetry。

**ctor**:`PolicyEngine(IPolicyControl& control, RunStateStore* store, const MetricRegistry& registry, PolicyEngineConfig config={})`

**`SystemPhase` 4 状态机** (`DeterminePhase`):

| 当前 → 目标 | 触发条件 |
|---|---|
| kNormal → kRecovering | 任一 channel 处于 booting / recovering |
| kRecovering → kNormal | 无 channel 在恢复,且 `unhealthy_ratio < degraded_channel_ratio` |
| kRecovering → kDegraded | 无 channel 在恢复,且 `unhealthy_ratio ≥ degraded_channel_ratio` |
| kNormal/kDegraded → kStalled | 连续 `required_stall_windows` 个 cov_rate 窗口 < `stall_threshold` |
| kStalled → kNormal | cov_rate 回升 |

**`ApplyProfile`** (`policy_engine.cpp:175-182`) 在相位变 kNormal/kStalled 时调:
- `control_.SwitchMutationPolicy(profile.mutation_policy)`
- `control_.SwitchSchedulingPolicy(profile.scheduling_policy)`
- `control_.SwitchCorpusAdmissionPolicy(profile.corpus_policy)`

`min_dwell` 冷却(默认 60s)防抖动。

**输入 metric**:
- `fuzzer.results{kind=completion|abnormal}` + `fuzzer.cov.new_total` 算 cov_rate
- `executor.channels.total` / `executor.stop_requested`
- `channel.lifecycle_state{channel_id,state}` one-hot
- `fuzzer.current_policy{kind,name}` one-hot 判断当前策略是否已匹配目标

**线程**:`current_phase_` / `switch_count_` 是 atomic;由 `ProjectLoop` 在 telemetry 后台线程调 `Evaluate()`,主线程读 `CurrentPhase()`。

### 4.8 `PolicyMonitor`(辅助件,**未接主路径**)
`telemetry/include/refuzz/telemetry/policy/policy_monitor.hpp`

更早期的停滞检测 helper,功能与 `PolicyEngine` 部分重叠。需调用方主动 `Tick(registry)` 才工作。

**当前事实**:`grep PolicyMonitor` 在 `control/orchestrator/src/` 与 `control/src/` 下**无生产路径引用**(仅 `_test.cpp` 引用)。即 PolicyMonitor 编译进 lib 但**主路径不调**,等同实验/测试件。

### 4.9 `CoverageTracker`
`telemetry/include/refuzz/telemetry/coverage/coverage_tracker.hpp`

实现 `core::ICoverageSink`,把 coverage hash 从热路径异步搬到磁盘。

**结构**:
- `inbox_`: bounded `deque<vector<uint64_t>>`,默认上限 `max_inbox_batches=4096`
- `coverage_hashes_`: 去重后 `unordered_set<uint64_t>`
- `dropped_batches_`: inbox 满时丢弃计数

**方法**(全部受单 mutex 保护):
| API | 行为 |
|---|---|
| `OnCoverageHashes(vector<u64>)` | 生产者调,快速入 inbox;满则 `dropped_batches_++` |
| `Drain()` | 从 inbox 合并到 `coverage_hashes_` |
| `Persist(output_dir)` | `Drain()` + 创建目录 + 写三文件 |
| `Flush(output_dir)` | `Persist` 别名 |
| `TotalHashCount()` / `DroppedBatches()` | 读统计 |

**落盘**:`coverage_hashes.bin` / `coverage_hashes.txt` / `coverage_hashes.json`。Persist 失败**不返回错误,不打日志**——主流程稳定优先,运维可见性弱。

后台 drain 线程由 `Orchestrator` 拥有,周期调 `Drain()` 与 `Persist()`。

---

## 5. 数据流详解

### 5.1 Metric 流(主体)

**唯一上游契约**:`docs/telemetry-redesign/090_component_metric_recipe.md` 5 步 recipe。
五个 `XxxMetrics::Bind()` 在组件构造期一次性把 `Counter*` / `Gauge*` 缓存为成员;热路径只调 `Inc/Set/Add`,**禁止 `CounterOf`**。

**生产者一览**:

| 组件 | metrics struct | 文件 |
|---|---|---|
| FuzzerLoop / CorpusManager | `FuzzerMetrics` | `core/src/metrics/fuzzer_metrics.cpp` |
| Executor / dispatcher | `ExecutorMetrics` | `core/src/metrics/executor_metrics.cpp` |
| Channel | `ChannelMetrics` | `core/src/metrics/channel_metrics.cpp` |
| Policy 状态 one-hot | `PolicyStatePublisher` | `core/src/metrics/policy_state_publisher.cpp` |

**核心收益**:组件不挂 → 对应 series 不存在 → 下游自动跳过,等同"按 active 组件拼出实际 schema"。

**Projector pull 周期**:`pull_interval=1000ms`;每轮 `CollectPrefix` 四次拼成一个 sample 向量,**整份替换**到 `RunStateStore::SampleMap`(简单可靠;cardinality 升高时拷贝成本上升)。

### 5.2 Channel event 流

`ChannelObserveEvent` 是 `BroadcastBus` 的 ring buffer。Projector 持订阅句柄 `channel_event_sub`,每 tick `Drain()`。订阅落后被覆盖 → `Drain()` 返 dropped 数 → Projector 补一条 `subject="channel_event_gap" detail="dropped=N"`,**显式承认观测缺口**。

翻译表见 §4.3。

### 5.3 RunSummary 流

每 tick:
```
samples = registry.CollectPrefix(...)
summary = ComputeRunSummary(samples, session_start, now, is_final=false)
store.UpdateMetricSamples(samples)   ◀ 必须先于
store.UpdateRunSummary(summary)         ◀ 这一行,保证 reader 不会读到"summary 已更新但 samples 还是旧的"
```

Stop 路径:Projector 同步再跑一次 `is_final=true` → `JsonSink.WriteFinal()` 由 Orchestrator 在 service Stop 后单次落盘 → `<logs_dir>/run_summary.json`(原子 rename)。

**Fuzz phase 时间剥离**:`FuzzerLoop` 首次 producer 成功投 task 时,把 `(now − session_start).us` Set 进 `fuzzer.fuzz_phase_started_us` Counter(一次性,不重写)。run_summary 派生 `fuzz_started_us` / `elapsed_fuzz_ms` / `exec_fuzz_s` 三字段,后者自动驱动所有速率字段把启动开销从分母剥离。

### 5.4 Coverage 流(独立,不进 RunStateStore)

```
feedback / fuzzer ─→ CoverageTracker::OnCoverageHashes(batch) ─→ inbox
                  ↑ 热路径只入队
Orchestrator 后台线程 ─→ tracker.Drain() / Persist(logs_dir)
                                        ↓
                logs/coverage_hashes.{bin,txt,json}
```

目的是"保留集合供离线分析",不渲染。

### 5.5 Policy 流

```
fuzzer/results + cov.new_total ─┐
channel.lifecycle_state         ├─→ PolicyEngine.Evaluate() (in ProjectLoop)
fuzzer.current_policy           ─┘            │
                                              ▼
                                       SystemPhase 状态机
                                              │
                                  需切换 + 过 min_dwell 冷却
                                              ▼
                                IPolicyControl.SwitchMutationPolicy
                                IPolicyControl.SwitchSchedulingPolicy
                                IPolicyControl.SwitchCorpusAdmissionPolicy
                                              │
                                              ▼
                                      RuntimeSnapshot.policy_phase
                                      RuntimeSnapshot.policy_switch_count
                                      可选:RuntimeEvent 推 store
```

---

## 6. 生命周期与线程

### 6.1 装配序(`control/orchestrator/src/orchestrator.cpp`)

1. 创建可选 `CoverageTracker`
2. **`started_at = steady_clock::now()`** —— session_start 锚点(传给 FuzzerLoop ctor + Projector)
3. `FuzzerLoop`(收到 session_start,首次 produce 时打 `fuzz_phase_started_us`)
4. `RunStateStore`
5. `PolicyEngine(IPolicyControl=*loop, store, registry, ...)`
6. `ObservabilityProjector(store, channel_event_bus.Subscribe(), config, policy_engine, &registry, started_at, started_at_wall)`
7. `RunSummaryJsonSink({logs_dir}, store)`
8. `TerminalDashboard(store, config)`
9. `TelemetryService(projector, dashboard)` 注册到 `ServiceRegistry`

### 6.2 启动序

`TelemetryService::Start()`:
1. `projector_->Start()` —— 后台 pull 线程开始周期 tick
2. `dashboard_->Start()` —— TTY 线程起,首屏不再空白(因为 store 已被刷新一次)

### 6.3 停止序(与启动反向)

`TelemetryService::Stop()`:
1. `dashboard_->Stop()` —— 先停渲染,避免 projector 退出后继续画
2. `projector_->Stop()` —— 设 running_=false → cv 唤醒 → join → 同步跑一次 `ComputeAndStoreSummary(is_final=true)` 写到 store
3. (Orchestrator 在 service stop 后)`run_summary_json_sink->WriteFinal()` 一次性落盘

### 6.4 线程清单

| 线程 | 由谁创建 | 干什么 |
|---|---|---|
| Projector ProjectLoop | `Projector::Start()` | 周期 pull registry / drain channel events / drive policy / write store |
| Dashboard render | `TerminalDashboard::Start()` | 周期 read store / 渲染 / ANSI 写 fd |
| Coverage drain | `Orchestrator` | 周期 `tracker.Drain() + Persist()` |
| 主 fuzz 线程 | `FuzzerLoop` 自身 | 生产 metric / coverage hash;不直接动 telemetry 内部结构 |

### 6.5 并发原语

- `RunStateStore`:单 `std::mutex mu_`(简单可靠,cardinality 上升时是潜在瓶颈)
- `CoverageTracker`:单 `std::mutex mu_` 罩 inbox + dedup set
- `Projector` / `Dashboard`:`atomic<bool> running_` + `cv` 做 sleep/wakeup
- `MetricRegistry`:自带并发,telemetry 只按订阅者读
- `PolicyEngine.current_phase_` / `switch_count_`:atomic

---

## 7. 降级与容错

| 场景 | 行为 |
|---|---|
| 无 TTY | `dashboard.Start()` 返 false → Orchestrator 每 5s 打印 `RenderRuntimePanel(...)` 到日志,fuzz 不阻塞 |
| 事件总线溢出 | Projector 补 `channel_event_gap` event(detail=`dropped=N`),原始事件无法恢复 |
| metric 缺失 | counter/gauge 查不到按 0 处理;lifecycle one-hot 未发布显示 `unknown`;`fuzzer.current_policy` one-hot 未发布时 `PolicyEngine::CurrentPoliciesMatch()` 返 true(视为"先不切",避免启动早期误触发) |
| coverage 落盘失败 | `Persist` 静默返回,不抛不日志(主流程稳定优先) |
| `registry==nullptr` 或 samples 为空 | `RunSummaryInvariants.status = kSkipped`,JsonSink 返 `kSkipped` 不写文件 |

---

## 8. 不变量速查

读代码前先记住这几条:

1. **`UpdateMetricSamples` 必须先于 `UpdateRunSummary`** —— 顺序由 Projector 保证(`observability_projector.cpp:234` 附近),否则 reader 看到不一致。
2. **派生字段在 schema 中必须出现在依赖之后** —— `RunSummarySchema` 顺序 = 计算顺序;`elapsed_fuzz_ms` 依赖 `fuzz_started_us` + `elapsed_ms`,不能调换。
3. **Counter / Gauge 一个 name 一种 kind** —— `r.CounterOf("x")` 与 `r.GaugeOf("x")` 不能并存。
4. **热路径不调 `CounterOf` / `GaugeOf`** —— 哈希表查询会拖慢;构造期一次 Bind,业务点只 `Inc/Set`。
5. **label 基数有界** —— 严禁 `seed_id` / `task_id` / `timestamp` 进 label。
6. **`fuzz_phase_started_us` 一次性写** —— FuzzerLoop 首次 producer 成功后置闸,后续 RunOnce 不重写;Set(0) 表示 session_start 是 epoch(测试路径)。
7. **JsonSink 只在 Stop 后写一次** —— 没有 checkpoint;真崩了拿不到 final summary,但 Projector 在 ProjectLoop 每 tick 也更新 store,dashboard 上能看实时值。
8. **`PolicyEngine` 是 telemetry 中唯一的执行面跨界** —— 经 `IPolicyControl` 切策略;`PolicyMonitor` 主路径未接,等同实验件。

---

## 9. 关键引用

| 主题 | 文件 |
|---|---|
| 命名 catalog(新加 metric 必先改这里) | `docs/telemetry-redesign/020_naming_catalog.md` |
| 新组件接入 metric 五步 | `docs/telemetry-redesign/090_component_metric_recipe.md` |
| RunSummary schema 完整列表 | `telemetry/src/observation/run_summary.cpp` |
| ProjectLoop 实现 | `telemetry/src/observation/observability_projector.cpp` |
| FuzzerLoop 首次 produce 打戳 | `control/src/loop/fuzzer_loop.cpp` (RunOnce 内 `fuzz_phase_started_` 闸) |
| session_start 锚点 | `control/orchestrator/src/orchestrator.cpp` (FuzzerLoop 构造前 lock) |
