# Worker perf 阶段模型

`worker_perf` 只在 `LoopRuntime` 做一次采样判定。一条被采样的 program 使用同一个
`ProgramPerfSample`，依次汇集 loop、fork parent、program child、driver 和 worker
thread 的数据，最后由 `RecordProgramSample` 统一聚合与输出。

## 可相加的阶段

`scope=loop relation=exclusive` 表示 loop 进程的主动工作时间：

1. `prepare`：创建/恢复 workdir 和 reset loop device；
2. `executor`：调用 `IProgramExecutor::ExecuteProgram`；
3. `delivery`：写出 `DoneMsg`；
4. `cleanup`：回复后的 cwd 恢复和 workdir 回收。

`loop.total = prepare + executor + delivery + cleanup`。阻塞等待下一条请求的时间不计入
`total`，因此空闲队列不会被误报为执行开销。

`scope=fork_parent relation=exclusive` 表示 fork parent 在 `executor` 内的顺序阶段：

1. `prepare`：fork 前一次性资源准备；
2. `isolation`：`fork()`；
3. `watch`：建立 pidfd/reaper 和观察关系；
4. `wait_for_child`：等待 program child 结束，包含 child 的真实执行时间；
5. `reclamation`：回收/终止残留 descendant；
6. `result_read`：读取 result page 并分类结果。

不要把 `wait_for_child` 当成纯等待损耗。它包含 child 执行，这是旧采样最容易产生错误归因的地方。

`scope=critical_path relation=exclusive` 仅对成功提交 perf page 的 fork 样本输出。它使用
fork 前后的同一 `CLOCK_MONOTONIC` 时间轴，将关键路径切成：

1. `isolation`：parent 开始 fork 到 child 获得执行；
2. `child_setup`：child 入口到 runtime 入口；
3. `execution`：`ProgramRuntimeRunInline`；
4. `result_publish`：runtime 返回到 result page 准备提交；
5. `completion`：result ready 到 parent 观察并 reap child；
6. `reclamation`：parent 回收 descendant；
7. `result_read`：parent 读取和分类结果。

这组阶段互斥且可相加，适合回答“一条 program 的时间到底花在哪个阶段”。timeout、crash-before-commit
等没有完整 child 时间线的样本不会混入这组统计，但仍计入 `loop` 和 `fork_parent`。

## 嵌套诊断

- `scope=child_runtime`、`scope=execute_task`、`scope=driver` 的
  `relation=exclusive` 可在各自父阶段内相加，`unattributed` 显示尚未细分的剩余时间。
- `execute_task/program_fd_cleanup` 是 fork-per-program child 在 backend
  返回后、observation SessionEnd 前关闭 fd 3..30 的时间；因此设备 release
  触发的 remote coverage 仍可进入本轮 feedback，而不会落入 `completion`。
- `driver` 在 `wire_walk` 后额外拆分 `post_walk_drain`（等待仍在运行的
  async call）和 `task_cleanup`（结束线程 KCOV session 并清理 per-task context）。
- `[WorkerPerfDrain]` 汇总真正带着 in-flight call 进入 `post_walk_drain` 的
  program 数、入口 call 数、drain 内完成数和 deadline 到期后仍未完成数。
  `deadline_per_call` 表示 `wait_start + 2 * per_call_timeout` 生效，
  `deadline_program` 表示 `program_start + program_timeout / 6` 生效，
  `deadline_extra` 表示 `wait_start + max(call.prog_timeout)` 生效。
- `scope=wire_detail relation=nested` 是 `wire_walk` 内部细项；不同细项可能互相嵌套。
- `scope=remote_kcov relation=nested stage=remote_kcov_settle_sleep` 只统计
  settle 循环实际执行 `nanosleep` 的时间；`[WorkerPerf]` 同时输出累计 settle
  次数、累计 sleep 时间和每次 settle 的平均 sleep 时间。
- `scope=thread_detail relation=diagnostic` 是 threaded 调度、worker 工作和同步延迟，不应横向求和。
- 每行的 `share` 始终相对当前 `scope` 的 `total`；`n` 是真正进入该 scope 的样本数。

输出统一使用 `[WorkerPerf]` 汇总行和机器可解析的 `[WorkerPerfStage]` 阶段行。
