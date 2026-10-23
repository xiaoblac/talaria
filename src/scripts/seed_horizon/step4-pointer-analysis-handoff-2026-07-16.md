# Step 4 Kernel Bitcode Pointer Analysis Handoff

状态：2026-07-16 交接快照。当前位于 Step 4 Stage A；源码含未完成补丁，最后一个已编译二进制仍使用旧的
callsite 语义。

本文只讨论 Linux kernel LLVM Bitcode 静态指针分析。当前不做漏洞分析，也尚未进入 variant resolver。

## 1. 当前目标与位置

完整方法管线是：

```text
Kernel Bitcode
  -> schema-v3 objects/points-to/memory/call constraints
  -> recognizer seeds and API summaries
  -> Step 4 global Pt/MemPt/CallTarget/ArgFlow/ReturnFlow fixpoint
  -> Step 5 struct-policy experiments
  -> Step 6 variant-conditioned query
  -> Step 7 recursive dispatch resolver
  -> candidate handler sets and provenance
```

当前只在 Step 4。Step 4 完成的含义是：声明的抽象语义达到经过独立 checker 验证的全量闭包；不表示候选
handler 已经计算，也不表示静态候选是真实运行时真值。

## 2. 文档地图

| 文档/程序 | 职责 | 当前权威性 |
|---|---|---|
| `handler-candidate-pointer-analysis-plan.md` | 总目标、Step 0-9 方法、Step 4 Stage A-D 验收计划 | 方法主文档 |
| `step4-pointer-analysis-handoff-2026-07-16.md` | 当前代码、数据、诊断、在途补丁和接手顺序 | 当前状态主文档 |
| `points-to-constraint-schema.md` | schema v3 object/value identity 和通用约束格式 | Step 2 输入契约 |
| `recognizer-seed-schema.md` | registration seeds、API summaries 及 Step 3/4 边界 | Step 3 输入契约 |
| `docs/plans/dispatch-install-framework.md` | ObjectId/Install/Dispatch/OpSelector 四边组合与结构 recognizer | recognizer/后续 resolver 设计；不是 Step 4 solver 验收 |
| `step4-gate-schema.md` | Stage Gate 文件格式、守恒条件、closure 和 determinism | Step 4 验收契约 |
| `probes/check_step4_gate.py` | 执行 Stage Gate，生成 JSON 报告 | 已实现；closure 所需产物尚未全部生成 |
| `README.md` | 原 seed_horizon S/P/R 工具链总览 | 背景文档；不能替代本交接或 Step 4 计划 |

## 3. 已完成阶段

### 3.1 Step 0-3

- 固定 8245 个 syzkaller variant 的旧候选基线和逐候选 provenance。
- 建立统一 `VariantInputs`，保留多 producer，不强压成单 object 或单 handler。
- 从 627/627 kernel linked batches 抽取 schema v3 facts。
- recognizer 只提供结构注册根和 summary；禁止 basename、handler 名或 subsystem 名 fallback。
- 旧 recognizer 已按 `ObjectId -> Install -> Dispatch + OpSelector` 四边组合整理。

全量 schema v3 manifest：

```text
/tmp/kernel_constraints_v3_final/constraint_manifest.json
batch_count                         627
objects.tsv                   3,468,125 rows
points_to_constraints.tsv     5,480,395 rows
memory_constraints.tsv        1,834,471 rows
call_constraints.tsv          8,307,865 rows
total                        19,090,856 rows
```

manifest 保存每个输入文件、提取 binary 和 driver 的 SHA-256。正式 solver 当前从
`run/seed_horizon/{objects,points_to_constraints,memory_constraints,call_constraints}.tsv` 加载，并同时加载
`registration_seeds.tsv` 与 `api_summaries.tsv`。

### 3.2 Step 4 已实现能力

`resolve/pointsto_global.cpp` 已具有：

- C++ semi-naive worklist fixpoint。
- `Pt`、`MemPt`、indirect `CallTarget`、direct/indirect argument/return transfer。
- copy SCC folding 和 pointer-sink/value-all 两种执行模式。
- schema v3 contained-struct compatibility policy。
- structured dynamic GEP 与有限 strided expansion。
- 带 `base/stride/bound` 的 symbolic affine region、clip 和 memory overlap。
- K=1..4 call-string value context，以及可选 stack-object cloning。
- relation derivation、hotspot、field-cycle、affine 和 call-transfer 输出。
- Stage Gate 的 Python 实现；其独立 selftest 为 6/6 PASS。

最新一次完成编译时，C++ selftest 共 43 项通过。该结果早于本交接所述的未完成 `ContextScope` 补丁。

## 4. 可复核数据基线

### 4.1 旧的完整关系基线

```text
/tmp/kernel_pt_v3_affine_final_current
tuples             9,372,221
pending                     0
truncated               false
value_slice                all
```

该目录的 `step4_gate_report.json`：

```text
global_stats_contract             PASS
core_relation_artifacts           PASS
call_transfer_conservation        FAIL  (当时还没有 call flow artifacts)
summary_relation_conservation     FAIL
constraint_activation_accounting  FAIL
independent_closure_certificate   FAIL
deterministic_rerun                NOT_RUN
```

因此它是旧 solver relation 基线，不是 Step 4 完成证明。

### 4.2 Stage A 最新诊断

```text
/tmp/kernel_pt_stagea_global_diag_20260715
policy.value_slice        pointer-sinks
materialized constraints       411,642
tuples                     30,000,004
pending                     4,901,787
indirect targets                8,736
truncated                        true
```

该运行用 `--no-tuples --no-derivations` 控制磁盘，但保留了约 385 MiB `call_transfer_map.tsv`、501 MiB
`call_arg_flows.tsv` 和 46 MiB `call_return_flows.tsv`。它是诊断目录，不能进入最终 gate。

`drivers/net` 子集的 call-transfer conservation 已通过：5,898 transfers、1,350 argument flows、126 return
flows。小 batch 只证明实现回归，不替代全量 gate。

## 5. 当前根因

最新全量 provenance 显示：

```text
pcluster_pool
  -> __kmem_cache_create_args formal
  -> strstr shared formal
  -> CALL_RETURN broadcasts to unrelated callers
```

这是 context-insensitive call/return mismatch。它不是 affine region、dynamic GEP、struct 白名单或 tuple 上限
问题。提高 `--max-tuples` 只会继续计算已经污染的闭包。

已经确定的混合调用语义：

```text
selected callsite
    every caller instance, including baseline caller
    -> contextual callee transfer
    -> disable that site's baseline CALL_ARGUMENT/CALL_RETURN

unselected callsite
    -> context-insensitive baseline callee transfer

function body
    -> baseline body always retained
    -> contextual body cloned only for selected contexts
```

此前“selected callsite 同时保留 baseline transfer”会重新合并 formal，是错误实现。此前“baseline caller
经过 selected site 时进入 baseline callee”也会丢失 callsite 隔离；它必须进入该 selected site 的 contextual
callee。

## 6. 当前源码的在途状态

最后可运行 binary：

```text
/tmp/pointsto_global_stagea_o3
```

它仍包含旧语义，不能作为下一次正式结果。

工作树中的 `resolve/pointsto_global.cpp` 已做但尚未验证：

1. `CopyConstraint.directSite` 保存原始 direct call copy 对应的静态 site index。
2. `loadCalls/wireStaticCall` 已把真实 site index 写入 baseline `CALL_ARGUMENT/CALL_RETURN`。
3. 新增 `ContextScope::{Handler, Global}` 和 `functionInScope`；global scope 不依赖 handler reachability。
4. selected site 现在总会建立 baseline-caller -> contextual-callee transition。

仍未完成：

1. 所有 `materializeCallsiteContexts` 调用尚未适配新 `ContextScope` 参数。
2. CLI 尚无 `--context-scope handler|global`，stats 也未记录该 policy。
3. `callConstraintEnabled` 尚未禁用 selected site 的 baseline call copies。
4. `writeCallTransfers` 尚未跳过 selected site 的 context-insensitive transfer。
5. selftest 仍断言 selected baseline formal 合并，必须反转为 baseline inactive。
6. 尚缺 unselected direct/indirect、baseline-to-contextual boundary 和 selected-site replacement 测试。

因此当前源码预计不能编译。接手者不能直接开始全量运行，也不能把最后 binary 的结果当作新补丁验证。

## 7. 下一执行顺序

### 7.1 完成 Stage A 代码

1. 接通 `ContextScope` 的 Options、CLI、stats、usage 和全部调用。
2. `CallFlowMode::Callsite` 下，仅当 `directSite` 被 `contextualDirectSites` 选中时禁用 baseline call copy。
3. transfer map 对 selected direct site 只输出 contextual transitions；unselected site 只输出 CI baseline。
4. 保留 baseline 函数体；不要恢复 selected site 的 baseline actual/formal/return 边。
5. 更新 selftest，检查 selected 隔离、unselected 保流和 baseline/contextual 边界守恒。

### 7.2 编译和自测

```bash
clang++-20 -std=c++20 -O3 -DNDEBUG \
  scripts/seed_horizon/resolve/pointsto_global.cpp \
  -o /tmp/pointsto_global_stagea_o3

/tmp/pointsto_global_stagea_o3 --selftest
```

### 7.3 先跑低磁盘全量诊断

以下命令只有在 `--context-scope` 接通后才有效：

```bash
/tmp/pointsto_global_stagea_o3 \
  --sh run/seed_horizon \
  --out /tmp/kernel_pt_stagea_global_diag_next \
  --batch all \
  --unknown drop \
  --field-dynamic strided \
  --field-type compatible \
  --field-cycle affine \
  --dynamic-alias none \
  --offset-overflow drop \
  --copy-scc on \
  --value-slice pointer-sinks \
  --call-flow callsite \
  --context-scope global \
  --context-objects shared \
  --context-depth 1 \
  --context-value-slice escape \
  --context-sites run/seed_horizon/pointsto/global-all-strided-escape-active-round1-k1/direct_callsite_activity.tsv \
  --max-contexts 2000000 \
  --max-tuples 30000000 \
  --no-tuples \
  --no-derivations
```

只有该诊断不再出现 CI hotspot，才运行 `value-slice=all`。正式 gate 运行必须去掉 tuple 上限并生成完整
tuple、derivation 和后续 Stage B-D artifacts。

## 8. Step 4 后续阶段

Stage A 通过后，仍有三阶段，不能直接进入 resolver：

1. **Stage B**：把 `dispatch_field/context_field/cmd_selector` 输出为一等 summary relations。
2. **Stage C**：输出每种 constraint 的 row-level activation census，并得到全量无截断闭包。
3. **Stage D**：独立 checker 重新计算 obligation，要求 violations=0，并做第二次确定性 rerun。

最终命令：

```bash
python3 scripts/seed_horizon/probes/check_step4_gate.py RESULT_A \
  --compare RESULT_B \
  --json-out RESULT_A/step4_gate_report.json
```

只有 overall=`PASS` 才能进入 Step 5 struct NONE/ALL/WHITELIST，再进入 Step 6 variant query 和 Step 7
recursive resolver。

## 9. 方法约束

- 不按函数名、subsystem、resource basename 或 handler 名过滤污染。
- 不靠提高 `max_tuples` 掩盖 context mismatch。
- 不用几个 subsystem 样本替代全量 closure checker。
- 不把候选标为“可靠/不可靠”；所有 handler 输出都是候选集合。
- 不在 Step 4 gate 通过前继续 recognizer tail、precision sampling 或 dependency graph。
- 所有 policy drop、unresolved 和跨 batch identity gap 必须保留完整分母和 provenance。

## 10. 工作树状态

与本轨相关但尚未提交：

```text
M  scripts/seed_horizon/handler-candidate-pointer-analysis-plan.md
M  scripts/seed_horizon/points-to-constraint-schema.md
M  scripts/seed_horizon/resolve/pointsto_global.cpp
?? scripts/seed_horizon/probes/check_step4_gate.py
?? scripts/seed_horizon/step4-gate-schema.md
?? scripts/seed_horizon/step4-pointer-analysis-handoff-2026-07-16.md
```

仓库中还有大量与本任务无关的用户改动和生成文件；接手时只处理上述指针分析路径，不得回退其他文件。
