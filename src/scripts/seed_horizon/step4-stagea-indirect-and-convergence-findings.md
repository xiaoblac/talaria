# Step 4 Stage A — Indirect Contextualization + Convergence Findings

状态：2026-07-16。承接 `step4-pointer-analysis-handoff-2026-07-16.md`。本文记录 Stage A 代码补齐后的实测结果、
根因诊断与尚未决定的收敛策略。它不改变方法目标，只补充交接文档缺失的实证。

## 1. 已完成并验证的代码

`resolve/pointsto_global.cpp`：

- 交接文档 §7.1 的六项 direct-call 补丁全部完成，`--selftest` 46/46 通过（原 43 + 反转 2 条 baseline-merge
  断言为 baseline-inactive + 新增 3 类测试：unselected 保 baseline、selected 隔离、mixed 选择记账）。
- `--context-scope handler|global` 已接通 Options/CLI/stats/driver 与全部 `materializeCallsiteContexts` 调用。
- `callConstraintEnabled` 对 selected direct site 的 baseline `CALL_ARGUMENT/CALL_RETURN` 禁用。
- `writeCallTransfers` 对 selected site 不再输出 CI baseline transfer。
- 新增 `baselineFunctionLive` 门：只有当 caller baseline 实例可能承载指针流（handler root / 有 unselected
  incoming direct site / address-taken 可间接目标 / 无 selected incoming）时才建立 baseline-caller ->
  contextual-callee transition，避免 refinement 下产生空 context。

- **间接调用上下文化（plan §10.1 item 4 的实现）**：新增 `--indirect-targets FILE`。读入上一轮
  `indirect_call_targets.tsv`，把每个 (indirect callsite, target function) 提升为一个 synthetic contextual
  direct site（clone 目标 body/formal，禁用该 pair 的 baseline 间接连边）。`wireIndirect` 对已上下文化的
  (callsite,function) 只记录 target、跳过 baseline 连边。目标集跨轮单调精化（sound 过近似）。

编译：`clang++-20 -std=c++20 -O3 -DNDEBUG`，通过。

## 2. 实测：direct + indirect 上下文化都生效

正式输入为 schema v3：`/tmp/kernel_constraints_v3_final`（`objects.tsv`/`points_to_constraints.tsv` 为 v3；
`run/seed_horizon` 下这两个文件被无关改动回退成 v2，故 `--sh` 指向 v3 目录。`call_constraints.tsv` 两处逐字节
一致，round1 `--context-sites` 的 site index 因此可复用）。

- Direct：`strstr` 从 145 个 context_insensitive callsite 变为 477 contextual / 0 CI。广播消除。
- Indirect：`device_release` 从 baseline `arg:0` 变为逐 callsite 的 `ctx:` clone；`indirect_targets`
  16262 -> 6591（其余被上下文化、跳过 baseline 连边）。

## 3. 收敛阻塞的根因（与交接前提不符）

三组受控实验一致指向：**全量闭包仍在 tuple 上限截断，但主因不是 CI call/return 广播，而是设备模型 fat
pointer 的 context 复制。**

| 配置 | scope / slice | 结果 | 主导 hotspot |
|---|---|---|---|
| round1 sites | handler / pointer-sinks | 30M 截断（轮3） | `strstr:arg:0`（direct，选择不足） |
| all-escape | global / pointer-sinks | 30M 截断（轮4） | `device_release:arg:0`（**indirect** callback） |
| round1 sites | handler / value_slice=all | 60M 截断 | `kasan/ubsan/kcov` + `strcmp`（direct 插桩） |
| all-escape + `--indirect-targets` | global / pointer-sinks | 40M 截断（轮1） | **全部为 `ctx:` 节点**：`device_release`/`rpm_*`/`kobject_put` |

关键证据（all-escape + indirect 轮次）：

- Root 维度：极少数 `platform_device` 全局（`vicodec_pdev`、`vim2m_pdev`、`vimc_pdev`、`rtc_device` …）各被
  ~1.0–1.3M tuple 指向。
- Rule 维度：`STORE`(20M) + `LOAD`(12M) 主导，即这些设备指针在（已上下文化的）调用图里的 memory 闭包。
- 子集复现（5 batch，2265 context，收敛 9.8M）：`vicodec_pdev` in-degree 已达 1.44M，含 **2636 个不同的
  `AFF(base,1,1599)` 字节粒度 affine region**，全部由一个字符串常量 `.str.24.501` 指入设备结构体。
- 换 `--field-cycle iterate|drop`：总 tuple 9.8M -> 6.3M/6.0M，但 `vicodec_pdev` in-degree 仍 ~1.4–1.5M。
  **affine 只是表示形式，不是根因。**
- 2 batch 时 `vicodec_pdev` 仅 313；加入 `__vmlinux_orphan`（`kobject_put`/`kref_*`/`device_release`）后
  暴涨。放大来自设备指针流经通用设备模型基础函数，再被 global-scope 逐 callsite 上下文化复制。

结论：闭包**有限但超出 19GB**（tuples ≤ contexts × objects）；杠杆是 **context 数量（选择）**，不是 tuple
上限，也不是 affine policy，更不是可定位的单条错误边。对通用设备模型（kobject/device/kref/pm）做精确
context-sensitive points-to 本身是已知的难点。插桩函数（kasan/kcov/ubsan）在 pointer-sink slice 下不被 demand，
仅 value_slice=all 时成为额外 direct 广播。

交接前提「补齐 call/return 混合语义即可让闭包收敛」在 global scope 下被证否：call 语义是必要且已完成的，但
不充分。

## 4. 尚未决定的收敛策略（需人工判断）

1. **precision-guarded selection**：对 baseline formal 已经 fat 的 callee，其 callsite 上下文化不增精度只增复制。
   加一次 CI 预估 formal 对象集大小的 pass，跳过 fat-formal 的上下文化（自然排除 device_release/kobject_put，
   保留 strstr）。结构化、无名字过滤，但设备模型高度连通，可能仍不足以完全 bound。
2. **handler scope 作为诚实边界**：以 handler scope（~26K context，类似旧 9.37M 基线）交付 Stage A，配合已修正的
   retain-baseline + indirect 上下文化，显式报告 out-of-cone gap 为已知限制。
3. **子集验证优先**：先在一个 bounded 子系统跑通完整管线（direct+indirect）+ Step 4 gate，证明实现端到端正确与
   守恒成立，再据此精确 scope 全量选择工作。
4. **上游 fat pointer 的 field/offset 抽象**：折叠大结构体的字节偏移暴涨——但属交接明确排除的 affine/precision
   territory，且实测换 field-cycle 并不降低 in-degree。

## 5. 复现实验的命令骨架

```bash
# 全量 all-escape（选中全部 escaping direct site），产出 indirect_call_targets.tsv
/tmp/pointsto_global_stagea_o3 --sh /tmp/kernel_constraints_v3_final --out OUT \
  --batch all --unknown drop --field-dynamic strided --field-type compatible \
  --field-cycle affine --dynamic-alias none --offset-overflow drop --copy-scc on \
  --value-slice pointer-sinks --call-flow callsite --context-scope global \
  --context-objects shared --context-depth 1 --context-value-slice escape \
  --max-contexts 8000000 --max-tuples 30000000 --no-tuples --no-derivations

# 第二轮：上下文化上一轮解析出的间接目标
... 追加 --indirect-targets OUT/indirect_call_targets.tsv
```

子集根因诊断用 `--batch drivers__base__built-in.000,...,__vmlinux_orphan__.000 --value-slice all`（保留
tuples/derivations），再对 `:global:<device>` 做 root/rule/offset 分解。

## 6. Value-context (signature) 模型：已实现并验证

按 2026-07-16 决定实现「输入签名共享 context + per-callee overflow widening」：

- 新增 `--context-model callstring|signature` 与 `--context-budget N`。
- Phase 1：CI baseline 预分析（`--call-flow global`，无 context）。`Solver::forEachValueObject` 枚举
  pointer actual 的 Pt。
- `computeSignatureContexts`：对每个 direct site（含 indirect 提升的 synthetic site）按 target formal 的
  Pt 对象集算规范化签名；相同签名共享一个 context；每个 callee 超过 budget 的签名折叠进一个确定性 overflow
  context（formal 取并集，sound）。
- `materializeCallsiteContexts` 增加 signature 模式：makeKey 用 `signatureOf[siteIndex]` 作 context key；
  signature 模式下选择所有 pointer-flow in-scope site（budget 取代 escape/activity 过滤）。
- `context_signature_census.tsv` + fixpoint_stats 输出 census（原始 sites、唯一 signatures、等价合并、
  overflow functions/sites）。
- selftest 增至 50：新增同签名合并、异签名隔离、overflow 并集保流、direct/indirect 一致。

**子集实测（5 batch）**：signature 收敛 5.98M（callstring 9.8M，-39%），context 1367（callstring 2265），
3006 site → 1367 unique + 1639 merged。

**全量实测（`--context-scope global --context-model signature --context-budget 64 --value-slice
pointer-sinks`）**：

```text
CI 预分析 ci_tuples          60,000,539  (truncated=1, 即 CI 基线本身 ≥60M)
signature sites               1,001,357
  unique signatures             117,954
  equivalence_merged            635,098   # 大规模共享成功
  overflow_functions                219
  overflow_merged               248,305
materialized contexts         118,173     # vs all-escape 691,879，减少 5.9x
final tuples               60,000,762     (truncated=1)
  value_tuples                7,434,333
  memory_tuples              52,566,429   # 88%
```

**结论**：signature 模型达成其目标——把「同一 device 状态被数千 callsite 复制」从 691,879 context 压到
118,173，value tuple 也受控。但闭包**下限是 CI baseline 本身的 60M**，其中 88% 是 memory tuple。这来自
device 结构体的 field-offset / affine 字节区域爆炸（`<device>@AFF(base,1,1599)` × ~2636 区域 × devices 的
STORE/LOAD），是 context-insensitive 的，任何 context 策略都无法降到其之下。

因此 value-context 已解决 callsite 复制维度；剩余阻塞是 CI 级别的 memory/field-offset 爆炸（affine 字节区域），
属交接明确排除的 affine/precision 维度，需人工决定是否进入。此外 pointer-sink demand loop 存在 round-4
过近似（单轮从 1.2M 跳到 60M），value_slice=all 无此 round 结构但基线本身即 ≥60M。

## 7. 2026-07-16（二）修正实验前提后的实测

按修正后的固定步骤重做，全部实现并通过 50 项 selftest：

1. **actual-demand CI prepass + 收敛门**：新增 `Solver` 的 `demandForcedOnly` 模式，只 demand 所有 pointer
   actual 的 backward slice；driver 跑该 demand loop，要求 `pending=0 && truncated=false`，否则抛错拒绝生成
   signature（不再用截断 Pt）。
2. **exact object-set 判等**：signature 用完整排序对象集合判等（`ActualSignature` + unordered_map），hash 仅
   分桶。
3. **affine subsumption canonicalization**：新增 `--affine-canon none|subsumption`；`internAffine` 在
   subsumption 下把每个 region 规范化为其 (root, stride, congruence) 类在对象全 extent 上的极大 region，
   使被包含/同余重叠 region 塌缩到同一 ObjKey（tuple index 去重）。sound（只 widen）。
4. **affine overlap/subsumption census**：`affine_region_census.tsv` 输出每 root 原始/subsumed/retained region。

**关键实测（子集 5 batch，CI value_slice=all）**：

```text
                 total_tuples   vicodec in-degree   distinct AFF regions   concrete-offset tuples
affine=none         5,175,054           1,039,494                  3,198                976,735
affine=subsumption  4,500,727             976,765                      1                976,734
```

- affine canonicalization **确实生效**：vicodec AFF regions 3198 -> 1，全量 67,396 次 canonicalize，总 tuple
  -13%。
- 但**主导成本是 concrete 字节偏移 tuple**（vicodec 976,734，几乎不变）。`--field-dynamic drop` 只从 976,765
  降到 972,125（≈0），证明**不是 strided 展开**。
- 分解：vicodec 被 **2,533 个 value** 指向，覆盖 **3,200 个不同 concrete 字节偏移**（即 [-1600,1599] 全 extent
  的每个字节）。来自 container_of（device 内嵌于多种 container 类型 -> 多负偏移）+ 字段访问，`offset-overflow
  drop` 裁剪到对象范围。

**结论修正**：actual-demand prepass 在全量仍 truncate（value_tuples 59.8M / pending 9.65M / 60M cap），故按门禁
**拒绝生成 signature**。真正的下限不是 affine（已被 canonicalization 塌缩），而是**大结构体（device）上字节粒度
concrete field-object 的增殖**——每个字节偏移都物化成独立 object，乘以数千 value。这属 field-sensitivity 粒度
问题，affine canonicalization 不覆盖，减小 strided 展开也无效。

## 8. 2026-07-16（三）location-sensitive subobject policy

再次修正前提：concrete byte-offset **不是**不可避免的 floor，而是**对象位置语义过宽**。证据：`vicodec_pdev` 是
size 1600 的完整 `struct platform_device` global（vicodec-core.c:77），合法 root-relative offset 应为 [0,1599]，
但闭包里出现了 [-1600,-1]。原类型门（现 pointsto_global.cpp:3785）只检查“root 任意位置是否包含该 struct”，不
验证当前 offset 是否正好落在该 subobject，于是 container_of/GEP 从错误位置反复应用。

实现（solver-only，第一档）：`--field-location root-wide|subobject`。subobject 下，已知大小 root 的最终 concrete
与 affine offset 严格限制到 [0,size)；负最终 offset 视为指向分配之前的非法访问被拒绝；未知/incomplete 大小 root
保守不裁剪。新增 `offsetLowerBound`、`location_rejected_offsets` 统计。selftest 增至 54（负偏移拒绝、container_of
回 @0、同类型多成员保持不同位置、unknown layout 不误删）。

**5-batch 实测（CI value_slice=all，affine=subsumption）**：

```text
                 total_tuples   vicodec in-degree   neg_offsets   pos_offsets   location_rejected
root-wide           4,500,727             976,765          1600          1600                   0
subobject           1,890,784             460,965             0          1600               7,683
```

- subobject **移除全部 1600 个非法负偏移**，总 tuple -58%，vicodec in-degree -53%。**「concrete byte offset 是
  真实 floor」的结论被推翻**：负偏移是位置过宽的 over-approx。
- 残留：仍有 1600 个**正**字节偏移（[0,1599] 每个字节）。这是 typed GEP 在每个 offset 都能应用的问题，需要
  points 1-3 的完整 subobject 布局类型（DataLayout/DWARF 的 offset->type->parent），属 extractor 侧数据。

**全量两个独立下限**：

1. **device field-offset 过宽**：负偏移已由 subobject 修掉（局部 -58%）；正偏移残留需完整 subobject 布局类型。
   全量 value_slice=all CI（subobject+subsumption）仍 >55M（约从 ~130M 减半），但 value_slice=all 含
   KASAN/KCOV/UBSAN 路径，是最坏情形。
2. **prepass 的 CI call 广播**：actual-demand prepass 加不加 subobject，round-1 都截断在同一 value_tuples
   (59.857M)——因为 prepass 是 **CI**（无 context），其 round-1 爆炸主要来自 shared-return 的 **CI call 广播**
   （strstr 类），而不是 device field-offset。subobject 修的是 field 维度，修不到 call 维度。这暴露一个 bootstrap
   张力：signature 需要 CI Pt（prepass），但 CI Pt 恰恰带有 signature model 要消除的 call 广播。

下一步候选（均需人工定夺）：(a) 完整 subobject 布局类型化以裁掉正偏移残留（extractor 改动）；(b) 解开 prepass
bootstrap（例如 prepass 也用 callsite/signature、或用不含 shared-return 广播的更弱 Pt 抽象来定签名）。

## 9. 2026-07-16（四）两阶段 bootstrap（无循环依赖 Pt）

按决定实现两阶段，避免“更弱 CI Pt 当 exact signature”：

- **Phase 0 bounded callsite bootstrap**（`computeBootstrapContexts`）：无 CI prepass；每 callee 前 B 个
  pointer-flow site 各占 dedicated context，其余进 deterministic per-callee overflow（输入并集）。selected
  site 禁用 baseline call transfer，故无 strstr 类直接广播。
- **Phase 1 exact signature**（`computeSignaturesFromBootstrap`）：从收敛的 Phase 0 读每个 context 的
  contextual formal 完整 Pt 生成 exact signature；同签名 bootstrap context 合并；overflow 保持并集；re-load
  一个全新 database 用 signatureOf 独立重跑最终 Pass。新增 `Database::contextInfo`、`siteContextId`、
  `runSolveLoop`/`loadDatabase` 因子化、census（bootstrap_* / exact_signature_* / final_*）。selftest 增至
  60（bootstrap 无 prepass、Phase0 无广播收敛、overflow 并集、同/异 formal 集合并/隔离、mapping 确定性）。

**子集实测（5 batch）**：Phase 0 收敛（bootstrap_pending=0, truncated=0，tuples 3514，sites 3006 →
dedicated 2928 + overflow_fns 3/78 sites）；Phase 1 exact_signature_contexts=839，equivalence_merged=2092，
final 收敛。broadcast-free Phase-0 Pt 比旧 CI prepass 合并更多（839 vs 1360 unique）。**两阶段在子集上成立。**

**全量实测**：Phase 0 仍在 round-1 截断于 60M（pending 58.16M，19.6s）。根因是**间接广播**：不带
`--indirect-targets` 时 indirect callback（device_release 类）用 baseline formal → 广播。带上一轮 CI 的
`--indirect-targets`（7329 promoted）后，Phase 0 内部仍 resolve 出 14359 个 indirect target，未覆盖的 ~7000 个
继续广播 → 仍截断。这构成 direct/indirect/field 三者互相依赖的**循环 bootstrap**：完整 indirect 目标需要收敛
的一轮，而收敛又需要完整目标。此外 bootstrap B=64 在全量产生 347,507 dedicated context，materialize/solve 很重
（峰值 ~10.5GB）。

**整个 Stage-A 阻塞的分层总结（每层都已实现并局部验证）**：

| 维度 | 状态 |
|---|---|
| direct call 广播（strstr 类） | 已修：hybrid 语义 + 上下文化 |
| indirect call 广播（device_release 类） | 已修（对 promoted 目标）；但**完整 promotion 循环依赖** |
| fat pointer 的 context 复制 | 已由 value-context signature（两阶段 bootstrap）处理 |
| affine 字节区域增殖 | 已修：subsumption canonicalization（vicodec 3198→1，全量 98% subsumed） |
| device 非法负偏移 | 已修：subobject location [0,size)（5-batch -58%，移除全部负偏移） |
| device 正偏移残留（每字节） | **未修**：需 extractor 侧完整 `Subobject(root,offset,type,parent)` 类型 |
| 完整 indirect 目标 | **未修**：循环 bootstrap |

因此全量收敛的两个真实剩余阻塞是：(a) **完整 subobject 布局类型化**（extractor 改动，裁掉每字节正偏移）；
(b) **完整 indirect 目标解析**（打破 direct/indirect 循环，例如一次性 function-pointer-only 解析，或迭代到
不再发现新目标）。当前 `--field-location subobject` 只是合法 allocation bounds 第一档，非完整 subobject 模型。
所有代码（60 selftest）已就绪，缺的是这两块数据/收敛层。

## 10. 2026-07-17（五）单调 target-frontier 迭代（打破循环 bootstrap）

按决定实现**单调 target-frontier 迭代**（不写“只追踪 function object”的弱分析）。核心是**发现模式
(discovery mode)**：每轮 `wireIndirect()` 永远记录 CallTarget，但只为**已 promoted pair**接通 contextual
actual/return；**未 promoted pair 只记录、DEFER（不接 baseline arg/return）**，从而不产生 device_release 类
间接广播，每轮保持有界。deferred pair 构成 frontier，下一轮 promote 后其参数流可能发现更深层 target；因为流
只增不减，target 集单调增长且有限 → 固定点。

**实现（`pointsto_global.cpp`，全部含 selftest）**：
- `Solver` 增 `discoveryMode_`；`wireIndirect` 在 contextualized 分支后增 discovery defer 分支
  （`deferredIndirectPairs_` + `stats.deferredIndirectPairs`）。新增 `indirectTargets()` / `deferredIndirectPairs()`
  访问器。
- `Database::promoteIndirectPairs(vector<pair<string,string>>)`：从**字符串身份**（callsite 名 + 目标 object 名）
  promote，`loadResolvedIndirectTargets` 重构为其文件读取壳。字符串身份使 TN 在每轮 fresh database（interned
  整数 id 不同）间保持稳定。
- `runIndirectBootstrap()` 驱动：每轮 fresh DB → `promoteIndirectPairs(TN)` → `computeBootstrapContexts`
  （bootstrap 上下文，无 prepass、不依赖 direct activity 文件——signature 模式绕过 escape/activity 过滤，故
  **无循环依赖**）→ discovery-mode `runSolveLoop` → 收集 discovered、`new = discovered \ TN`、`TN ∪= new`。
  产出 `indirect_target_bootstrap.tsv`（round/promoted_in/targets_seen/new_targets/deferred_pairs/tuples/
  pending/truncated）与最终完整 `indirect_call_targets.tsv`。
- **完成判据**（`indirectBootstrapComplete`）：`new_targets==0 && deferred==0 && pending==0 && !truncated`。
  任一轮 `truncated || pending>0` → 拒绝（返回 2），并 dump `truncated_hotspots.tsv` 等诊断。
- selftest 增至 **67**（+7 discovery）：未 promoted 只记录不广播、promoted 后 contextual 生效、嵌套目标下一轮
  发现、target 集单调、固定点确定、overflow 上下文 defer、完成判据。

**关键新发现（全量 round-1 截断的真因，不是间接广播）**：把间接完全 defer 后，全量 round-1（promote=0）**仍**
截断于 30M。dump `truncated_hotspots.tsv` + derivations 定位：~7677 个全局内存 cell 各持有**恰好 7677** 个对象
（一个 7677 大小的并集广播进所有 cell）。derivation 链自底向上为 `&key`(ADDR_OF) → callsite arg:2(FIELD_ADDR)
→ **`lockdep_init_map_type:arg:2` 经 CALL_ARGUMENT 进 `ctx:232`** → STORE 进多个全局 cell → LOAD 回来 → 7677 团。
`ctx:232` 是 `lockdep_init_map_type`（约 7677 个 callsite 的 mega-fan-in 工具函数）的 **overflow context**：B=64
只 dedicate 64，其余约 7600 callsite 的不同 `lock_class_key` 全并进一个 overflow formal → 7677 key 并集经
store/load alias 团广播 → 7677² ≈ 59M。**即 bootstrap overflow bucket 自身对 mega-fan-in 工具函数重新引入了
direct 广播**（两阶段“direct 已修”只在小 fan-in 子集成立）。

**修复（direct 版的 defer，与用户 indirect defer 语义对称）**：`computeBootstrapContexts` 增 `overflowSiteMask`
输出；`materializeCallsiteContexts` 增 `deferFlowSites`，在 `wireDirectContext` 中对 overflow site **跳过 arg/return
copy**（site 仍在 `contextualDirectSites` → baseline 仍禁用 → 无 CI 广播；formal 空 → 无 overflow 并集广播）。
callee body clone 仍在（由其 dedicated 上下文分析）。函数指针 dispatch 主要经**内存**（&func 存入 ops 表）到达
indirect site，不受此 defer 影响。新增 selftest “overflow context deferred”。

**全量实测（`--context-budget 64 --field-location subobject --affine-canon subsumption --max-tuples 30M`）**：
- round 1：promote=0 → targets_seen=7582，new=7582，deferred=13800，tuples **395,735**，pending=0，truncated=0
  （对比修复前 30M 截断）。
- round 2：promote=7582 → targets_seen=7923，new=**341**，tuples 584,011，pending=0，truncated=0。
- new_targets 7582 → 341 迅速收敛；tuples 保持 <1M。迭代进行中（更新见下）。

（注：`targets_seen` 按 callsite 名去重的**逻辑** pair 数；`deferred_pairs` 计 context-clone 级去重事件，故
后者略大。round-1 的 7582 逻辑目标已超过上一轮不完整的 7329 promoted。）

**round-3 再次截断——第三类广播（context 链塌缩，非 fan-in）**：round 3（promote=7923）截断于 30M
（pending 10.6M，new=904）。dump `truncated_hotspots.tsv`：node 热点全是 runtime-PM 链
（`rpm_resume/rpm_suspend/__rpm_callback/__rpm_put_suppliers/rpm_idle/serial_port_runtime_*`），root 热点是
`platform_bus`（in-degree **95,441**）与数千个 `*_i2c_driver`/`*_driver`（各约 **86,700**）。derivation 链
（自底向上）：`&vim2m_pdev`(ADDR_OF) → `platform_device_unregister:arg:0` → FIELD_ADDR `@16`(&pdev->dev) →
`device_del:arg:0` → `device_pm_remove` → `pm_runtime_remove` → `__pm_runtime_disable` → `rpm_resume:arg:0`
→ `rpm_suspend:arg:0`，全部 arg:0，单个 K=1 context 汇聚 **4908** 个 device。

根因是 **K=1 context 链塌缩**：设备指针沿 device-model / PM 这条 ~7 跳深的直接调用链传播；每跳的 callee 只有
少数 callsite，K=1 下其 context 仅由**紧邻 callsite**决定，故上游所有携带不同 device 的 caller context 在该
callee 处**合并**。这与已修的 fan-in overflow（单 callee >B callsite）**不同**——是少 callsite、多 caller
context 的链式合并，overflow defer 抓不到。触发时机是 round-2 promote 了 PM/device 间接回调后，contextual 流把
device 指针接进了 PM 链。

**关键推论**：完整 indirect 目标**不足以**保证 Phase 0 收敛——这条 K=1 链塌缩 device 合并对**最终 Phase 0
同样成立**（不是 discovery 特有）。因此除了 (a) subobject 正偏移、(b) indirect 完整性，还存在**第三个正交阻塞**：
(c) 深调用链上 device/driver 指针的 K-limited context 链塌缩合并。用户已明确禁止靠提高 max-tuples 或 K 掩盖
context mismatch，而 signature/bootstrap 模式下现有 adaptive refinement（refineMinContexts）不生效（signature
模式的 `makeKey` 直接用 signature id、跳过 call-string 与 refinement），故该链塌缩需要新的结构化处理。

**进展小结**：单调 frontier 迭代**已实现并跑通前两轮深化**（7582 → +341），并**新定位并修复了一类直接
overflow 广播**（lockdep_init_map 类）。frontier 在 round 3 暴露的是**第三类、更深的 context-链塌缩阻塞**，它
横跨 discovery 与最终 Phase 0，是一个需要用户定夺的战略分叉（如何在不掩盖 context mismatch 的前提下界定
device-model 深链合并）。所有代码 67 selftest 通过，二进制 `/tmp/pointsto_global_stagea_o3` 为最新。

## 11. 2026-07-17（五）完整性修正 + context-merge census（诊断先行）

按用户决定：先修完整性洞，再做一次 census-only 分析定位 merge，然后据结果决定 selective refinement。

**(A) 完整性修正**：direct overflow deferral 是**无 promotion/recovery 的 under-approximation**（不同于 indirect
frontier 的 promote-next-round）。新增 `counts.deferredDirectSites/Transfers`；census 增 `deferred_direct_sites`
`deferred_direct_transfers` 两列；完成判据收紧为 `new_indirect=0 ∧ deferred_indirect=0 ∧ deferred_direct_transfers=0
∧ pending=0 ∧ ¬truncated`（selftest 增 deferred-direct 用例，共 67）。含义：只要还在 defer direct flow，frontier
就**不能**声称 complete——这只有当 selective refinement 取代 deferral 后才归零，是诚实记账。

**(B) context-merge census（`--context-merge-census`，无 solver、无 tuple closure）**：materialize bootstrap
context 图并捕获 transition 图（新增 `Database::captureTransitions_`/`capturedTransitions`），对每个 callee context
统计 incoming_transitions / distinct_caller_contexts / distinct_static_sites / distinct_parent_tokens /
pointer_formals / bootstrap_overflow，并静态模拟 K1/K2/K3（K2=K1+父 token，K3=+两级父 token），输出
`context_merge_census.tsv` + `context_merge_summary.tsv`。峰值仅 ~3GB、秒级。

**全量 base-graph census 结果（无 indirect promotion）**：
- contexts=342,062，transitions=3,425,538，bootstrap_overflow_sites=660,197。
- K1 max caller-context in-degree=**60,125**，merged=198,819；K2 total=2,043,704（max in-degree 1）；K3 total=9,256,426。
- in-degree 直方图**重尾但集中**：in-degree≥128 仅 367 个 context，≥1024 仅 98 个，≥16384 仅 17 个；其余
  ~175K merge point 都是 in-degree 2–7 的轻微合并。

**关键判定（推翻“chain-collapse=高 context in-degree”模型）**：in-degree≥128 的 367 个严重 merge **全部是
overflow context**（`bootstrap_overflow=1`），且 `distinct_static_sites ≈ distinct_caller_contexts`——即**纯 fan-in**：
`__kasan_check_write`(in=60125,sites=41263)、`__sanitizer_cov_trace_switch`、`_printk`、`_raw_spin_lock/unlock`、
`mutex_*`、`kfree`、`__kmalloc_*`、`lock_acquire/release` 等通用工具/插桩函数。**没有一个是 chain-collapse
（sites≤4）**。对这些，K2 的 `parent_tokens == in_degree`（每个 caller 一个 token）→ 精化=逐 caller 爆炸，正是要
避免的；故 **selective parent-token refinement 对 severe 合并无效，deferral 才是对的**。

**带 promotion 复跑 census（7923 partial targets）确认**：contexts 342K→348,778（仅 +6.7K），K1 max in-degree
60,902（仍是 utility overflow），severe tail 依旧全 overflow。**PM 链核心函数 `rpm_suspend`/`rpm_resume`/
`__rpm_callback`/`device_pm_remove` 根本不在 merge 表里（context in-degree ≤ 1）**；所有 runtime-PM 函数中最高的
`__pm_runtime_resume` 也只有 in-degree=579（sites=276，偏 fan-in）。而 round-3 solve 里 `rpm_suspend` 的**单个
context** 的 arg 却装了 **4908 个 device 值**。

**据此定论（诊断结果，非猜测）**：
1. **selective parent-token refinement 不是解**——严重的 context in-degree 合并（≥128 的 367 个）**全是 overflow
   utility**（kasan/printk/lock/alloc），K2 精化=逐 caller 爆炸；deferral 已是对的。census 未支持 refinement，反而
   证伪了它。
2. **round-3 PM 崩塌是值级合并，不是 context 级**：`rpm_suspend` 只有 1 个 context（in-degree≤1）却汇入 4908 个
   device 值——K=1 把深链上游所有 device 漏斗进这唯一 context 的 arg。要分开需 K≈7（链深）或 per-device
   value-context（~5000 context）→ 两者都爆炸。context-merge census（测 context in-degree）**结构上测不到**它。
3. 因此 fix 方向**不在 parent-token refinement**，而在值级：候选是 (a) 用户备选的 **lazy value-context**（按 device
   值分 context，但 ~5000 device → 需 lazy/选择性否则爆炸）；(b) 认识到 **device 值流经 PM 链 body 对 target
   discovery 冗余**（PM 回调 target 在 ops 表里、经 memory 可达；深链 body 对 dev 的大量字段访问与发现目标无关），
   据此像 overflow deferral 那样**界定喂入间接 dispatcher 的 direct 值流**；(c) 收紧 demand slice，只跟 pm→suspend
   字段链而非整个 device。

census 实现：`--context-merge-census`（无 solver），产出 `context_merge_census.tsv`（每 merge context 一行）+
`context_merge_summary.tsv`（K1/K2/K3 + 直方图）。二进制 `/tmp/pointsto_global_stagea_o3`，67 selftest。分析目录
`/tmp/kernel_pt_mergecensus`（base）、`/tmp/kernel_pt_mergecensus_pm`（带 promotion）。

## 12. 2026-07-17（五）selective/lazy value-context（按诊断结果实现）

用户据 census 选 lazy value-context。关键机制：**callsite-signature-context 单独无法拆开 PM 合并**（`rpm_suspend`
的少数 callsite 各自已传入合并后的 device 集，合并发生在**上游**），故 value-context 集合必须**沿值流向上游生长**
到 device 仍可区分处。实现：
- `Solver::valueMergeFunctions(threshold)`：返回任一 value 的 points-to > threshold 的**属主函数**（在截断的
  solve 上正是爆炸的 merge 点；因 discovery 的 overflow deferral 让 utility formal 为空，故只检出 PM/device 链而非
  kasan/printk 等 utility）。
- `buildActualSignature` 抽出复用；`computeBlendedContexts(db, ci, valueContextFns, budget, …)`：value-context
  callee 的 site 按 actual 对象集签名（bounded budget，overflow 并集）分 context 并**从 overflow mask 移除**（携分裂
  流而非 defer），其余 site 保持 bootstrap；签名 id 占不相交高区间。
- frontier 内层 refine 循环：iter0 bootstrap；截断则 `valueContextNames ∪= valueMergeFunctions ∪ 其 pointer-flow
  callers`（向上游生长），在**同一 db** 上算出 per-site context（site index 跨相同 load 稳定）再应用到下一个 fresh
  load——始终只驻留一个 db。集合按**函数名**持久化跨 round 单调增长。completion 判据已含 `deferred_direct_transfers=0`。
- selftest：value-context blend 按不同对象集分裂、空集回退 bootstrap、wide formal 检测（共 70）。
- CLI：`--value-context-refine --value-context-threshold N --value-context-max-iters K`。

**全量实测（负结果，重要）**：`/tmp/kernel_pt_indboot_vc`。round 1/2 照常收敛（deferred_direct_transfers
2.27M——诚实记账生效，未 complete）。round 3（promote=7923）iter0 仍截断 30M（pending 10.6M），vc-refine 一步把
value_context_fns 涨到 **14,227**、仅 11,661 签名 context（即多数函数只得**单一合并签名**）；iter1 **更差**：
截断 30M（pending **14.3M**），value_context_fns 涨到 **40,669**。**发散**，遂 kill。

**根因（callsite-signature value-context 结构性失败）**：
1. **过度生长**：在**截断**的 solve 上 `valueMergeFunctions` 因一切已合并而返回上千函数，一步吞掉大半可达函数；
2. **无法分裂**：签名取自截断 solve 的 actual points-to，而那已是**合并后**的集合 → 同一签名 → 不分裂；
3. 于是每轮只**增加合并 context**而不拆分 → 严格变差、无界增长。

**结论**：callsite-input 签名的 value-context（即便迭代、即便向上游生长）**无法从已合并的 solve 里自举出分裂**——
分裂要求上游对象仍可区分，而这正需要**对象敏感（object-sensitivity）**：context = 接收者对象（分配点），在定点
求解**过程中按对象按需**创建，从对象仍可区分的源头开始保持分离。这是 solver 定点结构的改动（比现有 callsite-
context 机制大），不是 callsite-signature 能替代的。且不存在“先收敛再据以分裂”的捷径：任何带 PM 流的 bounded
solve 都会截断（round 3），构成 merge↔split 的循环。

代码（`--value-context-refine` + `computeBlendedContexts`/`valueMergeFunctions`，70 selftest）保留为该结论的可复现
证据；机制本身（selective signature blend）正确，但对**上游合并**这一类无效。下一步是真正的 selective
object-sensitivity（solver 内建），或转向 affine/memory 轴（截断实为 device 存入共享 affine 区的 quadratic）。

## 13. 2026-07-17（五）affine/memory multiplier 诊断（诊断先行，非猜测）

用户判定：先确认 4908 device 合并发生在 **call context 之前**还是 **affine memory cell 内**——若已困在同一抽象 cell，
object-sensitivity 也拆不开。实现只读 `--affine-memory-census`（gated instrumentation，无 solver 修改语义）：
- `internAffine` 记录每 canonical cell 的 pre-canon (base,bound) 集合（`canonicalized_from_count`）。
- store/load 循环记录每 affine cell 的 store/load 值+source（provenance）。
- `addTuple` 计数 affine-node/affine-derived tuple（穿过 affine cell 的比例）。
- `writeAffineMemoryCensus`：每 cell 一行（region_cardinality/canon_from/store_sites/load_sites/distinct_store_values/
  distinct_loaded_values/**distinct_store_roots**/memory_tuples/provenance），并汇总 widened/wide_root/derived。

**复现 round-3（promote 7923 partial，一次性）并对照 canon=subsumption vs none（30M 截断，pending 10.63M，两者
tuple 完全一致 30003865/30003776）**：

| affine-canon | cells | widened(canon_from>1) | affine_node_tuples | affine_derived_tuples | max_store_roots |
|---|---|---|---|---|---|
| subsumption | 232 | **1** (max canon_from=2) | 141 | 33 | 32 |
| none | 195 | 0 | 35 | 34 | — |

**结论（对照 #1 决定性）**：affine memory cell **不是** multiplier——30M 中仅 ~33–141 tuple 穿过 affine cell
（≈0.0006%）；subsumption **几乎不 widen**（232 cell 中仅 1 个 canon_from>1，max 2），且开/关 subsumption 截断点
**完全一致**。故用户决策树的“canonicalization 过度合并”和“affine may-alias cell 身份丢失”两支**均被排除**；不是
affine/canon 轴。

**真正的 30M 结构（hotspots）**：`node` 维 top 全是**值 formal**（`rpm_suspend:arg:0`=4908 device、`__rpm_callback:arg:1`
=4852…）；`root` 维 top 是 ~6 个 media/usb **platform_device**（vim2m_pdev/vivid_pdev/vimc_pdev/vicodec_pdev/platform_dev）
各出现在 **~1.10M** 个 tuple 里；derivation 链是纯 CALL_ARGUMENT 深链（device→platform_device_unregister→device_del
→device_pm_remove→pm_runtime_remove→__pm_runtime_disable→rpm_resume→rpm_suspend），夹杂 concrete STORE/LOAD。

**扩展 census 至 concrete cell（`distinct_store_roots` 由 cell points-to 直接算，provenance 由 cell tuple 的 source
读出，均无热路径插桩）**，定位到**concrete-memory clique**：memory_cells=7099，其中 **5937 个 concrete cell 持有
≥64 distinct root（max 1267）**；top clique cell 全是 `platform_dev/*_pdev@416/@424/@432/@440`（嵌入 struct device
的连续指针字段），各持 **~1175 distinct root / ~2113 tuple**。

**provenance 决定性（对照 #3）**：所有 top clique cell 的 store 只来自**极少数常量**——`memory_constraints.tsv:3115`
= **`__kobject_del` 在 offset 8 的 STORE**、`:5067` = **`rb_erase`（红黑树删除）在 offset 8 的 STORE**（`node->rb_link=other`）。
即：**通用容器操作**（rb_erase / __kobject_del）通过其被合并的指针形参写内部字段。当 device 流把 ~1175 个
platform_device 在某 device-cleanup formal 合并后，它们内嵌的 rb_node/kobject 经**单个 dedicated callsite**流进
rb_erase，store `node->@8=other` 把 1175 个互相连接 → **~1175² 二次爆炸**，摊到数千 concrete cell。

**最终定论（回答用户核心问题）**：4908/1175 device 合并**发生在 call context**（device 对象在 device-model/PM
函数 formal 上合并），**不在 affine memory cell 内**（affine 0.0004%）；随后经 concrete 容器 store（rb_erase/kobject_del）
放大成二次 clique。按用户决策树：规则 1（canonicalization）、规则 2（affine 身份丢失）**均排除**；canon=none 下爆炸
**完全一致**（真 may-merge，非 canon artifact）→ **规则 3：object-sensitivity**；且不能按 distinct source 拆 store
（规则 4）。**object-sensitivity（按接收者 device/container 对象分 context）既治本（call-context 合并）又打断二次
clique（1175²→1175），是唯一 sound 且能真正缩小 30M 的修法**——但为 solver 内建的最大改动。诊断二进制
`/tmp/pointsto_global_stagea_o3`（`--affine-memory-census`，70 selftest）；产物 `/tmp/kernel_pt_affmem_{sub,none}`、
`/tmp/kernel_pt_memclique{,2}`。

## 14. 2026-07-17（五）on-demand object-sensitivity：设计 + P1（静态基座）

按用户决定实施 on-demand object-sensitivity，先写设计再改 fixpoint。设计见
`object-sensitivity-design.md`（已按用户 review 修正：SHARED_UNKNOWN 仅收显式 ObjectKind::Unknown、
root@DYN/affine 保留 concrete root、baseline 与 SHARED_UNKNOWN 各自独立 id、ReceiverFormal 用跨过程反向
不动点、templateComponents 只用 owner=F 的非 call intra copy SCC、callsite 作为 call template 由 on-demand 协议
连接）。识别、动态 NodeKey、receiver-watch 方向经用户确认正确。

**P1（静态基座，未改生产 fixpoint）已完成，当前 82/82 selftest 通过**：
- `Database::computeReceiverFormals()`：deref base（field/load/store/indirect-callee 的指针操作数）→ 同 owner
  非 call copy 的 LocalDeref 反向闭包 → 沿 direct-call 实参转发做**跨过程反向最小不动点**（转发 wrapper 正确判为
  receiver）。产出 `receiverArity[F]`、`receiverFormalIndex[F]`（arity==1 才给 unique index，即 V1 gate）。
- `ObjectContexts` interner：`(callee, receiver_formal_index, receiver_root)` → context_id；id 0 保留 baseline、
  SHARED_UNKNOWN_ROOT 走 per-(F,i) 独立 union id、concrete root 走各自 id、同 key 全局复用。
- `Database::computeObjectSensitivityTemplates()`：只为 unique-receiver 函数构建 per-function、call-free copy SCC；
  仅同 owner 的普通 `COPY` 参与，`CALL_ARGUMENT`、`CALL_RETURN` 和 cross-owner copy 均不能跨模板合并；同时记录
  component representative、component 间 copy edge 和 function-local stack-object ordinal。
- `ObjectContextNodes`：按已 intern 的 ObjectContext 分配连续节点区间，维护 `nodeContext` 与 baseline origin；owned
  value 映射到 `(template_component, context_id)`，shared/global value 保持 baseline node。
- synthetic eager-materialization fixture：两个 receiver root 经过相同的 outer→middle→leaf 静态 forwarding chain，
  小型 copy fixpoint 验证两个 root 在每层 context node 中保持隔离；fixture 不读取任何全量或截断 baseline 结果。
- 新增 7 项 P1 回归：local copy-SCC collapse、排除 call copy、排除 cross-owner copy、component/stack template、
  deep forwarding isolation、node context/origin、shared baseline。原有 75 项全部保持通过，合计 **82/82**。
- 已接入 `loadDatabase`：每次 load 依次计算 receiver fixpoint 与 object templates，并输出 `[receiver]`、
  `[object-template]` census。

**全量 receiver 选择实测（scale 验证，非退化）**：receiver functions=**135,079**，unique_receiver=**79,749（59%）**
（V1 object-sensitive），multi_receiver=**55,330（41%）**（保留 bootstrap union，按要求单独记账）。

**当前边界**：P1 只完成静态模板、节点身份和 synthetic isolation 验证，生产 Solver 的 worklist 尚未使用
ObjectContextNodes，因此 full-kernel 30M/60M 截断尚未被实际消除。下一步是 P2 on-demand（receiver watch +
`ensureReceiverContext` + `instantiateTemplate` + tuple replay）；随后 P3 把 indirect `(target, receiver_root)` 合入
同一 fixpoint 并移除 single-receiver bootstrap/deferral，P4 再跑 5-batch、round-3 和全量 closure gate。当前二进制
`/tmp/pointsto_global_stagea_o3` 已重新编译并验证 **82/82**。

## 15. 2026-07-17（六）P2 接口审计 + unified SolverNodeArena

开始 P2 前先完成动态节点与调用流接口审计，结论写入 `object-sensitivity-design.md` §4.4。审计确认 P2 不能直接
把 `ObjectContextNodes` 接进现有 worklist：旧 Solver 用 `node < valueCount_` 判断 value/memory，并用
`valueCount_ + memory_index` 生成 memory node；memory cell 已在 solve 中动态创建，再插 context node 会造成编号冲突
或错误分类。因此节点命名空间必须先结构化，不能靠调整 `valueCount_` 兼容。

**接口结论**：
- 单一 append-only node arena，显式区分 `BaselineValue / ContextValue / Memory`；memory index、context id、origin、
  core 均来自 node metadata，不再由 node id 算术推导。
- memory 与 context node 可以在同一 solve 中交错创建；保留 `memoryNodeByIndex` 反向映射供 alias、memcpy、输出使用。
- 动态模板不能直接复用 `build()` 的批量插边：除了 `addCopyEdge` 已有 replay，field/dynamic/strided/load/store、
  memcpy watch、indirect watch 都必须抽成“安装时 replay 历史 tuple、之后接收未来 tuple”的增量 API。
- 调用流单位必须是 `CallInstance=(kind, static_site, caller_context, target?)`。同一静态 site 在 baseline 和每个
  caller object-context 中是不同实例；receiver wiring 去重键必须包含 caller context。
- P2 runtime transfer 需要记录 solver node id + original value id，不能依赖旧 callsite-context 方案生成的 synthetic
  `Database::values` clone。

**第一个 P2 基础切片已实现（无求解语义变化）**：
- 新增 `SolverNodeArena`，baseline value、未来 context value 和 memory cell 使用统一 append-only id 空间。
- Solver 的 memory 创建、dynamic/affine alias、load/store、memcpy、tuple census、输出、render、root-handler 统计已全部
  改为显式 node metadata / `memoryNodeIds_`；代码中不再存在 `valueCount_ + memoryIndex`、`node-valueCount_` 或
  `node < valueCount_` 的 memory 分类。
- 新增交错分配回归：`memory → context block → memory` 后 kind、memory index、context、origin、core 全部保持正确。
- 当前重新编译成功，**83/83 selftest 通过**（原 82 项无回归）。

**当前边界**：生产 Solver 尚未创建任何 object context node，也尚未安装 receiver watch。下一切片严格限定为把
field/dynamic/strided/load/store/memcpy/indirect-watch 的 build-only 逻辑抽成可 replay 的增量 installer；完成并测试后，
才接 template constraint index 和 direct `CallInstance + ReceiverWatch`。

## 16. 2026-07-17（七）P2 incremental installers + historical replay

第二个 P2 基础切片完成：将动态 context 实例化所需的所有非 copy 约束从 `build()` 批量逻辑抽成增量 installer，
并保证“晚安装 edge/watch”不会漏掉安装前已经存在的 tuple。

**实现结构**：
- `build()` 与未来 `instantiateTemplate()` 共用 `installFieldEdge`、`installDynamicFieldEdge`、
  `installStridedFieldEdge`、`installLoadEdge`、`installStoreEdge`、`installMemoryCopy`、
  `installIndirectWatch`，不存在绕过 installer 的第二条 Solver edge 创建路径。
- 每种 installer 先把 edge/watch 挂入对应 head，再遍历源节点当前 tuple 调用其 `apply*`；正常 worklist 处理未来
  tuple 时调用相同 `apply*`。因此历史 replay 与未来传播使用完全相同的 field/type/offset/affine/demand/call 语义。
- 原内联 solve 循环拆成 `processTuple()` + `drainWorklist()`；遍历 edge 时先保存 `next`，允许 `apply*` 过程中
  新 context/edge 导致 vector 扩容，且新 edge 自己负责 replay 当前 tuple。
- memcpy 不再把 runtime state index 假定为 `db.memoryCopies[index]`。`CopyState` 自带 `size/source`，
  `installMemoryCopy` 可为未来 context template 动态创建独立 dst/src watches 和 transfer state。
- indirect watch 现在也支持安装时 replay：callee node 已经持有 function tuple 时，watch 会立即调用同一
  `wireIndirect`；watch 安装后出现的新 function tuple 继续由 worklist 触发。

**回归**：新增 late-install fixture，在 tuple 已存在后依次安装 field、dynamic field、strided field、load、store、
memcpy 和 indirect watch，并在安装后继续加入新的 root/target；同时验证历史 tuple 被补传播、未来 tuple 继续传播、
memory copy 与 indirect actual→formal 均闭合。当前重新编译成功，**84/84 selftest 通过**，原 83 项无回归。

**当前边界**：生产 Solver 仍未物化 object context。下一切片是给 `ObjectFunctionTemplate` 增加 address/field/
dynamic/strided/load/store/store-object/memcpy 及 outgoing call-template 的 constraint index，然后让
`ObjectContextNodes` 使用 `SolverNodeArena` 分配真实 context block；完成 body 实例化测试后才安装 direct
`CallInstance + ReceiverWatch`。

## 17. 2026-07-18（一）完整 ObjectFunctionTemplate + real context body

第三个 P2 基础切片完成：`ObjectFunctionTemplate` 已从 copy-SCC 骨架扩展为完整的 function-body/call-template
索引，Solver 可通过 `SolverNodeArena` 实际创建 object context body；仍未安装生产 receiver watch。

**完整静态索引**：
- body：address seed、normalized copy component edge、field、dynamic field、strided field、load、store、
  store-object、memcpy。
- call templates：由该函数拥有的 direct site 和 indirect site；callsite 只作为模板记录，未错误实例化成普通 body edge。
- 每项保存原始 constraint/site index，实例化时才通过 `ctxNode/ctxRoot` 映射，因此 provenance 与原始 relation 保留，
  没有 synthetic `Database::values` clone。
- 新增 `object_template_census.tsv`，逐函数输出 component、每类 body constraint、stack object 和 direct/indirect
  call-template 数量；JSON/input census 同步加入各类总数。

**真实 body 物化**：
- `ObjectContextNodes` 不再维护独立 `nextNode/nodeContext/origin`，改为向统一 `SolverNodeArena` 申请连续
  context block，只保存 `(context_id → function,base,count)`。
- `instantiateObjectContext(ctx)` 分配 context value nodes、context-local stack object roots，然后依次通过 P2
  incremental installers 安装 copy/field/dynamic/strided/load/store/store-object/memcpy，最后加入 context-local
  address seeds；所有晚安装 shared-source edge 自动 replay。
- stack root 使用紧凑 `ContextStackRange + flat object-id` 映射。`contextObjectRoot(F,root)` 同时检查 object owner，
  只重映射 F 自己的 stack object；其他函数即使拥有相同 local ordinal 也保持原 root。
- 新增显式 accounting：materialized contexts、context value nodes、context stack objects、context constraints。

**测试**：
- 新增完整双-context fixture：两个 receiver root 物化同一函数，验证 field/store/load 只连接各自 context-local
  stack root，store-object 和 memcpy 正确映射 cloned stack cells，dynamic/strided edge 生效，node context/origin
  正确，重复 instantiate 幂等，其他函数 stack root 不被 ordinal 误映射。
- 当前 **85/85 selftest 通过**。
- 两批次真实数据集成加载（`drivers__base__built-in.000,__vmlinux_orphan__.000`）成功：receiver functions=1128，
  unique=766，模板 values=11446、components=11411、copy edges=1713、stack objects=146、body constraints=9181、
  call templates=22569。`object_template_census.tsv` 共 767 行（header + 766 templates），逐列求和与 stderr 汇总
  完全一致；相同命令重跑后 template census 与 callsite census 均 `cmp` 相同。

**当前边界**：`instantiateObjectContext` 已是真实 Solver 实现，但目前只由 synthetic test 显式调用；生产 worklist
还没有 receiver watch 自动触发。下一切片是 direct `CallInstance=(site,caller_context)`、receiver actual watch、
`ensureReceiverContext` 与全 actual/return wiring，并保证 selected unique-receiver site 不再向 baseline formal 接流。
