# Kernel Bitcode Variant-to-Handler Candidate Analysis Plan

状态：方法与实验计划；Step 0–3 已完成，Step 4 仍在进行中。Step 4 已实现 C++ semi-naive worklist、
K=1 callsite context、schema v3、structured dynamic GEP 和 symbolic affine region；当前
`value-slice=all` Pass 已在 `pending=0 && truncated=false` 下收敛并生成完整 tuple 文件，但函数间
`ArgFlow/ReturnFlow` 仍只覆盖 handler-rooted call cone，dispatch/selector summary 也尚未成为一等关系，
因此不能称为完整全局关系闭包，2026-07-15。

当前代码、数据与未完成补丁的交接快照见
`scripts/seed_horizon/step4-pointer-analysis-handoff-2026-07-16.md`。

本文只讨论 Linux kernel Bitcode 上的 `syz variant -> candidate handlers` 静态分析。当前重点是
handler 候选绑定，不是依赖图构建，也不是漏洞分析。

## 1. 目的

### 1.1 核心目标

对每个 syzkaller variant `v`，从 kernel Bitcode 和 syzkaller 类型/常量语义出发，计算一个候选
handler 集合：

```text
C(v) = { h | 在当前静态分析 Pass 的抽象语义下，存在一条从 v 到 h 的可行分派路径 }
```

候选路径至少需要表达：

```text
variant
  -> syz resource 的可能 producer/object
  -> object 上安装的 dispatch object（fops/ops/table）
  -> operation field 或 cmd/key selector
  -> helper、间接调用和下一层 dispatch object
  -> candidate handler
```

最终输出必须是候选集合，不能假设 kernel 中存在一个静态唯一 handler。一个 syz resource 可以由多个
producer 创建，一个 dispatch field 也可以由多个驱动实现，因此多候选本身不是错误。

### 1.2 评价原则

静态分析不存在一个能够对整个 kernel 保证完全准确的方法，因此本文不把候选标成“可靠 handler”或
“不可靠 handler”。所有静态输出都只是候选。

不同 Pass 只能说明候选集合是如何变化的：

```text
Added(Pi, v)   = C_i(v) - C_(i-1)(v)
Removed(Pi, v) = C_(i-1)(v) - C_i(v)
```

这些差异可以机械统计，但不能自动等价为 precision 提升或下降。候选真假只能通过以下证据判断：

1. 人工沿 kernel 源码检查 producer、object、install、selector 和 handler 路径。
2. 必要时使用运行时 tracing 验证实际对象实例和间接调用目标。
3. 对每个 Pass 引入或删除的候选分别采样，不能只看一个整体比例。

因此，Pass provenance 的作用是解释候选来源和支持人工审查，不是给候选贴真值标签。

方法验收必须进一步区分四个层次：

1. **Solver closure correctness**：在声明的抽象语义和 Pass policy 下，所有前提成立的 transfer obligation
   都已经产生结论，或具有可机械复核的 policy disposition。该层由独立全量 closure checker 验证。
2. **Model coverage accounting**：每条输入 constraint/seed/summary 都进入 resolved、unreachable、policy
   dropped 或 unresolved frontier，不能因没有生成 tuple 而从统计中消失。
3. **End-to-end query accounting**：进入 Variant Query 和 recursive resolver 后，全部 variant、producer
   branch 和 dispatch state 都必须进入 successor、candidate、visited-merge 或显式 unresolved 终态。
4. **Empirical candidate precision**：候选是否对应真实 kernel 运行路径，只能在上述机械账完整后通过人工源码
   审查或运行时 tracing 评价；它不是 solver closure 的验收方法。

HID、TTY、socket、DVB 等小样本只能作为单元测试、回归测试和 derivation 格式示例，不能作为“完整方法已经
成立”的分母。本文中的“Step 4 完成”只表示关系在声明的抽象语义下达到经过独立检查的闭包，不表示静态分析
恢复了 kernel 运行时的全部真实路径。

### 1.3 非目标

当前阶段不做以下事情：

- 不把候选集合强压成单 handler。
- 不根据函数名、资源名后缀或 basename 猜 handler。
- 不把 candidate count 变小直接称为 precision 提高。
- 不把 candidate coverage 变大直接称为 recall 提高。
- 不用手工 struct 白名单证明某个候选为真。
- 不在 handler 候选方法稳定前继续扩展 variant dependency graph。

### 1.4 当前基线及其含义

2026-07-12 的当前运行快照：

```text
variants                  8245
candidate non-empty       5273
unique candidate          4725
candidate size 2-5         500
candidate size >=6          48
```

这些数字只描述当前实现的输出，不是最终方法结论。当前实现有两个已知结构性限制：

1. `resolve/fixpoint.py` 只允许少数手写 struct 进入 type-wide provider。
2. `resolve/dispatch.py` 的 scoped、collapse、bridge、inline 等 Pass 目前共同组成最终候选集合。

当前“2 轮收敛”只说明现有 provider/negative-cache 不再产生新 demand，不代表通用 points-to 关系已经
闭包，也不代表递归分派已经完整。

## 2. 整体思路

### 2.1 术语

- **Abstract object**：静态分析中的对象身份，例如 global、allocation site、registration site、
  syz producer 创建的对象，或某对象的字段子对象。
- **Constraint**：从 Bitcode 指令生成的 points-to、memory、call、return 或 selector 关系。
- **Recognizer**：识别 kernel 特定注册/表结构并产生 seed facts 或 summary 的 Bitcode 分析。
- **Fixpoint engine**：对通用 constraints 做工作队列传播，直到关系集合不再增长。
- **Struct expansion policy**：决定哪些被 demand 的 struct 允许进行 type-wide 展开；这是实验策略，
  不是 Fixpoint 引擎能力。
- **Variant-conditioned query**：使用 variant 的 resource、operation 和 selector，在全局关系上做有根
  可达性查询。
- **Resolver**：执行 variant-conditioned query，并递归收集最终候选 handler。
- **Pass**：一套明确的分析配置。所有 Pass 都输出候选集合，Pass 本身不代表真值。

### 2.2 总体管线

```text
Kernel Bitcode
  -> 通用 IR constraints + kernel-specific recognizer seeds
  -> 全局 points-to/install/call Fixpoint
  -> Struct expansion policy: NONE / ALL / WHITELIST
  -> Variant-conditioned dispatch query
  -> Recursive handler candidate collection
  -> Candidate provenance + per-Pass delta
  -> 人工源码分析 / 可选运行时验证
```

逻辑上可写为：

```text
KernelRelations_P = least_fixpoint(BitcodeConstraints, policy=P)
C_P(v)            = ReachableHandlers(KernelRelations_P, VariantInputs(v))
```

Fixpoint 和 variant query 可以在实现上交错执行，但必须保留两个职责：

- Fixpoint 回答“指针、对象字段和函数指针可能指向什么”。
- Variant query 回答“从这个 resource、operation、cmd/key 出发能到哪些 handler”。

### 2.3 步骤零：建立可复现基线

在改变分析方法前，固定 kernel build、syzkaller catalog、facts、resolver 配置和当前每个 variant 的完整
候选集合。所有后续 Pass 都与这份基线做逐 variant、逐 handler diff，而不是只比较总数。

基线同时记录每个当前候选经过的 provider、collapse、bridge、inline 等路径，使现有隐式 Pass 可以被拆开
比较。

### 2.4 步骤一：定义 Variant 查询输入

每个 variant 转换为统一查询：

```text
VariantInputs(v) = {
    producers/resources,
    operation field,
    selector values,
    constructor/path/family constraints
}
```

示例：

```text
ioctl$HIDIOCSFEATURE
  resources = {fd_hidraw}
  operation = ioctl
  selector  = HIDIOCSFEATURE

setsockopt$inet_tcp_TCP_ULP
  resources = {sock_tcp}
  operation = setsockopt
  selectors = {level=SOL_TCP, optname=TCP_ULP}
```

如果 resource 有多个合法 producer，查询必须遍历每个 producer 对应的 abstract object，最终集合取并集。
可以保留 producer 维度用于解释，但不能无依据删除其中一个 producer。

### 2.5 步骤二：从 Bitcode 生成通用约束

基础 points-to 约束至少包括：

```text
AddressOf:  p = &object
Copy:       q = p
FieldAddr:  q = gep p, field
Load:       x = load q
Store:      store x, q
CallArg:    call f(actual) -> formal
Return:     return x -> call result
Phi/Select: 多来源值合并
Container:  container_of / pointer adjustment 保持对象身份
```

目标关系包括：

```text
Pt(value, object)
MemPt(object, field, target)
CallTarget(callsite, function)
ArgFlow(callsite, actual, callee, formal)
ReturnFlow(callee, value, caller-result)
```

DWARF 用于恢复 source-level struct/field 身份，但不能用“相同 struct 类型”代替“相同 object 实例”。

### 2.6 步骤三：加入 Kernel-specific Recognizer Seeds

通用指针约束需要 kernel 外部语义入口。现有 recognizer 继续负责提供 seed 或 summary：

- misc/cdev/class/device registration：建立 device object 与 dispatch object 的初始关系。
- proc/debugfs/cgroup/fill-table：建立 path、dentry/inode object 与 ops table 的关系。
- socket/protosw/proto registration：建立 family/type/protocol 与 socket object/ops 的关系。
- anon inode：建立 producer callsite 与新 fd object/fops 的关系。
- CMD/GENLCMD/key-table：建立 selector 到下一 handler 的控制/表分派关系。
- bridge/callback：建立参数和 callback 的调用关系。

Recognizer 只补充通用 IR 难以直接表达的注册根和 API summary，不应为每个新 struct 手写完整 handler
管线，也不应通过名字匹配直接生成 handler。

### 2.7 步骤四：全局 Fixpoint

Fixpoint 使用统一工作队列，对任意 struct/object 传播关系：

```text
新增 Pt
  -> 触发新的 Load/Store 结果
  -> 发现新的 CallTarget
  -> 增加新的 CallArg/Return 传播
  -> 产生新的 MemPt
  -> 再发现新的间接调用目标
  -> 直到没有新 tuple
```

收敛对象是关系 tuple 集合，例如：

```text
(value, object)
(object, field, target)
(callsite, function)
```

收敛轮数只证明当前约束系统达到 fixed point；它不能单独证明候选准确。

### 2.8 步骤五：Struct Expansion 实验策略

Fixpoint 引擎必须具备处理任意被 demand struct 的能力。在同一个引擎上运行三种策略：

```text
NONE       不做 type-wide struct expansion
ALL        所有被 demand 的 struct 均允许展开
WHITELIST  只展开白名单中的 struct
```

对应候选集合：

```text
C_none(v)
C_all(v)
C_W(v)
```

白名单是实验 Pass，不是真值列表。它必须来自 global demand census、单 struct 消融和人工分析，而不是先
手工选择少数 struct 再用结果证明它们重要。

### 2.9 步骤六：Variant-conditioned Query

Variant query 使用第一步得到的 query 输入，在 Fixpoint 关系上建立初始状态：

```text
State = (
    variant,
    program point / handler,
    abstract object environment,
    selector environment,
    derivation path
)
```

它不是新的 recognizer，也不是针对 variant 名字匹配。它只负责把全局关系按以下条件切片：

- 哪些 abstract objects 可以由 variant 的 resource producers 创建。
- 当前 operation 对应 dispatch object 的哪个字段。
- 当前 cmd/level/optname/key 允许哪些 control-flow 或 table edges。
- 参数常量和 object context 如何传入下一层 helper/indirect call。

### 2.10 步骤七：递归 Dispatch Resolver

Resolver 在状态图上重复处理以下边：

```text
dispatch field:   (object, ops field) -> handler
cmd/key table:    (dispatcher, selector) -> handler
direct bridge:    caller -> helper
callback bridge:  helper -> callback
call/return:      actual/formal/return value propagation
object load:      object.field -> next dispatch object
```

递归必须携带 abstract object 和 selector environment，不能只携带 `struct type`。同一 origin 下不同深度的
CMD 不能一次性平铺；应当进入当前最浅层 handler 后继续解析下一层状态。

现有 scoped、collapse、bridge、inline 行为保留为独立实验 Pass，分别输出候选集合和 derivation，不预先
决定删除或保留。这样才能比较每个 Pass 引入了哪些候选以及产生了什么精度问题。

### 2.11 步骤八：全局、单 Struct 与白名单实验

对每个 Pass `P` 保存完整候选与推导路径：

```text
(variant, handler, pass, producer, abstract objects, fields, selectors, callsites)
```

机械指标包括：

- candidate non-empty variants。
- candidate set size 的分布、中位数、P95 和大集合数量。
- 每个 struct demand 影响的 variants、fields 和候选数量。
- resolver 到达的递归深度和 unresolved states。
- Fixpoint tuple 数、迭代次数、运行时间和内存。
- 每个 Pass/struct 的 `Added`、`Removed` 和累计边际贡献。

### 2.12 步骤九：人工分析与结果报告

人工指标来自对候选增量的源码核对：

- 候选对应的 producer/object 是否可能由该 variant 获得。
- dispatch object 是否确实安装在该 object 上。
- field/cmd/key 是否允许到达对应 callsite。
- helper 参数、返回值和 callback 是否保持所需语义。
- 被 Pass 增加或删除的 handler 在 kernel 中是否真实可达。

## 3. 每一步的详细计划

### 3.1 建立可复现基线

**输入**

- 当前 kernel linked Bitcode batches。
- 当前 syzkaller variant catalog。
- 当前 `reg.tsv`、`fields.tsv`、`cmd.tsv` 和 candidate 输出。

**工作**

1. 固定 kernel build、syzkaller revision、extractor binary hash 和配置。
2. 记录当前 8245 variant 的完整候选集合，不只记录 count。
3. 为当前 resolver 的每个候选补充 `pass/source fact` 字段。
4. 把当前六 struct provider、collapse、bridge、inline 分别视为独立配置开关。

**输出**

```text
baseline_manifest.tsv
baseline_candidates.tsv
baseline_candidate_provenance.tsv
baseline_pass_config.json
```

**验收**

- 同一输入重复运行得到字节一致的候选与 provenance。
- 8245 variants 的分类和候选集合总数守恒。
- 任何候选都能追溯到具体 fact 和 Pass。

**2026-07-12 执行结果**

Step 0 已冻结以下产物：

```text
run/seed_horizon/baseline_manifest.tsv
run/seed_horizon/baseline_candidates.tsv
run/seed_horizon/baseline_candidate_provenance.tsv
run/seed_horizon/baseline_pass_config.json
```

基线人口与候选集合：

```text
variants                         8245
candidate non-empty              5273
variant-handler candidate pairs  6428
fixpoint rounds                      2
```

当前获胜 Pass 的 variant 分布：

```text
scoped_precise          4053
unscoped_collapse         14
field_bridge               67
inline_leaf               260
syscall_multiplexer       896
genl_table                657
fs_table                   73
no_dispatch              1075
unresolved               1150
```

连续运行两次后，四个基线文件的 SHA-256 均保持一致；`candidate_trace.tsv` 也保持 8245 条
variant 记录。`baseline_manifest.tsv` 同时记录输入 facts、extractor binary、相关源码以及基线生成器
自身的哈希。

当前 provenance 的边界必须保留：`resolver_pass` 精确表示第一个产生非空候选集合的 Pass；`trace`
仍是该 variant 在该 Pass 中观察到的边集合，不是每个 `(variant, handler)` 各自的完整前驱链。逐候选
derivation 将在 3.8 的递归状态传播中补齐，不能把当前 trace 当作候选真值证明。

### 3.2 定义 Variant 查询输入

**输入**

- syzkaller variant catalog 和 resource inheritance。
- `variant_grammar.jsonl` 中的常量参数。
- producer/consumer 关系及 open path、socket family/type/protocol 信息。

**工作**

1. 为每个 variant 输出全部 resources 和全部合法 producers，不提前选择单个 producer。
2. 将 syscall base 转换为 operation field，但保留无法确定字段的状态。
3. 提取 ioctl cmd、sockopt level/optname、genl cmd 和 syscall opcode 等 selector。
4. 将固定 path、constructor 和 family/type/protocol 保存为独立约束，不从 suffix 名称猜测。
5. 对缺失、运行时决定和多值 selector 明确编码，不使用默认值静默补齐。

**输出**

```text
variant_inputs.tsv
variant_producers.tsv
variant_selectors.tsv
variant_input_gaps.tsv
```

**验收**

- 8245 variants 全部存在一条输入记录。
- 多 producer resource 保留所有 producer 分支。
- 任何 selector 都能追溯到 syzkaller 常量/类型事实或明确标为 runtime/unknown。
- 不使用 variant suffix 与 handler 名称相似性建立输入关系。

**2026-07-12 执行结果**

Step 1 已生成：

```text
run/seed_horizon/variant_inputs.tsv
run/seed_horizon/variant_producers.tsv
run/seed_horizon/variant_selectors.tsv
run/seed_horizon/variant_input_gaps.tsv
```

全量结果：

```text
variant input records             8245
producer branches              1209106
selector/constructor/path facts   60629
dispatch selector facts            7091
explicit input gaps                 422
```

`variant_producers.tsv` 按 syzkaller `resource.kind` 继承关系展开每个输入 resource 的全部兼容
producer，不预选单个 producer。以 `sock_tcp` 为例，同一 consumer 明确保留
`socket$inet_tcp`、`socket$inet_smc` 和 subtype `socket$inet_mptcp` 三个分支。输出 resource
另保留当前 variant 的 `self` producer 分支。该表约 159 MB 是完整展开的结果，不是候选重复去重失败。

selector 和约束只从 generated syscall/type 语义恢复：

- ioctl 使用 syscall ABI 的第二个参数，sockopt 使用第二、第三个参数；实际 syzkaller 字段名即使是
  `opt` 而不是 `optname`，仍按参数位置规范化为 `optname`，同时保留真实字段名作为 provenance。
- `ConstType` 输出单值；非 bitmask `FlagsType` 输出完整有限值域；bitmask 只输出 atoms 并明确记录
  `domain-not-expanded`，不假装已经枚举所有组合。
- Struct/Union/Ptr/Array 类型图递归恢复嵌套 selector。例如
  `sendmsg$DEVLINK_CMD_GET` 的 `msg.vec.addr.payload.cmd=1` 来自
  `genlmsghdr_t[DEVLINK_CMD_GET].cmd`，不是从 variant suffix 解析。
- 固定 path 来自 `BufferType`。例如 `syz_open_procfs$pagemap` 得到 `file="pagemap"`，修复了此前
  把 generated type 误读成占位字符串的问题。
- socket family/type/protocol 分别保存为 constructor constraints，不与 handler 绑定混在一起。
- `variant_grammar.jsonl` 仅作为数值交叉证据；如果常量没有映射到有语义字段，就写入 gap，不按数组
  位置或 suffix 做 fallback。

按结构识别到的 query kind 分布：

```text
cmd_dispatch          3811
direct_operation      1638
fs_dispatch             73
genl_dispatch          754
syscall_multiplexer    896
syz_helper             163
no_dispatch_model      910
```

这里的 754 个 GENL variant 全部具有从嵌套 generated type 恢复的 `genl_cmd`；它比旧实现按
`_CMD_` suffix 分类的 657 个更多，但目前只改变输入建模，不改变旧 resolver 候选集合。

422 条 gap 的组成是 selector 385、path 17、constructor 12、无 catalog producer 8。主要是
`$auto` 对应的运行时 `IntType`、未展开 bitmask 组合和无法静态固定的 path/constructor；这些状态均
显式输出，没有默认值和名字 fallback。

四个 Step 1 文件连续生成两次 SHA-256 一致。旧候选基线同时回归为 8245 variants、5273 个非空
候选集合和 6428 个候选对，说明本步骤只规范化查询输入，没有暗改 handler resolver。

### 3.3 定义通用 Constraint Schema

**输入**

- LLVM IR 指令。
- DataLayout 和 DWARF struct/field 信息。
- 现有 `TYPEDFIELD/TYPEDSTORE/OPSFIELD/FIELD_ICALL` 事实。

**工作**

1. 定义 abstract object ID：global、alloc site、registration site、producer site、field subobject。
2. 定义 `Pt/MemPt/CallTarget/ArgFlow/ReturnFlow` tuple schema。
3. 明确 GEP、cast、phi、select、load/store、call/return 的约束生成规则。
4. 明确 `container_of`、embedded object 和 pointer adjustment 的对象身份规则。
5. 对无法恢复对象身份的事实保留 unknown object，不用 struct 名替代 object ID。

**输出**

```text
objects.tsv
points_to_constraints.tsv
memory_constraints.tsv
call_constraints.tsv
```

**验收**

- Schema 不包含 handler 名字匹配规则。
- 每条约束可追溯到 batch、function、instruction/callsite。
- 相同 struct 类型的不同 global/alloc site 保持不同 object ID。

**2026-07-12 执行与审计结果**

Step 2 已实现为独立 LLVM extractor，不修改现有 REG/CMD recognizer。全量提取覆盖 627/627 linked
batches，`constraint_manifest.json` 记录四张表共 19,090,856 行：

```text
objects.tsv                 3,468,125
points_to_constraints.tsv   5,480,395
memory_constraints.tsv      1,834,471
call_constraints.tsv        8,307,865
```

逐表流式审计结果：所有行列宽正确，行数与 manifest 完全一致，kind 分布为：

```text
objects: global 864363, function 178875, stack 45058,
         unknown 2379084, block 744, null 1
points:  ADDR_OF 1090209, COPY 334438, FIELD_ADDR 1520218,
         FIELD_ADDR_DYNAMIC 156446, UNKNOWN_ADDR 2379084
memory:  LOAD 683675, STORE 188833, STORE_OBJECT 961830,
         MEMCPY 132, MEMMOVE 1
calls:   FUNCTION_FORMAL 275327, CALL_TARGET 6016503,
         CALL_CALLEE_VALUE 39807, CALL_ACTUAL 1813783,
         CALL_RESULT 151149, RETURN_VALUE 11296
```

关键语义检查：

1. 52,622 条 constant GEP 保留负 offset；其中 60 条绝对值大于等于 1 MiB 的 offset 来自 KASAN
   shadow address 计算，不是 extractor 的 signed-offset 溢出。
2. 156,446 条 dynamic GEP 全部保留为 `FIELD_ADDR_DYNAMIC`；35,309 条带 source struct type，因 offset
   运行时决定，没有伪造固定 field name。
3. 2,379,084 条 `UNKNOWN_ADDR` 均指向各自 site-local unknown object；其中 2,365,344 条 opcode 为
   `inttoptr`。这些边在 extractor 中保留，后续必须把 unknown 传播策略作为独立 Pass 测量，不能静默删除或
   按 struct 合并。
4. 相同 LLVM type 的不同 globals、不同 alloca sites 使用不同 object ID；`llvm.compiler.used` 等
   appending linkage globals 也按 linked batch 隔离。
5. 真实 fops 初始化链存在：`tun_fops` global object 与 `tun_chr_ioctl` function object 分别由
   `ADDR_OF` 建立地址 seed，global initializer 再产生
   `STORE_OBJECT(tun_fops + 80, tun_chr_ioctl)`。Step 2 只恢复内存关系，offset 对应的 dispatch field
   语义由后续 typed seed/query 连接。
6. 744 个 LLVM `BlockAddress` 均产生独立 `block` object 和 `ADDR_OF` seed；此前只是 schema 文档漏写，
   数据与实现一致。

可重复审计入口：

```text
scripts/seed_horizon/probes/audit_pointer_constraints.py
run/seed_horizon/constraint_audit.json
```

### 3.4 统一现有 Recognizer 为 Seed/Summary

**输入**

- 现有 `enum*` facts。
- proc/cgroup/socket/cdev/anon 等注册机制。

**工作**

1. 对每个 recognizer 标注它产生的是 object seed、install edge、selector edge 还是 call summary。
2. 删除 recognizer 内部重复的端到端 variant->handler 连接逻辑；Python join 只连接 syz 输入与 object seed。
3. 对 kernel API 建立参数化 summary，例如 registration 参数、返回 object、callback 参数位置。
4. 保留无法由通用指令约束恢复的 kernel namespace/path/family 语义。

**输出**

```text
recognizer_seed_schema.md
registration_seeds.tsv
api_summaries.tsv
```

**验收**

- 每个 recognizer 只负责一种 seed/summary 关系。
- 新 dispatch struct 不需要新增端到端 recognizer。
- 现有 cdev、proc、cgroup、socket、anon 关键样例的 object roots 不丢失。

**2026-07-12 执行结果**

Step 3 增加类型化 `InstallSeed` carrier，并在 `build_full_provenance_rows` 合并每个 builder 时保留
`relation/root/method/reg_row/source`。现有 resolver 仍消费原来的 `res2rows/variant2rows`，因此该步骤只
显式化 recognizer 关系，不改变候选计算。

统一导出结果：

```text
registration_seeds.tsv          1,335 rows
  unique install relations      1,115
  entry_install                 1,259 provenance rows
  context_install                  76 provenance rows

api_summaries.tsv              172,596 rows
  dispatch_field                 3,467
  cmd_selector                  92,839
  field_forward/site            42,280
  cmd reachability              30,853
  cmd/callback bridges           2,311
  genl/fs selectors                840
  resource-scoped context_field      6
```

`registration_seeds.tsv` 不把 ops symbol 当 object identity。导出器按以下结构链连接 Step 2 object：

```text
REG row index
  -> reg.by_tu.tsv 的 linked batch
  -> objects.tsv 的 (batch, global symbol)
  -> dispatch_object_id
```

结果为 1,083 条 `exact` object provenance 和 252 条显式 `synthetic` provenance，`unresolved=0`、
`fanout=0`。synthetic 只用于 cgroup projected REG rows 与 resource-scoped block context，不与其他
resource 或相同 struct type 合并。导出器不使用全局 symbol fallback。

守恒与回归：

1. 最终 `res2rows/variant2rows/sock_proto_ctx` 的 1,115 个唯一安装关系全部存在对应 seed，missing=0、
   extra=0，stable-ID collision=0。
2. 输出连续生成两次 SHA-256 一致。
3. 候选基线保持 8,245 variants、6,428 `(variant, handler)` pairs；candidate、provenance 和 Pass config
   三个冻结文件逐字节不变。
4. `api_summaries.tsv` 只规范化 REG/CMD/GENLCMD/FIELD_ICALL/bridge 等现有结构事实，不根据 variant
   suffix、basename、resource 名或 handler 名补边。

当前迁移边界：部分 Python builder 仍把 `ObjectSeed + Install` 复合为 `ROOT_INSTALL`。schema 明确把它
标为 Step 3 boundary seed；Step 4 接入 points-to Fixpoint 时再使用 Step 2 object constraints 将其拆成
独立 object seed 与 install edge，不能把复合 seed 当成完整对象分析。

产物与入口：

```text
scripts/seed_horizon/model/recognizer.py
scripts/seed_horizon/probes/recognizer_seeds.py
scripts/seed_horizon/recognizer-seed-schema.md
run/seed_horizon/registration_seeds.tsv
run/seed_horizon/api_summaries.tsv
run/seed_horizon/recognizer_seed_manifest.json
```

### 3.5 实现通用 Points-to Fixpoint

**输入**

- 通用 constraints。
- recognizer seeds 和 API summaries。

**工作**

1. 使用 semi-naive worklist，只传播新增 tuple。
2. 当 `CallTarget` 新增时，动态激活该 callee 的 `ArgFlow/ReturnFlow`。
3. 当 `Pt` 或 `MemPt` 新增时，只重新处理依赖这些 tuple 的 constraints。
4. 跨 batch 通过 symbol/global/object summary 连接 declaration 与 definition。
5. 保存每个 tuple 的 derivation predecessor，用于后续候选解释。
6. 设置资源上限只影响运行终止状态，不能静默转成 handler 候选。

**输出**

```text
points_to.tsv
memory_points_to.tsv
indirect_call_targets.tsv
call_arg_flows.tsv
call_return_flows.tsv
call_transfer_map.tsv
dispatch_summary_relations.tsv
selector_summary_relations.tsv
summary_relation_census.tsv
fixpoint_derivations.tsv
field_cycle_edges.tsv
affine_regions.tsv
affine_region_clips.tsv
constraint_activation_census.tsv
fixpoint_obligation_census.tsv
fixpoint_violations.tsv
policy_dispositions.tsv
unresolved_relation_frontier.tsv
fixpoint_checker_stats.json
step4_gate_report.json
fixpoint_stats.json
```

**验收**

- 任意 struct 都可通过同一 solver 传播，不需要 `_TYPE_UNION_PROVIDER_STRUCTS` 才能继续。
- 收敛条件是没有新增 tuple，而不是 provider 白名单耗尽。
- 独立 closure checker 对全部 activated transfer obligations 报告 `violations=0`。
- 全部 input rows、policy dispositions 和 unresolved relations 具有全局守恒账；小样本只保留为回归测试。

**2026-07-12 执行结果**

Step 4 第一版通用 Fixpoint 实现为独立 side-by-side solver，不 import、不修改现有候选 resolver
（`resolve/fixpoint.py`、`resolve/dispatch.py`、`resolve/candidates.py` 均未改动）：

```text
scripts/seed_horizon/resolve/pointsto_fixpoint.py   引擎（constraint/seed loader + solver + derivation）
scripts/seed_horizon/probes/pointsto_solve.py       单 batch 驱动 + 三样例验证 + 确定性 selftest
```

引擎同时消费六个输入：Step 2 的 `objects/points_to/memory/call_constraints.tsv` 与 Step 3 的
`registration_seeds.tsv`、`api_summaries.tsv`。

抽象对象是二元组 `(root_object_id, signed_byte_offset)`。基对象是 `(root,0)`，字段子对象是 `(root,K)`；
相同 LLVM struct 类型的不同 global/alloca/unknown-site 因 `root_object_id` 不同而始终是不同对象。
`struct_type`/`field_name` 只是 GEP 元数据，引擎从不读取它们做合并或分派（probe 用 `tokenize` 扫描引擎
代码标识符做回归断言：无 `_TYPE_UNION_PROVIDER_STRUCTS`/`whitelist`/`struct_type` 等）。内存建模为
“每个抽象对象一个 cell”，cell 作为伪节点参与传播，因此 LOAD/STORE 归约为随指针 points-to 增长动态加入的
copy 边（标准 inclusion-based / Andersen）。调用图 on-the-fly：新 `CallTarget` 出现时才激活 `actual->formal`
和 `return->result`（直接调用构建期无条件连接，间接调用在 `Pt(callee)` 含函数对象时连接）。

约束到传递函数：`ADDR_OF/UNKNOWN_ADDR` 种子；`COPY` 复制边；`FIELD_ADDR` 物化 `FieldObject(root, off+K)`
（K 带符号，`container_of` 负 offset 原样保留）；`FIELD_ADDR_DYNAMIC -> (root, DYN)`；`LOAD/STORE` 动态
copy 边；`STORE_OBJECT` 无条件边 `src -> cell(obj, off)`。

Step 3 seed 消费（recognizer-seed-schema §1）：`registration_seeds` 的复合 `ROOT_INSTALL` 被拆成
`ObjectSeed(root, 合成 kernel 对象) + Install(合成对象, dispatch_object)`——即
`Pt(seed:value:root:<R>) ⊇ {root_obj@0}` 与 `MemPt(root_obj@0) ⊇ {dispatch_object@0}`，`dispatch_object_id`
用 Step 2 精确对象身份，不退回 symbol 名。`api_summaries` 的 `dispatch_field (dispatch_object, op名)->handler`
与 `cmd_selector (dispatcher, cmd)->handler` 作为 name-keyed 关系消费（op 名/cmd 值不是 byte offset，与
STORE_OBJECT 的 byte-offset 值并存、互相交叉验证，永不按类型合并）。这样 solver 可沿四边合成
`resolve(root) = Dispatch(Install(ObjectId(root)), op)` 走 root → 安装的 dispatch 对象 → handler。

终止性：字段 GEP 在 copy 环中会生成无界 offset；偏移饱和把越界 offset 收敛到 `(root, DYN)`（已知 size 时
界为 `[-size, size)`，未知 size 用硬上界），映射由 offset 决定、与插入顺序无关，故 sound 且每 root distinct
offset 有限，单调 worklist 必达不动点。饱和次数计入 `saturated_offsets`。

显式策略维度（全部计数，绝不静默）：`unknown = opaque(默认)|drop`；`field_dynamic = root_dyn(默认)|drop`；
`saturate_by_size`；`memcpy_unmodeled`（MEMCPY/MEMMOVE 识别但暂未字段展开，计数保留）；`max_tuples` 安全阀
（大 batch blow-up 时显式停机并置 `truncated=true`）。`(root, DYN)` 仍限定在该 root 内，不是类型并集；
struct expansion 的 NONE/ALL/WHITELIST 是后续 Step 6 实验层，不在本引擎内。

`prov[(node,obj)]` 记录首次导出该 tuple 的 predecessor，`derivation_chain` 回溯到 base 种子。例如
`fd_tun` 的 Install tuple 回溯为 `MEM:seed:object:root:fd_tun@0 <- INSTALL <- OBJECT_SEED`
（seed_id 对应 registration_seeds 行）。

验证：确定性 selftest（合成约束）5/5 PASS——table load、`container_of` 负 offset 回到基址、间接 arg/return
flow、间接 CallTarget on-the-fly。真实 IR：

```text
drivers__net__built-in.000  (16,433 objects, 0.09s, 68 MiB)
  [PASS] tun_fops@80 的 MemPt = { tun_chr_ioctl }                     # ADDR_OF + STORE_OBJECT 真实链
  [PASS] 负 offset 代数 tun_fops@0 +80 -> @80 -80 -> @0               # 带符号，root 保持
  [PASS] seed 四边链 fd_tun -> install tun_fops
         -> field-name ioctl=tun_chr_ioctl / open=tun_chr_open ...    # api_summaries dispatch_field
         -> byte-offset @80=tun_chr_ioctl / @104=tun_chr_open ...     # STORE_OBJECT 闭包（两源一致）
  pt_tuples=22016 mem_tuples=2553 pops=21850 saturated=105 install_seeds=6 roots_reaching_handler=3

drivers__tty__built-in.000  (7,106 objects, 997k tuples, 1.6s, 275 MiB)
  [PASS] 负 offset 命名 root tty_drivers@0 -> tty_drivers@-132
  [PASS] 间接目标：tty_init_dev 的 driver->ops->install 解析为候选集
         { gsmtty_install, ntty_install, pty_install, pty_unix98_install }，且 arg0 流入形参
  [PASS] seed 四边链 fd_console_fops_tty_io -> install { console_fops, tty_fops }（多 dispatch 对象候选并集）
```

`driver->ops->install` 与 `fd_console -> {console_fops, tty_fops}` 都保留候选并集，不压成唯一 handler，
正是计划要的候选集合语义。输出对 tuple 排序，跨不同 `PYTHONHASHSEED` 逐字节一致。

未扰动 Step 0-3：`baseline_snapshot.py` 重生成后三个冻结文件 SHA-256 与基线完全一致（8245 variants、
6428 pairs）；`recognizer_seeds.py` conservation=1115/missing=0/extra=0 且 Step-3 输出逐字节复现；
`audit_pointer_constraints.py` rows=19,090,856 errors=0。

产物与入口：

```text
python3 scripts/seed_horizon/probes/pointsto_solve.py --selftest
python3 scripts/seed_horizon/probes/pointsto_solve.py --batch drivers__net__built-in.000
run/seed_horizon/pointsto/<batch>/{points_to,memory_points_to,indirect_call_targets,
                                    applied_seeds,fixpoint_derivations}.tsv + fixpoint_stats.json
```

当前边界与全量运行设计（“先小 batch 验证、再设计全量”）：

1. 单 batch 正确且便宜，但直接铺全量会遇到经典 field × copy-cycle 代价：实测 `lib__built-in.000`
   （约 11k objects）在 4–6 GB 处 MemoryError，最热 root `obj_hash` 承载 56.5 万 tuple、603 个不同 offset
   （含大量负 offset），再经 copy 环广播到约 1.9 万节点，unknown（inttoptr/inline-asm）各出现在约 6.2 万
   tuple 中。这是 field-sensitive Andersen 的固有代价，非本引擎 bug。
2. 全量下一增量：**环消除**（copy 子图在线 SCC 折叠 / offline variable substitution，最大单项收益）；
   **字段粒度策略**（把每 root distinct offset 数作为显式策略维度，超阈值按确定性规则合并，扩展现有
   `saturate_by_size` 机制）；**跨 batch sym 链接**（全量 `batches=None` 时 `sym:` 对象天然共享，
   单 batch `[INFO] 无 in-batch 间接目标`即因 root 对象来自其它 batch，全量或 Step 7 variant 种子接入后解析）；
   `max_tuples` 安全阀保证任何单批不 OOM-kill。以上均在现有策略/接口内扩展，不需重写 worklist，也不引入
   struct 白名单。
3. MEMCPY/MEMMOVE 暂只计数；`cmd_selector`/`field_forward` 等递归 dispatch summary 已消费但其递归求解
   属 Step 8。收敛轮数/内存只证明约束系统达到不动点，不单独证明候选准确——真值仍靠人工源码/运行时证据。

#### 2026-07-12 C++ 全局执行与方法审计

Python 原型只证明了单 batch 语义，不能承担 1,909 万行约束的全局求解。新增整数化 C++ 引擎：

```text
scripts/seed_horizon/resolve/pointsto_global.cpp
run/seed_horizon/pointsto_global
```

引擎继续使用精确 `(root_object_id, signed_offset)` 对象，不按 struct、函数名或 subsystem 合并；支持
`LOAD/STORE/STORE_OBJECT`、负 GEP、dynamic GEP、MEMCPY/MEMMOVE、on-the-fly indirect target、Step 3
synthetic install seed、tuple predecessor 和资源安全阀。合成 selftest 为 7/7，通过字段 load、负 offset、
间接 actual/formal、间接 return/result、聚合 copy、动态 target 激活和 root→handler。

单 batch 回归：`drivers__net__built-in.000` 的 `tun_fops@80 -> tun_chr_ioctl` 仍由真实
`STORE_OBJECT` 恢复；`applied_seeds.tsv` 与未切片完整运行 SHA-256 相同。copy-SCC、memory demand、
handler-rooted call graph 和 edge dedup 均未改变该 handler 输出。

全局执行先发现并修正了三个通用对象语义问题，而不是 driver 特例：

1. `special:object:null` 不能成为 GEP/LOAD/STORE 的可解引用 memory object。
2. function object 可以作为函数指针值传播，但不能作为普通 struct base 生成 `@65520` 等字段 cell。
3. 未被 root/load 查询的 `STORE_OBJECT` 与动态 store 不应无条件展开；memory cell 和 store source 改为
   demand-driven 迭代，直到新增 cell/source 均为零。

同时实现了精确的 copy-SCC 凝聚、重复 `(src,dst)` copy edge 去重、handler-rooted direct-call 可达闭包，
以及 core value 与仅用于 store-alias 查询的 value 分离。以上均由约束角色和对象 kind 决定，不使用
basename、variant suffix、函数名黑名单或 struct 白名单。

当前同版 Pass 对照：

```text
Pass                                  tuples      indirect  rounds  truncated
unknown=drop, call-flow=none          148,445     2,251     5       false
unknown=drop, call-flow=reachable     20,001,728  948       2       true
```

`call-flow=none` 只用于消融，不能作为最终 handler 分析，因为它删除 actual→formal 和
return→result。它能在 1.51 GiB RSS 内收敛，证明对象、字段和 demand-driven memory worklist 本身可运行。

`call-flow=reachable` 从 1,696 个已安装 handler 函数根得到 22,708 个 direct-call 可达函数。第一轮在
12,042,940 tuples 收敛；随后加入 4,357 个 demanded memory cells、11,850 个实际命中这些 cell 的 store
source 和 19 个间接调用值。第二轮达到 20,001,728 tuples 时仍有 14,257,335 个 pending tuples，故明确
标记 `truncated=true`，不能作为全局 Fixpoint 结果。

消融结论：当前剩余瓶颈不是 recognizer 数量、struct 白名单或 copy 环，而是 context-insensitive
interprocedural merge。多个 callsite 的 actual 合入同一个 formal，随后 store source 在共享 helper 中互相
污染；继续提高 tuple 上限只会计算更大的混合集合。

因此 Step 4 **尚未完成**。下一实现增量必须把跨函数传播改为 callsite-preserving function summary 或
有界 call context；先在该模型下得到 `pending=0 && truncated=false`，再进入 Struct Policy。Struct
NONE/ALL/WHITELIST 是后续精度 Pass，不能替代函数间上下文模型。

#### 2026-07-13 Callsite、Offset 与 Dynamic-GEP Pass 审计

实现了通用 call-string 上下文化，不按函数名、subsystem 或 struct 选择路径：

- SSA value 按 `(function, last-K direct callsites)` 克隆；global/function/heap object 默认共享。
- `--context-objects stack` 可独立克隆 alloca object，用于对象敏感度消融。
- 只为存在 pointer actual→formal 或 pointer return→result 的 direct call 创建上下文；无指针接口调用仍在
  共享函数上下文中保留其全局副作用。
- `--context-depth K` 支持 K=1..4，`--max-contexts` 是显式安全阀。
- contextual value 在热点和 derivation 中映射回原始 LLVM SSA；新增 `hotspot_derivations.tsv`。

方法自测从 7 项增至 9 项，新增：两个调用点进入同一 helper 时 contextual formal 不合并；通过 helper
局部 alloca STORE/LOAD 后仍不合并。`drivers__net__built-in.000` 的
`fd_tun -> tun_fops@80 -> tun_chr_ioctl` 保持，`applied_seeds.tsv` SHA-256 仍为
`5823cbd29623a187c0311ba005e82117737d74f43d41f9ecb5d429b0370ed7dd`。

全局 Pass 对照如下。所有 handler 都仍是候选；表中的候选规模变化不是 precision 真值。

```text
Pass                                      tuples       pending     indirect  结论
CI reachable, root_dyn, size->DYN         20,001,728   14,257,335  948       截断
K=1, root_dyn, size->DYN                  20,000,001   10,537,518  3,628     截断
K=1 + contextual stack object             20,000,785   10,534,417  3,687     与 shared object 近同
K=2, root_dyn, size->DYN, 30M limit       30,000,789   47,675      5,793     第一轮仍截断
K=1, dynamic GEP drop, exact offset        3,377,198   0           2,454     6 轮收敛
K=1, dynamic GEP drop, overflow drop          56,858   0           2,454     6 轮收敛
```

关键推导结论：

1. K=1 的污染路径由 provenance 还原为多层共享 helper，例如
   `_raw_spin_lock_irqsave -> lock_acquire -> __lock_acquire -> register_lock_class -> assign_lock_key`。
   1-CFA 在第二层后丢失外层调用历史；K=2 将同预算下的热点单节点候选从约 1,337 降到约 120，但显式
   上下文从 162,310 增至 1,136,414，SSA value 增至 20,277,035，成本过高。
2. `stack-context` 几乎不改变全局结果，排除了“共享 alloca 是主因”的假设。
3. 原 size saturation 把越界/循环 GEP 折叠为 root-wide `DYN`，是主要扩散器。完全保留 exact offset 虽然
   收敛，却让有限数组循环产生 13 万级 offset 候选，不能作为默认策略。
4. 新增 `--offset-overflow dynamic|drop|exact`。`drop` Pass 明确丢弃 1,119 个越过已知 object size/hard cap
   的派生，得到 56,858 tuples；它与 exact Pass 的 2,454 个间接目标逐行相同，`applied_seeds.tsv` 也相同。
   这只是本数据上的机械等价，不证明被丢弃 offset 永远无语义。
5. 重新启用真实 `FIELD_ADDR_DYNAMIC` 后，即使 exact offset 也在第一轮超过 20M。当前剩余核心缺口不是
   recognizer，而是 extractor 把 dynamic GEP 只记录成 root-wide DYN，缺少 affine base/stride/bound。

因此 Step 4 当前有一个可运行的**控制 Pass**：

```text
--unknown drop
--call-flow callsite --context-depth 1
--field-dynamic drop --offset-overflow drop
--value-slice pointer-sinks
```

它用于后续 Pass 比较，不应被称为完整或可靠的 handler 解。当时识别出的下一缺口是从 LLVM GEP
提取 `constant_base + dynamic_index * stride`，在值域可证明时生成有限 offset set；该缺口的实现和
全量结果记录如下。

#### 2026-07-14 Structured Dynamic-GEP 子项

该子项已经完成，但它只修复 Step 4 的一个 transfer function，不代表 Step 4 已完成。方法不依赖
handler 名、struct 白名单或 subsystem 特例：

1. extractor 使用 LLVM `collectOffset` 把 GEP 分解为 constant term 和 variable terms。
2. 仅在恰有一个 variable term，constant/multiplier 可表示为 signed 64-bit，且
   `computeConstantRange` 得到有限、非 signed-wrap 区间时，生成
   `FIELD_ADDR_STRIDED(base,stride,count)`。
3. solver 的 `strided` Pass 对每个输入 `Root@K` 传播
   `Root@(K+base+i*stride)`；超过 `--max-strided-expansion` 的约束和 unresolved dynamic GEP 都只计数，
   绝不回退到 root-wide `DYN`。
4. `root_dyn` 和 `drop` 保留为独立对照 Pass。旧 root-dynamic 语义在 `drivers/net` 上的
   `applied_seeds.tsv` SHA-256 仍为
   `5823cbd29623a187c0311ba005e82117737d74f43d41f9ecb5d429b0370ed7dd`。

627/627 batches 全量重抽取保持 19,090,856 行和各表行数不变；objects/memory/call 三表 SHA-256
逐字节不变。points-to kind census：

```text
FIELD_ADDR_DYNAMIC   156,446 -> 131,514
FIELD_ADDR_STRIDED                 24,932
strided count <=64                  4,289
strided count <=256                 5,296
strided count >256                 19,636
```

全表 schema/kind/offset/witness 审计为 0 错误。C++ 自测为 16/16，覆盖正/负 stride、展开上限不回退
`DYN`、unresolved dynamic 显式 drop。全局 Pass 对照：

```text
Pass                       tuples  pending  indirect  seeded roots  结论
drop                        56,858  0        2,454     503           精确复现控制基线
strided, max=64             69,818  0        2,454     503           收敛
strided, max=256            90,182  0        2,456     503           收敛
strided, max=1024           90,182  0        2,456     503           与 256 输出相同
```

`max=256` 相比 `64` 新增的两个 target row 是同一语义目标的两个 call context：Btrfs
`prop_handlers_ht[hash_min(hash,8)] -> hlist -> prop_handlers[0].apply -> prop_compression_apply`。该链已沿
kernel 6.19.13 源码和 tuple predecessor 人工核对成立。`applied_seeds.tsv` 与 `roots_reaching_handler=503`
仍和 drop Pass 相同，因此本增量改善了通用间接调用闭包，但当前没有改变 variant-root handler 候选。
这是一项机械结果，不应外推为所有 strided 边都是真候选。

#### Step 4 验收复核（更新于 2026-07-15）

原 Step 4 的验收对象是通用全局 `Pt/MemPt/CallTarget/ArgFlow/ReturnFlow` 不动点，不是某一个 GEP Pass
收敛。按 §3.5 逐项复核后的当前状态：

```text
要求                                           当前状态                              结论
semi-naive 新 tuple 工作队列                    已实现                                已满足
新 CallTarget 激活 actual/formal/return          handler call cone 内已实现             部分满足
Pt/MemPt 增量触发依赖约束                       已实现                                已满足
跨 batch declaration/definition                 sym object 共享，缺全局 unresolved census 部分满足
每个 tuple 的 predecessor                       IR tuple 已实现，summary relation 未实现 部分满足
资源上限不静默生成 handler                      stats/truncated/drop 均显式             已满足
完整 tuple/derivation 输出                      value-slice=all Pass 已生成             已满足
任意 struct 不依赖手写 provider                 byte-offset solver 不读 struct 名        已满足
全局 constraints 达到无新增 tuple               value/memory 已收敛，函数间流仍被切片    未满足
独立全量 closure obligation 验证                 尚未实现                                未满足
```

其中有三个不能用“9,372,221 tuples、`pending=0`”替代的结构性缺口：

1. 当前最终 Pass 已使用 `--value-slice all`，但 `call-flow=callsite` 会先删除原始直接调用的全部
   `CallArgument/CallReturn` copy edges，只为 `handlerReachableFunctions` 中选中的 callsite 重建上下文边。
   handler call cone 外的 direct call 没有保留 context-insensitive 参数/返回传播，因此当前结果仍不是全局
   interprocedural closure。
2. `dispatch_field/context_field` 目前主要用于预先确定 handler roots 和生成 `applied_seeds.tsv`；它们没有
   作为带 predecessor 的一等 relation 进入统一 closure。`cmd_selector` 在 C++ loader 中目前只计数，尚未
   保存为后续 variant query 可消费的 relation。因而 `applied_seeds.tsv` 不等价于一条完整 Fixpoint
   derivation。
3. 当前 affine Pass 仍显式丢弃 131,514 条无法证明有限范围的 dynamic GEP、超过 expansion 上限的
   strided edges 和 overflow offsets。显式 policy drop 可以形成一个收敛的实验 Pass，但必须通过 activation
   census 与 provenance 单独记账，不能把“该 Pass 已闭包”写成“全部 Bitcode 语义已闭包”。

此前“继续审计 affine-vs-drop 剩余 134 个 target，并优先从 LLVM loop/range 收紧 bound”的安排从 Step 4
主线删除。前者属于候选/target 人工评价，后者属于 affine policy 的后续精化；它们都不能补齐当前缺失的
全局函数间关系和 summary relation。

Step 4 后续工作重新固定为：

1. 修复 callsite-preserving interprocedural 语义：保留每个函数的 baseline context 及其函数体约束；每个
   call transfer instance 必须恰好采用一种显式传播方式。contextual caller 中被选择的站点使用 contextual
   `ArgFlow/ReturnFlow`，baseline caller 或未选择的站点连接 callee baseline context。不能因 callsite 不在
   handler call cone 中而删除基本传播。间接调用在新增 `CallTarget` 后遵守同一规则，并输出
   contextual/CI/unresolved transfer census。
2. 把 `dispatch_field/context_field/cmd_selector` 保存为带 source/predecessor 的一等 summary relation；
   selector 是否激活由 Step 6 variant query 决定，但 Step 4 不能只保留计数。
3. 在修复后的 `value-slice=all` Pass 上重新生成完整关系文件，并增加 constraint activation census。
   row-level 记录互斥覆盖状态，event-level 分别记录执行、新 tuple、重复、policy drop 和 unresolved 次数；
   每类保留 source/provenance 样本。验收仍要求 `pending=0 && truncated=false`。
4. 实现独立全量 closure checker，对 `Pt/MemPt/CallTarget/ArgFlow/ReturnFlow` 的全部 transfer obligations
   做 relation join + anti-join 验证；输出 violation、policy disposition 和 unresolved frontier，而不是选择
   subsystem 小样本人工判断。
5. 以上完成后才能把 Step 4 标记为完成并进入 Struct NONE/ALL/WHITELIST。HID/socket/TTY/DVB 只作为
   回归测试；affine 的 134 个剩余 target 人工审计移到 Step 9；LLVM loop/range bound、unresolved
   dynamic GEP 和 MEMCPY-region 作为明确 backlog，
   不再阻塞关系层主线，也不能用来替代上述四项验收。

历史 demand-sliced `strided,max=256` Pass 曾补生成验收格式的关系表：85,340 条 value points-to、4,842 条
memory points-to、2,456 条 indirect target 和 90,182 条 derivation。它们证明输出路径可用，但文件中的
`policy.value_slice=pointer-sinks` 明确表明这只是切片关系；当前 `value-slice=all` 结果已经替代它作为
Step 4 的运行基线。

#### 2026-07-14 Schema v3 与字段类型兼容 Pass

Step 4 的输入已从 schema v2 独立升级为 schema v3，并在不覆盖正式 v2 facts 的前提下完成全量重抽：

```text
binary                         /tmp/ir_constraints_v3
batch manifest                 627/627 OK
objects.tsv                    3,468,125 rows
points_to_constraints.tsv      5,480,395 rows
memory_constraints.tsv         1,834,471 rows
call_constraints.tsv           8,307,865 rows
total                          19,090,856 rows
```

schema v3 的对象行增加 `contained_structs`。它由 LLVM aggregate type 递归产生，穿过 struct/array/vector
但不穿过 pointer；因此它是对象自身完整类型的机械证据，不是按 root 名字或 subsystem 写的白名单。RCU 单批与
627 批全量的列宽、kind、offset、unknown、dynamic、call/memory invariants 审计均为 0 error。

solver 增加独立实验选项：

```text
--field-type all          # 控制组：不使用对象类型反证
--field-type compatible   # 只有完整 aggregate 明确不含 GEP struct 时丢弃字段传播
```

`compatible` 对 unknown、pointer、synthetic 或没有完整 aggregate 证据的对象保留传播。每次过滤都记录
统计与最多 10,000 条带 predecessor 的 `field_type_drops.tsv` 样本；因此样本截断不会隐藏总 drop 数，也不能
把该 Pass 自动当作真值。

同一 v3 facts、同一 escape-active round2 配置的对照结果如下：

```text
Pass          tuples       pending  indirect_targets  truncated  typed drops
all           25,002,617   10,022   3,204              yes        0
compatible     5,336,978        0   2,930              no         34,988
```

`all` 的热点 predecessor 明确为 `process_srcu:i730 <- obj_hash@96`，32,263 个对象；`compatible` 的热点中
该路径消失，并在 drop sample 中观察到 `obj_hash@0 -> hlist_head` 的跨类型传播。这个结果证明该 Pass 能
机械切断当前已识别的跨类型扩散，但不证明所有被删除边都是错误，也不证明 `compatible` 已成为最终策略。
drop sample 和候选变化的真实路径评价属于 Step 9，不作为 Step 4 closure 验收。Step 4 需要证明的是该
policy 下所有保留、删除和 unresolved obligation 均被全量记账并通过独立 checker；不能因为该 Pass 收敛就
称为“全部 kernel 语义完成”。

### 3.6 实现 Struct Policy 实验层

**输入**

- 通用 solver。
- 全局 struct demand census。

**工作**

1. 实现 `NONE/ALL/WHITELIST` 三种 policy，共用同一 constraint 和 solver 代码。
2. `ALL` 对所有被 demand struct 应用相同 type-wide expansion 规则。
3. `WHITELIST` 从外部文件读取 struct 集合，不在代码中硬编码。
4. 每个 expansion tuple 标记 `expanded_struct` 和 policy。
5. 输出被 policy 阻断但仍存在的 demands，不用 fallback 隐藏。

**输出**

```text
struct_demands.tsv
struct_expansions.tsv
unresolved_struct_demands.tsv
```

**验收**

- 更换 policy 不需要修改 recognizer 或 resolver 源码。
- `ALL` 能覆盖 demand census 中所有存在 typed facts 的 struct。
- `WHITELIST` 的输出可精确还原每个候选由哪个 struct expansion 引入。

### 3.7 实现 Variant-conditioned Query

**输入**

- `KernelRelations_P`。
- syzkaller resources、producers、operation 和 selector constants。

**工作**

1. 为每个 producer 建立初始 abstract object set。
2. 将 syscall base 映射到 operation field，例如 ioctl、read、write、setsockopt。
3. 将 ioctl cmd、sockopt level/optname、genl cmd 等映射为 selector environment。
4. 保留 producer 维度执行查询，再对同一 variant 求候选并集。
5. 不使用 variant suffix 或 handler 名字相似性生成路径。

**输出**

```text
variant_query_seeds.tsv
variant_producer_candidates.tsv
variant_candidates.tsv
variant_query_census.tsv
unresolved_variant_queries.tsv
```

**验收**

- variant catalog 守恒：每个 variant 的每个 producer branch 都进入 seeded 或带 reason 的 unresolved 状态。
- resource、operation 和 selector 输入只能引用 Step 1 facts 与 Step 4 relation IDs，不允许名字 fallback。
- 多 producer 的 union 保留 branch provenance；任何 branch 都不能因已有另一个 branch 产生候选而被跳过。
- `variant_query_census.tsv` 对全部 variant/producer/selector 状态守恒；具体 socket/cmd 案例只作为回归测试。

### 3.8 实现递归 Dispatch 状态传播

**输入**

- Variant query seeds。
- points-to/call/selector relations。

**工作**

1. 使用 `(variant, program point, object env, selector env)` 作为 visited key。
2. 逐层处理 field dispatch、cmd table、helper、callback、call/return。
3. 参数常量传播只在值可证明时剪枝；未知值保留所有分支。
4. 对每个状态保存 predecessor 和使用的 relation tuple。
5. 将 scoped、collapse、bridge、inline 实现为独立可开关 Pass，而不是隐藏在一个 resolver 返回值中。
6. 达到资源上限、缺失 relation 或 unknown object 时输出 unresolved state。

**输出**

```text
dispatch_states.tsv
candidate_handlers_by_pass.tsv
candidate_derivations.tsv
unresolved_dispatch_states.tsv
dispatch_state_census.tsv
dispatch_transition_violations.tsv
```

**验收**

- 不需要按 struct 名字注册 resolver provider。
- 同一 origin 的深层 CMD 不被平铺到第一层候选。
- 每个候选可重放完整 producer->object->dispatch->handler 路径。
- 每个 reachable state 的每条 applicable relation 都产生 successor/candidate，或进入带 reason 的 unresolved；
  独立 transition checker 的 `violations=0`。
- 全部状态守恒到 `expanded/visited_merge/candidate/unresolved/resource_limit`，不能用几个成功链路代替全局账。

### 3.9 全局、单 Struct 与白名单实验

**输入**

- `C_none`、`C_all`。
- `struct_demands.tsv`。

**工作**

1. 运行 `NONE` 得到无 type-wide expansion 基线。
2. 运行 `ALL` 得到全 struct expansion 候选集。
3. 对每个 demanded struct `X` 运行单 struct 配置 `C_{X}`。
4. 计算每个 `X` 对 variants、候选数量、递归深度和 unresolved states 的影响。
5. 按机械边际贡献构造累计白名单 `W0, W1, ...`，但不把机械排序称为 precision 排序。
6. 对 `C_X-C_none` 和 `C_all-C_W` 分层抽样人工分析。

**输出**

```text
struct_ablation.tsv
whitelist_curve.tsv
candidate_delta_by_struct.tsv
candidate_delta_by_pass.tsv
```

**验收**

- 可以回答“加入 struct X 后具体哪些 variant/handler 发生变化”。
- 可以验证少数 struct 是否贡献大部分候选变化。
- 白名单选择过程可复现，不依赖事后手工修改代码。

### 3.10 人工源码核对与结果报告

该步骤只在全局 relation/query/state accounting 已生成后评价候选 precision。人工审查不能补写缺失 relation、
不能把 unresolved state 改成 candidate，也不能作为 Step 4–7 的完成证明。

**输入**

- 每个 Pass/struct 的候选增量。
- 完整 candidate derivation。
- 对应 kernel source 和可选 runtime trace。

**工作**

1. 按 producer、subsystem、candidate size 和引入 Pass 分层采样。
2. 人工检查完整 dispatch 路径，不只检查 handler 名字是否合理。
3. 对候选标注人工结论、证据位置和无法判断原因。
4. 分别报告每个 Pass 的人工结果和未审查人口。
5. 保留误报、漏报和未知案例，禁止只报告成功样例。

**输出**

```text
manual_candidate_labels.tsv
manual_review_evidence.tsv
pass_comparison_report.md
```

**验收**

- 任何 precision 数字都有明确分母、采样方法和 Pass 配置。
- 报告区分机械 candidate delta 与人工真假判断。
- 不使用“唯一候选”等价“真实 handler”的表述。

### 3.11 与当前代码的迁移关系

当前实现中的以下部分可以继续复用：

- `extract/ir_defuse.cpp` 的 DWARF field、CMD、FIELD_ICALL、registration 和 table facts。
- `model/variant.py` 的 variant/resource/selector 解析。
- `provenance/` 中 syz resource 到 kernel registration roots 的结构化 join。
- `probes/candidate_trace.py` 和 `region_audit.py` 的 population/candidate-set 报告框架。

需要重新定位的部分：

- `_TYPE_UNION_PROVIDER_STRUCTS` 从 solver 能力列表改为外部 WHITELIST policy。
- `run_fixpoint` 从“按 struct provider 补 context”改为通用 points-to tuple worklist。
- `dispatch.resolve` 的四个隐式 fallback pass 改为独立实验配置，并分别输出候选与 derivation。
- `ctx[X]` 从 struct type 级字段字典改为 abstract object 级 `MemPt(object, field, target)` 查询。

迁移期间必须同时保留旧、新两套候选输出，通过逐 variant diff 判断每次变化，而不是用总数相同作为无回归证明。

## 8. 2026-07-15 Field-cycle 与 DYN memory alias 对照

本轮使用同一份 schema v3 全量 facts、同一份 callsite context 输入和同一组 solver 参数，只改变
`field-cycle` 与 `dynamic-alias`。配置为 `unknown=drop`、`field-dynamic=strided`、
`field-type=compatible`、`max-strided-expansion=256`、`offset-overflow=drop`、
`call-flow=callsite`、`context-depth=1`、`value-slice=all`，tuple 安全阀为 30M。

```text
Pass                                      tuples       pending  indirect  truncated
field-cycle=drop, alias=none               4,573,043          0      3021  false
field-cycle=root_dyn, alias=none          11,379,055          0      3021  false
field-cycle=iterate, alias=none           30,000,582      8782      3195  true
field-cycle=root_dyn, alias=root          15,633,549          0      3461  false
```

所有四组的 `field_cycle_edges` 都是 12,613。`root_dyn` 组将这 12,613 条边显式记为
`field_cycle_edges_root_dynamic`；`drop` 组将其记为 `field_cycle_edges_dropped`。方向化
`dynamic-alias=root` 额外生成 15,561 条 `MEMORY_ALIAS` 边，并保留 LOAD/STORE source provenance。

机械结论：

1. `max-tuples` 不是造成局部最优的根因。`iterate` 在达到上限时仍有 pending tuples，说明约束闭包
   仍在增长；提高上限只会继续展开 cycle。
2. `field-cycle=root_dyn` 消除了该类无界展开并达到 pending=0，但它是 root-wide 抽象，不保留具体
   数组 offset，不能直接作为最终语义。
3. 仅使用独立 DYN cell 会漏掉动态地址与具体 memory cell 的关系；方向化 alias 修复了 LOAD/STORE
   的基本 may-alias 方向，并新增 440 个间接目标（3021→3461）。这说明它比 `alias=none` 信息更完整，
   但 `static_calls_table@DYN` 等热点仍然显示 root-wide 区域过宽。
4. `applied_seeds.tsv` 在 `drop`、`root_dyn/none` 和 `root_dyn/root` 之间逐字节相同；本轮新增目标
   目前只改变通用间接调用闭包，尚未改变 handler seed 的直接绑定结果。这个事实不能外推为候选真假。

因此本轮没有把任何 Pass 标成“精确”或“可靠”。root-wide `DYN` 的下一项通用子任务是用带
`base/stride/bound` 的 symbolic affine region 表示 field cycle，并为 region-to-memory 的 LOAD/STORE
关系保存一等 provenance。该子任务解决 Step 4 的终止性和区域表达问题，但不改变 Step 4 对全局函数间
关系、summary relation 和验收链的要求。

## 9. 2026-07-15 Symbolic affine region 实现

本轮将上一节提出的 root-wide `DYN` 替换为通用的 `AffineRegion` 抽象。抽象对象仍然保持独立的
`root_object`，region 只描述该 root 内的 offset 集合：

```text
AFF(base, stride, bound)
{ base + i * stride | 0 <= i, base + i * stride <= bound }
```

实现要点：

- `ObjKey` 增加稳定的 region ID，region 表挂在 `Database` 上，因此 demand 多轮和不同 solver
  实例共享同一 `{base,stride,bound}` 定义；对象结构仍为 16 字节。
- `field-cycle=affine` 只对 Bitcode 中检测到的字段边 + COPY 回边生效。直接字段 cycle 和
  `FIELD_ADDR_STRIDED` cycle 都计算 offset 生成元的 gcd，并在已知 object size 的范围内生成有限
  progression；同一 closure 再次经过回边时复用原 region，不逐 offset展开。
- 普通 constant GEP 对 region 做 base/bound 平移；在 `offset-overflow=drop` 下，平移后的 progression
  与对象合法 offset 范围求交并按原 residue/stride 对齐，只删除越界成员，不能因一个尾部成员越界而
  删除整个 region。每次求交写入 `affine_region_clips.tsv`，包含输入/输出区间、字段偏移、constraint
  source 和 application count。
- region LOAD/STORE 只与 progression 相交的 concrete/region cells 建方向化 `MEMORY_ALIAS`。所有
  region 生成和 alias 边都保留 tuple predecessor 与 source provenance。
- 未知 object size、算术溢出或无法形成正 stride 时显式计数并回退 `DYN`；没有名字匹配、struct
  白名单或 subsystem 分支。

全量配置与上一节相同，只将 `field-cycle=affine`，`dynamic-alias=none`：

```text
Pass                                      tuples       pending  indirect  truncated
field-cycle=drop, alias=none               4,573,043          0      3021  false
field-cycle=affine, alias=none             9,372,221          0      3195  false
field-cycle=root_dyn, alias=none          11,379,055          0      3021  false
field-cycle=root_dyn, alias=root          15,633,549          0      3461  false
field-cycle=iterate, alias=none           30,000,582      8782      3195  true
```

affine 全量统计为：`field_cycle_edges=12,613`、`field_cycle_edges_affine=12,613`、
`affine_region_applications=53,518`、`affine_regions_created=7,917`、
`affine_region_clips=20,881`、`affine_alias_edges=14,698`、
`affine_region_fallback_dynamic=0`，且 `pending=0`。输出包含 10,932 个 root-region 实例，逐行检查
`stride>0`、`base<=bound`、bound 同余和 count 均为 0 error；19,388 条唯一 clip provenance 覆盖
232 个 root，application count 求和与统计一致。

`applied_seeds.tsv` 与 drop/root_dyn 两组逐字节相同。相对 drop，affine 新增 174 个间接目标、
没有删除目标；相对 root-wide alias=root，affine 是严格子集（少 266 个目标）。这些是 Pass delta，
不是 precision 真值。

边界审计发现并修复了原 constant-field 平移的 all-or-nothing bug：例如
`pci_dev_acs_enabled[]` 的循环 region `AFF(16,16,2640)` 再取函数字段时，旧实现因尾部成员越界删除
整个 region，只留下常量折叠的 1 个 handler；求交后恢复源码表中的全部 14 个 handler。修复相对
pre-clip 新增 40 个 target，逐项只来自三个真实回调表：PCI ACS 13、Ceph vxattr 23、USB audio
validator 4。其余新增 region 主要来自 `vpanic.buf`、`global_trace`、ACPI printf buffer 等字节缓冲区，
没有改变间接目标集合。

同次审计还发现，schema v2 `objects.tsv` 会使 `field-type=compatible` 的所有检查退化为 unknown。
solver 现在要求 compatible Pass 必须读取带 `contained_structs` 的 schema v3，否则直接失败；
`fixpoint_stats.json` 写入 `object_schema_version`，不能再静默产生看似收敛但类型过滤未生效的结果。

真实热点 `lib__built-in.000` 的 `obj_hash` cycle `+72` 被表示为例如
`AFF(72,72,1441728)`，count 为 20,024；这个 bound 是 object size 推出的保守边界，不是源码循环
trip count。它证明无限 tuple 展开已被替换为有限符号对象，也记录了未来可以用 LLVM loop/range 证据
收紧 bound 的 policy backlog；该精化不是当前 Step 4 主线。

当前仍明确未完成的部分：131,514 条无法证明有限范围的 `FIELD_ADDR_DYNAMIC` 在 `strided` 配置中
仍被丢弃；region 与 `MEMCPY` 的复杂交互暂时回退 DYN；region-region overlap 使用保守同余判定，
可能增加候选但不会自动证明候选为真。174 条 affine-vs-drop 新增目标目前只对 clipping 新增的 40 条
完成逐项源码表核对，其余 134 条移入 Step 9 人工评价 backlog。它们不再作为 Step 4 的下一执行步骤；
Step 4 当前回到 §3.5 的关系层验收，优先补齐全局 `ArgFlow/ReturnFlow` 和一等 summary relations。

## 10. 2026-07-15 Step 4 纠偏后的执行计划

### 10.1 阶段 A：补齐全局函数间传播

**目标**

在保持 K=1 contextual Pass 的同时，保证所有 Bitcode direct callsite 都有显式的参数/返回传播语义，不能
因为 callsite 不在 handler-rooted context 集合中而消失。

**实现**

1. 为每个函数保留一个 context-insensitive baseline instance；创建 contextual clone 时不能无条件删除
   baseline 的函数体约束，只有确认没有 baseline transfer 的具体关系才允许去重。
2. 按 callsite policy 连接调用：**已选站点**的每个 caller instance（包括 baseline caller）都进入由该
   callsite/call-string 标识的 contextual callee；**未选站点**进入 callee baseline。函数 baseline body 始终
   保留，但已选站点原始的 context-insensitive `CALL_ARGUMENT/CALL_RETURN` 必须被 contextual transfer
   替换，不能同时传播。一个静态 callsite 可以有多个 caller-context transfer，但每个 transfer instance
   只有一种语义。
3. 为每个 direct transfer 记录 `contextual`、`context_insensitive`、`no_pointer_interface` 或
   `unresolved_callee`，并断言需要 pointer flow 的 transfer 不会落入无传播状态。
4. `CallTarget` 新增后，间接站点使用相同策略连接 actual/formal/return；handler reachability 只能选择是否
   增加 context precision，不能决定基本 call flow 是否存在。
5. 增加 selftest：handler cone 外的 direct helper、contextual/CI 双向跨边界、handler cone 外新发现的
   indirect target 均能传播参数和返回值，同时两个 contextual callsite 仍保持隔离。

**验收**

- direct pointer-flow transfers 守恒：`contextual + context_insensitive + unresolved = total`。
- 未选择 contextual 的站点仍能在 derivation 中看到 `CALL_ARGUMENT/CALL_RETURN`。
- baseline 与 contextual 函数体均存在可重放 derivation，跨边界 transfer 不进入没有函数体约束的死节点。
- K=1 隔离 selftest 保持通过。

### 10.2 阶段 B：Summary relation 一等化

**目标**

Step 4 输出 kernel relations，而不是只用 summary 预选 handler roots。

**实现**

1. 为 `dispatch_field`、`context_field` 和 `cmd_selector` 建立稳定 relation ID。
2. 保存 subject object/dispatcher、field 或 selector key、target handler、source 和 predecessor。
3. 输出 `dispatch_summary_relations.tsv` 与 `selector_summary_relations.tsv`。
4. `cmd_selector` 在 Step 4 只保存，不按 variant 激活；Step 6 再用 variant selector environment 查询。

**验收**

- `api_summaries.tsv` 中所有可解析 summary 均进入 relation census，重复项有明确去重统计。
- `applied_seeds.tsv` 的每条 summary 使用都能引用 relation ID，而不是重新按名字连接。
- `cmd_selector` 不再只有总数统计。

### 10.3 阶段 C：正式全量闭包与激活审计

**目标**

在 schema v3 和 affine Pass 上重新得到可解释的全量关系闭包，并解释 19,090,856 条输入约束如何产生最终
tuple，而不是直接比较两个不可比总数。

**实现**

1. 运行 `value-slice=all`、修复后的 callsite Pass，保留完整 tuple 和 derivation 输出。
2. row-level 按 constraint kind 统计互斥集合：`never_source_reached`、`reached_not_executed`、
   `executed_produced_new`、`executed_no_new`；保证它们与 loaded rows 守恒。
3. event-level 另外统计 `executions/new_tuple_events/duplicate_events/policy_drop_events/unresolved_events`。
   这些计数允许同一 constraint 同时贡献多个事件类别，不能相加冒充 constraint coverage。
4. 输出 `constraint_activation_census.tsv` 和分层 provenance samples。
5. 单独报告 dynamic GEP、strided expansion limit、typed field、offset overflow 和 unknown policy 的 drop。

**验收**

- `pending=0`、`truncated=false`，且没有因 handler reachability 删除基本 call flow。
- `points_to.tsv`、`memory_points_to.tsv`、`indirect_call_targets.tsv`、完整 derivation 和 summary relations
  同时存在。
- row-level 互斥状态守恒到 loaded constraints；event-level 单独报告，重复 tuple 不被误写为未执行约束。

### 10.4 阶段 D：独立全量闭包验证

**目标**

验证最终关系是否对全部输入约束满足声明的抽象语义。这里不判断候选在真实运行时是真是假，也不选择几个
subsystem 链路作为方法成立的证据。

**实现**

1. 新增独立 closure checker，消费 schema v3 constraints、context/transfer map、Pass policy、summary
   relations 和最终 `Pt/MemPt/CallTarget/ArgFlow/ReturnFlow`。checker 可以复用 schema parser，但不能调用
   solver worklist 或 solver transfer 实现来证明自己。
2. 对每个 `(constraint_id, premise tuple/context)` 生成稳定 obligation key。按 value/root/callsite 分区，
   使用流式或 sort-merge relation join 与 anti-join 检查，避免物化全部 satisfied obligation：
   `ADDR_OF/UNKNOWN_ADDR -> Pt`、`COPY -> Pt`、`FIELD -> transformed Pt`、
   `LOAD -> Pt`、`STORE -> MemPt`、`callee Pt -> CallTarget`、
   `CallTarget + actual/formal/return -> ArgFlow/ReturnFlow`。
3. affine、strided、typed-field、unknown、offset overflow 等 policy 由 checker 根据输入和配置重新计算。
   没有结论的 obligation 必须进入带 reason 的 `policy_disposition` 或 `unresolved`；不能只相信 solver
   自己写出的 drop counter。
4. 对 `dispatch_field/context_field/cmd_selector` 做输入 summary 到一等 relation 的全量守恒检查；Step 4
   只检查关系存在，不激活 variant selector。
5. 对跨 batch identity 做总体检查：所有可解析 `sym:` declaration/definition 使用同一 canonical
   value/object/function ID；无法连接的 symbol 全部进入 unresolved frontier，不使用几个跨 batch 样例代替。
6. 输出 `fixpoint_obligation_census.tsv`、`fixpoint_violations.tsv`、`policy_dispositions.tsv` 和
   `unresolved_relation_frontier.tsv`。完整 satisfied obligations 可只保存计数与确定性分层样本，所有
   violation 和 unresolved 必须完整保存。

**验收**

- `fixpoint_violations=0`，且 checker 自己没有达到资源上限或截断。
- 每个前提成立的 obligation 都属于 `satisfied/policy_disposition/unresolved`，三类按 obligation key 守恒。
- 每个新增 `CallTarget` 的所有 pointer actual/formal/return transfer 均被覆盖，没有 handler-rooted gate。
- input constraint、seed、summary、cross-batch symbol 和 policy drop 均有明确分母及 unresolved frontier。
- 相同输入和配置重复运行，关系文件与 checker census 的排序后 hash 一致。

HID、socket、TTY、DVB 和合成 call-context 场景继续保留为快速 selftest/regression fixture；它们只能帮助
定位违反哪条 transfer rule，不能替代上述全量验收。阶段 A–D 全部通过后，Step 4 才能标记完成。

### 10.5 Stage Gate 实现状态

门禁入口已经实现：

```bash
python3 scripts/seed_horizon/probes/check_step4_gate.py RESULT_DIR \
  --json-out RESULT_DIR/step4_gate_report.json

# 最终验收必须提供第二次独立运行：
python3 scripts/seed_horizon/probes/check_step4_gate.py RESULT_DIR_A \
  --compare RESULT_DIR_B \
  --json-out RESULT_DIR_A/step4_gate_report.json
```

退出码 `0` 只表示所有必需检查和 deterministic rerun 均通过；存在 relation/accounting/closure failure 时返回
`1`，未提供独立 rerun 时最高只能得到 `INCOMPLETE`。完整 artifact schema 见
`scripts/seed_horizon/step4-gate-schema.md`。

当前 `/tmp/kernel_pt_v3_affine_final_current` 的门禁结果为：

```text
global_stats_contract             PASS
core_relation_artifacts           PASS
call_transfer_conservation        FAIL     missing call transfer relations
summary_relation_conservation     FAIL     missing first-class summary relations
constraint_activation_accounting  FAIL     missing activation census
independent_closure_certificate   FAIL     checker not implemented
deterministic_rerun                NOT_RUN
```

因此当前下一 blocker 固定为阶段 A 的 `call_transfer_conservation`，不能转去 affine target 人工审计或新的
policy 精化。
