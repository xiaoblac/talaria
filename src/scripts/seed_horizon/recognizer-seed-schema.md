# Recognizer Seed and API Summary Schema

状态：Step 3 schema，2026-07-12。

该 schema 把现有 kernel recognizer 的输出投影成统一关系。它不根据 syzkaller variant 名称、资源名
basename 或 handler 名称补边，也不把候选标记为真或假。

## 1. 分层边界

Step 2 从 Bitcode 生成通用 `Pt/MemPt/CallTarget` 约束。Step 3 只补充通用 IR 无法独立恢复的 kernel
注册根、namespace 语义和 dispatch summary：

```text
ROOT_INSTALL(root, dispatch_object)
DISPATCH_FIELD(dispatch_object, field, function)
CMD_SELECTOR(dispatcher, selector, function)
FIELD_FORWARD(function, field_slot)
CALL_BRIDGE(caller, callee, argument_index)
```

当前 `ROOT_INSTALL` 是迁移边界上的复合 seed：现有 Python builder 已经把 syzkaller root 与 kernel
registration/install 语义连接后返回 `REG row`。它不是 Step 2 的 Bitcode object ID，也不能替代对象身份。
Step 4 Fixpoint 接入时，应逐步把该复合 seed 拆成：

```text
ObjectSeed(root, abstract_object)
Install(abstract_object, dispatch_object)
```

在拆分完成前，`method` 和 `source` 必须保留，以便逐 Pass 比较每类复合 seed 引入的候选。

## 2. `registration_seeds.tsv`

```text
#seed_id relation root_kind root method dispatch_kind dispatch_object_id dispatch_symbol object_status batch reg_row fields subsystem source parent_root
```

- `relation`：`entry_install` 或 `context_install`。
- `root_kind`：`resource` 或 `variant`。variant seed 用于 producer 返回通用 resource、但 producer 自身
  对象语义更精确的情况。
- `root`：syzkaller resource/variant 的精确 catalog ID，不做字符串近似匹配。
- `method`：产生关系的结构方法，例如 `devpath-registration`、`fs-fill-table`、
  `typed-key-table`、`anon-producer`、`socket-protocol`。
- `dispatch_object_id`：通过 `reg.by_tu.tsv` 的 batch 与 Step 2 `objects.tsv` 做精确
  `(batch, global symbol)` join 后得到的 abstract object ID。禁止退化成全局 symbol-name fallback。
- `dispatch_symbol`：REG fact 中的原始 ops global，仅作 provenance，不作为对象身份。
- `object_status`：`exact`、`fanout`、`synthetic` 或 `unresolved`。block/cgroup projected context 使用
  resource/REG-row scoped synthetic object；无法完成 batch-object join 的行显式保留 unresolved。
- `fields`：REG row 的现有 field projection，仅用于审计；规范化 field summary 同时写入
  `api_summaries.tsv`。
- `parent_root`：仅资源 kind 传播使用，记录实际提供 dispatch context 的 child resource。

同一 `(root, dispatch_object)` 可以由多个结构方法产生。导出器保留每条方法 provenance，不通过先到者
覆盖其他方法。

## 3. `api_summaries.tsv`

```text
#summary_id relation subject_kind subject key target_kind target arg_index context source_fact source
```

关系包括：

```text
dispatch_field      (dispatch_object, field) -> function
context_field       (resource-scoped context object, field) -> function
cmd_selector        (dispatcher, cmd/key) -> function
genl_selector       (genl family, cmd) -> function
fs_selector         (filesystem key, mount) -> function
field_forward       function -> field_slot
field_forward_site  (function, instruction) -> field_slot
cmd_reach/_not      selector reachability gate
cmd_call_bridge     cmd-carrying direct call
cmd_data_bridge     data-comparison bridge
cmd_cross_bridge    cross-dispatch bridge
cmd_field_forward   cmd-carrying indirect field call
callback_bridge     callback argument and cmd argument mapping
```

`context` 是关系特有的结构化参数，例如 CMD depth/key kind、callback helper、field-forward site 或 REG
subsystem。`source_fact/source` 保留原始事实类型和行号/builder，summary 可以回溯到原始 Bitcode fact。

## 4. 身份与候选语义

- `dispatch_object_id` 使用 Step 2 的 kernel global object identity，不按 symbol 或 struct type 合并。
- block context 没有已恢复的全局 ops object，因此使用 `seed:resource:<R>:block_device_operations`，明确
  限定在 resource root 内，不创建全局 type union。
- 一个 root 对应多个 dispatch objects 时全部保留；它们共同构成候选上下文。
- summary 只表达静态分析关系，不表示目标 handler 在某次运行中必然执行。

## 5. 生成入口

```text
python3 scripts/seed_horizon/probes/recognizer_seeds.py
```

输出：

```text
run/seed_horizon/registration_seeds.tsv
run/seed_horizon/api_summaries.tsv
run/seed_horizon/recognizer_seed_manifest.json
```
