# Step 4 Points-to Analysis Gate Schema

状态：schema v1，2026-07-15。

该门禁约束 Linux kernel Bitcode points-to Step 4 的执行顺序。它验证声明抽象语义下的关系闭包、输入守恒和
确定性，不判断 candidate handler 的运行时真假。小样本只用于 selftest/regression，不能使门禁通过。

## 1. 入口与状态

```bash
python3 scripts/seed_horizon/probes/check_step4_gate.py RESULT_DIR
python3 scripts/seed_horizon/probes/check_step4_gate.py RESULT_DIR_A --compare RESULT_DIR_B
python3 scripts/seed_horizon/probes/check_step4_gate.py --selftest
```

状态：

```text
PASS        检查满足
FAIL        关系、守恒或闭包违反
NOT_RUN     缺少独立 rerun 等尚未执行的验收
INCOMPLETE  没有 FAIL，但仍有 NOT_RUN
```

进程只有在 overall=`PASS` 时返回 `0`；`FAIL/INCOMPLETE` 返回 `1`。`next_blocker` 是检查顺序中的第一个
`FAIL`，没有 `FAIL` 时为第一个 `NOT_RUN`。

## 2. 检查顺序

```text
global_stats_contract
core_relation_artifacts
call_transfer_conservation
summary_relation_conservation
constraint_activation_accounting
independent_closure_certificate
deterministic_rerun
```

后续工作只能处理当前 `next_blocker`，除非明确修改计划目标。precision 审计、loop-bound 精化和新 subsystem
recognizer 不能越过未通过的 closure blocker。

## 3. Global 与核心关系

`fixpoint_stats.json` 必须满足：

```text
batch                              all
policy.value_slice                 all
input.object_schema_version        3
solver.pending_tuples              0
solver.truncated                   false
solver.tuples                      value_tuples + memory_tuples
```

以下文件必须存在、header 匹配且至少有一条数据：

```text
points_to.tsv               #value object
memory_points_to.tsv        #object target
indirect_call_targets.tsv   #callsite function_object function
fixpoint_derivations.tsv    #node object rule predecessor_node predecessor_object source
```

这些条件只证明当前 Pass 终止并产生关系，不单独证明函数间闭包。

## 4. Call Transfer

`call_transfer_map.tsv`：

```text
#transfer_id kind callsite caller caller_context callee callee_context mode status \
expected_arg_flows emitted_arg_flows expected_return_flows emitted_return_flows reason source
```

枚举：

```text
kind    direct | indirect
mode    contextual | context_insensitive | -
status  active | no_pointer_interface | unresolved
```

`active` 必须满足 expected=emitted、具有合法 mode 且 reason=`-`。`no_pointer_interface` 的四个 flow count
必须均为零。`unresolved` 必须有 reason。任何 emitted count 都不能超过 expected count。

`call_arg_flows.tsv`：

```text
#transfer_id callsite caller_context actual callee callee_context formal index source
```

`call_return_flows.tsv`：

```text
#transfer_id callsite caller_context callee callee_context return_value result_value source
```

两个 flow 文件只能引用 `active` 或部分解析的 `unresolved` transfer，逐 transfer 行数必须与 map 中 emitted
count 相等；`no_pointer_interface` 不能拥有 flow。最终 closure checker 另外负责把 unresolved transfer 中
缺失的单个参数/返回 obligation 写入 frontier，并证明 transfer population 覆盖全部适用 direct/indirect call
obligations。

## 5. Summary Relations

`dispatch_summary_relations.tsv` 与 `selector_summary_relations.tsv`：

```text
#relation_id kind subject key target source
```

`summary_relation_census.tsv`：

```text
#kind input_rows emitted_relations duplicate_rows unresolved_rows
```

至少包含 `dispatch_field/context_field/cmd_selector` 三类，并满足：

```text
input_rows = emitted_relations + duplicate_rows + unresolved_rows
```

relation ID 在两个关系文件中全局唯一，关系文件按 kind 的实际行数必须等于 census 的 emitted count。

## 6. Constraint Activation

`constraint_activation_census.tsv`：

```text
#table kind loaded never_source_reached reached_not_executed executed_produced_new executed_no_new \
executions new_tuple_events duplicate_events policy_drop_events unresolved_events
```

逐 `(table,kind)` 的 row-level 状态必须满足：

```text
loaded = never_source_reached
       + reached_not_executed
       + executed_produced_new
       + executed_no_new
```

event-level 字段不是互斥集合，不能相加作为 constraint 分母。三张 constraint table 的 loaded 总数必须分别
等于 `fixpoint_stats.json` 中的 `point_rows/memory_rows/call_rows`。

## 7. Closure Certificate

`fixpoint_obligation_census.tsv`：

```text
#rule obligations satisfied policy_dispositions unresolved violations
```

逐 rule 必须满足：

```text
obligations = satisfied + policy_dispositions + unresolved + violations
```

必须覆盖：

```text
ADDR_OF UNKNOWN_ADDR COPY
FIELD_ADDR FIELD_ADDR_STRIDED FIELD_ADDR_DYNAMIC
LOAD STORE STORE_OBJECT MEMCPY MEMMOVE
CALL_TARGET CALL_ARGUMENT CALL_RETURN
DISPATCH_SUMMARY SELECTOR_SUMMARY
```

完整异常文件：

```text
fixpoint_violations.tsv
  #obligation_id rule constraint_id premise detail

policy_dispositions.tsv
unresolved_relation_frontier.tsv
  #obligation_id rule constraint_id reason source
```

`fixpoint_checker_stats.json`：

```json
{
  "schema_version": 1,
  "truncated": false,
  "obligations": 0,
  "satisfied": 0,
  "policy_dispositions": 0,
  "unresolved": 0,
  "violations": 0
}
```

JSON 总数必须与 census 及完整异常文件一致。最终门禁要求 `violations=0` 和 `truncated=false`；unresolved
允许非零，但必须完整保留并报告分母，不能解释为已恢复的 kernel 路径。

## 8. Determinism

最终门禁需要两个独立 result directory。脚本比较核心 relation、call transfer、summary、activation 和 closure
文件的 SHA-256，并比较去除 load/solve 时间后的 `fixpoint_stats.json` 以及完整
`fixpoint_checker_stats.json`。同一路径不能作为自己的 comparison。

## 9. 当前基线

`/tmp/kernel_pt_v3_affine_final_current` 当前通过：

```text
global_stats_contract
core_relation_artifacts
```

当前第一个 blocker 是 `call_transfer_conservation`。这意味着下一代码增量是保留 baseline 函数体和所有基本
`ArgFlow/ReturnFlow`，不是继续审计 affine target。
