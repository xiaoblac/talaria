# Kernel Bitcode Points-to Constraint Schema

状态：Step 2 schema v3，2026-07-14。

该 schema 描述从 LLVM Bitcode 机械生成的、与具体 handler 名称无关的指针约束。它是后续
Fixpoint 的输入，不直接产生 `variant -> handler` 绑定。

## 1. 身份规则

### 1.1 Value ID

Value ID 表示 LLVM SSA value：

```text
sym:value:function:<symbol>             外部可见 function value
sym:value:global:<symbol>               外部可见 global address
batch:<B>:local:value:function:<name>   internal/private function value
batch:<B>:local:value:global:<name>     internal/private global address
batch:<B>:ssa:<function>:arg:<index>    formal argument
batch:<B>:ssa:<function>:i<ordinal>     instruction result
batch:<B>:expr:<site>                   ConstantExpr / synthetic pointer value
special:value:null                      null pointer
```

`ordinal` 是函数内按 basic-block/instruction 顺序分配的稳定序号。所有非 symbol value 都带 batch，
避免不同 linked batch 中同名 internal function/global 相撞。

### 1.2 Abstract Object ID

```text
sym:object:function:<symbol>             外部可见函数对象
sym:object:global:<symbol>               外部可见全局对象
batch:<B>:local:object:function:<name>   internal/private 函数对象
batch:<B>:local:object:global:<name>     internal/private 全局对象
batch:<B>:site:object:stack:<fn>:i<N>    alloca site
batch:<B>:site:object:unknown:<site>     无法恢复身份的 site-local unknown
batch:<B>:site:object:block:<site>       LLVM BlockAddress 对象
special:object:null                      null object
```

后续 recognizer/API summary 可以在同一命名空间加入：

```text
site:object:heap:<callsite>
site:object:registration:<callsite>
site:object:producer:<variant-or-callsite>
```

字段子对象不按 struct type 合并，而由 solver 根据根对象和累计 byte offset 物化：

```text
FieldObject(root_object, signed_byte_offset)
```

因此两个相同类型的 global/alloc site 始终是不同对象。`struct_type` 和 `field_name` 只是 GEP 的
DWARF/IR 元数据，不能替代 object identity。

## 2. `objects.tsv`

```text
#object_id kind scope symbol parent_object byte_offset type contained_structs size batch function instruction debug detail
```

- `kind`：`global`、`function`、`stack`、`unknown`、`block`、`null`。
- `scope`：`symbol`、`batch`、`site`、`special`。
- `parent_object/byte_offset` 为后续物化字段对象保留；Step 2 基对象通常为 `-`。
- `type/size` 来自 LLVM Type/DataLayout，不参与对象合并。
- `contained_structs` 是 LLVM aggregate type 与对象 DWARF type 两条递归证据的命名 struct 并集。两者都
  遍历 struct/union/class、array 和 fixed vector 的内嵌元素，但不穿过 pointer。必须合并两条证据，
  因为 LLVM 优化可能把同布局的 C struct 合并成另一个 IR type，而 DWARF 仍保留源语言成员类型。
- 完整空集编码为 `-`；若任一递归遇到 opaque/forward/incomplete type，则以 `?` 前缀编码不完整证据，
  例如 `?foo,bar` 或仅 `?`。type-compatible Pass 只能在没有 `?` 且集合明确不含 typed GEP 所需 struct
  时拒绝该 GEP。pointer、unknown、synthetic 或不完整对象必须保留。

## 3. `points_to_constraints.tsv`

```text
#constraint_id kind dst_value src_value object_id byte_offset offset_kind struct_type field_name \
 batch function instruction opcode debug detail dynamic_base dynamic_stride dynamic_count source_type
```

约束语义：

```text
ADDR_OF           Pt(dst, object)
UNKNOWN_ADDR      Pt(dst, site_unknown), 且该 object 标记为 unknown
COPY              Pt(src, O) => Pt(dst, O)
FIELD_ADDR        Pt(src, Root@K) => Pt(dst, Root@(K+byte_offset))
FIELD_ADDR_STRIDED
                  Pt(src, Root@K) => Pt(dst, Root@(K+dynamic_base+i*dynamic_stride)),
                  其中 0 <= i < dynamic_count
FIELD_ADDR_DYNAMIC
                  offset 不是常量；保留 base value、source type 和 dynamic 状态，
                  不把它折叠成“同 struct 的任意对象”
```

`source_type` 是 LLVM GEP 的 source element type，经统一 `typeLabel` 编码。它独立于 DWARF
`struct_type`：即使 opaque pointer 或缺失 DWARF 使 `struct_type=-`，数组、整数或命名 struct 的
LLVM 访问类型仍可作为后续 type-compatible Pass 的机械输入。

`offset_kind` 的机器编码固定为：

```text
ADDR_OF / UNKNOWN_ADDR  exact
COPY                    -
FIELD_ADDR              constant
FIELD_ADDR_STRIDED      strided
FIELD_ADDR_DYNAMIC      dynamic
```

`UNKNOWN_ADDR` 的 `exact` 表示该 value 精确指向一个 site-local unknown object，不表示已经知道真实
kernel object。它不能与其他 unknown site 按类型合并。

生成规则：

- global/function address、alloca 和 null 生成 `ADDR_OF`。
- bitcast/addrspacecast/freeze、pointer phi/select 生成 `COPY`。
- constant-offset GEP 生成 `FIELD_ADDR`，signed negative offset 原样保留，因此 `container_of` 可通过
  根对象累计 offset 回到 parent。
- 只有一个 variable term、constant/multiplier 可表示为 signed 64-bit，且该 variable 的 LLVM
  `ConstantRange` 是有限、非 signed-wrap 区间时，dynamic-index GEP 生成 `FIELD_ADDR_STRIDED`。
- 对原式 `constant + multiplier * index` 和可证明区间 `[L,U]`，机器列记录：
  `dynamic_base=constant+multiplier*L`、`dynamic_stride=multiplier`、
  `dynamic_count=U-L+1`。区间内不可能值可被保守包含，但不会越出 LLVM 证明的范围。
- 多 variable term、full/wrapped range、超过 signed 64-bit 或无法证明范围的 dynamic-index GEP
  继续生成 `FIELD_ADDR_DYNAMIC`，不能使用数组名、struct 名或函数名补范围。
- `inttoptr`、无法解释的 pointer ConstantExpr、pointer extract/inline-asm 等生成 site-local
  `UNKNOWN_ADDR`，不能用 struct 名称补对象身份。

## 4. `memory_constraints.tsv`

```text
#constraint_id kind dst_value pointer_value src_value object_id byte_offset size \
 batch function instruction opcode debug detail
```

约束语义：

```text
LOAD          Pt(ptr, O) and MemPt(O, T) => Pt(dst, T)
STORE         Pt(ptr, O) and Pt(src, T) => MemPt(O, T)
STORE_OBJECT  Pt(src, T) => MemPt(FieldObject(object, byte_offset), T)
MEMCPY        copy pointer-bearing memory from src pointer to dst pointer for size bytes
MEMMOVE       与 MEMCPY 相同，但允许区域重叠
```

`STORE_OBJECT` 用于递归展开 global initializer 中的非 null pointer leaves。null initializer 不产生
handler/object edge。运行时 aggregate copy 通过 `MEMCPY/MEMMOVE` 保留，具体 field 展开由 solver 决定。

## 5. `call_constraints.tsv`

```text
#constraint_id kind callsite caller callee target_object index value result_value \
 batch function instruction opcode attributes debug detail
```

关系：

```text
FUNCTION_FORMAL   (callee, index) -> formal value
CALL_TARGET       direct callsite -> function object
CALL_CALLEE_VALUE indirect callsite -> callee pointer value
CALL_ACTUAL       (callsite, index) -> actual value
CALL_RESULT       callsite -> pointer result value
RETURN_VALUE      callee -> returned pointer value
```

后续 Fixpoint 在 `CallTarget(callsite, function)` 新增时，连接同 index 的 `CALL_ACTUAL` 和
`FUNCTION_FORMAL`，并把 `RETURN_VALUE` 传播到 `CALL_RESULT`。`byval/sret/inalloca/nest` 等参数属性保留在
`attributes`，不在 extractor 中静默按普通 copy 处理。

## 6. Provenance 和边界

每条约束保存：

- linked `batch`；
- `function`；
- 函数内 `instruction` ordinal 或 global initializer site；
- LLVM `opcode`；
- 可用时的 DWARF `file:line:column`。

当前 Step 2 有意不把以下语义硬编码进通用 Pass：

- 哪个 kernel API 分配 heap object；
- registration/producer object；
- proc/cdev/socket/anon 等 namespace 安装语义；
- 哪个 selector 控制哪个 dispatch。

这些在 Step 3 作为 typed seed/API summary 加入。通用 Pass 不根据函数名猜 allocator/handler，也不根据
相同 struct type 合并对象。

## 7. Solver Policy（2026-07-14）

`FIELD_ADDR_DYNAMIC` 与 constant GEP 越过已知 object size 是两个不同问题，必须用独立 Pass 控制：

```text
--field-dynamic root_dyn|drop|strided
--max-strided-expansion N
--field-cycle iterate|root_dyn|affine|drop
--dynamic-alias none|root
--offset-overflow dynamic|drop|exact
```

- `root_dyn`：dynamic-index GEP 产生同一 root 下的 `DYN` offset；不跨 root/type 合并。
- `drop`（field dynamic）：不传播 unresolved/strided dynamic GEP，并在 Pass 配置中显式报告。
- `strided`：只展开 `FIELD_ADDR_STRIDED` 的有限 offset set；`FIELD_ADDR_DYNAMIC` 仍作为 unresolved
  计数，不回退 `root@DYN`。
- `max-strided-expansion`：单条 strided 约束的显式资源上限。超过上限计入
  `strided_edges_over_limit`，不回退 `root@DYN`。
- `dynamic`（offset overflow）：constant offset 越过 size/hard cap 时折叠到该 root 的 `DYN`。
- `drop`（offset overflow）：越界派生停止，计入 `dropped_offsets`。
- `exact`：在 hard cap 内继续保留 signed offset，不按 object size 截断。

Field-cycle 和 dynamic-memory alias 是独立的实验维度：

- `--field-cycle root_dyn`：检测到字段边与 COPY 回边形成直接 cycle 时，将该边的结果归并为同一
  root 的 `DYN`，避免逐 offset 无限展开；它不删除 cycle，也不声称保留了每个具体 offset。
- `--field-cycle affine`：将 cycle 的 offset 传递闭包表示为规范化的
  `AFF(base,stride,bound)`。`stride` 始终为正，`base/bound` 为 inclusive；普通常量 GEP 对 region
  做符号平移。`offset-overflow=drop` 对平移后的 progression 与对象范围求交，再按原 residue/stride
  对齐；只删除越界成员，不因一个尾部成员越界删除整个 region。当前 bound 来自 abstract object 的
  静态 size，不使用函数名、数组名或 struct 白名单；object size 未知时显式回退到同 root 的 `DYN`
  并计入 `affine_region_fallback_dynamic`。
- `--field-cycle drop`：删除检测到的 cycle 边，只作为漏报/收敛对照。
- `--dynamic-alias none`：不把 `DYN` memory cell 与具体 cell 建立额外关系，保持最小控制 Pass。
- `--dynamic-alias root`：按访问方向建立 root-local may-alias：LOAD 使用
  `具体 cell -> DYN cell`，STORE 使用 `DYN cell -> 具体 cell`。alias 边带有触发 LOAD/STORE 的 source
  provenance，并计入 `dynamic_alias_edges`；它仍是 root-wide 抽象，不等价于 affine 数组区域。
- affine region 的 LOAD/STORE 使用 progression membership 建立方向化 `MEMORY_ALIAS`；region 与 region
  先检查区间相交和 stride 最大公约数的同余兼容。每条边保留触发 LOAD/STORE 的 source，统计为
  `affine_alias_edges`。`affine_regions.tsv` 保存 root object、base、stride、bound 和派生 count；
  `affine_region_clips.tsv` 保存每个唯一求交的输入/输出 region、字段 offset、constraint source 和
  application count。

`--field-type compatible` 依赖 schema v3 `objects.tsv` 的 `contained_structs`。solver 对 schema v2
输入直接报错，不允许把所有类型检查静默降级成 unknown；`fixpoint_stats.json` 的
`input.object_schema_version` 记录实际输入版本。

v2 全量 census 中，原 156,446 条 dynamic GEP 有 24,932 条转为 `FIELD_ADDR_STRIDED`，131,514 条仍为
`FIELD_ADDR_DYNAMIC`。该分类来自 Bitcode 值域，不是 handler/struct 白名单。`root_dyn`、`drop`、`strided`
都保留为独立 Pass，用候选集合差异和人工源码核对评价，不能把某个 Pass 自动称为真值。
