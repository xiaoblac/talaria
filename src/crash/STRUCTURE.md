# crash 目录组织说明（V2 / syz）

本文档用于约束 `crash` 组件内的文件落位，避免再次出现“同一逻辑多路径并存”。

## 一、当前分层

- `crash/pipeline`
  - `manager/`：对外入口与流程驱动
  - `engine/linuxkernel/syz_engine/`：Linux kernel + syz 的目标语义能力
  - `policy/linuxkernel/syz_xxx_policy/`：流程编排和参数策略
  - `ops/linuxkernel/syz_ops/`：处理步骤/操作单元
- `crash/repro`
  - `manager/`：repro 对外入口与流程驱动
  - `engine/linuxkernel/syz_engine/`：repro 目标语义能力
  - `policy/linuxkernel/syz_xxx_policy/`：repro 阶段策略
  - `ops/linuxkernel/syz_ops/`：执行交互操作（含 channel adapter）
- `crash/components`
  - 共享组件（当前仅 `symbolizer`）
- `crash/infra`
  - 跨 `pipeline/repro/components` 共享的基础模型与基础存储实现
  - `include/refuzz/crash/infra/`：稳定共享契约
  - `src/`：基础落盘与去重实现（当前 `DiagnosticStore`，直接按六分类落盘）

## 二、root 与 infra 规则

`crash` 根目录不再承载共享头与实现；共享基础能力统一放在 `crash/infra`。

当前 `infra` 承载文件：

- `crash_context.hpp`
- `crash_report.hpp`
- `diagnostic_store.hpp`
- `diagnostic_artifact.hpp`
- `diagnostic_attachment_provider.hpp`

### 归档规则（后续新增/迁移）

- **同时被 pipeline 和 repro 使用且属于基础模型/基础存储**：放 `crash/infra/include/refuzz/crash/infra/`
- **仅 pipeline 使用**：放 `crash/pipeline/include/refuzz/crash/pipeline/...`
- **仅 repro 使用**：放 `crash/repro/include/refuzz/crash/repro/...`
- **可复用基础能力（如 symbolizer）**：放 `crash/components/include/refuzz/crash/components/...`

## 三、空文件夹规则

- 只保留“将被立即使用”的目录骨架。
- 若目录暂时为空但确定保留，放置 `.gitkeep` 并在同级 `README` 写明用途。
- 已弃用目录不保留空壳，不再放兼容代码路径。

## 四、命名规则

- engine：`syz_*_engine`
- policy：`syz_*_policy`
- ops：`syz_*_ops` 或具体 ops 名（如 `channel_exec_ops`）
- 平台段固定：`linuxkernel`

## 五、边界规则（重要）

- `ReproManager` 不直接依赖 `ReproChannel`，只依赖 `ops/adapter`（当前 `ChannelExecOps`）。
- `policy` 不直接触达 channel 细节，只描述阶段顺序与参数。
- `engine` 不做流程调度，只做语义能力（parse/match/minimize/symbolize）。

