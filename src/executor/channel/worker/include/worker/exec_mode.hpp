// ExecMode: 执行模式抽象
// 两个正交维度：IntraTask (单程序内 syscall 执行方式) × TaskShape (task payload 包含几个子程序)

#pragma once

#include "refuzz/proto_wire/ivshmem_protocol.h"
#include <cstdint>

namespace refuzz::worker {

// 维度 1: 单子程序内 syscall 如何执行
enum class IntraTaskMode : uint8_t {
    kSerial   = TASK_FLAG_INTRA_SERIAL,    // 逐条串行
    kThreaded = TASK_FLAG_INTRA_THREADED,   // 每条 syscall 一个线程, futex barrier 同步
};

// 维度 2: 一个 task payload 包含几个子程序
enum class TaskShape : uint8_t {
    kSingle = TASK_FLAG_SHAPE_SINGLE,       // 一个子程序 → 一个 child
    kForked = TASK_FLAG_SHAPE_FORKED,       // 多个子程序 → 多个 child (未实现)
};

// Local-only scratch reset policy. This is not encoded in TaskSlot.flags:
// topology selects it after decoding the wire flags.
enum class ScratchResetMode : uint8_t {
    // Long-lived inline child: scratch may contain bytes from the previous
    // program, so keep the historical full-window clear.
    kFullClear = 0,
    // Fork-per-program child: the loop parent owns the clean scratch mapping;
    // writes in the program child die with that child, so a full 16 MiB clear
    // would only create COW/page-fault work.
    kForkClean = 1,
};

struct ExecMode {
    IntraTaskMode intra = IntraTaskMode::kSerial;
    TaskShape     shape = TaskShape::kSingle;
    ScratchResetMode scratch_reset = ScratchResetMode::kFullClear;
};

// 从 TaskSlot.flags 提取 ExecMode
inline ExecMode ExecModeFromFlags(uint32_t flags) {
    ExecMode m;
    m.intra = static_cast<IntraTaskMode>(task_flags_get_intra(flags));
    m.shape = static_cast<TaskShape>(task_flags_get_shape(flags));
    return m;
}

// 检查 ExecMode 是否在 v1 支持范围内 (只支持 kSingle shape)
inline bool ExecModeIsSupported(ExecMode m) {
    return m.shape == TaskShape::kSingle &&
           (m.intra == IntraTaskMode::kSerial ||
            m.intra == IntraTaskMode::kThreaded);
}

// 当前 worker 支持的 flags 占用 intra + shape + collect_comps 三个字段；
// 其余保留位必须为 0，否则视为不支持，避免静默降级执行。
//
// [v2 Epic 5 PR-5-B] CollectComps 加入 supported mask；KCOV_TRACE_CMP
// 模式由 KcovSink 在 OnEvent(kTaskStart) 读 collect_comps 后切换。
inline bool ExecFlagsAreSupported(uint32_t flags) {
    constexpr uint32_t kSupportedMask =
        TASK_FLAG_INTRA_MASK | TASK_FLAG_SHAPE_MASK | TASK_FLAG_COLLECT_COMPS |
        TASK_FLAG_TRACE_SAMPLED;  // [RTT] host-observation gate; no exec-mode effect
    if ((flags & ~kSupportedMask) != 0U) {
        return false;
    }
    return ExecModeIsSupported(ExecModeFromFlags(flags));
}

} // namespace refuzz::worker
