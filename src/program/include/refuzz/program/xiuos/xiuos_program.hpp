// Copyright 2026 reFuzz project author -------youngkk.
//
// XiUOS in-memory program representation + program → bytes encoder.
//
// Architecture: `program/` is the substrate that channel / corpus / mutator /
// feedback all consume (see program/design.md §1). XiUOS-specific *program*
// concepts — what an API call looks like, which APIs exist, how a list of
// calls becomes the PROGRAM payload bytes — belong here, not in
// `executor/channel/`. The channel layer owns wire-level concerns (frames,
// CRC, sync, RESULT status decoding) and consumes these program-level
// types downward.
//
// Constants (XIUOS_PROGRAM_VERSION, XIUOS_CALL_RECORD_SIZE, XIUOS_MAX_PAYLOAD,
// and the C-compatible C enums) live in
// `proto/wire/include/refuzz/proto_wire/xiuos_uart_protocol.h`; both `program/`
// and `executor/channel/` link `refuzz_proto_wire` to see them.

#pragma once

#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace refuzz::program::xiuos {

// ───── Typed C++ enums (mirror the C enum tags in xiuos_uart_protocol.h) ─────

enum class XiuosApiId : std::uint8_t {
    SemCreate    = XIUOS_API_SEM_CREATE,
    SemDelete    = XIUOS_API_SEM_DELETE,
    SemObtain    = XIUOS_API_SEM_OBTAIN,
    SemAbandon   = XIUOS_API_SEM_ABANDON,
    SemSetValue  = XIUOS_API_SEM_SET_VALUE,

    MutexCreate  = XIUOS_API_MUTEX_CREATE,
    MutexDelete  = XIUOS_API_MUTEX_DELETE,
    MutexObtain  = XIUOS_API_MUTEX_OBTAIN,
    MutexAbandon = XIUOS_API_MUTEX_ABANDON,

    MsgqCreate       = XIUOS_API_MSGQ_CREATE,
    MsgqDelete       = XIUOS_API_MSGQ_DELETE,
    MsgqSend         = XIUOS_API_MSGQ_SEND,
    MsgqRecv         = XIUOS_API_MSGQ_RECV,
    MsgqUrgentSend   = XIUOS_API_MSGQ_URGENT_SEND,
    MsgqReinit       = XIUOS_API_MSGQ_REINIT,

    EventCreate      = XIUOS_API_EVENT_CREATE,
    EventDelete      = XIUOS_API_EVENT_DELETE,
    EventTrigger     = XIUOS_API_EVENT_TRIGGER,
    EventProcess     = XIUOS_API_EVENT_PROCESS,

    TimerCreate      = XIUOS_API_TIMER_CREATE,
    TimerDelete      = XIUOS_API_TIMER_DELETE,
    TimerStartRun    = XIUOS_API_TIMER_START_RUN,
    TimerQuitRun     = XIUOS_API_TIMER_QUIT_RUN,
    TimerModify      = XIUOS_API_TIMER_MODIFY,
    TimerAssignMemberRun = XIUOS_API_TIMER_ASSIGN_MEMBER_RUN,

    TaskSpawnBlockSem      = XIUOS_API_TASK_SPAWN_BLOCK_SEM,
    TaskSpawnBlockEvent    = XIUOS_API_TASK_SPAWN_BLOCK_EVENT,
    TaskSpawnBlockMsgqRecv = XIUOS_API_TASK_SPAWN_BLOCK_MSGQ_RECV,
    TaskTerminate          = XIUOS_API_TASK_TERMINATE,
    TaskPrioSet            = XIUOS_API_TASK_PRIO_SET,
    TaskSpawnSelfSuspend   = XIUOS_API_TASK_SPAWN_SELF_SUSPEND,
    TaskWakeup             = XIUOS_API_TASK_WAKEUP,
    TaskSpawnSelfDelay     = XIUOS_API_TASK_SPAWN_SELF_DELAY,
    TaskSpawnBlockSemTimeout = XIUOS_API_TASK_SPAWN_BLOCK_SEM_TIMEOUT,
    TaskSpawnBlockEventTimeout = XIUOS_API_TASK_SPAWN_BLOCK_EVENT_TIMEOUT,
    TaskSpawnBlockMsgqRecvTimeout = XIUOS_API_TASK_SPAWN_BLOCK_MSGQ_RECV_TIMEOUT,
    TaskSpawnBlockMutexTimeout = XIUOS_API_TASK_SPAWN_BLOCK_MUTEX_TIMEOUT,
    TaskSpawnBlockGbAlloc = XIUOS_API_TASK_SPAWN_BLOCK_GB_ALLOC,
    TaskSpawnBlockMsgqSendTimeout = XIUOS_API_TASK_SPAWN_BLOCK_MSGQ_SEND_TIMEOUT,
    TaskGetPrio             = XIUOS_API_TASK_GET_PRIO,
    TaskSpawnBlockMutexHigh = XIUOS_API_TASK_SPAWN_BLOCK_MUTEX_HIGH,

    WqCreate               = XIUOS_API_WQ_CREATE,
    WqDeinit               = XIUOS_API_WQ_DEINIT,
    WqSubmit               = XIUOS_API_WQ_SUBMIT,
    WqSubmitDelayed        = XIUOS_API_WQ_SUBMIT_DELAYED,

    DqInit                 = XIUOS_API_DQ_INIT,
    DqDeinit               = XIUOS_API_DQ_DEINIT,
    DqPush                 = XIUOS_API_DQ_PUSH,
    DqPop                  = XIUOS_API_DQ_POP,
    DqPeek                 = XIUOS_API_DQ_PEEK,

    WaitqInit              = XIUOS_API_WAITQ_INIT,
    WaitqSpawnWait         = XIUOS_API_WAITQ_SPAWN_WAIT,
    WaitqWake              = XIUOS_API_WAITQ_WAKE,

    ResourceSnapshot       = XIUOS_API_RESOURCE_SNAPSHOT,
    HeapSnapshot           = XIUOS_API_HEAP_SNAPSHOT,
    TickMsToTick           = XIUOS_API_TICK_MS_TO_TICK,
    TickToMs               = XIUOS_API_TICK_TO_MS,
    HeapIntegrity          = XIUOS_API_HEAP_INTEGRITY,

    Malloc                 = XIUOS_API_MALLOC,
    Free                   = XIUOS_API_FREE,
    Realloc                = XIUOS_API_REALLOC,
    Calloc                 = XIUOS_API_CALLOC,

    CaInit                 = XIUOS_API_CA_INIT,
    CaRelease              = XIUOS_API_CA_RELEASE,
    CaReset                = XIUOS_API_CA_RESET,
    CaWrite                = XIUOS_API_CA_WRITE,
    CaRead                 = XIUOS_API_CA_READ,
    CaGetDataLength        = XIUOS_API_CA_GET_DATA_LENGTH,

    AvlInsert              = XIUOS_API_AVL_INSERT,
    AvlDelete              = XIUOS_API_AVL_DELETE,
    AvlModify              = XIUOS_API_AVL_MODIFY,
    AvlSearch              = XIUOS_API_AVL_SEARCH,
    AvlCount               = XIUOS_API_AVL_COUNT,
    AvlCheck               = XIUOS_API_AVL_CHECK,

    CapFlagSet             = XIUOS_API_CAP_FLAG_SET,
    CapFlagCheck           = XIUOS_API_CAP_FLAG_CHECK,
    CapAddTask             = XIUOS_API_CAP_ADD_TASK,
    CapAddRoot             = XIUOS_API_CAP_ADD_ROOT,
    CapAddRootSelf         = XIUOS_API_CAP_ADD_ROOT_SELF,
    CapRemoveTask          = XIUOS_API_CAP_REMOVE_TASK,
    CapCheckTask           = XIUOS_API_CAP_CHECK_TASK,
    CapSetTask             = XIUOS_API_CAP_SET_TASK,

    GbCreate               = XIUOS_API_GB_CREATE,
    GbDelete               = XIUOS_API_GB_DELETE,
    GbAlloc                = XIUOS_API_GB_ALLOC,
    GbFree                 = XIUOS_API_GB_FREE,
};

enum class XiuosSuiteId : std::uint8_t {
    CommonKernel = XIUOS_SUITE_COMMON_KERNEL,
};

// ───── In-memory program element ─────

struct XiuosProgramCall {
    XiuosApiId                   api_id;
    std::array<std::uint32_t, 4> args{};   // unused tail must remain 0
    std::uint8_t                 argc{0};  // 0..4
    std::uint16_t                flags{0};
};

inline constexpr std::size_t kXiuosProgramHeaderSize = 4u;
inline constexpr std::size_t kXiuosMaxCallsPerProgram =
    (XIUOS_MAX_PAYLOAD - kXiuosProgramHeaderSize) / XIUOS_CALL_RECORD_SIZE;

// ───── Program → bytes encoder (PROGRAM payload only; not wire frame) ─────

// Encode one call into 20 wire bytes. argc must be 0..4 (Phase 1 worker
// rejects argc > 4 with PROGRAM_REJECTED).
std::array<std::uint8_t, XIUOS_CALL_RECORD_SIZE>
XiuosEncodeCall(const XiuosProgramCall& call);

// Encode a full PROGRAM payload (header + N call records). The result is
// what goes into ChannelDispatchRequest.payload — the channel layer then
// wraps it in a wire frame with CRC.
// Throws std::invalid_argument if calls.size() exceeds the 8-bit call_count
// field or the PROGRAM payload would exceed XIUOS_MAX_PAYLOAD.
std::vector<std::uint8_t>
XiuosEncodeProgram(std::span<const XiuosProgramCall> calls,
                   XiuosSuiteId suite_id = XiuosSuiteId::CommonKernel,
                   std::uint8_t flags = 0);

// ───── Bytes → program decoder (symmetric pair of XiuosEncodeProgram) ─────
//
// Consumed by host-side mutator / repro / minimize that need to read the
// structured calls back out of a Seed.payload or AbnormalCompletion
// program_payload. Throws std::invalid_argument on:
//   - too-short payload (< 4 bytes header)
//   - payload longer than XIUOS_MAX_PAYLOAD
//   - program_version mismatch
//   - call_count * XIUOS_CALL_RECORD_SIZE + 4 != payload.size()
//   - argc > 4 in any individual call record
//
// argc and api_id are NOT validated against XIUOS_API_* — the worker may
// well receive a mutated PROGRAM with an unknown api_id (the test surface
// for "unsupported API" path), so the decoder preserves whatever the wire
// said. Consumers that need ABI-validity should run their own check.
struct XiuosDecodedProgram {
    XiuosSuiteId                  suite_id{XiuosSuiteId::CommonKernel};
    std::uint8_t                  flags{0};
    std::vector<XiuosProgramCall> calls;
};

XiuosDecodedProgram
XiuosDecodeProgram(std::span<const std::uint8_t> payload);

}  // namespace refuzz::program::xiuos
