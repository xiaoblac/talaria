// Copyright 2026 reFuzz project author -------youngkk.
//
// ErrorCode — 底层执行器/worker 返回的错误码枚举。
// 从 ivshmem_protocol.h 中提取，供 executor、proto、channel 等模块独立引用。

#ifndef REFUZZ_PROTO_ERROR_CODES_H
#define REFUZZ_PROTO_ERROR_CODES_H

typedef enum {
    ERR_OK                = 0,
    ERR_TIMEOUT           = 1,
    ERR_WORKER_CRASHED    = 2,
    ERR_INVALID_INPUT     = 3,
    ERR_OUTPUT_TOO_LARGE  = 4,
    ERR_EXECUTOR_ERROR    = 5,
    ERR_HARNESS_OUTER_FORK_EAGAIN = 6,
    ERR_HARNESS_OUTER_FORK_FAILED = 7,
    ERR_HARNESS_MAIN_REAP_FAILED = 8,
    ERR_HARNESS_STOPPED_REAP_TIMEOUT = 9,
    ERR_HARNESS_FORK_SERVER_PROTOCOL = 10,
    ERR_DOMAIN_WATCHDOG_TIMEOUT = 11,
    ERR_HARNESS_CLEANUP_FAILED = 12,
    ERR_HARNESS_KCOV_STATE_INVALID = 13,
    ERR_DOMAIN_REPLACEMENT_START_FAILED = 14,
    ERR_DOMAIN_OWNERSHIP_UNRECLAIMED = 15,
    ERR_PROGRAM_CHILD_CRASHED = 16,
    ERR_TASK_CANCELLED = 17,
    // 兜底:走到了不该走到的分支(未知 wire status / 未匹配的 kind)。配
    // COMP_STATUS_UNKNOWN 使用。出现即 bug 信号,不是正常终态。
    ERR_UNKNOWN = 18,
} ErrorCode;

#endif // REFUZZ_PROTO_ERROR_CODES_H
