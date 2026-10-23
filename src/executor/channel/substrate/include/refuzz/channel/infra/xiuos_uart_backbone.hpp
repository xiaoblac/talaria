#pragma once

// XiuosUartBackbone — host-side TCP serial transport for XiUOS reFuzz worker.
//
// Phase 2 §B v1, sibling of IvshmemBackbone in role: an infra-level shared
// resource that the XiUOS UART ControlPlane / DataPlane / (future) Evidence
// source all consume via `shared_ptr<XiuosUartBackbone>`. The XiUOS worker
// (kernel/refuzz/refuzz_worker.c in the XiUOS fork) writes / reads on the
// guest's NS16550 UART; on the host side, QEMU forwards that UART as a TCP
// serial chardev. This class owns the host-side socket fd and frame I/O.
//
// Wire-level framing (magic / sync / CRC / state machine) is the pure-C codec
// in proto/wire/include/refuzz/proto_wire/xiuos_uart_codec.h, shared with the
// XiUOS guest worker so both sides cannot diverge.
//
// What this class does NOT own:
//   - The QEMU subprocess — that is the XiUOS ISubstrate impl's job.
//   - Channel-level orchestration (Submit/Boot/...) — that lives in
//     `Channel` (orchestration/) which the XiUOS CP/DP impls plug into.
//
// Threading contract:
//   - Connect() must return before any other method is called.
//   - SendFrame / WaitFrame must be serialized by the caller (single
//     reader/writer). They are intended to run on Channel::loop_thread_ per
//     executor/design.md §7.2. CP heartbeat and DP PROGRAM/RESULT share the
//     same backbone and the same loop thread; cross-type frames received
//     while waiting for a specific (type, seq) are buffered in a bounded
//     pending queue, not silently discarded.
//   - Close() can be called concurrently from another thread. It performs
//     shutdown(SHUT_RDWR) before close(), so an in-flight SendFrame /
//     WaitFrame returns Error{kConnection, ...} promptly instead of
//     blocking forever. After Close() returns, all subsequent methods
//     return kConnection.
//   - IsConnected() / BufferedFrameQueueSize() are best-effort
//     observability; concurrent reads while WaitFrame mutates state yield
//     stale snapshots.

#include "refuzz/channel/result.hpp"
#include "refuzz/proto_wire/xiuos_uart_codec.h"     // shared pure-C codec

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace refuzz::channel::infra {

// Wire-level frame type tag. Mirrors the C enum XIUOS_FRAME_* (in
// proto_wire/xiuos_uart_protocol.h) — this is just the typed C++ flavor
// the backbone API speaks. CP/DP and tests reference it via the backbone
// header; there is no separate `xiuos_uart_codec.hpp` wrapper anymore.
enum class XiuosFrameType : std::uint8_t {
    Ready   = XIUOS_FRAME_READY,
    Ping    = XIUOS_FRAME_PING,
    Pong    = XIUOS_FRAME_PONG,
    Ack     = XIUOS_FRAME_ACK,
    Program = XIUOS_FRAME_PROGRAM,
    Result  = XIUOS_FRAME_RESULT,
    Reset   = XIUOS_FRAME_RESET,
    Nack    = XIUOS_FRAME_NACK,
};

// One assembled frame produced by the backbone. Backbone owns its bytes;
// the C-level XiuosFrameView from xiuos_uart_codec.h is short-lived and not
// exposed beyond this implementation.
struct XiuosFrameMessage {
    XiuosFrameType            type{XiuosFrameType::Nack};
    std::uint16_t             seq{0};
    std::vector<std::uint8_t> payload;
};

class XiuosUartBackbone {
public:
    struct Config {
        // Transport 选择:kTcp = QEMU 把 guest UART 转发成 TCP serial chardev(host
        // 连过去);kSerial = 物理板的真实串口设备(/dev/ttyACM*)。frame send/recv +
        // 帧状态机完全相同,只有 fd 的获取(connect vs open+termios)与 read/write
        // 原语(recv/send vs read/write)分支。"同机制、不同参数"(见
        // docs/plans/xiuos-ch32-bringup.md §2.3)。
        enum class Transport : std::uint8_t { kTcp, kSerial };
        Transport                  transport{Transport::kTcp};

        // ── kTcp(QEMU)──
        std::string                host{"127.0.0.1"};
        std::uint16_t              port{0};

        // ── kSerial(物理板)──
        std::string                serial_device;          // e.g. "/dev/ttyACM0"
        std::uint32_t              baud{115200};

        std::chrono::milliseconds  connect_timeout{std::chrono::seconds(5)};
        std::chrono::milliseconds  frame_timeout{std::chrono::seconds(10)};
        std::size_t                read_chunk{4096};
        // Upper bound on the pending-frame queue. Frames received while
        // WaitFrame is waiting for a different (type, seq) are queued for
        // later WaitFrame calls (CP/DP share the backbone). When the queue
        // hits this bound, the oldest entry is dropped so a hung consumer
        // can't keep memory growing without limit. 128 is enough for any
        // realistic single-loop interleaving.
        std::size_t                max_queued_frames{128};
    };

    static refuzz::channel::Result<std::shared_ptr<XiuosUartBackbone>>
    Create(const Config& cfg);

    ~XiuosUartBackbone();

    refuzz::channel::Result<void> Connect();

    refuzz::channel::Result<void>
    SendFrame(XiuosFrameType type,
              std::uint16_t seq,
              std::span<const std::uint8_t> payload = {});

    refuzz::channel::Result<XiuosFrameMessage>
    WaitFrame(XiuosFrameType want_type,
              std::optional<std::uint16_t> want_seq,
              std::chrono::milliseconds timeout);

    refuzz::channel::Result<void> Close();

    bool        IsConnected() const noexcept;
    std::size_t BufferedFrameQueueSize() const noexcept;

private:
    XiuosUartBackbone(const Config& cfg);

    // Connect() 按 config_.transport 分派到这两者之一。
    refuzz::channel::Result<void> ConnectTcp();
    refuzz::channel::Result<void> ConnectSerial();

    refuzz::channel::Result<void> WriteAll(int fd, const std::uint8_t* data, std::size_t len);
    refuzz::channel::Result<bool> PollReadable(int fd, std::chrono::milliseconds remaining);

    Config                              config_;
    std::atomic<int>                    fd_{-1};
    XiuosDecodeState                    decode_;      // pure-C state machine
    std::deque<XiuosFrameMessage>       queued_frames_;
};

}  // namespace refuzz::channel::infra
