// xiuos_uart_codec_test.cpp
//
// Phase 2 §B v1 — XiUOS UART wire codec unit tests, against the pure-C
// codec at proto/wire/include/refuzz/proto_wire/xiuos_uart_codec.h.
//
// Golden hex is harvested from tools/xiuos_refuzz/phase0_hifive1_smoke.py
// and phase1_virt_empty_program.py smoke output. The same C codec is the
// one the XiUOS guest worker (kernel/refuzz/refuzz_worker.c) will use once
// migrated; this test guards both sides of that shared implementation
// against drift.

#include "refuzz/proto_wire/xiuos_uart_codec.h"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <vector>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

template <std::size_t N>
bool BytesEqual(const std::uint8_t* got, std::size_t got_len,
                const std::array<std::uint8_t, N>& want) {
    if (got_len != N) return false;
    return std::memcmp(got, want.data(), N) == 0;
}

// ───── CRC primitive ─────

int TestCrc16KnownVectors() {
    // CRC-16/CCITT-FALSE check value of "123456789" is 0x29B1.
    const std::array<std::uint8_t, 9> data{'1','2','3','4','5','6','7','8','9'};
    CHECK(::XiuosCrc16(data.data(), data.size()) == 0x29B1);
    return 0;
}

// ───── XiuosBuildFrame ─────

int TestBuildReadyFrameMatchesSmokeHex() {
    // Phase 0 smoke: READY frame is `52 46 01 01 00 00 00 00 e6 c4`.
    std::uint8_t buf[XIUOS_HEADER_SIZE + XIUOS_MAX_PAYLOAD + 2];
    const std::size_t n =
        XiuosBuildFrame(buf, sizeof(buf), XIUOS_FRAME_READY, /*seq=*/0, nullptr, 0);

    const std::array<std::uint8_t, 10> want{
        0x52, 0x46, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xE6, 0xC4,
    };
    CHECK(BytesEqual(buf, n, want));
    return 0;
}

int TestBuildPongFrameMatchesSmokeHex() {
    // Phase 0 smoke: PONG(seq=1) frame is `52 46 01 03 00 01 00 00 95 77`.
    std::uint8_t buf[XIUOS_HEADER_SIZE + XIUOS_MAX_PAYLOAD + 2];
    const std::size_t n =
        XiuosBuildFrame(buf, sizeof(buf), XIUOS_FRAME_PONG, /*seq=*/1, nullptr, 0);

    const std::array<std::uint8_t, 10> want{
        0x52, 0x46, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x95, 0x77,
    };
    CHECK(BytesEqual(buf, n, want));
    return 0;
}

int TestBuildRejectsOversizedPayload() {
    // [截断修复] codec 传输上限现为 XIUOS_RESULT_MAX_PAYLOAD(RESULT 帧承载稀疏覆盖,
    // 可达 ~3072B)。PROGRAM 帧的 512 上限由 channel/submit 层把关,不在 codec 层。
    // 故 codec 只拒超过 XIUOS_RESULT_MAX_PAYLOAD 的 payload。
    std::uint8_t buf[1024];
    std::vector<std::uint8_t> oversized(XIUOS_RESULT_MAX_PAYLOAD + 1, 0);
    CHECK(XiuosBuildFrame(buf, sizeof(buf), XIUOS_FRAME_RESULT, 1, oversized.data(),
                          static_cast<std::uint16_t>(oversized.size())) == 0);

    // 介于旧 512 上限与新传输上限之间的 payload 现在被 codec 接受(解耦)——build 成功。
    std::vector<std::uint8_t> mid(XIUOS_MAX_PAYLOAD + 1, 0);  // 513B
    const std::size_t n =
        XiuosBuildFrame(buf, sizeof(buf), XIUOS_FRAME_RESULT, 1, mid.data(),
                        static_cast<std::uint16_t>(mid.size()));
    CHECK(n == static_cast<std::size_t>(XIUOS_HEADER_SIZE) + (XIUOS_MAX_PAYLOAD + 1) + 2);
    return 0;
}

int TestBuildRejectsUndersizedOutBuf() {
    std::uint8_t small[5];
    const std::size_t n =
        XiuosBuildFrame(small, sizeof(small), XIUOS_FRAME_READY, 0, nullptr, 0);
    CHECK(n == 0);
    return 0;
}

// ───── XiuosDecodePush state machine ─────

XiuosDecodeStatus PushAll(XiuosDecodeState* s, const std::uint8_t* buf, std::size_t n,
                          XiuosFrameView* out) {
    XiuosDecodeStatus last = XIUOS_DECODE_NEED_MORE;
    for (std::size_t i = 0; i < n; ++i) {
        last = XiuosDecodePush(s, buf[i], out);
        if (last != XIUOS_DECODE_NEED_MORE) return last;
    }
    return last;
}

int TestDecodeRoundTripReady() {
    const std::array<std::uint8_t, 10> ready{
        0x52, 0x46, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xE6, 0xC4,
    };
    XiuosDecodeState s;
    XiuosDecodeInit(&s);
    XiuosFrameView v{};
    const XiuosDecodeStatus rc =
        PushAll(&s, ready.data(), ready.size(), &v);
    CHECK(rc == XIUOS_DECODE_FRAME_READY);
    CHECK(v.type == XIUOS_FRAME_READY);
    CHECK(v.seq == 0);
    CHECK(v.payload_len == 0);
    return 0;
}

int TestDecodeSkipsLeadingJunk() {
    // Worker UART may emit XiUOS kernel KPrintf banner bytes before frames.
    std::vector<std::uint8_t> stream{'c','o','n','s','o','l','e',' ','i','n','i','t','\n'};
    const std::array<std::uint8_t, 10> ready{
        0x52, 0x46, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xE6, 0xC4,
    };
    stream.insert(stream.end(), ready.begin(), ready.end());

    XiuosDecodeState s;
    XiuosDecodeInit(&s);
    XiuosFrameView v{};
    const XiuosDecodeStatus rc =
        PushAll(&s, stream.data(), stream.size(), &v);
    CHECK(rc == XIUOS_DECODE_FRAME_READY);
    CHECK(v.type == XIUOS_FRAME_READY);
    return 0;
}

int TestDecodeByteAtATime() {
    const std::array<std::uint8_t, 10> pong{
        0x52, 0x46, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x95, 0x77,
    };
    XiuosDecodeState s;
    XiuosDecodeInit(&s);
    XiuosFrameView v{};
    for (std::size_t i = 0; i + 1 < pong.size(); ++i) {
        CHECK(XiuosDecodePush(&s, pong[i], &v) == XIUOS_DECODE_NEED_MORE);
    }
    CHECK(XiuosDecodePush(&s, pong.back(), &v) == XIUOS_DECODE_FRAME_READY);
    CHECK(v.type == XIUOS_FRAME_PONG);
    CHECK(v.seq == 1);
    return 0;
}

int TestDecodeBadCrcReturnsBadFrame() {
    // Same as READY frame, but flip the last CRC byte.
    const std::array<std::uint8_t, 10> bad_crc{
        0x52, 0x46, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xE6, 0xC5,
    };
    XiuosDecodeState s;
    XiuosDecodeInit(&s);
    XiuosFrameView v{};
    const XiuosDecodeStatus rc =
        PushAll(&s, bad_crc.data(), bad_crc.size(), &v);
    CHECK(rc == XIUOS_DECODE_BAD_FRAME);

    // Decoder must be re-syncable after a bad frame.
    const std::array<std::uint8_t, 10> good_pong{
        0x52, 0x46, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x95, 0x77,
    };
    const XiuosDecodeStatus rc2 =
        PushAll(&s, good_pong.data(), good_pong.size(), &v);
    CHECK(rc2 == XIUOS_DECODE_FRAME_READY);
    CHECK(v.type == XIUOS_FRAME_PONG);
    return 0;
}

int TestDecodeBadVersionReturnsBadFrame() {
    const std::array<std::uint8_t, 10> bad_ver{
        0x52, 0x46, 0x02, /* version=2 (bad) */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    XiuosDecodeState s;
    XiuosDecodeInit(&s);
    XiuosFrameView v{};
    const XiuosDecodeStatus rc =
        PushAll(&s, bad_ver.data(), bad_ver.size(), &v);
    CHECK(rc == XIUOS_DECODE_BAD_FRAME);
    return 0;
}

int TestDecodeOversizedLenReturnsBadFrame() {
    // Forge a header with payload_len > XIUOS_RESULT_MAX_PAYLOAD (=3072). Build by hand.
    std::array<std::uint8_t, 8> hdr{};
    hdr[0] = 0x52; hdr[1] = 0x46; hdr[2] = 0x01; hdr[3] = 0x10;  // type=PROGRAM
    hdr[4] = 0x00; hdr[5] = 0x01;                                // seq=1
    hdr[6] = 0xFF; hdr[7] = 0xFF;                                // len=65535
    XiuosDecodeState s;
    XiuosDecodeInit(&s);
    XiuosFrameView v{};
    const XiuosDecodeStatus rc =
        PushAll(&s, hdr.data(), hdr.size(), &v);
    CHECK(rc == XIUOS_DECODE_BAD_FRAME);
    return 0;
}

// ───── Build → push round trip ─────

int TestBuildThenDecodeRoundTrip() {
    const std::array<std::uint8_t, 7> payload{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70};
    std::uint8_t buf[XIUOS_HEADER_SIZE + XIUOS_MAX_PAYLOAD + 2];
    const std::size_t n = XiuosBuildFrame(
        buf, sizeof(buf), XIUOS_FRAME_PROGRAM, /*seq=*/0x4242,
        payload.data(), static_cast<std::uint16_t>(payload.size()));
    CHECK(n == XIUOS_HEADER_SIZE + payload.size() + 2);

    XiuosDecodeState s;
    XiuosDecodeInit(&s);
    XiuosFrameView v{};
    CHECK(PushAll(&s, buf, n, &v) == XIUOS_DECODE_FRAME_READY);
    CHECK(v.type == XIUOS_FRAME_PROGRAM);
    CHECK(v.seq == 0x4242);
    CHECK(v.payload_len == payload.size());
    for (std::size_t i = 0; i < payload.size(); ++i) {
        CHECK(v.payload[i] == payload[i]);
    }
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_uart_codec_test...\n");
    int run = 0, ok = 0;
    auto exec = [&](auto fn, const char* name) {
        ++run;
        std::fprintf(stderr, "  [RUN] %s\n", name);
        if (fn() == 0) { ++ok; std::fprintf(stderr, "  [PASS] %s\n", name); }
        else            { std::fprintf(stderr, "  [FAIL] %s\n", name); }
    };

    exec(TestCrc16KnownVectors,             "Crc16KnownVectors");
    exec(TestBuildReadyFrameMatchesSmokeHex,"BuildReadyFrameMatchesSmokeHex");
    exec(TestBuildPongFrameMatchesSmokeHex, "BuildPongFrameMatchesSmokeHex");
    exec(TestBuildRejectsOversizedPayload,  "BuildRejectsOversizedPayload");
    exec(TestBuildRejectsUndersizedOutBuf,  "BuildRejectsUndersizedOutBuf");
    exec(TestDecodeRoundTripReady,          "DecodeRoundTripReady");
    exec(TestDecodeSkipsLeadingJunk,        "DecodeSkipsLeadingJunk");
    exec(TestDecodeByteAtATime,             "DecodeByteAtATime");
    exec(TestDecodeBadCrcReturnsBadFrame,   "DecodeBadCrcReturnsBadFrame");
    exec(TestDecodeBadVersionReturnsBadFrame, "DecodeBadVersionReturnsBadFrame");
    exec(TestDecodeOversizedLenReturnsBadFrame, "DecodeOversizedLenReturnsBadFrame");
    exec(TestBuildThenDecodeRoundTrip,      "BuildThenDecodeRoundTrip");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}
