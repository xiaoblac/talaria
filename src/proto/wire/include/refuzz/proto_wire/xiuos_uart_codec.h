#ifndef XIUOS_UART_CODEC_H
#define XIUOS_UART_CODEC_H

/* XiUOS reFuzz worker UART wire codec — pure C, header-only.
 *
 * Shared between host (C++ via refuzz_channel) and XiUOS guest worker
 * (C via kernel/refuzz/refuzz_worker.c). Both sides must agree on framing
 * byte-for-byte; carrying two implementations is how divergence creeps in.
 * Protocol constants and primitive helpers (BE/CRC) live in
 * xiuos_uart_protocol.h; this header adds the framing logic on top.
 *
 * Wire frame layout (mirror of 030_worker_abi.md §"Wire Frame ABI"):
 *
 *   offset  size  field
 *   0       1     magic0 (0x52 'R')
 *   1       1     magic1 (0x46 'F')
 *   2       1     version (XIUOS_PROTOCOL_VERSION)
 *   3       1     type (XiuosFrameType — wire-level enum)
 *   4       2     seq (BE)
 *   6       2     payload_len (BE)
 *   8       N     payload
 *   8+N     2     crc16 (BE, CRC-16/CCITT-FALSE over the preceding 8+N bytes)
 *
 * Encoder API:
 *   - XiuosBuildFrame()  build a complete frame into a caller-provided buffer
 *
 * Decoder API (byte-stream state machine):
 *   - XiuosDecodeState   opaque-ish state; embedded fixed-size payload buffer
 *   - XiuosDecodeInit()  reset state at boot or after a peer reconnect
 *   - XiuosDecodePush()  push one byte; returns NEED_MORE / FRAME_READY / BAD_FRAME
 *   - XiuosFrameView     view into the latest assembled frame (valid until next push)
 *
 * Memory: XiuosDecodeState carries an XIUOS_MAX_PAYLOAD-byte buffer (=512),
 * so the state struct is ~520 bytes. On the XiUOS RTOS worker this matches
 * the current static-per-task allocation in RefuzzRecvFrame.
 */

#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== Encoder ==================== */

/* Build a wire frame in out_buf. Caller must provide out_buf of at least
 * (XIUOS_HEADER_SIZE + payload_len + 2) bytes.
 *
 * Returns the total number of bytes written, or 0 on:
 *   - payload_len > XIUOS_MAX_PAYLOAD
 *   - out_buf_size < (XIUOS_HEADER_SIZE + payload_len + 2)
 *   - payload_len > 0 && payload == NULL
 *
 * payload may be NULL when payload_len == 0 (zero-length frames like
 * READY / PING / PONG).
 */
static inline size_t XiuosBuildFrame(uint8_t* out_buf,
                                     size_t   out_buf_size,
                                     uint8_t  type,
                                     uint16_t seq,
                                     const uint8_t* payload,
                                     uint16_t payload_len) {
    /* [截断修复] 帧传输上限 = RESULT 帧上限(RESULT 比 PROGRAM 大);PROGRAM 侧另由
     * channel/submit 的 XIUOS_MAX_PAYLOAD 把关,故 program 帧实际仍 ≤512。 */
    if (payload_len > XIUOS_RESULT_MAX_PAYLOAD) return 0;
    if (payload_len > 0 && payload == NULL) return 0;
    const size_t total = (size_t)XIUOS_HEADER_SIZE + (size_t)payload_len + 2u;
    if (out_buf == NULL || out_buf_size < total) return 0;

    out_buf[0] = XIUOS_MAGIC_0;
    out_buf[1] = XIUOS_MAGIC_1;
    out_buf[2] = XIUOS_PROTOCOL_VERSION;
    out_buf[3] = type;
    XiuosPutU16Be(out_buf + 4, seq);
    XiuosPutU16Be(out_buf + 6, payload_len);
    for (uint16_t i = 0; i < payload_len; ++i) {
        out_buf[XIUOS_HEADER_SIZE + i] = payload[i];
    }

    const uint16_t crc = XiuosCrc16(out_buf,
                                    (size_t)XIUOS_HEADER_SIZE + (size_t)payload_len);
    XiuosPutU16Be(out_buf + XIUOS_HEADER_SIZE + payload_len, crc);
    return total;
}

/* ==================== Decoder ==================== */

typedef enum {
    XIUOS_DECODE_NEED_MORE  = 0,   /* state machine wants more bytes */
    XIUOS_DECODE_FRAME_READY,      /* a complete CRC-verified frame is in `view` */
    XIUOS_DECODE_BAD_FRAME,        /* version mismatch / oversized len / CRC fail —
                                      state has been reset to look for next sync */
} XiuosDecodeStatus;

typedef struct {
    uint8_t  state;                          /* 0..5 in the state machine */
    uint16_t header_offset;
    uint16_t payload_len;
    uint16_t payload_offset;
    uint16_t crc_high;
    uint8_t  header[XIUOS_HEADER_SIZE];
    uint8_t  payload[XIUOS_RESULT_MAX_PAYLOAD];  /* [截断修复] 容纳放大后的 RESULT 帧 */
} XiuosDecodeState;

typedef struct {
    uint8_t        type;
    uint16_t       seq;
    uint16_t       payload_len;
    const uint8_t* payload;                  /* points into XiuosDecodeState.payload */
} XiuosFrameView;

static inline void XiuosDecodeInit(XiuosDecodeState* s) {
    s->state          = 0;
    s->header_offset  = 0;
    s->payload_len    = 0;
    s->payload_offset = 0;
    s->crc_high       = 0;
}

/* Push one byte into the decoder.
 *
 * NEED_MORE:  no frame ready yet (or this byte was junk / lost sync).
 * FRAME_READY: a complete CRC-verified frame is available; `view` fields
 *              are valid until the next call to XiuosDecodePush. The state
 *              is internally reset; the very next push starts the next frame.
 * BAD_FRAME:  version/len/CRC was wrong; state has been reset to seek the
 *              next sync byte; caller may log diagnostics. `view` is NOT filled.
 */
static inline XiuosDecodeStatus
XiuosDecodePush(XiuosDecodeState* s, uint8_t b, XiuosFrameView* view) {
    switch (s->state) {
    case 0:
        if (b == XIUOS_MAGIC_0) {
            s->header[0] = b;
            s->state = 1;
        }
        return XIUOS_DECODE_NEED_MORE;

    case 1:
        if (b == XIUOS_MAGIC_1) {
            s->header[1] = b;
            s->header_offset = 2;
            s->state = 2;
        } else if (b == XIUOS_MAGIC_0) {
            /* keep last magic0; stay in state 1 */
            s->header[0] = b;
        } else {
            s->state = 0;
        }
        return XIUOS_DECODE_NEED_MORE;

    case 2:
        s->header[s->header_offset++] = b;
        if (s->header_offset == XIUOS_HEADER_SIZE) {
            if (s->header[2] != XIUOS_PROTOCOL_VERSION) {
                s->state = 0;
                s->header_offset = 0;
                return XIUOS_DECODE_BAD_FRAME;
            }
            s->payload_len = XiuosReadU16Be(s->header + 6);
            if (s->payload_len > XIUOS_RESULT_MAX_PAYLOAD) {
                s->state = 0;
                s->header_offset = 0;
                return XIUOS_DECODE_BAD_FRAME;
            }
            s->payload_offset = 0;
            s->state = (s->payload_len == 0) ? 4 : 3;
        }
        return XIUOS_DECODE_NEED_MORE;

    case 3:
        s->payload[s->payload_offset++] = b;
        if (s->payload_offset == s->payload_len) {
            s->state = 4;
        }
        return XIUOS_DECODE_NEED_MORE;

    case 4:
        s->crc_high = (uint16_t)((uint16_t)b << 8);
        s->state = 5;
        return XIUOS_DECODE_NEED_MORE;

    case 5: {
        const uint16_t got_crc = (uint16_t)(s->crc_high | (uint16_t)b);
        uint16_t want_crc = XIUOS_CRC_INIT;
        for (uint16_t i = 0; i < XIUOS_HEADER_SIZE; ++i) {
            want_crc = XiuosCrc16Update(want_crc, s->header[i]);
        }
        for (uint16_t i = 0; i < s->payload_len; ++i) {
            want_crc = XiuosCrc16Update(want_crc, s->payload[i]);
        }
        /* Reset for the next frame regardless of outcome. */
        s->state = 0;
        s->header_offset = 0;
        const uint16_t payload_len = s->payload_len;
        s->payload_len = 0;
        if (got_crc != want_crc) {
            return XIUOS_DECODE_BAD_FRAME;
        }
        if (view != NULL) {
            view->type        = s->header[3];
            view->seq         = XiuosReadU16Be(s->header + 4);
            view->payload_len = payload_len;
            view->payload     = (payload_len == 0) ? NULL : s->payload;
        }
        /* Keep the header readable in `view` until the next push: state 0
         * doesn't touch header[] except via case 0/1 writes. We DO reset
         * payload_len so any caller that re-reads it through `s` post-push
         * sees 0; the view captured payload_len by value above. */
        return XIUOS_DECODE_FRAME_READY;
    }

    default:
        s->state = 0;
        s->header_offset = 0;
        return XIUOS_DECODE_BAD_FRAME;
    }
}

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* XIUOS_UART_CODEC_H */
