#!/usr/bin/env python3
"""Validate the XiUOS reFuzz worker ABI helpers without starting QEMU."""

from worker_abi import (
    CALL_RECORD_SIZE,
    RESULT_HEADER_SIZE,
    ApiId,
    FrameDecoder,
    FrameType,
    ProgramCall,
    ResultStatus,
    decode_result,
    encode_program,
    make_frame,
)


def assert_equal(got, want, label):
    if got != want:
        raise AssertionError(f"{label}: got {got!r}, want {want!r}")


def test_legacy_phase0_frames():
    ready = make_frame(FrameType.READY, 0)
    pong = make_frame(FrameType.PONG, 1)

    assert_equal(ready.hex(" "), "52 46 01 01 00 00 00 00 e6 c4", "READY")
    assert_equal(pong.hex(" "), "52 46 01 03 00 01 00 00 95 77", "PONG")

    decoder = FrameDecoder()
    decoder.feed(b"boot log\n" + ready[:5])
    assert_equal(decoder.pop(), None, "partial frame")
    decoder.feed(ready[5:] + pong)

    frame = decoder.pop()
    assert frame is not None
    assert_equal(frame.frame_type, FrameType.READY, "ready type")
    assert_equal(frame.seq, 0, "ready seq")
    assert_equal(frame.payload, b"", "ready payload")

    frame = decoder.pop()
    assert frame is not None
    assert_equal(frame.frame_type, FrameType.PONG, "pong type")
    assert_equal(frame.seq, 1, "pong seq")
    assert_equal(frame.payload, b"", "pong payload")


def test_program_encoding():
    program = encode_program(
        [
            ProgramCall(ApiId.SEM_CREATE, (0, 1)),
            ProgramCall(ApiId.SEM_OBTAIN, (0, 0)),
            ProgramCall(ApiId.MUTEX_CREATE, (0,)),
        ]
    )

    assert_equal(program[:4], bytes([1, 0, 3, 0]), "program header")
    assert_equal(len(program), 4 + 3 * CALL_RECORD_SIZE, "program size")

    frame = make_frame(FrameType.PROGRAM, 7, program)
    decoder = FrameDecoder()
    decoder.feed(frame)
    decoded = decoder.pop()
    assert decoded is not None
    assert_equal(decoded.frame_type, FrameType.PROGRAM, "program frame type")
    assert_equal(decoded.seq, 7, "program seq")
    assert_equal(decoded.payload, program, "program payload")


def test_result_decoding():
    coverage = b"\x01\x00\x04\xff"
    payload = (
        bytes([1, ResultStatus.OK])
        + b"\x00\x00"
        + b"\x00\x03"
        + len(coverage).to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
        + b"\xff\xff\xff\xfe"
        + coverage
    )

    assert_equal(len(payload), RESULT_HEADER_SIZE + len(coverage), "result size")
    result = decode_result(payload)
    assert_equal(result.status, ResultStatus.OK, "result status")
    assert_equal(result.calls_executed, 3, "calls executed")
    assert_equal(result.trap_or_pc, 0, "trap_or_pc")
    assert_equal(result.aux, -2, "aux")
    assert_equal(result.coverage, coverage, "coverage")


def main():
    test_legacy_phase0_frames()
    test_program_encoding()
    test_result_decoding()
    print("PHASE1_ABI_SELFTEST_OK")


if __name__ == "__main__":
    main()
