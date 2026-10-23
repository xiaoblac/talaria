"""XiUOS reFuzz worker ABI helpers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable

MAGIC = b"RF"
VERSION = 0x01
HEADER_SIZE = 8
MIN_FRAME_SIZE = HEADER_SIZE + 2
CRC_INIT = 0xFFFF
CRC_POLY = 0x1021
PROGRAM_VERSION = 0x01
RESULT_VERSION = 0x01
CALL_RECORD_SIZE = 20
RESULT_HEADER_SIZE = 16


class FrameType(IntEnum):
    READY = 0x01
    PING = 0x02
    PONG = 0x03
    ACK = 0x04
    PROGRAM = 0x10
    RESULT = 0x11
    RESET = 0x12
    NACK = 0x7F


class SuiteId(IntEnum):
    COMMON_KERNEL = 0x00


class ApiId(IntEnum):
    SEM_CREATE = 0x01
    SEM_DELETE = 0x02
    SEM_OBTAIN = 0x03
    SEM_ABANDON = 0x04
    SEM_SET_VALUE = 0x05

    MUTEX_CREATE = 0x10
    MUTEX_DELETE = 0x11
    MUTEX_OBTAIN = 0x12
    MUTEX_ABANDON = 0x13

    # KMsgQueue family. Args: (slot, msg_size_idx, max_msgs_idx) for CREATE,
    # (slot, byte_pattern_idx) for SEND/URGENT_SEND, (slot, timeout) for
    # RECV, (slot,) for DELETE/REINIT. Worker maps the *_idx args through
    # bounded tables; see proto/wire/xiuos_uart_protocol.h for the table
    # contents and the corresponding worker dispatch.
    MSGQ_CREATE      = 0x20
    MSGQ_DELETE      = 0x21
    MSGQ_SEND        = 0x22
    MSGQ_RECV        = 0x23
    MSGQ_URGENT_SEND = 0x24
    MSGQ_REINIT      = 0x25

    # KEvent family. Args: (slot, options_idx) for CREATE; (slot,) for
    # DELETE; (slot, events_pattern_idx) for TRIGGER; (slot,
    # events_pattern_idx, timeout) for PROCESS. Worker maps each *_idx
    # through bounded tables (see proto/wire/xiuos_uart_protocol.h).
    EVENT_CREATE  = 0x30
    EVENT_DELETE  = 0x31
    EVENT_TRIGGER = 0x32
    EVENT_PROCESS = 0x33

    # KTimer family. 3-state lifecycle (EMPTY/CREATED/RUNNING).
    #   CREATE(slot, ticks_idx, mode_idx)  argc=3
    #   DELETE(slot)                       argc=1
    #   START_RUN(slot)                    argc=1
    #   QUIT_RUN(slot)                     argc=1
    #   MODIFY(slot, ticks_idx)            argc=2
    TIMER_CREATE    = 0x40
    TIMER_DELETE    = 0x41
    TIMER_START_RUN = 0x42
    TIMER_QUIT_RUN  = 0x43
    TIMER_MODIFY    = 0x44
    TIMER_ASSIGN_MEMBER_RUN = 0x45

    TASK_SPAWN_BLOCK_SEM        = 0x50
    TASK_SPAWN_BLOCK_EVENT      = 0x51
    TASK_SPAWN_BLOCK_MSGQ_RECV  = 0x52
    TASK_TERMINATE              = 0x53
    TASK_PRIO_SET               = 0x54
    TASK_SPAWN_SELF_SUSPEND     = 0x55
    TASK_WAKEUP                 = 0x56
    TASK_SPAWN_SELF_DELAY       = 0x57
    TASK_SPAWN_BLOCK_SEM_TIMEOUT = 0x58
    TASK_SPAWN_BLOCK_EVENT_TIMEOUT = 0x59
    TASK_SPAWN_BLOCK_MSGQ_RECV_TIMEOUT = 0x5a
    TASK_SPAWN_BLOCK_MUTEX_TIMEOUT = 0x5b
    TASK_SPAWN_BLOCK_GB_ALLOC = 0x5c
    TASK_SPAWN_BLOCK_MSGQ_SEND_TIMEOUT = 0x5d
    TASK_GET_PRIO = 0x5e
    TASK_SPAWN_BLOCK_MUTEX_HIGH = 0x5f

    WQ_CREATE                   = 0x60
    WQ_DEINIT                   = 0x61
    WQ_SUBMIT                   = 0x62
    WQ_SUBMIT_DELAYED           = 0x63

    DQ_INIT                     = 0x70
    DQ_DEINIT                   = 0x71
    DQ_PUSH                     = 0x72
    DQ_POP                      = 0x73
    DQ_PEEK                     = 0x74

    WAITQ_INIT                  = 0x80
    WAITQ_SPAWN_WAIT            = 0x81
    WAITQ_WAKE                  = 0x82

    RESOURCE_SNAPSHOT           = 0x90
    HEAP_SNAPSHOT               = 0x91
    TICK_MS_TO_TICK             = 0x92
    TICK_TO_MS                  = 0x93
    HEAP_INTEGRITY              = 0x94

    MALLOC                      = 0xA0
    FREE                        = 0xA1
    REALLOC                     = 0xA2
    CALLOC                      = 0xA3

    GB_CREATE                   = 0xB0
    GB_DELETE                   = 0xB1
    GB_ALLOC                    = 0xB2
    GB_FREE                     = 0xB3

    CA_INIT                     = 0xC0
    CA_RELEASE                  = 0xC1
    CA_RESET                    = 0xC2
    CA_WRITE                    = 0xC3
    CA_READ                     = 0xC4
    CA_GET_DATA_LENGTH          = 0xC5

    AVL_INSERT                  = 0xD0
    AVL_DELETE                  = 0xD1
    AVL_MODIFY                  = 0xD2
    AVL_SEARCH                  = 0xD3
    AVL_COUNT                   = 0xD4
    AVL_CHECK                   = 0xD5

    CAP_FLAG_SET                = 0xE0
    CAP_FLAG_CHECK              = 0xE1
    CAP_ADD_TASK                = 0xE2
    CAP_ADD_ROOT                = 0xE3
    CAP_ADD_ROOT_SELF           = 0xE4
    CAP_REMOVE_TASK             = 0xE5
    CAP_CHECK_TASK              = 0xE6
    CAP_SET_TASK                = 0xE7


class ResultStatus(IntEnum):
    OK = 0x00
    PROGRAM_REJECTED = 0x01
    UNSUPPORTED_API = 0x02
    WORKER_ERROR = 0x03
    TRAP = 0x80


@dataclass(frozen=True)
class Frame:
    frame_type: int
    seq: int
    payload: bytes
    raw: bytes = b""


@dataclass(frozen=True)
class ProgramCall:
    api_id: int
    args: tuple[int, ...] = ()
    flags: int = 0
    argc: int | None = None


@dataclass(frozen=True)
class Result:
    status: int
    flags: int
    calls_executed: int
    trap_or_pc: int
    aux: int
    coverage: bytes


def crc16_update(crc: int, byte: int) -> int:
    crc ^= (byte & 0xFF) << 8
    for _ in range(8):
        if crc & 0x8000:
            crc = ((crc << 1) ^ CRC_POLY) & 0xFFFF
        else:
            crc = (crc << 1) & 0xFFFF
    return crc


def crc16(data: bytes | bytearray | memoryview) -> int:
    crc = CRC_INIT
    for byte in data:
        crc = crc16_update(crc, byte)
    return crc


def u16be(value: int) -> bytes:
    return int(value).to_bytes(2, "big", signed=False)


def u32be(value: int) -> bytes:
    return (int(value) & 0xFFFFFFFF).to_bytes(4, "big", signed=False)


def read_u16be(data: bytes | bytearray | memoryview, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def read_u32be(data: bytes | bytearray | memoryview, offset: int) -> int:
    return (
        (data[offset] << 24)
        | (data[offset + 1] << 16)
        | (data[offset + 2] << 8)
        | data[offset + 3]
    )


def make_frame(frame_type: int | FrameType, seq: int, payload: bytes = b"") -> bytes:
    if not 0 <= int(frame_type) <= 0xFF:
        raise ValueError(f"frame_type out of range: {frame_type}")
    if not 0 <= seq <= 0xFFFF:
        raise ValueError(f"seq out of range: {seq}")
    if len(payload) > 0xFFFF:
        raise ValueError(f"payload too large: {len(payload)}")

    header = (
        MAGIC
        + bytes([VERSION, int(frame_type)])
        + u16be(seq)
        + u16be(len(payload))
    )
    frame_crc = crc16(header + payload)
    return header + payload + u16be(frame_crc)


class FrameDecoder:
    def __init__(self, *, max_payload: int = 0xFFFF) -> None:
        self.buffer = bytearray()
        self.max_payload = max_payload

    def feed(self, data: bytes | bytearray | memoryview) -> None:
        self.buffer.extend(data)

    def pop(self) -> Frame | None:
        while len(self.buffer) >= MIN_FRAME_SIZE:
            start = self.buffer.find(MAGIC + bytes([VERSION]))
            if start < 0:
                del self.buffer[:-2]
                return None
            if start:
                del self.buffer[:start]
            if len(self.buffer) < MIN_FRAME_SIZE:
                return None

            payload_len = read_u16be(self.buffer, 6)
            if payload_len > self.max_payload:
                del self.buffer[0]
                continue

            total_len = HEADER_SIZE + payload_len + 2
            if len(self.buffer) < total_len:
                return None

            raw = bytes(self.buffer[:total_len])
            del self.buffer[:total_len]

            got = read_u16be(raw, total_len - 2)
            want = crc16(raw[:-2])
            if got != want:
                continue

            return Frame(
                frame_type=raw[3],
                seq=read_u16be(raw, 4),
                payload=raw[HEADER_SIZE:-2],
                raw=raw,
            )

        return None


def encode_call(call: ProgramCall) -> bytes:
    args = tuple(int(arg) & 0xFFFFFFFF for arg in call.args)
    if len(args) > 4:
        raise ValueError(f"too many call args: {len(args)}")
    argc = len(args) if call.argc is None else int(call.argc)
    if not 0 <= argc <= 4:
        raise ValueError(f"argc out of range: {argc}")
    if not 0 <= int(call.api_id) <= 0xFF:
        raise ValueError(f"api_id out of range: {call.api_id}")
    if not 0 <= call.flags <= 0xFFFF:
        raise ValueError(f"call flags out of range: {call.flags}")

    padded_args = args + (0,) * (4 - len(args))
    encoded = bytes([int(call.api_id), argc]) + u16be(call.flags)
    for arg in padded_args:
        encoded += u32be(arg)
    return encoded


def encode_program(
    calls: Iterable[ProgramCall],
    *,
    suite_id: int | SuiteId = SuiteId.COMMON_KERNEL,
    flags: int = 0,
) -> bytes:
    call_list = list(calls)
    if len(call_list) > 0xFF:
        raise ValueError(f"too many calls: {len(call_list)}")
    if not 0 <= int(suite_id) <= 0xFF:
        raise ValueError(f"suite_id out of range: {suite_id}")
    if not 0 <= flags <= 0xFF:
        raise ValueError(f"program flags out of range: {flags}")

    payload = bytes([PROGRAM_VERSION, int(suite_id), len(call_list), flags])
    for call in call_list:
        payload += encode_call(call)
    return payload


def decode_result(payload: bytes | bytearray | memoryview) -> Result:
    if len(payload) < RESULT_HEADER_SIZE:
        raise ValueError(f"result payload too short: {len(payload)}")
    if payload[0] != RESULT_VERSION:
        raise ValueError(f"unsupported result version: {payload[0]}")

    coverage_size = read_u16be(payload, 6)
    expected_size = RESULT_HEADER_SIZE + coverage_size
    if len(payload) < expected_size:
        raise ValueError(
            f"truncated coverage: got {len(payload)}, want {expected_size}"
        )

    aux = read_u32be(payload, 12)
    if aux & 0x80000000:
        aux -= 0x100000000

    return Result(
        status=payload[1],
        flags=read_u16be(payload, 2),
        calls_executed=read_u16be(payload, 4),
        trap_or_pc=read_u32be(payload, 8),
        aux=aux,
        coverage=bytes(payload[RESULT_HEADER_SIZE:expected_size]),
    )
