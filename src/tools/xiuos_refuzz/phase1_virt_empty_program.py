#!/usr/bin/env python3
"""Run the XiUOS virt-rv32 Phase 1 PROGRAM/RESULT smoke."""

import argparse
import socket
import subprocess
import sys
import time

from corpus import encode_seed, load_descriptor, load_seeds
from worker_abi import FrameDecoder, FrameType, ResultStatus, decode_result, encode_program, make_frame

DEFAULT_ELF = (
    "/workspace/xiuos-work/xiuos/Ubiquitous/XiZi_IIoT_Macro/"
    "build/XiZi-virt-rv32.elf"
)
DEFAULT_QEMU = "qemu-system-riscv32"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 32171
DEFAULT_SEED = "sem_mutex_interleave"


def wait_frame(sock, want_type, want_seq, timeout):
    deadline = time.time() + timeout
    decoder = FrameDecoder()

    while time.time() < deadline:
        frame = decoder.pop()
        if frame is not None:
            if frame.frame_type == want_type and (
                want_seq is None or frame.seq == want_seq
            ):
                return frame

        sock.settimeout(max(0.1, min(0.5, deadline - time.time())))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue

        if not chunk:
            break
        decoder.feed(chunk)

    raise TimeoutError(f"timed out waiting for frame type={want_type} seq={want_seq}")


def wait_tcp_connect(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    deadline = time.time() + timeout

    while True:
        try:
            sock.connect((host, port))
            return sock
        except OSError:
            if time.time() > deadline:
                sock.close()
                raise
            time.sleep(0.05)


def start_qemu(args):
    return subprocess.Popen(
        [
            args.qemu,
            "-display",
            "none",
            "-machine",
            "virt",
            "-bios",
            "none",
            "-monitor",
            "none",
            "-serial",
            f"tcp:{args.host}:{args.port},server=on,wait=on",
            "-kernel",
            args.elf,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def stop_qemu(qemu):
    qemu.terminate()
    try:
        qemu.wait(timeout=2)
    except subprocess.TimeoutExpired:
        qemu.kill()
        qemu.wait(timeout=2)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate XiUOS virt-rv32 Phase 1 empty PROGRAM/RESULT."
    )
    parser.add_argument("--elf", default=DEFAULT_ELF, help="XiUOS ELF path")
    parser.add_argument("--qemu", default=DEFAULT_QEMU, help="qemu-system-riscv32 path")
    parser.add_argument("--host", default=DEFAULT_HOST, help="TCP serial host")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="TCP serial port")
    parser.add_argument("--seq", default=1, type=int, help="PROGRAM sequence number")
    parser.add_argument("--seed", default=DEFAULT_SEED, help="seed corpus name to execute")
    parser.add_argument("--timeout", default=10.0, type=float, help="frame wait timeout in seconds")
    parser.add_argument(
        "--connect-timeout",
        default=5.0,
        type=float,
        help="TCP serial connect timeout in seconds",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    descriptor = load_descriptor()
    seeds = {seed.name: seed for seed in load_seeds(descriptor)}
    if args.seed not in seeds:
        raise ValueError(f"unknown seed {args.seed!r}; available={sorted(seeds)}")
    seed = seeds[args.seed]

    qemu = start_qemu(args)
    sock = None

    try:
        sock = wait_tcp_connect(args.host, args.port, args.connect_timeout)

        ready = wait_frame(sock, FrameType.READY, None, args.timeout)
        print("READY", ready.raw.hex(" "))

        sock.sendall(make_frame(FrameType.PING, args.seq))
        pong = wait_frame(sock, FrameType.PONG, args.seq, args.timeout)
        print("PONG", pong.raw.hex(" "))

        empty_seq = (args.seq + 1) & 0xFFFF
        sock.sendall(make_frame(FrameType.PROGRAM, empty_seq, encode_program([])))
        empty_result_frame = wait_frame(sock, FrameType.RESULT, empty_seq, args.timeout)
        empty_result = decode_result(empty_result_frame.payload)
        print("EMPTY_RESULT", empty_result_frame.raw.hex(" "))
        print(
            "EMPTY_RESULT_DECODED",
            f"status={empty_result.status}",
            f"calls={empty_result.calls_executed}",
            f"coverage={len(empty_result.coverage)}",
            f"aux={empty_result.aux}",
        )

        if empty_result.status != ResultStatus.OK:
            raise RuntimeError(f"unexpected empty result status {empty_result.status}")
        if empty_result.calls_executed != 0:
            raise RuntimeError(
                f"unexpected empty calls_executed {empty_result.calls_executed}"
            )
        if len(empty_result.coverage) != 256:
            raise RuntimeError(f"unexpected empty coverage size {len(empty_result.coverage)}")
        if not any(empty_result.coverage):
            raise RuntimeError("empty program did not produce coverage")

        program_seq = (empty_seq + 1) & 0xFFFF
        sem_mutex_program = encode_seed(seed)
        sock.sendall(make_frame(FrameType.PROGRAM, program_seq, sem_mutex_program))
        result_frame = wait_frame(sock, FrameType.RESULT, program_seq, args.timeout)
        result = decode_result(result_frame.payload)
        print("RESULT", result_frame.raw.hex(" "))
        print(
            "RESULT_DECODED",
            f"status={result.status}",
            f"calls={result.calls_executed}",
            f"coverage={len(result.coverage)}",
            f"aux={result.aux}",
        )

        if result.status != ResultStatus.OK:
            raise RuntimeError(f"unexpected result status {result.status}")
        if result.calls_executed != len(seed.calls):
            raise RuntimeError(f"unexpected calls_executed {result.calls_executed}")
        if len(result.coverage) != 256:
            raise RuntimeError(f"unexpected coverage size {len(result.coverage)}")
        if not any(result.coverage):
            raise RuntimeError("sem/mutex program did not produce coverage")

        print("PHASE1_SEM_MUTEX_PROGRAM_OK")
    finally:
        if sock is not None:
            sock.close()
        stop_qemu(qemu)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"PHASE1_SEM_MUTEX_PROGRAM_FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
