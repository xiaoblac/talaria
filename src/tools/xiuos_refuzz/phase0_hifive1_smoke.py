#!/usr/bin/env python3
"""Run the XiUOS hifive1-emulator Phase 0 READY/PING/PONG smoke."""

import argparse
import socket
import subprocess
import sys
import time

from worker_abi import FrameDecoder, FrameType, make_frame

DEFAULT_ELF = (
    "/workspace/xiuos-work/xiuos/Ubiquitous/XiZi_IIoT_Macro/"
    "build/XiZi-hifive1-emulator.elf"
)
DEFAULT_QEMU = "qemu-system-riscv32"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 32170


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
            args.machine,
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
        description="Validate XiUOS hifive1-emulator Phase 0 READY/PING/PONG handshake."
    )
    parser.add_argument("--elf", default=DEFAULT_ELF, help="XiUOS ELF path")
    parser.add_argument("--qemu", default=DEFAULT_QEMU, help="qemu-system-riscv32 path")
    parser.add_argument("--machine", default="sifive_e", help="QEMU machine name")
    parser.add_argument("--host", default=DEFAULT_HOST, help="TCP serial host")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="TCP serial port")
    parser.add_argument("--seq", default=1, type=int, help="PING sequence number")
    parser.add_argument("--timeout", default=8.0, type=float, help="frame wait timeout in seconds")
    parser.add_argument(
        "--connect-timeout",
        default=5.0,
        type=float,
        help="TCP serial connect timeout in seconds",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    qemu = start_qemu(args)
    sock = None

    try:
        sock = wait_tcp_connect(args.host, args.port, args.connect_timeout)

        ready = wait_frame(sock, FrameType.READY, None, args.timeout)
        print("READY", ready.raw.hex(" "))

        sock.sendall(make_frame(FrameType.PING, args.seq))
        pong = wait_frame(sock, FrameType.PONG, args.seq, args.timeout)
        print("PONG", pong.raw.hex(" "))
        print("PHASE0_HANDSHAKE_OK")
    finally:
        if sock is not None:
            sock.close()
        stop_qemu(qemu)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"PHASE0_HANDSHAKE_FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
