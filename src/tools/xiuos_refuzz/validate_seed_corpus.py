#!/usr/bin/env python3
"""Dry-run validate generated XiUOS reFuzz seed corpus.

Modes:
  offline (default): load every seed via corpus.py, encode, verify size/argc
                     match the descriptor. Catches generator bugs without QEMU.
  online:            additionally start QEMU + worker and run each seed,
                     comparing actual RESULT.status / calls_executed against
                     the seed's expected_status / expected_min_calls.

Seeds that fail validation are moved (online) or copied (offline) to
corpus/validation_mismatch/ for investigation; they are NOT deleted.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import socket
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

from corpus import (
    DEFAULT_DESCRIPTOR,
    DEFAULT_GENERATED_DIR,
    encode_seed,
    load_descriptor,
    load_seed,
)
from worker_abi import (
    CALL_RECORD_SIZE,
    FrameDecoder,
    FrameType,
    ResultStatus,
    decode_result,
    encode_program,
    make_frame,
)


DEFAULT_MISMATCH_DIR = TOOL_DIR / "corpus" / "validation_mismatch"
DEFAULT_ELF = (
    "/workspace/xiuos-work/xiuos/Ubiquitous/XiZi_IIoT_Macro/"
    "build/XiZi-virt-rv32.elf"
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--descriptor", type=Path, default=DEFAULT_DESCRIPTOR)
    p.add_argument("--corpus", type=Path, default=DEFAULT_GENERATED_DIR,
                   help="root of generated seed JSON tree")
    p.add_argument("--mismatch-dir", type=Path, default=DEFAULT_MISMATCH_DIR,
                   help="where to park seeds whose validation failed")
    p.add_argument("--online", action="store_true",
                   help="also run each seed against QEMU + worker")
    p.add_argument("--elf", default=DEFAULT_ELF, help="worker ELF for --online")
    p.add_argument("--qemu", default="qemu-system-riscv32")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=32171)
    p.add_argument("--frame-timeout", type=float, default=10.0)
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--sample-per-rule", type=int, default=0,
                   help="if >0, randomly sample N seeds per source_rule "
                        "(deterministic with --sample-seed)")
    p.add_argument("--sample-seed", type=int, default=42)
    p.add_argument("--max-seeds", type=int, default=0,
                   help="upper bound on total seeds to validate (after sampling)")
    return p.parse_args()


def discover_seeds(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.json") if p.name != "manifest.json")


def maybe_sample(paths: list[Path], per_rule: int, seed: int, max_total: int) -> list[Path]:
    if per_rule <= 0 and max_total <= 0:
        return paths

    by_rule: dict[str, list[Path]] = defaultdict(list)
    for path in paths:
        rule = json.loads(path.read_text())["source_rule"]
        by_rule[rule].append(path)

    rng = random.Random(seed)
    sampled: list[Path] = []
    for rule, group in by_rule.items():
        if per_rule > 0 and len(group) > per_rule:
            sampled.extend(rng.sample(group, per_rule))
        else:
            sampled.extend(group)
    sampled.sort()

    if max_total > 0 and len(sampled) > max_total:
        rng.shuffle(sampled)
        sampled = sorted(sampled[:max_total])

    return sampled


def park(path: Path, root: Path, mismatch_root: Path, reason: str) -> None:
    relative = path.relative_to(root)
    destination = mismatch_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, destination)
    reason_file = destination.with_suffix(".reason.txt")
    reason_file.write_text(reason + "\n", encoding="utf-8")


def offline_check(path: Path, descriptor) -> tuple[bool, str]:
    try:
        seed = load_seed(path, descriptor)
    except Exception as exc:
        return False, f"load_seed: {exc}"

    try:
        payload = encode_seed(seed)
    except Exception as exc:
        return False, f"encode_seed: {exc}"

    expected_len = 4 + len(seed.calls) * CALL_RECORD_SIZE
    if len(payload) != expected_len:
        return False, f"encoded length {len(payload)} != expected {expected_len}"
    if payload[2] != len(seed.calls):
        return False, f"payload call_count byte {payload[2]} != {len(seed.calls)}"
    if seed.expected_min_calls > len(seed.calls):
        return False, (
            f"expected_min_calls {seed.expected_min_calls} > "
            f"len(calls) {len(seed.calls)}"
        )
    return True, ""


def wait_tcp_connect(host: str, port: int, timeout: float) -> socket.socket:
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


def wait_frame(sock, want_type, want_seq, timeout):
    deadline = time.time() + timeout
    decoder = FrameDecoder()
    while time.time() < deadline:
        frame = decoder.pop()
        if frame is not None:
            if frame.frame_type == want_type and (want_seq is None or frame.seq == want_seq):
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


def start_qemu(elf: str, qemu_bin: str, host: str, port: int) -> subprocess.Popen:
    return subprocess.Popen(
        [
            qemu_bin,
            "-display", "none",
            "-machine", "virt",
            "-bios", "none",
            "-monitor", "none",
            "-serial", f"tcp:{host}:{port},server=on,wait=on",
            "-kernel", elf,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def stop_qemu(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def online_check_batch(
    seed_paths: list[Path],
    descriptor,
    args,
) -> dict[Path, tuple[bool, str]]:
    """Run all seeds against one QEMU session; worker resets state per PROGRAM."""
    results: dict[Path, tuple[bool, str]] = {}
    qemu = start_qemu(args.elf, args.qemu, args.host, args.port)
    sock = None
    try:
        sock = wait_tcp_connect(args.host, args.port, args.connect_timeout)
        wait_frame(sock, FrameType.READY, None, args.frame_timeout)
        sock.sendall(make_frame(FrameType.PING, 1))
        wait_frame(sock, FrameType.PONG, 1, args.frame_timeout)

        seq = 1
        for path in seed_paths:
            seq = (seq + 1) & 0xFFFF
            try:
                seed = load_seed(path, descriptor)
                payload = encode_program(seed.calls, suite_id=seed.suite)
                sock.sendall(make_frame(FrameType.PROGRAM, seq, payload))
                frame = wait_frame(sock, FrameType.RESULT, seq, args.frame_timeout)
                result = decode_result(frame.payload)

                if int(result.status) != int(seed.expected_status):
                    results[path] = (
                        False,
                        f"status {ResultStatus(result.status).name} != "
                        f"expected {ResultStatus(seed.expected_status).name}",
                    )
                    continue
                if result.calls_executed < seed.expected_min_calls:
                    results[path] = (
                        False,
                        f"calls_executed {result.calls_executed} < "
                        f"expected_min {seed.expected_min_calls}",
                    )
                    continue
                if len(result.coverage) != 256:
                    results[path] = (False, f"coverage size {len(result.coverage)} != 256")
                    continue
                if not any(result.coverage):
                    results[path] = (False, "coverage all-zero")
                    continue
                results[path] = (True, "")
            except Exception as exc:
                results[path] = (False, f"online exception: {exc}")
    finally:
        if sock is not None:
            sock.close()
        stop_qemu(qemu)
    return results


def main() -> int:
    args = parse_args()

    if not args.corpus.exists():
        print(f"corpus dir not found: {args.corpus}", file=sys.stderr)
        return 2

    descriptor = load_descriptor(args.descriptor)
    paths = discover_seeds(args.corpus)
    if not paths:
        print("no generated seeds found", file=sys.stderr)
        return 2

    selected = maybe_sample(paths, args.sample_per_rule, args.sample_seed, args.max_seeds)
    print(f"OFFLINE validating {len(selected)} / {len(paths)} seeds")

    args.mismatch_dir.mkdir(parents=True, exist_ok=True)

    offline_fail = 0
    online_candidates: list[Path] = []
    for path in selected:
        ok, reason = offline_check(path, descriptor)
        if not ok:
            offline_fail += 1
            park(path, args.corpus, args.mismatch_dir, f"offline: {reason}")
            print(f"  OFFLINE_FAIL {path.relative_to(args.corpus)}: {reason}")
        else:
            online_candidates.append(path)

    print(f"OFFLINE_RESULT pass={len(online_candidates)} fail={offline_fail}")

    if not args.online:
        return 0 if offline_fail == 0 else 1

    print(f"ONLINE validating {len(online_candidates)} seeds against {args.elf}")
    online_results = online_check_batch(online_candidates, descriptor, args)
    online_fail = 0
    for path, (ok, reason) in online_results.items():
        if not ok:
            online_fail += 1
            park(path, args.corpus, args.mismatch_dir, f"online: {reason}")
            print(f"  ONLINE_FAIL {path.relative_to(args.corpus)}: {reason}")

    online_pass = len(online_results) - online_fail
    print(f"ONLINE_RESULT pass={online_pass} fail={online_fail}")

    return 0 if (offline_fail == 0 and online_fail == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
