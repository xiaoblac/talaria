#!/usr/bin/env python3
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
"""Step 3 of docs/plans/fixed-request-stream-performance-replay.md.

Validate that ENABLING the request-stream capture sink does not pollute
Syzkaller's own native performance measurement. It runs the SAME syz-manager
build (built with the sink) twice per round, interleaved:

    disabled  -- no -request-stream flag  (sink code compiled in but inert)
    enabled   -- -request-stream <file>   (sink armed after machine check)

Both arms use identical config, run window, and native RTT probes (-task-trace).
Throughput (programs/s, executed syscalls/s) comes from the manager's own
/metrics deltas; the host-clock E1->E9 service intervals come from the manager's
own syz_task_trace.jsonl. The request stream itself is NEVER used as a timing
source -- this driver only reads its byte size, decodes it for integrity, and
scrapes the sink's own queue-peak / record-count log line.

Gate 3 (see plan): the enabled-vs-disabled difference must stay within the
disabled arm's own run-to-run spread; the sink must leave no undrained backlog,
no sequence gap, and no temp file; every interval must come from native events.

The RTT / metric computation is imported verbatim from speed_compare.py so the
numbers are produced exactly as the established harness produces them.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import speed_compare as sc  # noqa: E402  (reuse the harness's own parsers)

# --------------------------------------------------------------------------
# Request-stream v2 decoder (schema: plan §4.2 / pkg/requeststream). Strict:
# any bad magic/version, sequence gap, truncation, or trailing byte raises.
# Used ONLY for integrity validation and program digests -- never for timing.
# v2's variable field is canonical syzlang text, not SerializeForExec bytes; the
# decoder treats it as opaque either way, only the magic/version differ.
# --------------------------------------------------------------------------
RS_MAGIC = b"RFZREQS2"
RS_FOOTER_MAGIC = b"RFZEND01"
RS_VERSION = 2
RS_HEADER_SIZE = 32
RS_FOOTER_SIZE = 36
RS_RECORD_FIXED = 60
RS_FOOTER_MARKER = 0xFFFFFFFF
RS_KIND_PROGRAM = 1


def decode_request_stream(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < RS_HEADER_SIZE:
        raise ValueError("stream shorter than header")
    if data[:8] != RS_MAGIC:
        raise ValueError("bad magic")
    version, header_size, flags, rsv32 = struct.unpack_from("<IIII", data, 8)
    (rsv64,) = struct.unpack_from("<Q", data, 24)
    if version != RS_VERSION or header_size != RS_HEADER_SIZE:
        raise ValueError(f"bad header version/size {version}/{header_size}")
    if flags or rsv32 or rsv64:
        raise ValueError("nonzero reserved header fields")
    pos = RS_HEADER_SIZE
    records: list[dict[str, Any]] = []
    import hashlib
    while True:
        if pos + 4 > len(data):
            raise ValueError("missing footer")
        (frame,) = struct.unpack_from("<I", data, pos)
        if frame == RS_FOOTER_MARKER:
            if len(data) - pos < RS_FOOTER_SIZE:
                raise ValueError("truncated footer")
            if data[pos + 4:pos + 12] != RS_FOOTER_MAGIC:
                raise ValueError("bad footer magic")
            fver, fsize = struct.unpack_from("<II", data, pos + 12)
            rec_count, last_seq = struct.unpack_from("<QQ", data, pos + 20)
            if fver != RS_VERSION or fsize != RS_FOOTER_SIZE:
                raise ValueError("bad footer version/size")
            if rec_count != len(records):
                raise ValueError(f"footer count {rec_count} != {len(records)}")
            if records and last_seq != len(records) - 1:
                raise ValueError("footer last_sequence mismatch")
            if pos + RS_FOOTER_SIZE != len(data):
                raise ValueError("trailing bytes after footer")
            if not records:
                raise ValueError("empty stream")
            return {
                "record_count": rec_count,
                "last_sequence": last_seq,
                "bytes": len(data),
                "payload_digest": hashlib.sha256(
                    b"".join(r["payload"] for r in records)).hexdigest(),
                "sequences_contiguous": True,
            }
        # `pos` points at the 4-byte frame_size prefix; the body of `frame` bytes
        # (kind..payload) starts at body = pos+4. RS_RECORD_FIXED counts the body
        # fixed part only, so every field offset is relative to body.
        if frame < RS_RECORD_FIXED or pos + 4 + frame > len(data):
            raise ValueError("record length out of range / truncated")
        body = pos + 4
        kind = data[body]
        if kind != RS_KIND_PROGRAM:
            raise ValueError(f"unknown record kind {kind}")
        seq, req_type = struct.unpack_from("<QQ", data, body + 4)
        asig_count, payload_size = struct.unpack_from("<II", data, body + 52)
        if seq != len(records):
            raise ValueError(f"sequence gap: got {seq} want {len(records)}")
        if req_type != 0:
            raise ValueError("non-program request type in stream")
        var = asig_count * 4 + payload_size
        if var != frame - RS_RECORD_FIXED:
            raise ValueError("record length != fields")
        payload_off = body + RS_RECORD_FIXED + asig_count * 4
        payload = data[payload_off:payload_off + payload_size]
        records.append({"seq": seq, "payload": payload})
        pos = body + frame


# --------------------------------------------------------------------------
# One measured run of the instrumented syz-manager.
# --------------------------------------------------------------------------
def make_config(base: dict[str, Any], run_dir: Path, http_port: int) -> Path:
    cfg = json.loads(json.dumps(base))  # deep copy
    work = run_dir / "syz_work"
    work.mkdir(parents=True, exist_ok=True)
    cfg["workdir"] = str(work)
    cfg["http"] = f"127.0.0.1:{http_port}"
    cfg["preserve_corpus"] = False
    vm = cfg.setdefault("vm", {})
    raw = vm.get("qemu_args")
    if raw:
        vm["qemu_args"] = str(raw).replace("<run_dir>", str(run_dir))
        if "-enable-kvm" not in vm["qemu_args"]:
            raise RuntimeError("qemu_args lost -enable-kvm; timings would be garbage")
    path = run_dir / "syzkaller_config.json"
    path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return path


def stop_syz(proc: subprocess.Popen[Any], grace: float) -> None:
    """SIGINT to the manager (triggers graceful shutdown + sink publish), then
    escalate to the process group only if it overstays the grace window."""
    if proc.poll() is not None:
        return
    try:
        os.kill(proc.pid, signal.SIGINT)
        proc.wait(timeout=grace)
        return
    except ProcessLookupError:
        return
    except Exception:
        pass
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=15)
    except Exception:
        pass
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)


def scrape_sink_log(log_path: Path) -> dict[str, Any]:
    """Read the sink's own log lines from syz-manager.log. Never a timing source."""
    out: dict[str, Any] = {"published": None, "peak": None, "invalidated": None}
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        if "request-stream: published" in line:
            # "... published N records to PATH (queue peak M)"
            try:
                out["published"] = int(line.split("published", 1)[1].split("records", 1)[0])
                out["peak"] = int(line.split("queue peak", 1)[1].split(")", 1)[0])
            except (ValueError, IndexError):
                pass
        elif "invalidated" in line or "capture not published" in line:
            out["invalidated"] = line.strip()
    return out


def run_once(binary: Path, base: dict[str, Any], run_dir: Path, http_port: int,
             enabled: bool, args: argparse.Namespace, syz_root: Path) -> dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = make_config(base, run_dir, http_port)
    http_addr = f"127.0.0.1:{http_port}"
    log_path = run_dir / "syz-manager.log"
    bench = run_dir / "syz_bench.txt"
    tt = run_dir / "syz_task_trace.jsonl"
    rs = run_dir / "request_stream.bin"
    cmd = [str(binary), "-config", str(cfg_path), "-bench", str(bench),
           "-task-trace", str(tt), "-task-trace-sample-rate", "1"]
    if enabled:
        cmd += ["-request-stream", str(rs)]
    row: dict[str, Any] = {"arm": "enabled" if enabled else "disabled",
                           "run_dir": run_dir.name, "status": "failed"}
    proc: subprocess.Popen[Any] | None = None
    print(f"[{row['arm']}] {run_dir.name}: launching ...", flush=True)
    try:
        with log_path.open("ab") as log:
            log.write(("+ " + " ".join(cmd) + "\n").encode())
            log.flush()
            proc = subprocess.Popen(cmd, cwd=str(syz_root), stdout=log,
                                    stderr=subprocess.STDOUT, preexec_fn=os.setsid)
            deadline = time.monotonic() + args.start_timeout
            started, last = False, 0
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f"manager exited early rc={proc.returncode}")
                snap = sc.fetch_syz_metrics(http_addr)
                if snap and snap.get("completed") is not None and snap.get("fuzz_time_ms"):
                    if snap["completed"] > last and (snap["fuzz_time_ms"] or 0) > 0:
                        started = True
                        break
                    last = snap["completed"] or 0
                time.sleep(1.0)
            if not started:
                raise TimeoutError(f"no fuzzing within {args.start_timeout}s")
            print(f"[{row['arm']}] {run_dir.name}: fuzzing started, "
                  f"warmup {args.warmup}s + measure {args.duration}s", flush=True)
            if args.warmup > 0:
                time.sleep(args.warmup)
            s0 = sc.fetch_syz_metrics(http_addr)
            time.sleep(args.duration)
            s1 = sc.fetch_syz_metrics(http_addr)
        if not s0 or not s1 or s0.get("fuzz_time_ms") is None or s1.get("fuzz_time_ms") is None:
            raise RuntimeError("missing metrics at window edges")
        fuzz_ms = int(s1["fuzz_time_ms"] or 0) - int(s0["fuzz_time_ms"] or 0)
        if fuzz_ms <= 0:
            raise RuntimeError("non-positive fuzz-time delta")
        seconds = fuzz_ms / 1000.0
        execs = max(0, int(s1.get("exec_total") or 0) - int(s0.get("exec_total") or 0))
        calls = max(0, int(s1.get("exec_calls") or 0) - int(s0.get("exec_calls") or 0))
        row.update(status="ok", wall_s=round(seconds, 3), execs=execs, calls=calls,
                   programs_per_sec=round(execs / seconds, 4),
                   syz_calls_per_sec=round(calls / seconds, 4))
    finally:
        if proc is not None:
            stop_syz(proc, args.sigint_grace)
    # ---- post-run, native RTT from the manager's own task-trace ----
    rows = sc.parse_syz_task_trace(tt)
    rtt = sc.compute_rtt_percentiles(rows, tool="syzkaller")
    seg = rtt.get("segments", {})
    for name in ("queue_wait", "dispatch_prep", "dispatch_wait", "transport_out",
                 "slot_wait", "execute", "result_copy", "feedback", "total"):
        s = seg.get(name, {})
        row[f"{name}_mean_ms"] = s.get("mean_ms")
        row[f"{name}_p50_ms"] = s.get("p50_ms")
    row["rtt_rows"] = rtt.get("rows_parsed")
    row["rtt_final"] = rtt.get("final_samples")
    row["service_mean_ms"] = rtt.get("zones", {}).get("service_mean_ms")
    # ---- sink integrity (enabled only) ----
    if enabled:
        sinkinfo = scrape_sink_log(log_path)
        row["sink_published"] = sinkinfo["published"]
        row["sink_peak"] = sinkinfo["peak"]
        row["sink_invalidated"] = sinkinfo["invalidated"]
        leftovers = list(run_dir.glob("*.partial"))
        row["sink_partial_leftover"] = [p.name for p in leftovers]
        if rs.exists():
            try:
                dec = decode_request_stream(rs)
                row["sink_decode_ok"] = True
                row["sink_records"] = dec["record_count"]
                row["sink_bytes"] = dec["bytes"]
                row["sink_payload_digest"] = dec["payload_digest"][:16]
                if sinkinfo["published"] is not None and dec["record_count"] != sinkinfo["published"]:
                    row["sink_decode_ok"] = f"count mismatch {dec['record_count']} vs log {sinkinfo['published']}"
            except Exception as e:  # noqa: BLE001
                row["sink_decode_ok"] = f"DECODE FAILED: {e}"
        else:
            row["sink_decode_ok"] = "no stream file produced"
    print(f"[{row['arm']}] {run_dir.name}: {row.get('status')} "
          f"prog/s={row.get('programs_per_sec')} calls/s={row.get('syz_calls_per_sec')} "
          f"dispatch_prep_mean_ms={row.get('dispatch_prep_mean_ms')}"
          + (f" sink_records={row.get('sink_records')} peak={row.get('sink_peak')}"
             if enabled else ""), flush=True)
    return row


def summarize(rows: list[dict[str, Any]]) -> str:
    ok = [r for r in rows if r.get("status") == "ok"]
    dis = [r for r in ok if r["arm"] == "disabled"]
    ena = [r for r in ok if r["arm"] == "enabled"]
    metrics = ["programs_per_sec", "syz_calls_per_sec", "dispatch_prep_mean_ms",
               "dispatch_prep_p50_ms", "service_mean_ms", "total_mean_ms",
               "execute_mean_ms"]
    lines = ["# Step 3 — sink isolation A/B", ""]
    lines.append(f"disabled runs: {len(dis)}   enabled runs: {len(ena)}")
    lines.append("")
    lines.append("| metric | disabled mean | disabled range | enabled mean | Δ(ena-dis) | within disabled range? |")
    lines.append("|---|---|---|---|---|---|")
    verdict_ok = True
    for m in metrics:
        dv = [r[m] for r in dis if isinstance(r.get(m), (int, float))]
        ev = [r[m] for r in ena if isinstance(r.get(m), (int, float))]
        if not dv or not ev:
            continue
        dmean = statistics.mean(dv)
        emean = statistics.mean(ev)
        drange = max(dv) - min(dv)
        delta = emean - dmean
        within = abs(delta) <= drange or (min(dv) <= emean <= max(dv))
        if not within:
            verdict_ok = False
        lines.append(f"| {m} | {dmean:.4g} | ±{drange/2:.3g} [{min(dv):.4g},{max(dv):.4g}] | "
                     f"{emean:.4g} | {delta:+.3g} | {'yes' if within else 'NO'} |")
    lines.append("")
    lines.append("## Sink integrity (enabled runs)")
    for r in ena:
        lines.append(f"- {r['run_dir']}: records={r.get('sink_records')} "
                     f"log_published={r.get('sink_published')} peak={r.get('sink_peak')} "
                     f"bytes={r.get('sink_bytes')} decode={r.get('sink_decode_ok')} "
                     f"partial_leftover={r.get('sink_partial_leftover')} "
                     f"invalidated={r.get('sink_invalidated')}")
    lines.append("")
    lines.append(f"## Gate 3 throughput/interval verdict: "
                 f"{'PASS (all metrics within disabled spread)' if verdict_ok else 'REVIEW (a metric exceeded disabled spread)'}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True, type=Path)
    ap.add_argument("--syz-config", type=Path,
                    default=_HERE.parent.parent / "run/speed_compare/configs/syz_6proc.json")
    ap.add_argument("--syz-root", type=Path, default=Path("/workspace/syzkaller"))
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--repeats", type=int, default=3, help="rounds per arm")
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--warmup", type=int, default=30)
    ap.add_argument("--start-timeout", type=int, default=900)
    ap.add_argument("--sigint-grace", type=float, default=12.0)
    ap.add_argument("--http-port-base", type=int, default=57600)
    ap.add_argument("--arms", default="disabled,enabled",
                    help="comma list; interleaved each round")
    ap.add_argument("--smoke", action="store_true",
                    help="single short enabled run to validate the pipeline")
    args = ap.parse_args()

    # syz-manager runs with cwd=syz_root, so every path handed to it (config,
    # bench, task-trace, request-stream, workdir) must be absolute.
    args.out_dir = args.out_dir.resolve()
    args.binary = args.binary.resolve()
    args.syz_root = args.syz_root.resolve()
    base = json.loads(args.syz_config.read_text(encoding="utf-8"))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    if args.smoke:
        arms, args.repeats = ["enabled"], 1

    rows: list[dict[str, Any]] = []
    idx = 0
    for rnd in range(args.repeats):
        for arm in arms:
            enabled = (arm == "enabled")
            run_dir = args.out_dir / f"run_{idx:02d}_{arm}"
            port = args.http_port_base + idx
            try:
                row = run_once(args.binary, base, run_dir, port, enabled, args, args.syz_root)
            except Exception as e:  # noqa: BLE001
                row = {"arm": arm, "run_dir": run_dir.name, "status": f"error: {e}"}
                print(f"[{arm}] {run_dir.name}: ERROR {e}", flush=True)
            rows.append(row)
            (args.out_dir / "step3_rows.jsonl").open("a", encoding="utf-8").write(
                json.dumps(row) + "\n")
            idx += 1

    summary = summarize(rows)
    (args.out_dir / "step3_summary.md").write_text(summary, encoding="utf-8")
    print("\n" + summary, flush=True)
    print(f"\nwrote {args.out_dir}/step3_summary.md and step3_rows.jsonl", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
