#!/usr/bin/env python3
"""Speed Compare — reFuzz vs upstream syzkaller execution-speed comparison.

Implements docs/plans/speed-compare.md (FREEZE 2026-05-25). syzkaller's
execution path is the fixed baseline; reFuzz is aligned to the same parameter
axes (single worker, sandbox=none, threaded, program timeout, coverage layer)
so the only variable is the implementation.

Arms (--arms, default D):

  D   full fuzz loop (generation+mutation+execute+feedback)
        reFuzz : control/orchestrator/refuzz  (FuzzerLoop, n_workers=1)
        syz    : syz-manager fuzzing (vm.count=1, procs=1)

  (The earlier B/C corpus-replay arms — bare/KCOV/strict replay of a fixed
  corpus — were removed: host-replay throughput proved not meaningful next to
  the full fuzz loop. Their runners/config builders are gone.)

Both sides execute in a QEMU guest on the SAME kernel image (base config's
channel.vm) so the only variable is the implementation.

Throughput口径 (computed externally from each tool's own JSON, not its logs):
  - syz_calls_per_sec: REAL executed syscall counters (reFuzz fuzzer.calls.executed
      vs syz_exec_calls_total) — the fair full-loop throughput. Missing counters
      fail the run instead of silently falling back to estimates.
  - programs_per_sec : auxiliary shape metric — reFuzz terminal results/s vs syz
      exec starts/s (the two loops generate different program shapes).

Fairness gates (§4.2): a run is flagged (no ratio) when timeout_or_hang_rate
exceeds the threshold. The reFuzz nominal↔executed gap is reported for
observation, not as a screening condition.

NOTE: this depends on a self-built syz-execprog carrying the measurement-only
`-speed_stats` flag (tools/syz-execprog/execprog.go). Stock binaries lack it.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import math
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, fields as dataclass_fields
from pathlib import Path
from typing import Any, Callable

# sibling module: solidified MAB fuzz-tool comparison metrics (task share +
# PC-per-syscall coverage), extracted from a reFuzz run's host_events.txt.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mab_metrics  # noqa: E402


ACTIVE_CHILD_PROC: subprocess.Popen[Any] | None = None
CVSH_MAGIC = 0x48535643
CVSH_VERSION_V2 = 2
CVSH_HEADER_SIZE = 24
CVSH_ENTRY_V2_SIZE = 16


# ---------------------------------------------------------------------------
# Generic helpers (ported verbatim from the retired bench_single_worker_compare).
# ---------------------------------------------------------------------------
def repo_root() -> Path:
    # scripts/speed_compare/speed_compare.py → parents[2] = repo root
    return Path(__file__).resolve().parents[2]


def mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: dict[str, Any]) -> None:
    mkdir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")


def write_lines(path: Path, lines: list[str]) -> None:
    mkdir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        if lines:
            f.write("\n".join(lines))
            f.write("\n")


def read_name_file(path: Path) -> set[str]:
    names: set[str] = set()
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if line:
                names.add(line)
    return names


def nested(root: dict[str, Any], *keys: str) -> dict[str, Any]:
    cur = root
    for key in keys:
        val = cur.get(key)
        if not isinstance(val, dict):
            val = {}
            cur[key] = val
        cur = val
    return cur


def overlay_json(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    for key, val in src.items():
        if isinstance(val, dict) and isinstance(dst.get(key), dict):
            overlay_json(dst[key], val)
        else:
            dst[key] = json.loads(json.dumps(val)) if isinstance(val, (dict, list)) else val
    return dst


def host_goarch() -> str:
    machine = platform.machine().lower()
    return {
        "x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64",
        "arm64": "arm64", "i386": "386", "i686": "386",
    }.get(machine, machine)


@dataclass
class SyzkallerTimeouts:
    slowdown: int
    scale: int
    syscall_timeout_ms: int
    program_timeout_ms: int


def syzkaller_manager_timeouts(base: dict[str, Any]) -> SyzkallerTimeouts:
    # Mirrors sys/targets/targets.go defaults + pkg/mgrconfig/load.go slowdown.
    channel = base.get("channel", {})
    vm = channel.get("vm", {}) if isinstance(channel, dict) else {}
    qemu = vm.get("qemu", {}) if isinstance(vm, dict) else {}
    qemu_blob = json.dumps(qemu, sort_keys=True) if isinstance(qemu, dict) else str(qemu)
    slowdown = 1
    if host_goarch() != "amd64" or "-accel tcg" in qemu_blob:
        slowdown = 10
    scale = min(slowdown, 3)
    return SyzkallerTimeouts(
        slowdown=slowdown, scale=scale,
        syscall_timeout_ms=50 * slowdown, program_timeout_ms=5000 * scale,
    )


def run_checked(cmd: list[str], cwd: Path, log_path: Path | None = None,
                timeout: float | None = None) -> None:
    print("+ " + " ".join(cmd), flush=True)
    if log_path is None:
        subprocess.run(cmd, cwd=cwd, check=True, timeout=timeout)
        return
    mkdir(log_path.parent)
    with log_path.open("ab") as log:
        log.write(("+ " + " ".join(cmd) + "\n").encode())
        log.flush()
        subprocess.run(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
                       check=True, timeout=timeout)


def process_cmdline(pid: int) -> str | None:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    return raw.replace(b"\0", b" ").decode("utf-8", errors="replace").strip()


def pgid_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def kill_pgid(pgid: int, label: str) -> None:
    if pgid <= 1 or not pgid_alive(pgid):
        return
    print(f"cleanup: stopping process group {pgid} ({label})", flush=True)
    for sig, delay in ((signal.SIGINT, 8.0), (signal.SIGTERM, 5.0), (signal.SIGKILL, 2.0)):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + delay
        while time.monotonic() < deadline:
            if not pgid_alive(pgid):
                return
            time.sleep(0.2)


def stop_process_group(proc: subprocess.Popen[Any], sigint_grace: float = 25) -> None:
    if proc.poll() is not None:
        return
    # [teardown EOF fix] 优雅停止只给 **refuzz 本进程** 发 SIGINT(os.kill(proc.pid),
    # 不是 os.killpg 整组)。refuzz 自己会有序拆掉 qemu/worker(先挂起 health/ConsoleSensor
    # 再关 qemu),所以串口 socket 在监控停掉之后才关闭,不会触发 teardown 假
    # kVmDead(serial_eof)。killpg 会同时把 SIGINT 发给 qemu → qemu 立刻关串口 socket →
    # refuzz 还活着、ConsoleSensor 读到 EOF → 误判 VM 死 + 试图 reboot(见 run
    # 20260602-080309 末尾的假 vm_dead)。killpg 只保留给 refuzz 不响应时的**强制兜底**
    # (SIGTERM/SIGKILL,防止孤儿 qemu/worker 残留)。
    try:
        os.kill(proc.pid, signal.SIGINT)
        proc.wait(timeout=sigint_grace)
        return
    except ProcessLookupError:
        return
    except Exception:
        pass
    if proc.poll() is not None:
        return
    # refuzz 未在宽限期内优雅退出 → 强制整组(此时优先保证不留孤儿,可接受 teardown 噪声)
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
        return
    except Exception:
        pass
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)


def install_signal_handlers() -> None:
    def handle(signum: int, _frame: Any) -> None:
        if ACTIVE_CHILD_PROC is not None:
            stop_process_group(ACTIVE_CHILD_PROC)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)


def cleanup_stale_for_out_dir(out_dir: Path) -> None:
    marker = str(out_dir.resolve())
    if out_dir.exists():
        for pgid_path in out_dir.glob("*_run_*/*.pgid"):
            try:
                pgid = int(pgid_path.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                continue
            kill_pgid(pgid, str(pgid_path))
    proc_root = Path("/proc")
    if not proc_root.exists():
        return
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        cmd = process_cmdline(pid)
        if not cmd or marker not in cmd:
            continue
        if any(t in cmd for t in ("syz-manager", "syz-execprog",
                                  "control/orchestrator/refuzz", "refuzz-exec-replayer")):
            try:
                kill_pgid(os.getpgid(pid), cmd[:160])
            except ProcessLookupError:
                continue


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build_refuzz(args: argparse.Namespace, out_dir: Path) -> None:
    cc = os.environ.get("REFUZZ_CC", "clang-20")
    cxx = os.environ.get("REFUZZ_CXX", "clang++-20")
    run_checked(
        ["cmake", "-S", str(args.refuzz_root), "-B", str(args.refuzz_build_dir),
         f"-DCMAKE_C_COMPILER={cc}", f"-DCMAKE_CXX_COMPILER={cxx}"],
        cwd=args.refuzz_root, log_path=out_dir / "build_refuzz.log",
    )
    run_checked(
        ["cmake", "--build", str(args.refuzz_build_dir), f"-j{os.cpu_count() or 1}"],
        cwd=args.refuzz_root, log_path=out_dir / "build_refuzz.log",
    )


def build_syzkaller(args: argparse.Namespace, out_dir: Path) -> None:
    # arm D needs syz-manager + the executor it deploys into the VM.
    run_checked(
        ["make", "manager", "executor",
         "TARGETOS=linux", "TARGETVMARCH=amd64", "TARGETARCH=amd64"],
        cwd=args.syzkaller_root, log_path=out_dir / "build_syzkaller.log",
    )


def build_syzgen_binary(args: argparse.Namespace, out_dir: Path) -> Path:
    binary = out_dir / "syzgen_speed"
    # [prebuilt] Same container rationale as COV_COMPARE_BIN: runtime images ship
    # no Go toolchain, so syzgen must be built on the build machine and copied in.
    prebuilt = os.environ.get("SYZGEN_BIN")
    if prebuilt:
        src_bin = Path(prebuilt)
        if not src_bin.is_file():
            raise RuntimeError(f"SYZGEN_BIN={prebuilt} does not exist")
        shutil.copy2(src_bin, binary)
        binary.chmod(0o755)
        print(f"  syzgen: using prebuilt {src_bin}", flush=True)
        return binary
    run_checked(
        ["go", "build", "-o", str(binary), "./tools/syzgen"],
        cwd=args.refuzz_root, log_path=out_dir / "build_syzgen.log",
    )
    return binary


# ---------------------------------------------------------------------------
# Pseudo policy (ported). Drives the syz-manager disable_syscalls (arm D) and
# the physical corpus pseudo-filter.
# ---------------------------------------------------------------------------
SYZKALLER_SURFACE_PSEUDO_PATTERNS = [
    "syz_mount_image*", "syz_read_part_table",
    "syz_kvm*", "syz_memcpy_off$KVM_*",
    "syz_usb*", "syz_emit_vhci", "syz_80211_*",
    "syz_fuse*",
    "syz_io_uring_*", "syz_memcpy_off$IO_URING_*",
    "syz_btf_*", "syz_kfuzztest_*",
    "syz_emit_ethernet", "syz_extract_tcp_res*",
    "syz_create_resource*", "syz_socket_connect_nvme_tcp",
]

# Heuristic unbounded-blocking call patterns for --filter-timeout-prone. This
# is a belt-and-suspenders static filter only; the authoritative protection is
# the runtime timeout_or_hang_rate gate (§4.2). Conservative by design — only
# calls with no bounded timeout argument in common usage.
TIMEOUT_PRONE_PATTERNS = [
    "pause", "ppoll", "poll", "select", "pselect6", "epoll_wait", "epoll_pwait",
    "futex", "read$*", "readv", "recvmsg", "recvmmsg", "recvfrom",
    "accept", "accept4", "wait4", "waitid", "mq_timedreceive", "msgrcv",
    "semop", "semtimedop", "flock", "fcntl$lock", "rt_sigtimedwait",
]


@dataclass
class PseudoAlignment:
    manifest_artifact: str = ""
    allowlist_artifact: str = ""
    summary_artifact: str = ""
    manifest_sha256: str = ""
    allowed_count: str = ""
    unsupported_count: str = ""


def load_pseudo_manifest(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise RuntimeError(f"empty pseudo manifest: {path}")
    if "name" not in rows[0]:
        raise RuntimeError(f"pseudo manifest missing name column: {path}")
    return rows


def syzkaller_disabled_syscalls(args: argparse.Namespace) -> list[str]:
    mode = args.syzkaller_pseudo_filter
    if mode == "none":
        return []
    if mode == "all_syz":
        return ["syz_*"]
    if mode == "surface":
        return list(SYZKALLER_SURFACE_PSEUDO_PATTERNS)
    raise ValueError(f"unknown syzkaller pseudo filter: {mode}")


def configure_refuzz_pseudo_policy(args: argparse.Namespace, target: dict[str, Any]) -> None:
    # reFuzz only supports all-or-nothing target.disable_pseudo_calls. For the
    # corpus filter we physically drop pseudo-bearing programs (see
    # prepare_corpus), so the replayer never sees them; disable_pseudo_calls is
    # the runtime backstop for D's mutator.
    target["disable_pseudo_calls"] = args.syzkaller_pseudo_filter != "none"


# ---------------------------------------------------------------------------
# Corpus prep: unpack -> filter (pseudo + optional timeout-prone) -> emit the
# sorted, filtered program set for BOTH tools in the SAME order.
#   filtered_raw/<016d>.syz   : argv-fed to syz-execprog (sorted glob == seed_id)
#   refuzz/<016x>/payload.bin : -corpus-dir for refuzz-exec-replayer (sorts by name)
# plus corpus_manifest.json (per_program_calls[] = auxiliary nominal source).
# ---------------------------------------------------------------------------
def program_call_names(text: str) -> list[str]:
    names: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rhs = line
        m = re.match(r"^r\d+\s*=\s*(.*)$", line)
        if m:
            rhs = m.group(1)
        cm = re.match(r"^([a-zA-Z0-9_$]+)\s*\(", rhs)
        if cm:
            names.append(cm.group(1))
    return names


def count_call_lines(text: str) -> int:
    n = 0
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            n += 1
    return n


def matches_any(names: list[str], patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, pat) for name in names for pat in patterns)


@dataclass
class CorpusPrep:
    refuzz_dir: Path          # <corpus>/refuzz/<016x>/payload.bin (reFuzz replayer)
    syz_dir: Path             # <corpus>/syz/<016d>.syz (syz-execprog argv)
    corpus_db: Path | None    # explicit --seed-corpus-db (syz-manager D warm start), else None
    manifest: dict[str, Any]
    manifest_path: Path


def prepare_corpus(args: argparse.Namespace, out_dir: Path) -> CorpusPrep:
    """STAGE 1 — data prep ONLY. Decide where the data comes from and lay it out
    in a STABLE order into two sibling folders. NO decode, NO filter, NO marking,
    NO good/bad judgement (those belong to stage 2 --check-decode and stage 3).

      <cache>/syz/<016d>.syz             — syz-execprog argv (glob sort == seed_id)
      <cache>/refuzz/<016x>/payload.bin  — reFuzz replayer (name sort == seed_id)

    Source (stable, deterministic):
      - default: syzkaller's built-in seeds sys/<os>/test/* enumerated sorted by
        filename and converted to concrete programs by `syzgen seeds-unpack`
        (replaces the nondeterministic syz-manager corpus-triage). Arch-mismatched
        / unparsable seeds are recorded to seed_skips.csv (not a quality filter —
        they simply aren't programs for this target).
      - --seed-corpus-db <db>: explicit override, unpacked via corpus-unpack-db.

    The corpus lives in a FIXED cache dir (default run/speed_compare/corpus,
    --corpus-cache-dir) and is REUSED across invocations — the per-run <ts>/ dir
    holds only results, not the corpus. It is (re)generated only when the cache
    is missing/incomplete, the source changed, or --refresh-corpus is passed."""
    cache_dir = (args.corpus_cache_dir.resolve() if args.corpus_cache_dir
                 else out_dir.parent / "corpus")
    syz_dir = cache_dir / "syz"
    refuzz_dir = cache_dir / "refuzz"
    manifest_path = cache_dir / "corpus_manifest.json"
    marker = cache_dir / ".corpus_source.json"

    if args.seed_corpus_db is not None:
        st = args.seed_corpus_db.stat()
        source = f"corpus.db:{args.seed_corpus_db}"
        want = {"source": source, "size": st.st_size, "mtime_ns": st.st_mtime_ns}
    else:
        source = f"builtin-seeds:{args.seeds_dir}"
        want = {"source": source}
    try:
        fresh = (manifest_path.exists() and syz_dir.exists() and refuzz_dir.exists()
                 and marker.exists() and load_json(marker) == want)
    except Exception:
        fresh = False
    if fresh and not args.refresh_corpus:
        manifest = load_json(manifest_path)
        print(f"corpus prep (stage 1): reusing cached {cache_dir} "
              f"({manifest.get('num_programs')} programs from {source}; "
              f"--refresh-corpus to regenerate)", flush=True)
        return CorpusPrep(refuzz_dir, syz_dir, args.seed_corpus_db, manifest, manifest_path)

    syzgen = build_syzgen_binary(args, out_dir)
    raw_dir = cache_dir / "raw"
    for d in (raw_dir, syz_dir, refuzz_dir):
        if d.exists():
            shutil.rmtree(d)
    mkdir(cache_dir)

    if args.seed_corpus_db is not None:
        run_checked(
            [str(syzgen), "corpus-unpack-db", "-corpus-db", str(args.seed_corpus_db),
             "-out", str(raw_dir)],
            cwd=args.refuzz_root, log_path=out_dir / "corpus_unpack.log",
        )
    else:
        if not args.seeds_dir.exists():
            raise SystemExit(f"seeds dir not found: {args.seeds_dir}")
        run_checked(
            [str(syzgen), "seeds-unpack", "-seeds-dir", str(args.seeds_dir),
             "-out", str(raw_dir), "-skip-out", str(cache_dir / "seed_skips.csv")],
            cwd=args.refuzz_root, log_path=out_dir / "corpus_unpack.log",
        )

    entries = sorted(p for p in raw_dir.iterdir() if p.is_file())
    if not entries:
        raise RuntimeError(f"no programs from {source}")

    mkdir(syz_dir)
    mkdir(refuzz_dir)
    per_program_calls: list[int] = []
    for idx, src in enumerate(entries, start=1):
        text = src.read_text(encoding="utf-8", errors="replace")
        shutil.copyfile(src, syz_dir / f"{idx:016d}.syz")
        dest = refuzz_dir / f"{idx:016x}"
        dest.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(src, dest / "payload.bin")
        per_program_calls.append(count_call_lines(text))

    n = len(per_program_calls)
    total_calls = sum(per_program_calls)
    manifest = {
        "source": source,
        "num_programs": n,
        "per_program_calls": per_program_calls,
        "corpus_total_calls": total_calls,
        "mean_calls_per_program": (total_calls / n) if n else 0.0,
        "syz_dir": str(syz_dir),
        "refuzz_dir": str(refuzz_dir),
        "note": "stage-1 data prep: stable order, NO filter / decode / marking",
    }
    write_json(manifest_path, manifest)
    write_json(marker, want)
    print(f"corpus prep (stage 1): {source} → {n} programs, total_calls={total_calls} "
          f"→ {cache_dir} (syz/ + refuzz/; no filter)", flush=True)
    return CorpusPrep(refuzz_dir, syz_dir, args.seed_corpus_db, manifest, manifest_path)


def clone_refuzz_corpus(master_dir: Path, run_dir: Path) -> Path:
    """Per-run clone so reFuzz SaveSeed writes (D) cannot pollute the master."""
    dest = run_dir / "seed_corpus"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(master_dir, dest)
    return dest


def refuzz_child_env() -> dict[str, str]:
    """Environment for the reFuzz child only -- jemalloc + rare-edge prior.

    Both knobs are part of reFuzz's own design and must not reach syz-manager
    (see the env= at the reFuzz Popen). Defaults mirror
    scripts/perf_compare/perf_sampling.sh:100,108 so the two harnesses launch
    reFuzz identically; override via the same variable names.

    LD_PRELOAD is only added if the .so actually exists: a non-existent preload
    makes the dynamic loader warn on every exec, and silently running without
    jemalloc is better than a run that dies at startup on a host that packages
    it elsewhere. The resolved value is what gets logged, so which case applied
    is visible after the fact.
    """
    env = dict(os.environ)
    jemalloc = os.environ.get("JEMALLOC_SO",
                              "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2")
    if Path(jemalloc).exists():
        prev = env.get("LD_PRELOAD", "")
        env["LD_PRELOAD"] = f"{jemalloc}:{prev}" if prev else jemalloc
    else:
        print(f"  [warn] JEMALLOC_SO={jemalloc} not found; reFuzz runs with "
              f"the system allocator", flush=True)
    # Per CLAUDE.md the D-arm reFuzz launch carries rarity prior alpha=8. Not
    # set for replay runs elsewhere (it steers scheduling), but this IS the
    # scheduling-on path.
    env.setdefault("REFUZZ_SEED_RARITY_PRIOR_ALPHA",
                   os.environ.get("RARITY_ALPHA", "8"))
    return env


def refuzz_short_root(out_dir: Path, run_id: int) -> Path:
    """Short per-output root for D-arm reFuzz sockets/logs under /tmp.

    The hash keeps concurrent or repeated speed_compare output directories from
    sharing /tmp/rfz_dNN, while staying short enough for Unix socket paths.
    """
    tag = zlib.crc32(str(out_dir).encode("utf-8")) & 0xffffffff
    return Path(f"/tmp/rfz_{tag:08x}_d{run_id:02d}")


def copy_if_exists(src: Path | None, dst: Path) -> Path | None:
    if src is None or not src.exists():
        return None
    mkdir(dst.parent)
    shutil.copyfile(src, dst)
    return dst


def decode_refuzz_coverage_hashes_bin(src: Path, dst: Path) -> int | None:
    """Decode reFuzz CoverageFile v2 to 0x<hex>/line.

    This is only a format decoder. Callers must decide whether the hashes are
    raw PCs or edge/hash signals from the run config before using the result in a
    PC-set comparison.
    """
    if not src.exists():
        return None
    data = src.read_bytes()
    if len(data) < CVSH_HEADER_SIZE:
        raise RuntimeError(f"{src}: truncated coverage file header")
    magic = int.from_bytes(data[0:4], "little")
    version = int.from_bytes(data[4:6], "little")
    flags = int.from_bytes(data[6:8], "little")
    count = int.from_bytes(data[8:16], "little")
    reserved = int.from_bytes(data[16:24], "little")
    if magic != CVSH_MAGIC or version != CVSH_VERSION_V2 or (flags & 1) == 0 or reserved != 0:
        raise RuntimeError(f"{src}: unsupported coverage file header")
    expect = CVSH_HEADER_SIZE + count * CVSH_ENTRY_V2_SIZE
    if len(data) != expect:
        raise RuntimeError(f"{src}: size mismatch, expected {expect}, got {len(data)}")
    mkdir(dst.parent)
    lines = []
    off = CVSH_HEADER_SIZE
    for _ in range(count):
        h = int.from_bytes(data[off:off + 8], "little")
        lines.append(f"0x{h:x}")
        off += CVSH_ENTRY_V2_SIZE
    dst.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return int(count)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _empty_cov_filter(cov: Any) -> bool:
    if not isinstance(cov, dict):
        return True
    return not (_string_list(cov.get("pcs")) or
                _string_list(cov.get("files")) or
                _string_list(cov.get("functions")))


def resolve_syz_filter_pc_path(args: argparse.Namespace, raw: str) -> Path:
    p = Path(raw)
    if p.is_absolute():
        return p.resolve()
    # syz-manager is launched with cwd=args.syzkaller_root, and upstream opens
    # RawPCs paths as-is. Fall back to config-dir resolution for local reports.
    for cand in (args.syzkaller_root / p, args.syz_config.parent / p):
        if cand.exists():
            return cand.resolve()
    return (args.syzkaller_root / p).resolve()


def syz_config_pc_filters(args: argparse.Namespace) -> tuple[list[Path], list[str]]:
    """Return PC allow-list files used as the offline comparison domain.

    This does not claim that reFuzz and syzkaller have identical runtime fuzzing
    behavior. It only constrains exported PC-set comparisons to the same PC
    membership domain. Only `pcs` files are usable here; `files`/`functions`
    require syzkaller's report-generator expansion.
    """
    try:
        cfg = load_json(args.syz_config)
    except OSError as exc:
        return [], [f"could not read syz config for PC filters: {exc}"]

    paths: list[Path] = []
    warnings: list[str] = []

    def add_cov_filter(cov: Any, where: str) -> None:
        if not isinstance(cov, dict) or _empty_cov_filter(cov):
            return
        if _string_list(cov.get("files")) or _string_list(cov.get("functions")):
            warnings.append(
                f"{where} uses files/functions; cannot mirror syzkaller's expanded PC filter "
                "offline. Pass --filter-pcs with an exported PC allow-list for filtered PC-set "
                "Jaccard.")
            return
        for raw in _string_list(cov.get("pcs")):
            paths.append(resolve_syz_filter_pc_path(args, raw))

    add_cov_filter(cfg.get("cover_filter"), "cover_filter")

    experimental = cfg.get("experimental")
    if not isinstance(experimental, dict):
        experimental = cfg.get("Experimental")
    focus_areas = experimental.get("focus_areas") if isinstance(experimental, dict) else None
    if isinstance(focus_areas, list):
        for idx, area in enumerate(focus_areas):
            filt = area.get("filter") if isinstance(area, dict) else None
            if _empty_cov_filter(filt):
                continue
            add_cov_filter(filt, f"experimental.focus_areas[{idx}].filter")

    seen: set[Path] = set()
    uniq: list[Path] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq, warnings


def configure_pc_filters(args: argparse.Namespace) -> None:
    explicit = list(getattr(args, "filter_pcs", []) or [])
    auto, warnings = ([], []) if args.no_auto_filter_pcs else syz_config_pc_filters(args)
    effective = explicit if explicit else auto
    args.effective_filter_pcs = effective
    args.pc_filter_warnings = warnings
    write_json(args.out_dir / "pc_filter_manifest.json", {
        "explicit_filter_pcs": [str(p) for p in explicit],
        "auto_filter_pcs": [str(p) for p in auto],
        "auto_filter_pcs_disabled": bool(args.no_auto_filter_pcs),
        "effective_filter_pcs": [str(p) for p in effective],
        "warnings": warnings,
        "note": "PC-set Jaccard is cropped offline to these PC allow-list files. "
                "This is a comparison-domain filter, not a claim about identical runtime fuzzing behavior.",
    })
    if effective:
        missing = [p for p in effective if not p.exists()]
        if missing:
            raise SystemExit("PC filter file(s) not found: " + ", ".join(str(p) for p in missing))
        print("pc-set filter: " + ", ".join(str(p) for p in effective), flush=True)
    for msg in warnings:
        print(f"pc-set filter warning: {msg}", flush=True)


def refuzz_coverage_mode(cfg: dict[str, Any]) -> dict[str, Any]:
    kcov = cfg.get("coverage", {}).get("kcov", {})
    if not isinstance(kcov, dict):
        kcov = {}
    raw_pc = bool(kcov.get("raw_pc", True))
    cover_edges = bool(kcov.get("cover_edges", False))
    return {
        "raw_pc": raw_pc,
        "cover_edges": cover_edges,
        "admission_unit": "edge" if cover_edges else ("raw_pc" if raw_pc else "hashed_pc"),
        "global_store_unit": "edge_bitmap" if cover_edges else ("raw_pc" if raw_pc else "hashed_pc"),
        "corpus_pc_unit": "raw_pc",
    }


def refuzz_run_config_path(args: argparse.Namespace, run_id: int) -> Path:
    return args.out_dir / f"D_refuzz_run_{run_id:02d}" / "refuzz_config.json"


def refuzz_run_coverage_mode(args: argparse.Namespace, run_id: int) -> dict[str, Any]:
    cfg_path = refuzz_run_config_path(args, run_id)
    if cfg_path.exists():
        return refuzz_coverage_mode(load_json(cfg_path))
    return refuzz_coverage_mode(load_json(args.refuzz_config))


def write_coverage_domain_manifest(args: argparse.Namespace, run_id: int,
                                   extra: dict[str, Any] | None = None) -> None:
    run_dir = args.out_dir / f"D_refuzz_run_{run_id:02d}"
    mode = refuzz_run_coverage_mode(args, run_id)
    manifest: dict[str, Any] = {
        "run": run_id,
        "pc_set_comparison_domain": {
            "filter_pcs": [str(p) for p in getattr(args, "effective_filter_pcs", []) or []],
            "note": "Offline allow-list cropping only; no reFuzz runtime filtering is implied.",
        },
        "domains": {
            "corpus_pc": {
                "status": "available_if_artifacts_exist",
                "refuzz_artifact": str(run_dir / "corpus_pc.txt"),
                "syz_artifact": str(args.out_dir / f"D_syz_run_{run_id:02d}" / "syz_pcs.txt"),
                "unit": "raw PC set for corpus-admitted programs",
                "normalization": "pc_set_compare subtracts --instr-len from reFuzz PCs",
            },
            "raw_all_pc": {
                "status": "unavailable",
                "unit": "raw PC set over all successful executions",
                "reason": "syzkaller exports max signal as a signal set/count, not a raw all-PC set in this script.",
            },
            "edge": {
                "status": "unavailable",
                "unit": "edge/signal set",
                "reason": "reFuzz and syzkaller edge signal sets are not both exported as comparable artifacts here.",
            },
        },
        "refuzz_mode": mode,
    }
    if extra:
        for key, value in extra.items():
            if key == "domains" and isinstance(value, dict):
                for dkey, dval in value.items():
                    if isinstance(dval, dict) and isinstance(manifest["domains"].get(dkey), dict):
                        manifest["domains"][dkey].update(dval)
                    else:
                        manifest["domains"][dkey] = dval
            else:
                manifest[key] = value
    write_json(run_dir / "coverage_domain_manifest.json", manifest)


def prepare_vm_images(args: argparse.Namespace, base: dict[str, Any],
                      out_dir: Path) -> tuple[Path | None, Path | None]:
    """One base rootfs image → an INDEPENDENT copy per side (reFuzz / syz), kept
    in a FIXED cache dir and REUSED across invocations.

    Both sides boot QEMU on the same kernel/rootfs *bits*, but each gets its own
    copy of the writable disk so the two never share a writable image (no qemu
    image lock, writeback, or temp-state cross-talk between sides). Only the path
    differs; contents are identical (same base). snapshot=True (enforced in the
    config builders) keeps each copy pristine, so the cache is reused run-to-run
    — the per-run timestamped dir holds ONLY results, never multi-GB images.

    Cache dir defaults to <out-dir>/../images (i.e. run/speed_compare/images),
    overridable via --image-cache-dir. A copy is (re)made only when the base
    image changed (path/size/mtime marker) or the cached file is missing.
    Uses `cp --reflink=auto` (instant + space-cheap on CoW filesystems)."""
    base_image = str(nested(base, "channel", "vm").get("image", ""))
    if not base_image or not Path(base_image).exists():
        raise SystemExit(f"base config channel.vm.image missing/not found: {base_image!r}")
    cache_dir = args.image_cache_dir.resolve() if args.image_cache_dir else (out_dir.parent / "images")
    mkdir(cache_dir)
    suffix = Path(base_image).suffix or ".img"

    # Per-side copy policy — simple + NON-DESTRUCTIVE:
    #   * copy already exists → USE IT (never delete, never re-copy).
    #   * copy missing        → copy once from the master base image.
    #   * base == the copy itself → refuse (config error: base must be the
    #                               original master, not a per-side copy).
    # Existence is the only gate; no freshness marker, no unlink-before-copy
    # (the old marker+unlink logic could delete an existing image and then
    # fail the copy, destroying it — see incident).
    def copy_for(tag: str) -> Path:
        dst = cache_dir / f"{tag}_rootfs{suffix}"
        if dst.exists():
            print(f"vm images: reusing existing {dst}", flush=True)
            return dst
        if Path(base_image).resolve() == dst.resolve():
            raise SystemExit(
                f"base image points at the per-side copy itself ({base_image}); "
                f"set base config channel.vm.image to the original master image")
        run_checked(["cp", "--reflink=auto", "--sparse=always", base_image, str(dst)],
                    cwd=out_dir, log_path=out_dir / "vm_images.log")
        print(f"vm images: copied master -> {dst}", flush=True)
        return dst

    refuzz_img = copy_for("refuzz") if args.only in ("both", "refuzz") else None
    syz_img = copy_for("syz") if args.only in ("both", "syzkaller") else None
    print(f"vm images @ {cache_dir} (refuzz={refuzz_img.name if refuzz_img else '-'}, "
          f"syz={syz_img.name if syz_img else '-'})", flush=True)
    return refuzz_img, syz_img


# ---------------------------------------------------------------------------
# Config builders (ported / adapted).
# ---------------------------------------------------------------------------
def make_refuzz_config(args: argparse.Namespace, base: dict[str, Any], run_dir: Path,
                       run_id: int, seed_corpus_dir: Path | None) -> Path:
    """Per-run reFuzz D config = the FIXED config (--refuzz-config, in
    run/speed_compare/configs/) parsed verbatim, with ONLY the per-run fields
    replaced. All behavioural params (image/target/coverage/sandbox/fuzzer/
    telemetry/...) come from the fixed config and are NOT re-set here — to
    change one, edit the fixed config. Mirrors make_syz_manager_config.

    Per-run replacements (the only things that can't be static):
      - work_dir + ivshmem/doorbell sockets → SHORT /tmp paths (Unix socket
        path must be < 108 bytes; the deep out_dir overflows it) + per-run unique
      - persistence.corpus.dir → this run's cloned warm-start corpus
      - phase1 run limit → this run's measured duration
    """
    cfg = load_json(args.refuzz_config)

    short_root = refuzz_short_root(args.out_dir, run_id)
    if short_root.exists():
        shutil.rmtree(short_root)
    work_dir = short_root / "work"
    ipc_dir = short_root / "ipc"
    mkdir(work_dir)
    mkdir(ipc_dir)
    cfg["work_dir"] = str(work_dir)

    transport = nested(cfg, "channel", "transport")
    transport["ivshmem_path"] = str(ipc_dir / "refuzz.ivshmem")
    transport["doorbell_socket_path"] = str(ipc_dir / "refuzz.sock")

    cfg["phase1_run_limit_mode"] = "runtime"
    cfg["phase1_runtime_seconds"] = args.start_timeout + args.warmup + args.duration + 30

    corpus_persist = nested(cfg, "persistence", "corpus")
    if seed_corpus_dir is not None:
        corpus_persist["enable"] = True
        corpus_persist["dir"] = str(seed_corpus_dir)
        corpus_persist["load_on_start"] = True
    else:
        corpus_persist["load_on_start"] = False

    # [RTT trace, coarse comparison phase] task_trace_sample_rate lives under
    # telemetry.logging (see control/orchestrator/include/refuzz/orchestrator/
    # orchestrator_config.hpp HostLoggingConfig) -- the base config already
    # has telemetry.logging.enable=true, so nothing else needs setting here.
    # logging.path is deliberately left unset: orchestrator_config.cpp
    # defaults it to <session_root>/logs/host_events.txt, which is exactly
    # where the existing host_events.txt discovery (newest_host_events /
    # parse_refuzz_snapshots below) already looks -- task_trace lines land in
    # the SAME file as everything else HostLogger writes, tagged
    # comp=FuzzerLoop\tevt=task_trace, filtered out by parse_refuzz_task_trace.
    if args.rtt_trace_sample_rate > 0:
        nested(cfg, "telemetry", "logging")["task_trace_sample_rate"] = args.rtt_trace_sample_rate

    # [fixed request stream] reFuzz-side mirror of --syz-request-stream. Injected
    # here, into the config speed_compare materialises anyway, for the same reason
    # syz-manager gets -request-stream as a manager ARGUMENT: capture must be a
    # driver-level switch over the SAME base config every other run uses. A
    # hand-forked capture config was tried first and silently diverged from the
    # baseline (it lost task_trace_sample_rate, which is injected right above and
    # was never meant to come from the config file at all), producing a capture
    # run that carried no per-program durations and was not comparable to
    # anything. One config, one switch.
    if getattr(args, "refuzz_request_stream", None) is not None:
        nested(cfg, "fuzzer")["request_stream_capture_path"] = str(args.refuzz_request_stream)

    # [corpus-pc-export] D PC-set: orchestrator dumps the corpus-admitted PC set (raw
    # KCOV PC, sorted) to this path on Stop() — read directly by run_pc_set_compare_d,
    # NO grown-corpus replay. Per-run under the short /tmp root.
    nested(cfg, "coverage", "export")["corpus_pc_path"] = str(short_root / "corpus_pc.txt")
    if getattr(args, "coverage_domains", False):
        # [coverage-compare] edge / all-exec dumps. Default kernel profile has
        # cover_edges=true → corpus_signal/all_signal are EDGE sets (corpus-edge /
        # all-edge domains). Gated: all_signal is a per-exec feed, so it is enabled
        # only for coverage-focused runs, never the default throughput path.
        nested(cfg, "coverage", "export")["corpus_signal_path"] = str(short_root / "corpus_signal.txt")
        nested(cfg, "coverage", "export")["all_signal_path"] = str(short_root / "all_signal.txt")
        # [edge-over-time] enable the dedicated corpus-EDGE time-series. reFuzz
        # writes it to its own coverage_edge_series.log in the logs directory,
        # providing a 10-second time axis against syz bench "signal".
        nested(cfg, "coverage", "export")["edge_series_enabled"] = True
    nested(cfg, "coverage", "kcov")["output_dir"] = str(short_root / "coverage")

    path = run_dir / "refuzz_config.json"
    write_json(path, cfg)
    return path


# archConfigs["linux/amd64"].QemuArgs in vm/qemu/qemu.go. Restated here because a
# qemu_args in the manager config replaces that default rather than extending it
# -- see make_syz_manager_config().
SYZ_QEMU_ARGS_AMD64_DEFAULT = "-enable-kvm -cpu host,migratable=off"


def syz_perf_serial(run_dir: Path) -> Path:
    """Host file QEMU writes the guest's second serial (ttyS1) into -- syz's
    first-layer perf channel, the counterpart of reFuzz's vm-*/serial.log. Written
    by loop() in executor/common.h; wired up in make_syz_manager_config()."""
    return run_dir / "syz_perf_serial.log"


def make_syz_manager_config(args: argparse.Namespace, run_dir: Path,
                            run_id: int) -> tuple[Path, list[str]]:
    """Per-run syz-manager config for arm D.

    The user's --syz-config (run/speed_compare/configs/syz.json) is used VERBATIM
    — image, kernel, ssh, vm, procs, sandbox, cover, etc. exactly as written. This
    injects ONLY the per-run essentials that cannot live statically in the shared
    template:

      - workdir → <run_dir>/work, so each run's manager state is isolated
      - http    → per-run port, so concurrent/sequential runs never collide
      - disable_syscalls → pseudo-policy parity (only if non-empty)

    D fuzzes from an empty workdir (preserve_corpus=False); every other field stays
    exactly as the user wrote it."""
    cfg = load_json(args.syz_config)
    work_dir = run_dir / "work"
    mkdir(work_dir)

    disable_syscalls = syzkaller_disabled_syscalls(args)
    cfg["workdir"] = str(work_dir)
    cfg["http"] = f"127.0.0.1:{args.http_port_base + run_id}"
    cfg["preserve_corpus"] = False
    if disable_syscalls:
        cfg["disable_syscalls"] = disable_syscalls

    # Second serial = the executor's first-layer perf channel (see loop() in
    # executor/common.h). qemu's own args already contain `-serial stdio` and
    # QemuArgs is appended after them, so this one becomes the guest's ttyS1 and
    # ttyS0 stays the console syz-manager parses for crashes -- perf lines can
    # never reach the crash stream. QEMU writes ttyS1 straight into this file,
    # which is what gives us something to parse (syz's console goes to the
    # manager, not to disk).
    #
    # syzkaller seeds cfg.QemuArgs from the arch default and then unmarshals the
    # JSON over it (vm/qemu/qemu.go ctor), so setting qemu_args REPLACES the
    # default instead of extending it. Losing -enable-kvm that way would silently
    # drop the VM to TCG and make every timing in this comparison meaningless, so
    # restate the default and assert it survived.
    vm_cfg = cfg.setdefault("vm", {})
    raw_qemu_args = vm_cfg.get("qemu_args")
    if raw_qemu_args:
        # <run_dir> is the one placeholder honored here, so a static shared config
        # can still point qemu at THIS run's private syz_perf_serial.log.
        base_qemu_args = str(raw_qemu_args).replace("<run_dir>", str(run_dir))
    else:
        base_qemu_args = SYZ_QEMU_ARGS_AMD64_DEFAULT
    # Wire the guest's ttyS1 perf serial into this file -- but only if the config
    # hasn't already done it. A config that sets up its own serial to
    # syz_perf_serial.log (e.g. `-chardev file,...,append=on -serial chardev:...`
    # to survive VM reboots without truncating) must NOT also get a truncating
    # `-serial file:` bolted on, or the two serials fight over the same file.
    #
    # SYZ_PERF_SERIAL=0 skips the injection entirely: the guest has no ttyS1,
    # executor's perf_fd stays -1 and every sampling hook no-ops. This is the
    # per-run sampling switch (coverage runs off, perf runs on); the executor
    # itself gates collection/output on perf_fd >= 0.
    #
    # 关闭时显式回到无 perf 串口的默认参数，而不是只"不追加"：基线配置
    # run/speed_compare/configs/syz_6proc.json 自带
    # `-chardev file,...syz_perf_serial.log,append=on -serial chardev:tlchr`，
    # 若只跳过追加，这条串口仍在，ttyS1 照样存在、采样照样开，开关就失效了。
    perf_path = str(syz_perf_serial(run_dir))
    perf_enabled = os.environ.get("SYZ_PERF_SERIAL", "1") != "0"
    if not perf_enabled:
        vm_cfg["qemu_args"] = SYZ_QEMU_ARGS_AMD64_DEFAULT
    elif perf_path in base_qemu_args:
        vm_cfg["qemu_args"] = base_qemu_args
    else:
        vm_cfg["qemu_args"] = f"{base_qemu_args} -serial file:{perf_path}"
    if "-enable-kvm" not in vm_cfg["qemu_args"]:
        raise RuntimeError(
            f"syz qemu_args lost -enable-kvm: {vm_cfg['qemu_args']!r}; "
            "the VM would fall back to TCG and every timing would be garbage")

    path = run_dir / "syzkaller_config.json"
    write_json(path, cfg)
    write_lines(run_dir / "syzkaller_disable_syscalls.txt", disable_syscalls)
    return path, disable_syscalls


# ---------------------------------------------------------------------------
# Standalone reFuzz decode-ability test (--check-decode). NOT part of a run.
# ---------------------------------------------------------------------------
def run_decode_check(args: argparse.Namespace, prep_all: CorpusPrep) -> bool:
    """Decode the FULL (unfiltered) corpus with reFuzz's own decoder via
    `refuzz-exec-replayer -decode-check` (no VM) and report any program reFuzz
    can't decode/encode. Returns True iff all decode+encode. A failure is a
    reFuzz decoder bug to investigate — we deliberately do NOT drop such programs
    before a run; execution stays direct and a real run flags them via
    corpus_decode_failed/encode_failed."""
    replayer = args.refuzz_build_dir / "refuzz-exec-replayer"
    out_json = args.out_dir / "decode_check.json"
    log_path = args.out_dir / "decode_check.log"
    cmd = [str(replayer), "-decode-check", "-corpus-dir", str(prep_all.refuzz_dir),
           "-stats-out", str(out_json)]
    print(f"decode-check: running reFuzz decoder over the full corpus "
          f"({prep_all.manifest.get('num_programs', '?')} programs) …", flush=True)
    with log_path.open("ab") as log:
        log.write(("+ " + " ".join(cmd) + "\n").encode())
        log.flush()
        rc = subprocess.run(cmd, cwd=args.refuzz_root, stdout=log,
                            stderr=subprocess.STDOUT).returncode
    if not out_json.exists():
        print(f"decode-check: replayer wrote no report (rc={rc}); see {log_path}", flush=True)
        return False
    s = load_json(out_json)
    print(f"decode-check: found={s.get('found')} decoded_ok={s.get('decoded_ok')} "
          f"decode_failed={s.get('decode_failed')} encode_failed={s.get('encode_failed')}",
          flush=True)
    # Stage-2 output: PASS = nothing emitted; on failure a single failure list
    # (seed_id, file, stage, error). No per-normal-program JSON / labels.
    rows = ["seed_id,file,stage,error"]
    for p in s.get("decode_failed_paths", []):  # "<016x seed-id>: <error>"
        sid, _, err = p.partition(": ")
        rows.append(f"{sid},refuzz/{sid}/payload.bin,decode,{err}")
        print(f"  DECODE FAIL {p}", flush=True)
    for sid in s.get("encode_failed_paths", []):
        rows.append(f"{sid},refuzz/{sid}/payload.bin,encode,serialize_for_exec rejected")
        print(f"  ENCODE FAIL {sid} (serialize_for_exec rejected)", flush=True)
    if len(rows) > 1:
        fail_csv = args.out_dir / "decode_failures.csv"
        write_lines(fail_csv, rows)
        print(f"decode-check: FAILURES list → {fail_csv}", flush=True)
    print(f"decode-check report → {out_json}", flush=True)
    return bool(s.get("all_ok", False))


# ---------------------------------------------------------------------------
# Result row.
# ---------------------------------------------------------------------------
@dataclass
class Row:
    arm: str
    tool: str
    run: int
    status: str
    programs_per_sec: float = 0.0
    syz_calls_per_sec: float = 0.0           # executed syscalls/sec
    syz_calls_per_sec_nominal: float = 0.0   # auxiliary
    executed_syz_calls: int = 0
    nominal_syz_calls: int = 0
    completed: int = 0
    wall_s: float = 0.0
    timeout_or_hang_rate: str = ""
    abnormal_rate: str = ""
    # arm-C cover liveness gate
    cover_entries: str = ""
    cover_decode_failed: str = ""
    calls_with_cover: str = ""
    # corpus order-parity (B/C reFuzz side)
    corpus_decode_failed: str = ""
    corpus_encode_failed: str = ""
    measurement_mode: str = ""
    config: str = ""
    artifact: str = ""
    log: str = ""
    error: str = ""


CSV_FIELDS = [f.name for f in dataclass_fields(Row)]


def append_csv(path: Path, row: Row) -> None:
    mkdir(path.parent)
    first = not path.exists()
    with path.open("a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if first:
            writer.writeheader()
        writer.writerow({k: getattr(row, k) for k in CSV_FIELDS})


def rate(num: float, denom: float) -> float:
    return num / denom if denom > 0 else 0.0


# ---------------------------------------------------------------------------
# Arm spec. Only the full-loop arm D remains; the B/C corpus-replay arms were
# removed — host-replay throughput proved not meaningful next to the full fuzz
# loop (D), so B/C are gone along with their runners/config builders.
# ---------------------------------------------------------------------------
@dataclass
class ArmSpec:
    name: str


ARMS: dict[str, ArmSpec] = {
    "D": ArmSpec("D"),
}
def nominal_calls_for_completed(per_program_calls: list[int], completed: int) -> int:
    """Σ .syz call lines over the first `completed` programs of the deterministic
    pos%N loop (full loops × total + exact tail). Auxiliary metric only."""
    n = len(per_program_calls)
    if n == 0 or completed <= 0:
        return 0
    total = sum(per_program_calls)
    full_loops, tail = divmod(completed, n)
    return full_loops * total + sum(per_program_calls[:tail])


# ---------------------------------------------------------------------------
# Arm D — full fuzz loop (ported steady-state / metrics machinery).
# ---------------------------------------------------------------------------
PROM_METRIC_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{[^}]*\})?\s+([0-9.eE+-]+)$")
REFUZZ_SNAPSHOT_TS_RE = re.compile(r"\[(?:RuntimePanel|ShutdownPanel)\] snapshot ts_us=(?P<ts>\d+)")
REFUZZ_TERMINAL_RE = re.compile(r"\bterminal=(?P<terminal>\d+)\b")
REFUZZ_EXEC_ERROR_RE = re.compile(r"\bexec_error=(?P<exec_error>\d+)\b")
REFUZZ_HARNESS_FATAL_RE = re.compile(r"\bharness_fatal=(?P<harness_fatal>\d+)\b")
# [speed-compare arm D] real executed-syscall counter (fuzzer.calls.executed),
# symmetric with syz_exec_calls_total — added to the runtime_panel for D.
REFUZZ_EXEC_CALLS_RE = re.compile(r"\bexec_calls=(?P<exec_calls>\d+)\b")


# ---------------------------------------------------------------------------
# RTT trace comparison (--rtt-trace-sample-rate). Both tools normalize to the
# same task handoff, transport, execution-response, and feedback boundaries.
# _rank_for is shared by both parsers so they use one percentile convention.
#
# Normalized row schema (both parsers produce this), matching the E1..E9
# contract in docs/plans/rtt-zone-measurement.md:
#   enqueued_us             E1 -- task entered the executable request queue
#   dequeued_us             E2 -- dispatcher pulled the task
#   prep_done_us            E3 -- request preparation finished
#   transport_start_us      E4 -- request transport started
#   guest_visible_us        E5 -- request became visible in the guest
#   claimed_us              E6 -- guest execution unit claimed the task
#   completion_observed_us  E7 -- host observed completion, before result copy
#   payload_available_us    E8 -- result payload is available in host memory
#   feedback_done_us        E9 -- feedback processing completed
#   final       -- True iff this row is the attempt that finalized the task
#   retry_count -- 0-based retry count (>0 means retried); see each parser's
#                  own comment for how it's derived per tool
# ---------------------------------------------------------------------------
# These adjacent intervals tile E1->E9. Every interval has one fixed zone for
# both tools; implementation differences appear as different durations, not as
# tool-specific labels.
RTT_SUBINTERVALS = (
    ("queue_wait",     "enqueued_us",            "dequeued_us"),
    ("dispatch_prep",  "dequeued_us",            "prep_done_us"),
    ("dispatch_wait",  "prep_done_us",           "transport_start_us"),
    ("transport_out",  "transport_start_us",     "guest_visible_us"),
    ("slot_wait",      "guest_visible_us",       "claimed_us"),
    ("execute",        "claimed_us",             "completion_observed_us"),
    ("result_copy",    "completion_observed_us", "payload_available_us"),
    ("feedback",       "payload_available_us",   "feedback_done_us"),
    ("total",          "enqueued_us",            "feedback_done_us"),
)

RTT_ZONE = {
    "queue_wait": "queue",
    "dispatch_prep": "orch",
    "dispatch_wait": "queue",
    "transport_out": "transport",
    "slot_wait": "queue",
    "execute": "exec",
    "result_copy": "transport",
    "feedback": "orch",
    "total": None,
}
SERVICE_ZONES = ("transport", "orch", "exec")


def parse_syz_task_trace(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        # E5 is derived from E6 and the guest-reported E5->E6 duration. An old
        # trace without slot_wait_us cannot locate E5; leave it unset instead of
        # assigning E4 or E6 and silently moving time between transport/queue.
        sent_us = int(row.get("sent_us") or 0)
        executing_us = int(row.get("executing_us") or 0)
        sw_raw = row.get("slot_wait_us")
        if sw_raw is None:
            guest_visible_us = 0
        else:
            guest_visible_us = executing_us - int(sw_raw or 0)
            if guest_visible_us < sent_us:
                guest_visible_us = 0
        out.append({
            "enqueued_us": int(row.get("enqueued_us") or 0),
            "dequeued_us": int(row.get("dequeued_us") or 0),
            # Syzkaller assembles the message and immediately calls Send, so
            # E3 and E4 intentionally share SentUs.
            "prep_done_us": sent_us,
            "transport_start_us": sent_us,
            "guest_visible_us": guest_visible_us,
            "claimed_us": executing_us,
            "completion_observed_us": int(row.get("completion_observed_us") or 0),
            "payload_available_us": int(row.get("result_received_us") or 0),
            "feedback_done_us": int(row.get("final_done_us") or 0),
            "attempt_result_us": int(row.get("attempt_result_us") or 0),
            # syzkaller's final has real meaning: False means this attempt's
            # result was discarded and a retry was triggered (see
            # fuzzer.processResult's candidate-retry path) -- excluded from
            # the clean distribution below.
            "final": bool(row.get("final", False)),
            # Read directly from the JSONL's own retry_count field -- do NOT
            # derive from "attempt" (max(0, attempt-1)): attempt only
            # increments in handleExecResult, so it silently misses
            # VM-crash/restart retries, which bypass handleExecResult
            # entirely (Runner.Shutdown() calls Request.Done() directly).
            # retry_count is incremented on BOTH retry paths (prepare() and
            # retryer.resubmit() -- see pkg/fuzzer/queue/queue.go), so it's
            # the only complete signal. "attempt" is kept in the JSONL for
            # diagnostics only, not read here.
            "retry_count": int(row.get("retry_count") or 0),
            # Fork-inclusive executor service duration. reFuzz feeds its
            # same-clock worker_done-worker_start duration into the same field.
            "service_us": int(row.get("elapsed_us") or 0),
        })
    return out


# reFuzz's HostLogger lines are tab-separated key=value tokens (values are
# already TextEscape()'d by HostLogger, so a raw tab can never appear inside
# one -- see logging/src/host_logger.cpp Serialize()), so a single
# key=<non-tab>* pattern safely tokenizes a whole line via findall().
REFUZZ_TASK_TRACE_FIELD_RE = re.compile(r"([a-zA-Z0-9_]+)=([^\t\n]*)")


def parse_refuzz_task_trace(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in lines:
        if "evt=task_trace" not in line:
            continue
        fields = dict(REFUZZ_TASK_TRACE_FIELD_RE.findall(line))

        def gi(key: str, fields: dict[str, str] = fields) -> int:
            try:
                return int(fields.get(key, "0") or "0")
            except ValueError:
                return 0

        # worker_start/done use the guest clock and may only be subtracted
        # from each other. All other normalized fields use the host clock.
        worker_start = gi("worker_start_ts_us")
        worker_done = gi("worker_done_ts_us")
        worker_clock_guest = fields.get("worker_clock_guest") == "1"
        service_us = 0
        if worker_clock_guest and worker_start > 0 and worker_done > 0 and worker_done >= worker_start:
            service_us = worker_done - worker_start
        out.append({
            "enqueued_us": gi("task_queue_push_ts_us"),
            "dequeued_us": gi("task_queue_pop_ts_us"),
            "prep_done_us": gi("dispatch_prep_done_ts_us"),
            "transport_start_us": gi("data_plane_call_ts_us"),
            # In the ivshmem path poll-return and CAS claim are one semantic
            # edge, so E5 and E6 intentionally share the host start-ack stamp.
            "guest_visible_us": gi("worker_start_ack_host_ts_us"),
            "claimed_us": gi("worker_start_ack_host_ts_us"),
            "completion_observed_us": gi("completion_observed_host_ts_us"),
            "payload_available_us": gi("output_copied_host_ts_us"),
            "feedback_done_us": gi("fuzzer_feedback_processed_ts_us"),
            "channel_event_queued_us": gi("channel_event_queued_ts_us"),
            "final": True,
            "retry_count": gi("submit_attempt"),
            "service_us": service_us,
        })
    return out


def refuzz_task_trace_rows(work_dir: Path) -> list[dict[str, Any]]:
    host_events = newest_host_events(work_dir)
    if host_events is None:
        return []
    return parse_refuzz_task_trace(host_events)


def refuzz_serial_logs(work_dir: Path) -> list[Path]:
    """Guest worker-diagnostic logs of the newest session.

    Preferred: <work_dir>/run-*/vm-<i>/worker.log -- the dedicated second
    serial (guest ttyS1), carrying only [WORKER]-prefixed lines. Falls back to
    serial.log (ttyS0, the kernel console) for runs recorded before that serial
    existed, where the same lines were interleaved with kernel printk.

    That interleaving is exactly why the second serial was added: on ttyS0 a
    printk can land mid-line and truncate a diagnostic record, and programs that
    trigger more kernel logging lose more lines -- a program-type-correlated
    sampling bias, not uniform loss. Newest-run selection mirrors
    newest_host_events().
    """
    runs = sorted(work_dir.glob("run-*"), key=lambda p: p.stat().st_mtime)
    if not runs:
        return []
    logs = sorted(runs[-1].glob("vm-*/worker.log"))
    if logs:
        return logs
    return sorted(runs[-1].glob("vm-*/serial.log"))


# [WorkerPerfStage] wid=0 scope=loop relation=exclusive stage=prepare n=128
#   avg_us=1234 p50_us=1000 p95_us=2000 max_us=5000 share=12.34%
# reFuzz emits [WorkerPerfStage] from ReportTiming() in
# executor/channel/worker/src/perf/worker_perf.cpp; syz emits [SyzPerfStage] from
# loop() in executor/common.h with the same leading fields -- deliberately, so one
# parser serves both tools. Only wid/scope/stage/n/avg_us are read: a per-worker
# `share` cannot be averaged across workers, so shares are recomputed below from
# n-weighted totals.
PERF_STAGE_MARKERS = ("[WorkerPerfStage]", "[SyzPerfStage]")
PERF_STAGE_RE = re.compile(
    r"\[(?:WorkerPerfStage|SyzPerfStage)\]\s+wid=(?P<wid>\d+)\s+scope=(?P<scope>\S+)\s+"
    r"relation=\S+\s+stage=(?P<stage>\S+)\s+n=(?P<n>\d+)\s+avg_us=(?P<avg_us>\d+)\b")

# scope=loop exclusive phases in execution order (worker perf README):
# loop.total = prepare + executor + delivery + cleanup, and the blocking wait for
# the next request is excluded from total -- an idle queue is never charged as
# execution cost.
WORKER_PERF_LOOP_STAGES = ("prepare", "executor", "delivery", "cleanup")
# `executor` (fork + syscalls + reap) is the execution unit both fuzzers inherit
# from syzkaller; the other three are what this execution model spends around it.
WORKER_PERF_MODEL_STAGES = ("prepare", "delivery", "cleanup")


def _parse_perf_loop_logs(logs: list[Path]) -> dict[str, Any] | None:
    """Fold `scope=loop` stage lines from any number of logs into one n-weighted
    breakdown -- shared core of parse_worker_perf_loop()/parse_syz_perf_loop().

    This opens up the RTT EXEC zone, which otherwise only says "the guest spent N ms
    on this program". The first layer is what the fork-server parent actually does
    per program: prepare (workdir + reset loop device), executor (fork+syscall+reap),
    delivery (write the result out), cleanup (workdir reclaim). Only `executor` is
    the execution unit both fuzzers share, so the other three are the
    execution-model overhead this comparison is about. Neither tool's deeper scopes
    are read: they dissect the syscall execution itself, which is the same
    machinery in both and would only drag in the workload's variance.

    Reports are CUMULATIVE, not windowed, in both tools -- every line is a "since
    this worker started" snapshot. So the last line per (log, wid, stage) already
    covers the whole run and summing lines would multiply-count. Workers, procs and
    VMs are combined n-weighted.
    """
    if not logs:
        return None
    # (log, wid, stage) -> (n, avg_us) from the last cumulative snapshot. Keyed by
    # log as well: wid restarts at 0 in each VM, so a bare wid collides across VMs.
    last: dict[tuple[str, str, str], tuple[int, int]] = {}
    for path in logs:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if not any(marker in line for marker in PERF_STAGE_MARKERS):
                continue
            m = PERF_STAGE_RE.search(line)
            if m is None or m.group("scope") != "loop":
                continue
            last[(str(path), m.group("wid"), m.group("stage"))] = (
                int(m.group("n")), int(m.group("avg_us")))
    if not last:
        return None

    totals: dict[str, dict[str, int]] = {}
    for (_log, _wid, stage), (n, avg_us) in last.items():
        acc = totals.setdefault(stage, {"n": 0, "total_us": 0})
        acc["n"] += n
        acc["total_us"] += n * avg_us

    def _total_us(stage: str) -> int:
        return totals.get(stage, {}).get("total_us", 0)

    def _mean_ms(stage: str) -> float:
        acc = totals.get(stage)
        if not acc or acc["n"] == 0:
            return 0.0
        return acc["total_us"] / acc["n"] / 1000.0

    # Denominator: the reported loop total, falling back to the four phases.
    denom_us = _total_us("total") or sum(_total_us(s) for s in WORKER_PERF_LOOP_STAGES)
    out: dict[str, Any] = {
        "serial_logs": len(logs),
        "samples": max((totals.get(s, {}).get("n", 0)
                        for s in WORKER_PERF_LOOP_STAGES), default=0),
        "loop_mean_ms": (_mean_ms("total") if "total" in totals
                         else sum(_mean_ms(s) for s in WORKER_PERF_LOOP_STAGES)),
        "stages": {},
    }
    for stage in WORKER_PERF_LOOP_STAGES:
        out["stages"][stage] = {
            "mean_ms": _mean_ms(stage),
            "share": (_total_us(stage) / denom_us) if denom_us else 0.0,
        }
    overhead_us = sum(_total_us(s) for s in WORKER_PERF_MODEL_STAGES)
    out["model_overhead_mean_ms"] = sum(_mean_ms(s) for s in WORKER_PERF_MODEL_STAGES)
    out["model_overhead_share"] = (overhead_us / denom_us) if denom_us else 0.0
    return out


def parse_worker_perf_loop(work_dir: Path) -> dict[str, Any] | None:
    """reFuzz's first layer, from the worker-perf lines its workers write to the
    guest console. Returns None when fuzzer.worker_perf.enable was off at run time.
    """
    return _parse_perf_loop_logs(refuzz_serial_logs(work_dir))


def parse_syz_perf_loop(run_dir: Path) -> dict[str, Any] | None:
    """syz's first layer, measured in loop() (executor/common.h) and written to the
    guest's second serial, which QEMU drops straight into this file -- the
    counterpart of reFuzz's vm-*/serial.log. Returns None for runs made before that
    instrumentation existed or without the second serial configured."""
    path = syz_perf_serial(run_dir)
    return _parse_perf_loop_logs([path] if path.exists() else [])


def _rank_for(count: int, percentile: int) -> int:
    """Nearest-rank percentile, 1-indexed into a sorted list."""
    if count == 0:
        return 0
    return max(1, (count * percentile + 99) // 100)


def _percentile(sorted_vals: list[Any], percentile: int) -> float:
    if not sorted_vals:
        return math.nan
    rank = _rank_for(len(sorted_vals), percentile)
    return float(sorted_vals[rank - 1])


def _us_percentile_ms(sorted_us: list[int], percentile: int) -> float:
    value = _percentile(sorted_us, percentile)
    return value / 1000.0 if not math.isnan(value) else math.nan


def compute_rtt_percentiles(rows: list[dict[str, Any]], tool: str = "refuzz") -> dict[str, Any]:
    """Two DIFFERENT views of the per-task cycle, answering two questions.

    * segments[name] p50/p95/p99  -- the LATENCY of each sub-interval (how slow,
      typical and tail). These are percentiles; they are NOT added together.
    * zones[z].share              -- the PROPORTION of service time each zone
      consumes, computed as sum(zone)/sum(service) over rows with a complete
      E1->E9 chain (== mean(zone)/mean(service)). This is the time-budget
      breakdown (Thunderkaller's "67.4%" style). It is a MEAN, NEVER a sum of
      p50s -- percentiles do not add (p95 of a sum != sum of p95s).

    Raw timestamps and durations stay in microseconds through aggregation. Only
    reported statistics are converted to milliseconds, preserving sub-ms costs.
    `tool` remains in the API for existing callers; interval classification is
    deliberately tool-independent.
    """
    rows_parsed = len(rows)
    retried = sum(1 for r in rows if r["retry_count"] > 0)
    clean = [r for r in rows if r["final"]]

    def dur_us(r: dict[str, Any], a_key: str, b_key: str) -> int | None:
        a, b = r.get(a_key, 0), r.get(b_key, 0)
        if a > 0 and b > 0 and b >= a:
            return b - a
        return None

    # ---- View 1: per-sub-interval latency (p50/p95/p99) + mean ----
    segments: dict[str, dict[str, float]] = {}
    for name, a_key, b_key in RTT_SUBINTERVALS:
        vals_us = sorted(d for r in clean
                         for d in (dur_us(r, a_key, b_key),) if d is not None)
        segments[name] = {
            "samples": len(vals_us),
            "p50_ms": _us_percentile_ms(vals_us, 50),
            "p95_ms": _us_percentile_ms(vals_us, 95),
            "p99_ms": _us_percentile_ms(vals_us, 99),
            "mean_ms": (sum(vals_us) / len(vals_us) / 1000.0) if vals_us else math.nan,
            "zone": RTT_ZONE.get(name) or "-",
        }

    # ---- View 2: mean-based zone proportion of service time ----
    # service = the three "working" zones (transport+orch+exec); queue excluded.
    # A row contributes only if every adjacent E1->E9 interval is valid. This
    # makes both service shares and queue_mean a conserved, full-chain account.
    bykey = {n: (a, b) for n, a, b in RTT_SUBINTERVALS}
    interval_names = [n for n, _, _ in RTT_SUBINTERVALS if n != "total"]
    service_names = [n for n in interval_names if RTT_ZONE.get(n) in SERVICE_ZONES]
    zone_us = {"queue": 0, "transport": 0, "orch": 0, "exec": 0}
    service_us_total = 0
    n_complete = 0
    row_share: dict[str, list[float]] = {z: [] for z in SERVICE_ZONES}
    for r in clean:
        interval_durs: dict[str, int] = {}
        for n in interval_names:
            d = dur_us(r, *bykey[n])
            if d is None:
                break
            interval_durs[n] = d
        if len(interval_durs) != len(interval_names):
            continue
        total = dur_us(r, *bykey["total"])
        if total is None or sum(interval_durs.values()) != total:
            continue
        svc = sum(interval_durs[n] for n in service_names)
        if svc <= 0:
            continue
        n_complete += 1
        service_us_total += svc
        for n, d in interval_durs.items():
            zone_us[RTT_ZONE[n]] += d
        per = {z: 0 for z in SERVICE_ZONES}
        for n in service_names:
            per[RTT_ZONE[n]] += interval_durs[n]
        for z in SERVICE_ZONES:
            row_share[z].append(per[z] / svc)

    zones: dict[str, Any] = {
        "complete_rows": n_complete,
        "service_mean_ms": (service_us_total / n_complete / 1000) if n_complete else math.nan,
        "queue_mean_ms": (zone_us["queue"] / n_complete / 1000) if n_complete else math.nan,
    }
    for z in SERVICE_ZONES:
        rs = sorted(row_share[z])
        zones[z] = {
            "mean_ms": (zone_us[z] / n_complete / 1000) if n_complete else math.nan,
            "share": (zone_us[z] / service_us_total) if service_us_total else math.nan,
            "row_share_p50": _percentile(rs, 50) if rs else math.nan,
            "row_share_p95": _percentile(rs, 95) if rs else math.nan,
        }

    service_vals_us = sorted(r["service_us"] for r in clean if r["service_us"] > 0)
    executor_service = {
        "samples": len(service_vals_us),
        "p50_ms": _us_percentile_ms(service_vals_us, 50),
        "p95_ms": _us_percentile_ms(service_vals_us, 95),
        "p99_ms": _us_percentile_ms(service_vals_us, 99),
    }
    return {
        # NOTE: named rows_parsed, not total_samples -- RTT_SUBINTERVALS includes
        # a sub-interval literally named "total", whose own "{seg}_samples" key
        # would collide with a top-level "total_samples" key in the flat CSV row.
        "rows_parsed": rows_parsed,
        "final_samples": len(clean),
        "retry_rate": (retried / rows_parsed) if rows_parsed else math.nan,
        "segments": segments,
        "zones": zones,
        "executor_service": executor_service,
    }


RTT_CSV_FIELDS = ["run", "tool", "rows_parsed", "final_samples", "retry_rate",
                  "programs_per_sec", "syz_calls_per_sec"]
for _seg, _a, _b in RTT_SUBINTERVALS:
    RTT_CSV_FIELDS += [f"{_seg}_samples", f"{_seg}_p50_ms", f"{_seg}_p95_ms",
                       f"{_seg}_p99_ms", f"{_seg}_mean_ms"]
RTT_CSV_FIELDS += ["complete_rows", "service_mean_ms", "queue_mean_ms"]
for _z in SERVICE_ZONES:
    RTT_CSV_FIELDS += [f"zone_{_z}_mean_ms", f"zone_{_z}_share",
                       f"zone_{_z}_rowshare_p50", f"zone_{_z}_rowshare_p95"]
RTT_CSV_FIELDS += ["executor_service_samples", "executor_service_p50_ms",
                   "executor_service_p95_ms", "executor_service_p99_ms"]
# EXEC first-layer split (reFuzz guest worker-perf scope=loop): splits the EXEC
# zone into the shared `executor` unit and this execution model's own overhead.
# Blank for syzkaller (no equivalent instrumentation) and for reFuzz runs made
# with fuzzer.worker_perf.enable=false.
RTT_CSV_FIELDS += ["exec_loop_samples", "exec_loop_mean_ms"]
for _st in WORKER_PERF_LOOP_STAGES:
    RTT_CSV_FIELDS += [f"exec_{_st}_mean_ms", f"exec_{_st}_share"]
RTT_CSV_FIELDS += ["exec_model_overhead_mean_ms", "exec_model_overhead_share"]


def _main_csv_lookup(main_csv_path: Path, run: int, tool: str, field: str) -> float:
    """Cross-references the RTT row against the existing throughput CSV
    (question 2 in the design: is RTT moving with exec/s) without
    duplicating any throughput-computation logic -- same DictReader-scan
    pattern write_summary() already uses below."""
    try:
        with main_csv_path.open("r", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                if r.get("arm") == "D" and r.get("tool") == tool and r.get("run") == str(run):
                    try:
                        return float(r.get(field) or "nan")
                    except ValueError:
                        return math.nan
    except OSError:
        pass
    return math.nan


def write_rtt_row(rtt_csv_path: Path, run_id: int, tool: str,
                  rows: list[dict[str, Any]], main_csv_path: Path,
                  exec_split: dict[str, Any] | None = None) -> dict[str, Any]:
    stats = compute_rtt_percentiles(rows, tool=tool)
    out_row: dict[str, Any] = {
        "run": run_id,
        "tool": tool,
        "rows_parsed": stats["rows_parsed"],
        "final_samples": stats["final_samples"],
        "retry_rate": stats["retry_rate"],
        "programs_per_sec": _main_csv_lookup(main_csv_path, run_id, tool, "programs_per_sec"),
        "syz_calls_per_sec": _main_csv_lookup(main_csv_path, run_id, tool, "syz_calls_per_sec"),
    }
    for seg, _a, _b in RTT_SUBINTERVALS:
        s = stats["segments"][seg]
        out_row[f"{seg}_samples"] = s["samples"]
        out_row[f"{seg}_p50_ms"] = s["p50_ms"]
        out_row[f"{seg}_p95_ms"] = s["p95_ms"]
        out_row[f"{seg}_p99_ms"] = s["p99_ms"]
        out_row[f"{seg}_mean_ms"] = s["mean_ms"]
    z = stats["zones"]
    out_row["complete_rows"] = z["complete_rows"]
    out_row["service_mean_ms"] = z["service_mean_ms"]
    out_row["queue_mean_ms"] = z["queue_mean_ms"]
    for zn in SERVICE_ZONES:
        out_row[f"zone_{zn}_mean_ms"] = z[zn]["mean_ms"]
        out_row[f"zone_{zn}_share"] = z[zn]["share"]
        out_row[f"zone_{zn}_rowshare_p50"] = z[zn]["row_share_p50"]
        out_row[f"zone_{zn}_rowshare_p95"] = z[zn]["row_share_p95"]
    service = stats["executor_service"]
    out_row["executor_service_samples"] = service["samples"]
    out_row["executor_service_p50_ms"] = service["p50_ms"]
    out_row["executor_service_p95_ms"] = service["p95_ms"]
    out_row["executor_service_p99_ms"] = service["p99_ms"]
    # EXEC first layer: `executor` is the shared fork+syscall+reap unit, the rest
    # is execution-model overhead. Guest clock (worker-perf) vs host clock (the
    # zones above), so these are an aligned view of the EXEC zone rather than an
    # exact per-task decomposition of it; cleanup also runs after the host has
    # already observed completion, i.e. off the RTT critical path.
    split = exec_split or {}
    split_stages = split.get("stages", {})
    out_row["exec_loop_samples"] = split.get("samples", "")
    out_row["exec_loop_mean_ms"] = split.get("loop_mean_ms", math.nan)
    for stage_name in WORKER_PERF_LOOP_STAGES:
        stage_row = split_stages.get(stage_name, {})
        out_row[f"exec_{stage_name}_mean_ms"] = stage_row.get("mean_ms", math.nan)
        out_row[f"exec_{stage_name}_share"] = stage_row.get("share", math.nan)
    out_row["exec_model_overhead_mean_ms"] = split.get("model_overhead_mean_ms", math.nan)
    out_row["exec_model_overhead_share"] = split.get("model_overhead_share", math.nan)
    first = not rtt_csv_path.exists()
    if not first:
        with rtt_csv_path.open("r", encoding="utf-8", newline="") as existing:
            header = next(csv.reader(existing), [])
        if header != RTT_CSV_FIELDS:
            raise RuntimeError(
                f"incompatible RTT CSV schema in {rtt_csv_path}; "
                "start a new output directory for millisecond RTT results")
    with rtt_csv_path.open("a", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=RTT_CSV_FIELDS)
        if first:
            w.writeheader()
        w.writerow(out_row)
    return out_row


def run_rtt_compare(args: argparse.Namespace, run_id: int, main_csv_path: Path) -> None:
    """Called once per run_id, after both tools' D-arm run has finished (see
    the main loop below). No-op unless --rtt-trace-sample-rate was set."""
    if getattr(args, "rtt_trace_sample_rate", 0) <= 0:
        return
    rtt_csv_path = args.out_dir / "rtt_compare.csv"

    syz_run_dir = args.out_dir / f"D_syz_run_{run_id:02d}"
    syz_rows = parse_syz_task_trace(syz_run_dir / "syz_task_trace.jsonl")
    syz_split = parse_syz_perf_loop(syz_run_dir)
    syz_out = write_rtt_row(rtt_csv_path, run_id, "syzkaller", syz_rows,
                            main_csv_path, exec_split=syz_split)

    refuzz_work_dir = refuzz_short_root(args.out_dir, run_id) / "work"
    refuzz_rows = refuzz_task_trace_rows(refuzz_work_dir)
    refuzz_split = parse_worker_perf_loop(refuzz_work_dir)
    refuzz_out = write_rtt_row(rtt_csv_path, run_id, "refuzz", refuzz_rows,
                               main_csv_path, exec_split=refuzz_split)

    def _f(out: dict[str, Any], key: str) -> float:
        try:
            return float(out.get(key))
        except (TypeError, ValueError):
            return float("nan")

    for tool, out in (("syz", syz_out), ("refuzz", refuzz_out)):
        print(f"  rtt    {tool}: {out['final_samples']}/{out['rows_parsed']} final, "
              f"{out['complete_rows']} full-chain, retry={out['retry_rate']:.3f}",
              flush=True)
        # View 1: each sub-interval's LATENCY (p50/p95). NOT a proportion.
        print("           queue p50/p95 ms |"
              f" wait {_f(out,'queue_wait_p50_ms'):.3f}/{_f(out,'queue_wait_p95_ms'):.3f}"
              f" dispatch {_f(out,'dispatch_wait_p50_ms'):.3f}/{_f(out,'dispatch_wait_p95_ms'):.3f}"
              f" slot {_f(out,'slot_wait_p50_ms'):.3f}/{_f(out,'slot_wait_p95_ms'):.3f}",
              flush=True)
        print("           service p50/p95 ms |"
              f" prep {_f(out,'dispatch_prep_p50_ms'):.3f}/{_f(out,'dispatch_prep_p95_ms'):.3f}"
              f" txout {_f(out,'transport_out_p50_ms'):.3f}/{_f(out,'transport_out_p95_ms'):.3f}"
              f" exec {_f(out,'execute_p50_ms'):.3f}/{_f(out,'execute_p95_ms'):.3f}"
              f" result {_f(out,'result_copy_p50_ms'):.3f}/{_f(out,'result_copy_p95_ms'):.3f}"
              f" feedback {_f(out,'feedback_p50_ms'):.3f}/{_f(out,'feedback_p95_ms'):.3f}",
              flush=True)
        # View 2: service-time PROPORTION per zone (mean-based, NOT summed p50s).
        print("           service share (mean-based):"
              f" EXEC {_f(out,'zone_exec_share')*100:.1f}%"
              f" TRANSPORT {_f(out,'zone_transport_share')*100:.1f}%"
              f" ORCH {_f(out,'zone_orch_share')*100:.1f}%"
              f"  (service~{_f(out,'service_mean_ms'):.0f}ms, queue~{_f(out,'queue_mean_ms'):.0f}ms)",
              flush=True)

    # View 4: what the EXEC zone -- nearly all of service time -- is actually made
    # of, on both sides. Only `executor` inside it is the fork+syscall+reap unit the
    # two fuzzers share; prepare/delivery/cleanup is what each execution model
    # spends around it. Side by side this IS the model-overhead comparison; without
    # it EXEC stays a black box and "reFuzz only touches TRANSPORT+ORCH" is
    # untestable.
    for tool, split, hint in (
            ("syz   ", syz_split,
             "needs a syz-executor with the loop() perf hooks and the second serial"),
            ("refuzz", refuzz_split,
             "needs fuzzer.worker_perf.enable=true at run time")):
        if not split:
            print(f"           {tool} EXEC first layer: no data ({hint})", flush=True)
            continue
        loop_stages = split["stages"]
        print(f"           {tool} EXEC first layer ({split['samples']} progs,"
              f" loop~{split['loop_mean_ms']:.1f}ms):"
              f" executor {loop_stages['executor']['share']*100:.1f}%"
              f" | model {split['model_overhead_share']*100:.1f}%"
              f" (prepare {loop_stages['prepare']['share']*100:.1f}%"
              f" delivery {loop_stages['delivery']['share']*100:.1f}%"
              f" cleanup {loop_stages['cleanup']['share']*100:.1f}%)",
              flush=True)


def fetch_http_text(url: str, timeout: float = 2.0) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def fetch_http_to_file(url: str, dest: Path, timeout: float = 20.0,
                       max_bytes: int = 256 * 1024 * 1024) -> str:
    """Stream an HTTP response straight to `dest` in 1 MiB chunks — never buffers
    the whole body in RAM — capping at max_bytes.

    syz dump endpoints (/rawcover, /corpusrawpc, /corpussignal, /maxsignal) can be
    large on a long run, and they're fetched at the worst moment: end of a multi-
    hour run when the host is already memory-pressured by both fuzzers. urlopen().
    read() would buffer the entire body in RAM and can thrash/freeze the box.
    Streaming to disk + a hard cap avoids that.

    Returns: "ok" (non-empty file written), "empty" (zero bytes), "capped" (cap
    hit; file truncated to max_bytes — still usable, last line may be partial), or
    "error" (URL/timeout/OS error). dest is removed on empty/error so callers can
    treat its absence uniformly. Each resp.read() inherits the socket timeout, so a
    stalled server raises rather than hanging forever.
    """
    written = 0
    capped = False
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp, \
                dest.open("wb") as out:
            while True:
                chunk = resp.read(1 << 20)  # 1 MiB
                if not chunk:
                    break
                if written + len(chunk) > max_bytes:
                    out.write(chunk[: max_bytes - written])
                    written = max_bytes
                    capped = True
                    break
                out.write(chunk)
                written += len(chunk)
    except (urllib.error.URLError, TimeoutError, OSError):
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        return "error"
    if written == 0:
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        return "empty"
    return "capped" if capped else "ok"


def prometheus_value(text: str, name: str) -> int | None:
    for line in text.splitlines():
        m = PROM_METRIC_RE.match(line)
        if m and m.group(1) == name:
            return int(float(m.group(2)))
    return None


def fetch_syz_metrics(http_addr: str) -> dict[str, int | None] | None:
    body = fetch_http_text(f"http://{http_addr}/metrics")
    if body is None:
        return None
    return {
        "started": prometheus_value(body, "syz_exec_total"),
        "exec_total": prometheus_value(body, "syz_exec_total"),
        # [corpus-run speed] executed syscalls (CallFlagExecuted), added to the
        # rpcserver (pkg/rpcserver). Drives executed syscalls/sec for corpus-run,
        # symmetric with reFuzz worker's kCallFlagExecuted tally.
        "exec_calls": prometheus_value(body, "syz_exec_calls_total"),
        "completed": prometheus_value(body, "syz_task_completed_total"),
        "fuzz_time_ms": prometheus_value(body, "syz_fuzz_time_ms"),
    }


def newest_host_events(work_dir: Path) -> Path | None:
    cands = sorted(work_dir.glob("run-*/logs/host_events.txt"), key=lambda p: p.stat().st_mtime)
    return cands[-1] if cands else None


def parse_refuzz_snapshots(path: Path) -> list[dict[str, int]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict[str, int]] = []
    for line in lines:
        if "evt=runtime_panel" not in line:
            continue
        ts = REFUZZ_SNAPSHOT_TS_RE.search(line)
        term = REFUZZ_TERMINAL_RE.search(line)
        if term is None:
            continue
        err = REFUZZ_EXEC_ERROR_RE.search(line)
        fatal = REFUZZ_HARNESS_FATAL_RE.search(line)
        ec = REFUZZ_EXEC_CALLS_RE.search(line)
        out.append({
            "snapshot_ts_us": int(ts.group("ts")) if ts else 0,
            "terminal": int(term.group("terminal")),
            "exec_error": int(err.group("exec_error")) if err else 0,
            "harness_fatal": int(fatal.group("harness_fatal")) if fatal else 0,
            "exec_calls": int(ec.group("exec_calls")) if ec else 0,
        })
    return out


def wait_for_refuzz_snapshot(proc: subprocess.Popen[Any], host_events: Path,
                             predicate: Callable[[dict[str, int]], bool],
                             timeout_s: int, err_msg: str) -> dict[str, int]:
    # [harness_fatal 监控移除] 这里只等两个东西:进程还活着 + predicate 满足。
    # 不再因为 runtime_panel 里的 harness_fatal 计数器就中断 run:harness_fatal
    # 可能是 worker 崩溃后 recovery 进行中的瞬时状态(recovery 一次 reboot 最多
    # 要 boot_timeout×3 ≈ 9min),python 提前判死会把正在恢复的 refuzz 强杀。
    # 是否真的不可恢复由 refuzz 自己决定(kFailChannel → 进程退出),这里靠
    # proc.poll() 发现进程死亡即可。
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"reFuzz exited early with code {proc.returncode}")
        for snap in parse_refuzz_snapshots(host_events):
            if predicate(snap):
                return snap
        time.sleep(1.0)
    raise TimeoutError(err_msg)


def validate_refuzz_run_summary(path: Path) -> None:
    if not path.exists():
        raise RuntimeError(f"missing reFuzz run_summary.json: {path}")
    summary = load_json(path)
    fields = summary.get("fields")
    invariants = summary.get("invariants")
    if not isinstance(fields, dict) or not isinstance(invariants, dict):
        raise RuntimeError(f"invalid reFuzz run_summary.json schema: {path}")
    invariant_status = str(invariants.get("status", "missing"))
    if invariant_status != "ok":
        failures = invariants.get("failures", [])
        raise RuntimeError(
            f"reFuzz run_summary invariants={invariant_status}: {failures}")


def run_refuzz_fuzz(args: argparse.Namespace, base: dict[str, Any], run_id: int,
                    csv_path: Path, prep: CorpusPrep) -> Row:
    global ACTIVE_CHILD_PROC
    run_dir = args.out_dir / f"D_refuzz_run_{run_id:02d}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    mkdir(run_dir)
    corpus_src = args.refuzz_seed_corpus if args.refuzz_seed_corpus else prep.refuzz_dir
    seed_dir = clone_refuzz_corpus(corpus_src, run_dir)
    cfg_path = make_refuzz_config(args, base, run_dir, run_id, seed_corpus_dir=seed_dir)
    cfg = load_json(cfg_path)
    work_dir = Path(str(cfg["work_dir"]))
    log_path = run_dir / "refuzz.log"
    runner = args.refuzz_build_dir / "control/orchestrator/refuzz"
    mean_calls = float(prep.manifest.get("mean_calls_per_program", 0.0))

    row = Row(arm="D", tool="refuzz", run=run_id, status="failed",
              measurement_mode="steady_state_runtime_panel", config=str(cfg_path), log=str(log_path))
    proc: subprocess.Popen[Any] | None = None
    try:
        with log_path.open("ab") as log:
            log.write((f"+ {runner} {cfg_path}\n").encode())
            log.flush()
            # [env scoping] jemalloc + rarity-prior go to reFuzz ONLY, via an explicit
            # env= rather than the ambient environment. Without this, the documented
            # launch recipe (`env LD_PRELOAD=libjemalloc.so.2
            # REFUZZ_SEED_RARITY_PRIOR_ALPHA=8 ...`, see scripts/perf_compare/
            # perf_sampling.sh:629) would have to be applied to this whole script,
            # and both children inherit it -- syz-manager would silently get
            # jemalloc too. That is not a fair baseline: the arm-D contract is that
            # each side runs its own real design, and jemalloc is part of reFuzz's.
            proc = subprocess.Popen([str(runner), str(cfg_path)], cwd=args.refuzz_root,
                                    stdout=log, stderr=subprocess.STDOUT, preexec_fn=os.setsid,
                                    env=refuzz_child_env())
            ACTIVE_CHILD_PROC = proc
            (run_dir / "runner.pgid").write_text(f"{os.getpgid(proc.pid)}\n", encoding="utf-8")
            deadline = time.monotonic() + args.start_timeout
            host_events: Path | None = None
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f"reFuzz exited early with code {proc.returncode}")
                host_events = newest_host_events(work_dir)
                if host_events is not None:
                    break
                time.sleep(1.0)
            if host_events is None:
                raise TimeoutError(f"no host_events.txt within {args.start_timeout}s")
            first = wait_for_refuzz_snapshot(proc, host_events, lambda s: s["terminal"] > 0,
                                             args.start_timeout, "no first terminal result")
            warm_us = first["snapshot_ts_us"] + args.warmup * 1_000_000
            start = wait_for_refuzz_snapshot(proc, host_events,
                                             lambda s: s["snapshot_ts_us"] >= warm_us and s["terminal"] > 0,
                                             args.warmup + 30, "no runtime panel after warmup")
            end_us = start["snapshot_ts_us"] + args.duration * 1_000_000
            end = wait_for_refuzz_snapshot(proc, host_events, lambda s: s["snapshot_ts_us"] >= end_us,
                                           args.duration + 30, "did not reach measurement window end")
        # [corpus-pc-export] SIGINT grace covering the orchestrator's fuzzer-thread
        # join + the EARLY corpus_pc dump (now before registry.StopAll(), which can
        # hang under SIGINT). 45s is ample for join(≤exec_timeout)+dump; StopAll may
        # still hang and get force-killed — fine, the dump already landed.
        stop_process_group(proc, sigint_grace=45)
        if proc.returncode != 0:
            raise RuntimeError(f"reFuzz exited with code {proc.returncode}")
        if ACTIVE_CHILD_PROC is proc:
            ACTIVE_CHILD_PROC = None
        live_root = refuzz_short_root(args.out_dir, run_id)
        cov_log = find_refuzz_cov_log(args.out_dir, run_id)
        copy_if_exists(cov_log, run_dir / "coverage_PC_series.log")
        # [edge-over-time] archive the dedicated edge series next to the PC one.
        if cov_log is not None:
            copy_if_exists(cov_log.parent / "coverage_edge_series.log",
                           run_dir / "coverage_edge_series.log")
        # [cov-compare fuzz-start anchor] run_summary.json lives in the same logs/
        # dir as the metric log; copy it alongside so cov-compare can re-base reFuzz's
        # coverage curve at first-fuzz-exec (strip the boot + machine-check
        # plateau), symmetric with syz's boot-excluded "fuzz time ms". Absent →
        # cov-compare falls back to anchoring at the earliest sample.
        summary_src = host_events.parent / "run_summary.json"
        copy_if_exists(summary_src, run_dir / "run_summary.json")
        validate_refuzz_run_summary(summary_src)
        copy_if_exists(live_root / "corpus_pc.txt", run_dir / "corpus_pc.txt")
        copy_if_exists(live_root / "coverage" / "coverage_hashes.bin",
                       run_dir / "coverage_hashes.bin")
        copied = decode_refuzz_coverage_hashes_bin(
            run_dir / "coverage_hashes.bin", run_dir / "coverage_hashes.txt")
        if copied is not None:
            print(f"  reFuzz D: coverage_hashes.bin -> coverage_hashes.txt ({copied} entries)",
                  flush=True)
        execs = max(0, end["terminal"] - start["terminal"])
        seconds = max(0.001, (end["snapshot_ts_us"] - start["snapshot_ts_us"]) / 1_000_000.0)
        # [speed-compare arm D] REAL executed syscalls/sec from fuzzer.calls.executed
        # (kCallFlagExecuted), symmetric with syz_exec_calls_total — not a
        # programs×corpus-mean estimate (generated/mutated progs differ from corpus).
        call_delta = max(0, int(end.get("exec_calls", 0)) - int(start.get("exec_calls", 0)))
        if call_delta <= 0:
            raise RuntimeError("missing/non-positive reFuzz fuzzer.calls.executed delta; "
                               "D syscall/s must use the real exec_calls counter")
        row.status = "ok"
        row.programs_per_sec = execs / seconds
        row.completed = execs
        row.wall_s = seconds
        row.executed_syz_calls = call_delta
        row.syz_calls_per_sec = call_delta / seconds              # executed syscalls/sec
        row.syz_calls_per_sec_nominal = (execs / seconds) * mean_calls  # auxiliary estimate
        row.artifact = str(host_events)
        # [MAB metrics] solidified per-run comparison data extracted from host_events:
        #   metric 1 = per-task execution share {gen,mut,triage,enrich}
        #   metric 2 = PC-per-syscall coverage (corpus/edge/kcov vs executed syscalls)
        # (metric 3 = speed, already in this Row). Never let a parse error fail the run.
        try:
            mm = mab_metrics.emit(host_events, run_dir,
                                  bucket=getattr(args, "syscall_bucket", mab_metrics.DEFAULT_SYSCALL_BUCKET))
            task = mm.get("task_share", {})
            pc = mm.get("pc_per_syscall", {})
            if task.get("available"):
                print(f"  reFuzz D: task share = {mab_metrics._fmt_share(task)}", flush=True)
            if pc.get("available"):
                eff = pc["efficiency"]
                print(f"  reFuzz D: PC-per-syscall = {eff['corpus_pc_per_1k']:.2f} corpus-PC / 1k "
                      f"syscalls ({pc['final_corpus_pc']} PC over {pc['final_exec_calls']} syscalls)",
                      flush=True)
        except Exception as exc:  # noqa: BLE001 — diagnostics must never abort a run
            print(f"  reFuzz D: mab_metrics extraction failed: {exc}", flush=True)
        write_coverage_domain_manifest(args, run_id, extra={
            "domains": {
                "corpus_pc": {
                    "status": "available",
                    "refuzz_artifact": str(run_dir / "corpus_pc.txt"),
                    "unit": "raw PC set for corpus-admitted programs",
                    "note": "CorpusCoverageMetadata.cover_hashes is raw PC; edge admission uses signal_cover_hashes separately.",
                },
                "raw_all_pc": {
                    "status": "available_if_raw_pc_mode" if copied is not None else "unavailable",
                    "refuzz_artifact": str(run_dir / "coverage_hashes.txt"),
                    "unit": "global coverage store; raw PC only when coverage.kcov.raw_pc=true and cover_edges=false",
                    "reason": "" if copied is not None else "coverage_hashes.bin was not produced",
                },
                "edge": {
                    "status": "unavailable",
                    "unit": "edge/signal set",
                    "reason": "reFuzz currently does not export the full edge set as a standalone text artifact here.",
                },
            },
        })
    except Exception as exc:
        row.error = str(exc)
    finally:
        if proc is not None:
            stop_process_group(proc)
            if ACTIVE_CHILD_PROC is proc:
                ACTIVE_CHILD_PROC = None
    append_csv(csv_path, row)
    return row


def run_syz_manager(args: argparse.Namespace, base: dict[str, Any], run_id: int,
                    csv_path: Path, prep: CorpusPrep) -> Row:
    global ACTIVE_CHILD_PROC
    run_dir = args.out_dir / f"D_syz_run_{run_id:02d}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    mkdir(run_dir)
    # D is the full fuzzing comparison: syz-manager must start from an empty
    # workdir and load its built-in seed corpus itself. `--seed-corpus-db` only
    # seeds the prepared corpus; do not copy it into D's syzkaller workdir.
    # reFuzz warm-starts from the prepared equivalent corpus.
    cfg_path, _ = make_syz_manager_config(args, run_dir, run_id)
    cfg = load_json(cfg_path)
    http_addr = str(cfg["http"])
    log_path = run_dir / "syz-manager.log"
    manager = args.syzkaller_root / "bin/syz-manager"
    mean_calls = float(prep.manifest.get("mean_calls_per_program", 0.0))
    # -bench writes a periodic stats snapshot (incl. "coverage" + "fuzz time ms")
    # that cov-compare reads for the coverage-over-time curve. Must not pre-exist
    # (syz opens it O_EXCL); run_dir is freshly created above.
    bench_path = run_dir / "syz_bench.txt"
    # [RTT trace, coarse comparison phase] mirrors -bench: empty/absent = off.
    # Must not pre-exist (syz-manager opens it O_EXCL); run_dir is fresh above.
    task_trace_path = run_dir / "syz_task_trace.jsonl"
    manager_args = [str(manager), "-config", str(cfg_path), "-bench", str(bench_path)]
    if args.rtt_trace_sample_rate > 0:
        manager_args += ["-task-trace", str(task_trace_path),
                         "-task-trace-sample-rate", str(args.rtt_trace_sample_rate)]
    if getattr(args, "syz_request_stream", None) is not None:
        manager_args += ["-request-stream", str(args.syz_request_stream)]

    row = Row(arm="D", tool="syzkaller", run=run_id, status="failed",
              measurement_mode="completed_fuzz_time_metrics", config=str(cfg_path), log=str(log_path))
    proc: subprocess.Popen[Any] | None = None
    try:
        with log_path.open("ab") as log:
            log.write((f"+ {' '.join(manager_args)}\n").encode())
            log.flush()
            proc = subprocess.Popen(manager_args,
                                    cwd=args.syzkaller_root, stdout=log,
                                    stderr=subprocess.STDOUT, preexec_fn=os.setsid)
            ACTIVE_CHILD_PROC = proc
            (run_dir / "manager.pgid").write_text(f"{os.getpgid(proc.pid)}\n", encoding="utf-8")
            # Wait until fuzzing produces completion metrics.
            deadline = time.monotonic() + args.start_timeout
            started = False
            last_completed = 0
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f"syz-manager exited early with code {proc.returncode}")
                snap = fetch_syz_metrics(http_addr)
                if snap and snap.get("completed") is not None and snap.get("fuzz_time_ms"):
                    if snap["completed"] > last_completed and (snap["fuzz_time_ms"] or 0) > 0:
                        started = True
                        break
                    last_completed = snap["completed"] or 0
                time.sleep(1.0)
            if not started:
                raise TimeoutError(f"syz-manager did not start fuzzing within {args.start_timeout}s")
            if args.warmup > 0:
                time.sleep(args.warmup)
            start_snap = fetch_syz_metrics(http_addr)
            if not start_snap or start_snap.get("completed") is None or start_snap.get("fuzz_time_ms") is None:
                raise RuntimeError("missing syzkaller metrics at measurement start")
            time.sleep(args.duration)
            (run_dir / "metrics_end.prom").write_text(
                fetch_http_text(f"http://{http_addr}/metrics", timeout=3.0) or "", encoding="utf-8")
            end_snap = fetch_syz_metrics(http_addr)
            if not end_snap or end_snap.get("completed") is None or end_snap.get("fuzz_time_ms") is None:
                raise RuntimeError("missing syzkaller metrics at measurement end")
            # [PC-set 对比] D: grab corpus raw cover (PreviousInstructionPC space) while the
            # manager is still alive — it is killed in the finally below. /rawcover with no
            # args = union of corpus.Items() cover. Best-effort: empty → PC-set D step skips.
            rc_status = fetch_http_to_file(f"http://{http_addr}/rawcover",
                                           run_dir / "syz_pcs.txt", timeout=20.0)
            if rc_status == "capped":
                print("  pc-set[D]: /rawcover hit size cap — using truncated PC set",
                      flush=True)
            elif rc_status != "ok":
                print(f"  pc-set[D]: /rawcover {rc_status} "
                      "(set cover:true / rawcover:true in syz.json?)", flush=True)
            # [coverage-compare] symmetric syz exports (new endpoints), best-effort
            # while the manager is alive. /corpusrawpc = RAW KCOV corpus PC (raw-vs-raw
            # with reFuzz, no instr-len offset); /corpussignal, /maxsignal = corpus &
            # all-exec edge signals (COUNT-comparable only). Gated to match the reFuzz side.
            if getattr(args, "coverage_domains", False):
                for ep, fn in (("corpusrawpc", "syz_corpus_rawpc.txt"),
                               ("corpussignal", "syz_corpus_signal.txt"),
                               ("maxsignal", "syz_max_signal.txt")):
                    st = fetch_http_to_file(f"http://{http_addr}/{ep}",
                                            run_dir / fn, timeout=20.0)
                    if st == "capped":
                        print(f"  coverage-domains[D]: /{ep} hit size cap — truncated",
                              flush=True)
                    elif st != "ok":
                        print(f"  coverage-domains[D]: /{ep} {st} — skip", flush=True)
        # [speed-compare arm D] programs = syz_exec_total (actual program executions),
        # NOT syz_task_completed_total — the latter is a slow fuzzer-level "task
        # completed" counter (lags exec by ~deflake factor), which made calls/prog
        # come out =1.00. exec_total pairs with exec_calls → calls/prog ≈ real.
        execs = max(0, int(end_snap.get("exec_total") or 0) - int(start_snap.get("exec_total") or 0))
        fuzz_ms = max(0, int(end_snap["fuzz_time_ms"] or 0) - int(start_snap["fuzz_time_ms"] or 0))
        if fuzz_ms <= 0:
            raise RuntimeError("non-positive syzkaller fuzz-time delta")
        seconds = fuzz_ms / 1000.0
        # [speed-compare arm D] REAL executed syscalls/sec from syz_exec_calls_total
        # (the rpcserver counter, CallFlagExecuted) — symmetric with reFuzz's
        # fuzzer.calls.executed. Do not estimate silently: a missing counter means
        # the syzkaller binary is not suitable for this comparison.
        call_delta = max(0, int(end_snap.get("exec_calls") or 0) - int(start_snap.get("exec_calls") or 0))
        if call_delta <= 0:
            raise RuntimeError("missing/non-positive syz_exec_calls_total delta; "
                               "rebuild syz-manager with the rpcserver exec-calls counter")
        row.status = "ok"
        row.programs_per_sec = execs / seconds
        row.completed = execs
        row.wall_s = seconds
        row.syz_calls_per_sec = call_delta / seconds              # executed syscalls/sec
        row.executed_syz_calls = call_delta
        row.syz_calls_per_sec_nominal = (execs / seconds) * mean_calls  # auxiliary estimate
        row.artifact = f"http://{http_addr}/metrics"
        domains_extra: dict[str, Any] = {
            "corpus_pc": {
                "status": "available",
                "syz_artifact": str(run_dir / "syz_pcs.txt"),
                "unit": "syz /rawcover corpus-PC dump (PreviousInstructionPC space)",
            },
            "raw_all_pc": {
                "status": "unavailable",
                "reason": "syzkaller keeps no all-execution raw-PC union (per-exec only "
                          "signal; raw cover fetched only for triage). Architectural "
                          "asymmetry — use edge counts for the all-exec domain.",
            },
        }
        if getattr(args, "coverage_domains", False):
            domains_extra["corpus_pc"]["syz_raw_artifact"] = str(run_dir / "syz_corpus_rawpc.txt")
            domains_extra["corpus_pc"]["note"] = ("raw-vs-raw via /corpusrawpc (no offset); "
                                                  "/rawcover kept for the canonicalized view")
            domains_extra["corpus_edge"] = {
                "status": "available_count_only",
                "syz_artifact": str(run_dir / "syz_corpus_signal.txt"),
                "unit": "corpus edge/signal set; COUNT-comparable only "
                        "(reFuzz/syz edge encodings differ → set membership not comparable)",
            }
            domains_extra["all_edge"] = {
                "status": "available_count_only",
                "syz_artifact": str(run_dir / "syz_max_signal.txt"),
                "unit": "all-exec max-signal set; COUNT-comparable only",
            }
        write_coverage_domain_manifest(args, run_id, extra={"domains": domains_extra})
    except Exception as exc:
        row.error = str(exc)
    finally:
        if proc is not None:
            stop_process_group(proc)
            if ACTIVE_CHILD_PROC is proc:
                ACTIVE_CHILD_PROC = None
    append_csv(csv_path, row)
    return row


# ---------------------------------------------------------------------------
# Coverage-over-time (arm D): cov-compare merges the corpus-PC view from reFuzz
# coverage metric logs and syz-manager -bench into one CSV; plot_cov_compare.py
# renders the final single-axes two-line PNG. Standalone Go tool (no syz import),
# built once.
# ---------------------------------------------------------------------------
def build_cov_compare(args: argparse.Namespace, out_dir: Path) -> Path:
    # [prebuilt] Containerized runs have no Go toolchain: the runtime image ships
    # only what a 48h run needs, and cov-compare is the one Go binary the coverage
    # path depends on. COV_COMPARE_BIN points at a copy built on the machine that
    # built everything else, so this stays a plain copy instead of a build.
    prebuilt = os.environ.get("COV_COMPARE_BIN")
    binary = out_dir / "cov-compare"
    if prebuilt:
        src_bin = Path(prebuilt)
        if not src_bin.is_file():
            raise RuntimeError(f"COV_COMPARE_BIN={prebuilt} does not exist")
        shutil.copy2(src_bin, binary)
        binary.chmod(0o755)
        print(f"  cov-compare: using prebuilt {src_bin}", flush=True)
        return binary
    src = args.refuzz_root / "tools/cov_compare"
    binary = out_dir / "cov-compare"
    run_checked(["go", "build", "-o", str(binary), "."],
                cwd=src, log_path=out_dir / "build_cov_compare.log")
    return binary


def find_refuzz_cov_log(out_dir: Path, run_id: int,
                        min_mtime: float = 0.0) -> Path | None:
    # work_dir lives under the short /tmp root (see make_refuzz_config socket-path fix).
    work = refuzz_short_root(out_dir, run_id) / "work"
    cands = sorted(work.glob("run-*/logs/coverage_PC_series.log"))
    # [fix] The live web (_start_d_live_web) polls during D startup and can race
    # the reFuzz thread's work_dir rmtree + VM boot, latching onto a stale log
    # left by an earlier run. Reject any file last written before
    # min_mtime (the web passes its own start time) so we only bind to THIS
    # run's freshly-written series. Post-run callers pass 0.0 (no filter).
    if min_mtime > 0.0:
        out = []
        for c in cands:
            try:
                if c.stat().st_mtime >= min_mtime:
                    out.append(c)
            except OSError:
                pass
        cands = out
    if not cands:
        return None
    try:
        return max(cands, key=lambda p: p.stat().st_mtime_ns)
    except OSError:
        return cands[-1]


def _cov_metric_pass(args: argparse.Namespace, run_id: int,
                     refuzz_log: Path | None, syz_bench: Path, *,
                     series: str, bench_field: str, tag: str, title: str,
                     syz_log: Path | None = None) -> None:
    """One metric pairing → merged CSV + static PNG. Best-effort.

    syz source: when syz_log is given AND exists, parse the 10s heartbeat
    'coverage=' straight from syz-manager.log (--syz-log) — 6× finer than the
    60s -bench; the log's wall-clock timestamps are converted to elapsed
    seconds. Used for the PC pass (the log has no 'signal', so the edge pass
    leaves syz_log=None and falls back to the 60s -bench).
    """
    cmd = [str(args.cov_compare_bin)]
    if refuzz_log is not None and refuzz_log.exists():
        cmd += ["--refuzz-log", str(refuzz_log), "--refuzz-series", series,
                "--refuzz-label", f"reFuzz ({tag})"]
    if syz_log is not None and syz_log.exists():
        cmd += ["--syz-log", str(syz_log), "--syz-bench-field", bench_field,
                "--syz-label", f"syzkaller ({tag})"]
    elif syz_bench.exists():
        cmd += ["--syz-bench", str(syz_bench), "--syz-bench-field", bench_field,
                "--syz-label", f"syzkaller ({tag})"]
    if len(cmd) == 1:
        print(f"  coverage[{tag}]: no series for run {run_id}, skipping", flush=True)
        return
    merged_csv = args.out_dir / f"D_cov_{tag}_run_{run_id:02d}.csv"
    png        = args.out_dir / f"D_cov_{tag}_run_{run_id:02d}.png"
    log        = args.out_dir / f"D_cov_{tag}_run_{run_id:02d}.log"
    cmd += ["--out", str(merged_csv)]
    try:
        run_checked(cmd, cwd=args.refuzz_root, log_path=log)
    except Exception as exc:
        print(f"  coverage[{tag}] compare failed: {exc}", flush=True)
        return
    try:
        run_checked([sys.executable, str(args.plot_cov), "--csv", str(merged_csv),
                     "--out", str(png), "--title", title],
                    cwd=args.refuzz_root, log_path=log)
        print(f"  coverage[{tag}]: {merged_csv.name} + {png.name}", flush=True)
    except Exception as exc:
        print(f"  coverage[{tag}] plot failed (CSV: {merged_csv.name}): {exc}", flush=True)


def run_coverage_compare(args: argparse.Namespace, run_id: int) -> None:
    """Coverage-over-time for arm D: corpus-PC (always) + corpus-EDGE.

    Two over-time pairings, both with a real time axis so you can read
    "time to reach coverage X" (the standard paper comparison):

      * corpus PC   : reFuzz corpus_pc  ↔  syz bench "coverage" (len corpus.cover).
                      Same address space (reFuzz raw KCOV PC − 5 == syz
                      PreviousInstructionPC), so Y is directly comparable.
      * corpus EDGE : reFuzz corpus_edge ↔  syz bench "signal" (corpus.Signal).
                      SAME edge encoding on both sides — reFuzz mirrors syzkaller
                      use_cover_edges (sig = pc ^ (mix(prev_pc)&0xfff)), so the
                      distinct-edge COUNT is comparable (collision <0.1%). This is
                      the "edges found over time" curve.

    Raw-all-PC / max-signal are not auto-plotted here (different domain; recorded
    in coverage_domain_manifest.json).
    """
    if not getattr(args, "cov_compare_bin", None):
        return
    refuzz_log = args.out_dir / f"D_refuzz_run_{run_id:02d}" / "coverage_PC_series.log"
    if not refuzz_log.exists():
        refuzz_log = find_refuzz_cov_log(args.out_dir, run_id)
    syz_bench = args.out_dir / f"D_syz_run_{run_id:02d}" / "syz_bench.txt"
    syz_log   = args.out_dir / f"D_syz_run_{run_id:02d}" / "syz-manager.log"
    # PC pass: read syz coverage from the 10s heartbeat in syz-manager.log
    # (--syz-log) — finer than the 60s -bench; the log's wall-clock timestamps
    # are converted to elapsed seconds for plotting. reFuzz stays at its native
    # 10s coverage_PC_series.log. (syz code untouched — log parsed directly.)
    _cov_metric_pass(
        args, run_id, refuzz_log, syz_bench,
        series="corpus_pc", bench_field="coverage", tag="corpus", syz_log=syz_log,
        title=f"Corpus PC coverage over time — same seed baseline, aligned PC domain (run {run_id})")
    # [edge-over-time] corpus distinct-edge count over time. reFuzz writes this
    # to its OWN coverage_edge_series.log (separate 10s stream), gated by
    # coverage.export.edge_series_enabled (set in
    # make_refuzz_config under --coverage-domains). corpus_edge
    # (fuzzer.cov.corpus_edge = corpus_edge_feedback_store->Count())
    # ↔ syz bench "signal" (len(corpus.signal)): both the corpus signal/edge
    # union under the same use_cover_edges encoding → count comparable. Answers
    # "time to reach N edges". Skipped if the file is absent (edge series off).
    edge_log = (refuzz_log.parent / "coverage_edge_series.log") if refuzz_log is not None else None
    if edge_log is not None and edge_log.exists():
        _cov_metric_pass(
            args, run_id, edge_log, syz_bench,
            series="corpus_edge", bench_field="signal", tag="edge",
            title=f"Corpus edge coverage over time — same use_cover_edges encoding (run {run_id})")
    else:
        print(f"  coverage[edge]: no coverage_edge_series.log (edge_series_enabled off?), skipping",
              flush=True)


# ---------------------------------------------------------------------------
# PC-set 对比(②收集PC对比 / ③过滤PC)。回答"两个工具执行到的内核 PC 是否一样深":
# 对齐到同一 PC 地址空间(reFuzz 原始 KCOV PC − instr_len == syz PreviousInstructionPC)
# 后比集合 —— Jaccard / reFuzz∖syz / syz∖reFuzz,差集按子系统分桶(噪声 vs 真深度差)。
#   arm C(两侧逐字节相同 corpus):严格保真度对比,Jaccard 应≈1(自带校验闸)。
#   arm D(输入已发散):探索力对比;reFuzz 侧 = live corpus_pc 导出,syz 侧 = /rawcover。
# ---------------------------------------------------------------------------
def run_pc_set_compare(args: argparse.Namespace, arm_name: str, run_id: int,
                       refuzz_pcs: Path, syz_pcs: Path, *, domain: str,
                       tag: str | None = None,
                       instr_len: int | None = None) -> dict[str, Any] | None:
    """Run pc_set_compare.py on the two PC dumps for this (arm, run) → pc_diff JSON.
    `tag` overrides the output-file stem (so two compares for the same arm don't
    collide); `instr_len` overrides the PC-space offset (pass 0 for raw-vs-raw)."""
    if not refuzz_pcs.exists() or not syz_pcs.exists():
        print(f"  pc-set[{tag or arm_name}]: missing dump (refuzz={refuzz_pcs.exists()} "
              f"syz={syz_pcs.exists()}) — skip", flush=True)
        return None
    tag = tag or arm_name
    out_json = args.out_dir / f"pc_diff_{tag}_run_{run_id:02d}.json"
    out_dir = args.out_dir / f"pc_diff_{tag}_run_{run_id:02d}"
    log_path = args.out_dir / f"pc_diff_{tag}_run_{run_id:02d}.log"
    cmd = [sys.executable, str(args.pc_set_compare),
           "--refuzz-pcs", str(refuzz_pcs), "--syz-pcs", str(syz_pcs),
           "--instr-len", str(args.instr_len if instr_len is None else instr_len),
           "--label", f"arm {arm_name} run {run_id} ({domain})",
           "--domain", domain,
           "--out-json", str(out_json), "--out-dir", str(out_dir)]
    for filter_pc in getattr(args, "effective_filter_pcs", []) or []:
        cmd += ["--filter-pcs", str(filter_pc)]
    if args.vmlinux is not None:
        cmd += ["--vmlinux", str(args.vmlinux)]
    try:
        run_checked(cmd, cwd=args.refuzz_root, log_path=log_path)
        d = load_json(out_json)
    except Exception as exc:
        print(f"  pc-set[{arm_name}] compare failed: {exc}", flush=True)
        return None
    print(f"  pc-set[{arm_name}]: jaccard={d.get('jaccard')} "
          f"jaccard_realpath={d.get('jaccard_realpath')} "
          f"syz_only_realpath={d.get('syz_only_realpath')} "
          f"refuzz_only={d.get('refuzz_only')}", flush=True)
    return d


def run_edge_count_compare_d(args: argparse.Namespace, run_id: int) -> None:
    """arm D edge domain: edges are COUNT-comparable only — reFuzz and syzkaller use
    different edge encodings (different hash/shift), so set membership is meaningless.
    Count distinct edges on each side (both dumps are deduped+sorted) → cardinality +
    ratio. reFuzz: corpus_signal/all_signal (edges in the default cover_edges profile);
    syz: /corpussignal (corpus.Signal) and /maxsignal (all-exec max signal)."""
    def _refuzz_dump(name: str) -> Path:
        p = args.out_dir / f"D_refuzz_run_{run_id:02d}" / name
        return p if p.exists() else refuzz_short_root(args.out_dir, run_id) / name

    def _count(p: Path) -> int | None:
        if not p.exists():
            return None
        with p.open(encoding="utf-8") as f:
            return sum(1 for ln in f if ln.strip())

    syz_dir = args.out_dir / f"D_syz_run_{run_id:02d}"
    pairs = (
        ("corpus_edge", _refuzz_dump("corpus_signal.txt"), syz_dir / "syz_corpus_signal.txt"),
        ("all_edge",    _refuzz_dump("all_signal.txt"),    syz_dir / "syz_max_signal.txt"),
    )
    domains: dict[str, Any] = {}
    for name, rp, sp in pairs:
        rc, sc = _count(rp), _count(sp)
        ratio = (rc / sc) if (rc and sc) else None
        domains[name] = {
            "refuzz_count": rc, "syz_count": sc, "ratio": ratio,
            "refuzz_artifact": str(rp), "syz_artifact": str(sp),
            "note": "count-only: reFuzz/syz edge encodings differ; set membership not comparable",
        }
        if rc is not None or sc is not None:
            rstr = f"{ratio:.3f}" if ratio is not None else "n/a"
            print(f"  edge-count[D] {name}: refuzz={rc} syz={sc} ratio={rstr}", flush=True)
    write_json(args.out_dir / f"edge_count_D_run_{run_id:02d}.json",
               {"run": run_id, "domains": domains})


def run_pc_set_compare_d(args: argparse.Namespace, base: dict[str, Any], run_id: int) -> None:
    """arm D PC-set: reFuzz corpus PC set = the orchestrator's on-shutdown dump
    (coverage.export.corpus_pc_path, injected by make_refuzz_config) — the LIVE
    corpus-admitted PC set, NO grown-corpus replay. syz side = the /rawcover dump from
    run_syz_manager. Compare (exploration view — inputs have diverged). `base` unused
    (kept for call-site symmetry with the replay arms)."""
    del base
    refuzz_pcs = args.out_dir / f"D_refuzz_run_{run_id:02d}" / "corpus_pc.txt"
    if not refuzz_pcs.exists():
        refuzz_pcs = refuzz_short_root(args.out_dir, run_id) / "corpus_pc.txt"
    syz_pcs = args.out_dir / f"D_syz_run_{run_id:02d}" / "syz_pcs.txt"
    run_pc_set_compare(args, "D", run_id, refuzz_pcs, syz_pcs,
                       domain="exploration, divergent input")
    if getattr(args, "coverage_domains", False):
        # raw-vs-raw corpus PC: reFuzz raw KCOV ↔ syz /corpusrawpc (raw KCOV), so the
        # set intersection is exact with NO instruction-length offset to reconcile.
        syz_rawpc = args.out_dir / f"D_syz_run_{run_id:02d}" / "syz_corpus_rawpc.txt"
        run_pc_set_compare(args, "D", run_id, refuzz_pcs, syz_rawpc,
                           domain="exploration, raw-vs-raw corpus PC",
                           tag="Draw", instr_len=0)
        run_edge_count_compare_d(args, run_id)


# ---------------------------------------------------------------------------
# Parallel D (coverage-focused, live). Runs reFuzz + syz CONCURRENTLY so you
# can watch corpus_pc vs syz_corpus_cover side-by-side in a browser. Same-seed
# warm-start is preserved (both still build from `prep`). NOTE: throughput
# (programs_per_sec) is host-CONTENDED in this mode and must NOT be read as the
# clean per-worker speed number — use the sequential default for that. This
# mode is for the coverage-over-time comparison.
# ---------------------------------------------------------------------------
def _start_d_live_web(args: argparse.Namespace, run_id: int):
    """Wait for the reFuzz coverage log, then launch cov-compare --web tailing
    reFuzz corpus_pc + syz /metrics (corpus_cover). Returns the Popen or None."""
    if not args.d_web or not getattr(args, "cov_compare_bin", None):
        return None
    syz_metrics = f"http://127.0.0.1:{args.http_port_base + run_id}/metrics"
    # Only bind to a reFuzz log written after the web starts.
    web_t0 = time.time()
    deadline = time.monotonic() + args.start_timeout
    coverage_log = None
    while time.monotonic() < deadline:
        coverage_log = find_refuzz_cov_log(args.out_dir, run_id, min_mtime=web_t0)
        if coverage_log is not None and coverage_log.exists():
            break
        time.sleep(2.0)
    cmd = [str(args.cov_compare_bin), "--web", args.d_web,
           "--syz-metrics", syz_metrics, "--syz-label", "syzkaller (corpus)"]
    if coverage_log is not None and coverage_log.exists():
        cmd += ["--refuzz-log", str(coverage_log), "--refuzz-series", "corpus_pc",
                "--refuzz-label", "reFuzz (corpus)"]
    log_path = args.out_dir / f"D_live_web_run_{run_id:02d}.log"
    log = log_path.open("ab")
    proc = subprocess.Popen(cmd, cwd=args.refuzz_root, stdout=log,
                            stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    print(f"  live web: http://localhost{args.d_web}  (corpus_pc vs syz_corpus_cover)",
          flush=True)
    return proc


def run_d_parallel(args: argparse.Namespace, base: dict[str, Any], run_id: int,
                   csv_path: Path, prep: CorpusPrep) -> None:
    import threading
    results: dict[str, Row] = {}

    def _ref():
        results["refuzz"] = run_refuzz_fuzz(args, base, run_id, csv_path, prep)

    def _syz():
        results["syz"] = run_syz_manager(args, base, run_id, csv_path, prep)

    threads: list[threading.Thread] = []
    if args.only in ("both", "refuzz"):
        threads.append(threading.Thread(target=_ref, name="refuzz-D"))
    if args.only in ("both", "syzkaller"):
        threads.append(threading.Thread(target=_syz, name="syz-D"))
    for t in threads:
        t.start()
    web = _start_d_live_web(args, run_id)
    for t in threads:
        t.join()
    if web is not None:
        try:
            stop_process_group(web)
        except Exception:
            pass
    for who, r in results.items():
        print(f"  {who} D (parallel): {r.status} {r.programs_per_sec:.2f} prog/s "
              f"[contended]", flush=True)


# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
def write_summary(args: argparse.Namespace, csv_path: Path, md_path: Path,
                  manifest: dict[str, Any]) -> None:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    def vals(arm: str, tool: str, field: str) -> list[float]:
        out = []
        for r in rows:
            if r["arm"] == arm and r["tool"] == tool and r["status"] == "ok":
                try:
                    out.append(float(r[field]))
                except (KeyError, ValueError):
                    pass
        return out

    def gate_red(arm: str) -> str | None:
        thr = args.timeout_hang_threshold
        for r in rows:
            if r["arm"] != arm or r["status"] != "ok":
                continue
            try:
                if r.get("timeout_or_hang_rate") and float(r["timeout_or_hang_rate"]) > thr:
                    return f"timeout_or_hang_rate>{thr}"
            except ValueError:
                pass
        return None

    lines = [
        "# Speed Compare summary (reFuzz vs syzkaller)",
        "",
        f"corpus: **{manifest.get('num_programs', '?')}** programs "
        f"(pseudo_dropped={manifest.get('pseudo_filtered_count', '?')}, "
        f"timeout_dropped={manifest.get('timeout_filtered_count', '?')}, "
        f"total_calls={manifest.get('corpus_total_calls', '?')})  ",
        f"duration={args.duration}s warmup={args.warmup}s runs={args.runs}",
        "",
        "| arm | tool | runs | programs/s (mean) | syz_calls/s (mean) | stdev p/s |",
        "|---|---|---:|---:|---:|---:|",
    ]
    if getattr(args, "effective_filter_pcs", None):
        lines[5:5] = [
            f"pc-set comparison domain: **allow-list enabled** ({len(args.effective_filter_pcs)} file(s)); "
            f"manifest `{args.out_dir / 'pc_filter_manifest.json'}`",
            "",
        ]
    elif getattr(args, "pc_filter_warnings", None):
        lines[5:5] = [
            f"pc-set comparison domain: **unfiltered**; see warnings in "
            f"`{args.out_dir / 'pc_filter_manifest.json'}`",
            "",
        ]
    arms_present = [a for a in ARMS if any(r["arm"] == a for r in rows)]
    for arm in arms_present:
        for tool in ("refuzz", "syzkaller"):
            pv = vals(arm, tool, "programs_per_sec")
            cv = vals(arm, tool, "syz_calls_per_sec")
            if not pv:
                continue
            stdev = statistics.stdev(pv) if len(pv) > 1 else 0.0
            cmean = statistics.mean(cv) if cv else 0.0
            lines.append(f"| {arm} | {tool} | {len(pv)} | {statistics.mean(pv):.3f} | "
                         f"{cmean:.3f} | {stdev:.3f} |")

    lines += ["", "## Ratios (reFuzz / syzkaller)", ""]
    for arm in arms_present:
        rp = vals(arm, "refuzz", "programs_per_sec")
        sp = vals(arm, "syzkaller", "programs_per_sec")
        if not rp or not sp:
            continue
        red = gate_red(arm)
        prog_ratio = rate(statistics.mean(rp), statistics.mean(sp))
        # [full-pipeline syscall/sec] both sides report REAL executed syscalls
        # (reFuzz fuzzer.calls.executed / syz syz_exec_calls_total), so the headline
        # is executed-syscalls/sec — the fair full-loop throughput. programs/s kept
        # as auxiliary (the two loops generate different program shapes).
        rc = vals(arm, "refuzz", "syz_calls_per_sec")
        sc = vals(arm, "syzkaller", "syz_calls_per_sec")
        call_ratio = rate(statistics.mean(rc), statistics.mean(sc)) if rc and sc else 0.0
        flag = f"  ⚠️ RED ({red}) — not a valid ratio" if red else ""
        lines.append(
            f"- **{arm}** (full-pipeline) syz_calls/s(executed)={call_ratio:.3f}x  "
            f"programs/s={prog_ratio:.3f}x{flag}  "
            f"(reFuzz {statistics.mean(rc):.1f} vs syz {statistics.mean(sc):.1f} exec-calls/s; "
            f"programs/s is reFuzz terminal results/s vs syz exec starts/s)"
            if rc and sc else
            f"- **{arm}** programs/s ratio: {prog_ratio:.3f}x{flag} (exec-calls counter missing)")

    failed = [r for r in rows if r["status"] != "ok"]
    if failed:
        lines += ["", "## Failures", ""]
        for r in failed:
            lines.append(f"- [{r['arm']}] {r['tool']} run {r['run']}: {r.get('error', '')} ({r.get('log', '')})")

    # [PC-set 对比] section — read the per-(arm,run) pc_diff_*.json artifacts.
    pc_files = sorted(args.out_dir.glob("pc_diff_*_run_*.json"))
    if pc_files:
        lines += ["", "## PC-set parity (Jaccard / 差集 / 子系统)", "",
                  "| arm | run | filter PCs | reFuzz PCs | syz PCs | jaccard | "
                  "jaccard_realpath | reFuzz∖syz (struct/real) | "
                  "syz∖reFuzz (struct/**real=深度差**) | flag |",
                  "|---|---:|---:|---:|---:|---:|---:|---|---|---|"]
        for pf in pc_files:
            try:
                d = load_json(pf)
            except Exception:
                continue
            parts = pf.stem.split("_")  # pc_diff_<arm>_run_<NN>
            arm = parts[2] if len(parts) > 3 else "?"
            run = parts[-1]
            jac = d.get("jaccard", "")
            # arm D is exploration with divergent inputs → a low jaccard is EXPECTED
            # (not a fidelity failure), so no jaccard-threshold RED flag here.
            flag = ""
            buckets = d.get("subsystem_buckets")
            ro = (f"{d.get('refuzz_only_structural','?')}/{d.get('refuzz_only_realpath','?')}"
                  if buckets else f"{d.get('refuzz_only','?')} (no vmlinux)")
            so = (f"{d.get('syz_only_structural','?')}/{d.get('syz_only_realpath','?')}"
                  if buckets else f"{d.get('syz_only','?')} (no vmlinux)")
            fp = d.get("filter_pcs_count", 0)
            rp_count = f"{d.get('refuzz_pcs','?')}/{d.get('refuzz_pcs_unfiltered','?')}"
            sp_count = f"{d.get('syz_pcs','?')}/{d.get('syz_pcs_unfiltered','?')}"
            lines.append(f"| {arm} | {run} | {fp} | {rp_count} | {sp_count} | "
                         f"{jac} | {d.get('jaccard_realpath','')} | {ro} | {so} | {flag} |")
        lines += ["",
                  "- arm **C**(两侧逐字节相同 corpus):jaccard 应≈1.0;偏低 → 对齐错 或 reFuzz "
                  "执行保真度差。syz∖reFuzz 的 **real** = 相同输入下 reFuzz 没跑到的真路径。",
                  "- arm **D**(输入已发散):jaccard 是探索力对比,非保真度;syz∖reFuzz 的 real = "
                  "syz 多探到的真路径。reFuzz 侧为 orchestrator shutdown 导出的 live corpus_pc。",
                  "- `reFuzz PCs` / `syz PCs` 单元格式为 filtered/unfiltered；filter PCs=0 表示未做 "
                  "offline allow-list 裁剪。",
                  "- reFuzz PC 已按 instr_len 平移进 syz PreviousInstructionPC 空间;详见 "
                  "`pc_diff_<arm>_run_<NN>.json` + `pc_diff_<arm>_run_<NN>/`。"]

    if any((args.out_dir / f"D_cov_corpus_run_{run_id:02d}.csv").exists()
           for run_id in range(1, args.runs + 1)):
        lines += ["", "## Coverage Curves", "",
                  "- `D_cov_corpus_run_*.csv/png`: syz empty workdir loads its built-in seed corpus; "
                  "reFuzz warm-start loads the prepared equivalent seed corpus.",
                  "- These curves compare exploration shape/slope in each tool's own corpus-PC metric. "
                  "Strict address-space equality belongs to the PC-set Jaccard artifacts, not the plot.",
                  ""]

    # [MAB metrics] solidified comparison data for the MAB fuzz tool (reFuzz side),
    # read from each run's mab_metrics.json (written by run_refuzz_fuzz). metric 3
    # (speed) already lives in the throughput tables above.
    mab_runs: list[tuple[int, dict[str, Any]]] = []
    for run_id in range(1, args.runs + 1):
        mj = args.out_dir / f"D_refuzz_run_{run_id:02d}" / "mab_metrics.json"
        if mj.exists():
            try:
                mab_runs.append((run_id, load_json(mj)))
            except Exception:
                pass

    task_runs = [(rid, m["task_share"]) for rid, m in mab_runs
                 if m.get("task_share", {}).get("available")]
    if task_runs:
        lines += ["", "## Metric 1 — task execution share (reFuzz MAB)", "",
                  "Per-stage produce counts; the four stages partition every producing "
                  "iteration (`gen+mut+triage+enrich == iter`).", "",
                  "| run | gen % | mut % | triage % | enrich % | total tasks | "
                  "gen | mut | triage | enrich | partition |",
                  "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|"]
        for rid, t in task_runs:
            sp, c = t["share_pct"], t["counts"]
            pok = "ok" if t.get("partition_ok") else ("—" if t.get("partition_ok") is None else "⚠️")
            lines.append(f"| {rid} | {sp['gen']:.1f} | {sp['mut']:.1f} | {sp['triage']:.1f} | "
                         f"{sp['enrich']:.1f} | {t['total_tasks']} | {c['gen']} | {c['mut']} | "
                         f"{c['triage']} | {c['enrich']} | {pok} |")

    pc_runs = [(rid, m["pc_per_syscall"]) for rid, m in mab_runs
               if m.get("pc_per_syscall", {}).get("available")]
    if pc_runs:
        lines += ["", "## Metric 2 — PC-per-syscall coverage (reFuzz)", "",
                  "Cumulative coverage vs **executed syscalls** (the PC-per-syscall efficiency "
                  "headline). `*/1k` = coverage per 1000 executed syscalls.", "",
                  "| run | exec syscalls | corpus PC | corpus edge | kcov PC | "
                  "corpus-PC/1k | corpus-edge/1k |",
                  "|---:|---:|---:|---:|---:|---:|---:|"]
        for rid, pc in pc_runs:
            eff = pc["efficiency"]
            lines.append(f"| {rid} | {pc['final_exec_calls']} | {pc['final_corpus_pc']} | "
                         f"{pc['final_corpus_edge']} | {pc['final_kcov_pc']} | "
                         f"{eff['corpus_pc_per_1k']:.2f} | {eff['corpus_edge_per_1k']:.2f} |")
        for rid, pc in pc_runs:
            lines += ["", f"**run {rid}** — coverage at executed-syscall milestones "
                      f"(bucket={pc['bucket']}):", "",
                      "| exec_calls milestone | exec_calls | corpus PC | corpus edge | kcov PC |",
                      "|---|---:|---:|---:|---:|"]
            for r in pc["milestones"]:
                lines.append(f"| {r['milestone_calls']} | {r['exec_calls']} | {r['corpus_pc']} | "
                             f"{r['corpus_edge']} | {r['kcov_pc']} |")
        lines += ["",
                  "- `pc_vs_syscalls.tsv` (per run): full raw (exec_calls → coverage) series.",
                  "- `task_share_series.tsv` (per run): task share over time (cumulative + "
                  "per-snapshot instantaneous %)."]

    lines += ["", "## Per-run detail", "",
              "| arm | tool | run | status | programs/s | syz_calls/s | executed | nominal | "
              "completed | wall_s | timeout/hang | cover_entries |",
              "|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        lines.append(
            f"| {r['arm']} | {r['tool']} | {r['run']} | {r['status']} | "
            f"{r.get('programs_per_sec', '')} | {r.get('syz_calls_per_sec', '')} | "
            f"{r.get('executed_syz_calls', '')} | {r.get('nominal_syz_calls', '')} | "
            f"{r.get('completed', '')} | {r.get('wall_s', '')} | "
            f"{r.get('timeout_or_hang_rate', '')} | {r.get('cover_entries', '')} |")
    lines += ["", f"Raw CSV: `{csv_path}`  |  corpus manifest: `{args.out_dir / 'corpus_manifest.json'}`", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI + main.
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    root = repo_root()
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--arms", default="D",
                   help="comma list of arms to run (only D — the full fuzz loop — remains)")
    p.add_argument("--seed-corpus-db", type=Path, default=None,
                   help="explicit syzkaller corpus.db source. OMIT to use the STABLE default: "
                        "enumerate syzkaller's built-in seeds --seeds-dir (sorted by filename) "
                        "and convert to concrete programs deterministically (syzgen seeds-unpack).")
    p.add_argument("--seeds-dir", type=Path, default=root.parent / "sys/linux/test",
                   help="built-in seed dir enumerated when --seed-corpus-db is omitted "
                        "(default <syzkaller>/sys/linux/test)")
    p.add_argument("--refresh-corpus", action="store_true",
                   help="regenerate the fixed corpus cache even if present (e.g. after the "
                        "seeds changed); without it the cached corpus is reused verbatim")
    p.add_argument("--corpus-cache-dir", type=Path, default=None,
                   help="fixed dir for the prepared corpus (syz/ + refuzz/), reused across runs "
                        "(default <out-dir>/../corpus = run/speed_compare/corpus)")
    p.add_argument("--duration", type=int, default=120, help="measured seconds per run")
    p.add_argument("--warmup", type=int, default=0, help="warmup seconds (arm D only)")
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--syscall-bucket", type=int, default=mab_metrics.DEFAULT_SYSCALL_BUCKET,
                   help="executed-syscall milestone step for the PC-per-syscall metric "
                        "(default 500000 = 0.5M)")
    p.add_argument("--rtt-trace-sample-rate", type=int, default=0,
                   help="task-chain comparison: 0 disables (default), 1 traces every task, "
                        "N traces every "
                        "Nth task. Wires syz-manager's -task-trace/-task-trace-sample-rate "
                        "and reFuzz's telemetry.logging.task_trace_sample_rate; "
                        "run_rtt_compare() then parses both trace logs into rtt_compare.csv. "
                        "Comparison runs should generally use 1 (full sampling) -- these are "
                        "finite benchmark runs, not long production fuzzing, so sampling "
                        "noise would undermine the comparison itself.")
    p.add_argument("--rtt-report", nargs=3, type=Path, default=None,
                   metavar=("SYZ_TASK_TRACE", "RFZ_HOST_EVENTS", "OUTPUT_MD"),
                   help="STANDALONE: read two already-captured task traces, write the RTT "
                        "zone report to OUTPUT_MD, and exit without running anything. "
                        "run_rtt_compare() can only reach traces sitting in speed_compare's "
                        "own D_syz_run_NN/ + refuzz work-dir layout, so any other harness "
                        "(perf_sampling.sh's replay-both) had no way to analyse the traces "
                        "it captures. This entry point exists so that harness reuses "
                        "RTT_SUBINTERVALS/RTT_ZONE/compute_rtt_percentiles from here instead "
                        "of growing a second, drifting copy of the zone accounting.")
    p.add_argument("--syz-request-stream", type=Path, default=None,
                   help="wires syz-manager's -request-stream <path>: an async host-side "
                        "sink (pkg/rpcserver/request_stream_sink.go) that captures the "
                        "program/order syz-manager's own source.Next() actually pulled, "
                        "in a fixed binary schema carrying no timestamps, results, or "
                        "execution identity. Unset (default) = zero cost. This is the sole "
                        "capture channel for a later fixed-input reFuzz replay; it does not "
                        "touch the guest and is unrelated to --rtt-trace-sample-rate.")
    p.add_argument("--refuzz-request-stream", type=Path, default=None,
                   help="reFuzz-side mirror of --syz-request-stream: sets "
                        "fuzzer.request_stream_capture_path on the materialised config, "
                        "which makes a normal fuzzing run also log every DISPATCHED request "
                        "as JSONL through control/src/request_stream_sink.cpp (async writer, "
                        "hooked on JobScheduler::TrySubmit). tools/syz-stream-from-jsonl then "
                        "converts it to a canonical stream. Unset (default) = zero cost. "
                        "Capture is a driver switch rather than a separate config file so the "
                        "capture run and the baseline runs share one base config; ignored "
                        "under run_mode=replay, where capturing would just re-emit the input.")
    p.add_argument("--start-timeout", type=int, default=1200,
                   help="grace seconds for VM/tool boot + first activity "
                        "(1200=20min: reFuzz's corpus_verify must finish + reach "
                        "first mutational 'terminal result' before the harness "
                        "gives up and kills it; raised from 300 to test whether "
                        "the harness was killing reFuzz prematurely)")
    p.add_argument("--refuzz-root", type=Path, default=root)
    p.add_argument("--syzkaller-root", type=Path, default=root.parent)
    p.add_argument("--refuzz-build-dir", type=Path, default=root / "build-llvm20")
    # D-arm reFuzz fuzz config. Sourced from run/speed_compare/configs/ (same dir
    # as --syz-config); refuzz_mabB.json is the fixed source of truth and
    # make_refuzz_config rewrites only per-run fields.
    p.add_argument("--base-config", type=Path,
                   default=root / "run/speed_compare/configs/refuzz_mabB.json")
    p.add_argument("--refuzz-config", type=Path,
                   default=root / "run/speed_compare/configs/refuzz_mabB.json",
                   help="static reFuzz fuzz-loop config (D); only per-run fields are replaced")
    p.add_argument("--refuzz-seed-corpus", type=Path, default=None,
                   help="explicit reFuzz warm-start corpus dir (D). When set, reFuzz "
                        "clones+loads THIS dir instead of the prepared corpus "
                        "(prep.refuzz_dir). Use to pin reFuzz to a fixed clean base "
                        "(e.g. run/seedmab_base) instead of the speed_compare cache; "
                        "the per-run clone isolates SaveSeed write-back so the source "
                        "dir is never grown ('don't persist').")
    p.add_argument("--syz-config", type=Path,
                   default=root / "run/speed_compare/configs/syz.json",
                   help="static syz-manager-shaped config template; per-run paths are injected")
    p.add_argument("--plot-cov", type=Path, default=root / "scripts/speed_compare/plot_cov_compare.py",
                   help="matplotlib script that renders the final coverage-over-time PNG (arm D)")
    # [PC-set 对比] reFuzz-vs-syz 覆盖 PC 集合 Jaccard/差集/子系统分桶(②③步)。
    p.add_argument("--pc-set-compare", type=Path, default=root / "scripts/speed_compare/pc_set_compare.py",
                   help="PC-set 对比脚本路径")
    p.add_argument("--vmlinux", type=Path, default=None,
                   help="带 debuginfo 的 vmlinux,供 PC-set 子系统分桶(addr2line);"
                        "省略=PC-set 只出 raw Jaccard")
    p.add_argument("--instr-len", type=int, default=5,
                   help="PC-set 对齐平移量=instructionLen(arch);amd64=5。reFuzz 原始 KCOV "
                        "PC 减此值进 syz PreviousInstructionPC 空间(self-validating: arm C Jaccard≈1)")
    p.add_argument("--filter-pcs", type=Path, action="append", default=[],
                   help="optional syzkaller PC allow-list file for PC-set Jaccard. May be passed "
                        "multiple times. If omitted, speed_compare auto-detects syz config "
                        "cover_filter.pcs / experimental.focus_areas[].filter.pcs when possible. "
                        "Files/functions filters cannot be mirrored offline and need an exported "
                        "PC allow-list.")
    p.add_argument("--no-auto-filter-pcs", action="store_true",
                   help="disable syz config auto-discovery for PC-set comparison; use only "
                        "explicit --filter-pcs values")
    p.add_argument("--pc-jaccard-threshold", type=float, default=0.9,
                   help="arm C 的 PC-set jaccard 低于此值标红(对齐错 或 执行保真度差)")
    p.add_argument("--coverage-domains", action="store_true",
                   help="arm D: also export & compare the edge + raw-vs-raw-PC coverage "
                        "domains (reFuzz corpus_signal/all_signal dumps + syz /corpusrawpc, "
                        "/corpussignal, /maxsignal). OFF by default so the per-exec all_signal "
                        "feed never contaminates the throughput number; turn ON for a "
                        "coverage-focused run.")
    p.add_argument("--d-parallel", action="store_true",
                   help="run reFuzz + syz D CONCURRENTLY (coverage comparison focus; "
                        "throughput becomes host-contended — not the clean speed number)")
    p.add_argument("--d-web", default="",
                   help="with --d-parallel: serve a live cov-compare web UI at this addr "
                        "(e.g. :8080), showing corpus_pc vs syz_corpus_cover")
    p.add_argument("--pseudo-manifest", type=Path, default=root / "configs/pseudo_manifest.csv")
    p.add_argument("--pseudo-allowlist", type=Path, default=root / "configs/pseudo_allowlist.txt")
    # [filtering deferred] Per 2026-05-25 decision, the pipeline does NO filtering
    # for now (stage 1 lays out the corpus as-is; decode consistency is checked
    # separately via --check-decode). These knobs are kept but default OFF and are
    # currently unused by prepare_corpus — revisit once decode parity is confirmed.
    p.add_argument("--syzkaller-pseudo-filter", choices=["none", "surface", "all_syz"],
                   default="none",
                   help="(reserved; not wired into corpus prep yet) none (default): keep all")
    p.add_argument("--filter-timeout-prone", action="store_true",
                   help="(reserved; not wired into corpus prep yet)")
    p.add_argument("--timeout-hang-threshold", type=float, default=0.01,
                   help="red-flag a run when timeout_or_hang_rate exceeds this")
    p.add_argument("--http-port-base", type=int, default=56941)
    p.add_argument("--out-dir", type=Path,
                   default=root / "run/speed_compare" / time.strftime("%Y%m%d-%H%M%S"))
    p.add_argument("--image-cache-dir", type=Path, default=None,
                   help="fixed dir holding the per-side rootfs copies, reused across "
                        "runs (default <out-dir>/../images = run/speed_compare/images)")
    p.add_argument("--check-decode", action="store_true",
                   help="STANDALONE pre-run test (not part of a measured run): decode the "
                        "FULL corpus with reFuzz's decoder and report any program reFuzz "
                        "can't decode/encode, then exit. Failures = a reFuzz decoder bug to "
                        "investigate — execution itself never pre-filters on decodability.")
    p.add_argument("--only", choices=["both", "refuzz", "syzkaller"], default="both")
    p.add_argument("--skip-build", action="store_true")
    p.add_argument("--no-cleanup-stale", action="store_true")
    return p.parse_args()


def preflight(args: argparse.Namespace, arms: list[str]) -> None:
    if args.seed_corpus_db is not None and not args.seed_corpus_db.exists():
        raise SystemExit(f"seed corpus.db not found: {args.seed_corpus_db}")
    if args.seed_corpus_db is None and not args.seeds_dir.exists():
        raise SystemExit(f"seeds dir not found: {args.seeds_dir} (or pass --seed-corpus-db)")
    if not args.base_config.exists():
        raise SystemExit(f"base config not found: {args.base_config}")
    # --check-decode is a standalone test: it needs only the replayer (+ syzgen,
    # which prepare_corpus builds) — NOT the D arm binaries.
    if args.check_decode:
        if args.skip_build and not (args.refuzz_build_dir / "refuzz-exec-replayer").exists():
            raise SystemExit("refuzz-exec-replayer missing (build it or drop --skip-build)")
        return
    if args.duration < 1 or args.runs < 1:
        raise SystemExit("--duration and --runs must be >= 1")
    if args.only in ("both", "refuzz"):
        if "D" in arms and not args.refuzz_config.exists():
            raise SystemExit(f"--refuzz-config template not found: {args.refuzz_config}")
        if "D" in arms and not (args.refuzz_build_dir / "control/orchestrator/refuzz").exists():
            raise SystemExit("reFuzz runner (control/orchestrator/refuzz) missing")
    if args.only in ("both", "syzkaller"):
        # arm D uses syz-manager fuzzing — needs the host syz-manager binary
        # (build: make manager).
        if "D" in arms and not (args.syzkaller_root / "bin/syz-manager").exists():
            raise SystemExit("bin/syz-manager missing (build: make manager)")
    # Native KVM / slowdown sanity (cross-arch or TCG silently 10x the budget).
    if syzkaller_manager_timeouts(load_json(args.base_config)).slowdown != 1:
        print("WARNING: slowdown != 1 (TCG/cross-arch?) — timeouts are 10x; "
              "results are not native-KVM apples-to-apples", flush=True)
    # [PC-set 对比] vmlinux is optional — without it PC-set diffs lack subsystem buckets.
    if args.vmlinux is not None and not args.vmlinux.exists():
        print(f"WARNING: --vmlinux not found ({args.vmlinux}); PC-set diffs will lack "
              f"subsystem buckets (raw Jaccard only)", flush=True)


def write_rtt_zone_report(syz_trace: Path, rfz_trace: Path, out_md: Path) -> int:
    """Render the RTT zone report for two already-captured traces.

    Both views come straight from compute_rtt_percentiles, so this shares one
    definition of the zones with run_rtt_compare and cannot drift from it.
    """
    stats = [("syz", compute_rtt_percentiles(parse_syz_task_trace(syz_trace), tool="syzkaller")),
             ("rfz", compute_rtt_percentiles(parse_refuzz_task_trace(rfz_trace), tool="refuzz"))]
    for tool, s in stats:
        if not s["rows_parsed"]:
            print(f"rtt-report: {tool} trace is empty or unparsable", file=sys.stderr)
            return 1

    L: list[str] = [
        "# RTT Zone Report", "",
        f"Generated: `{time.strftime('%Y-%m-%dT%H:%M:%S%z')}`", "",
        f"- Syzkaller task trace: `{syz_trace}`",
        f"- reFuzz host events: `{rfz_trace}`", "",
        "Zones follow `RTT_SUBINTERVALS`/`RTT_ZONE`: "
        "`wall = queue + transport + exec + orch`, `service = transport + exec + orch`. "
        "The two views answer different questions and must not be mixed -- View 1 is "
        "per-interval LATENCY (percentiles, which do not add), View 2 is the mean-based "
        "time BUDGET over rows with a complete E1->E9 chain.", "",
        "> `dispatch_wait` is host-side in reFuzz and `slot_wait` is guest-side in Syzkaller. "
        "They are the same queueing pressure observed at opposite ends of the pipeline and "
        "must never be compared to each other directly; compare the queue zone totals.", "",
        "## Population", "",
        "| tool | rows parsed | final | full-chain (E1->E9) | retry rate |",
        "|---|---:|---:|---:|---:|",
    ]
    for tool, s in stats:
        L.append(f"| {tool} | {s['rows_parsed']} | {s['final_samples']} | "
                 f"{s['zones']['complete_rows']} | {s['retry_rate']:.4f} |")

    L += ["", "## View 1 -- sub-interval latency (percentiles; these do NOT add)", "",
          "| segment | zone | tool | N | p50 ms | p95 ms | p99 ms | mean ms |",
          "|---|---|---|---:|---:|---:|---:|---:|"]
    for name, _a, _b in RTT_SUBINTERVALS:
        for tool, s in stats:
            g = s["segments"][name]
            L.append(f"| {name} | {g['zone']} | {tool} | {g['samples']} | {g['p50_ms']:.3f} | "
                     f"{g['p95_ms']:.3f} | {g['p99_ms']:.3f} | {g['mean_ms']:.3f} |")

    L += ["", "## View 2 -- zone share of service time (means over full-chain rows)", "",
          "| tool | service mean ms | queue mean ms | "
          + " | ".join(f"{z} ms (share)" for z in SERVICE_ZONES) + " |",
          "|---|---:|---:|" + "---|" * len(SERVICE_ZONES)]
    for tool, s in stats:
        z = s["zones"]
        cells = [f"{z[n]['mean_ms']:.3f} ({100 * z[n]['share']:.1f}%)" for n in SERVICE_ZONES]
        L.append(f"| {tool} | {z['service_mean_ms']:.3f} | {z['queue_mean_ms']:.3f} | "
                 + " | ".join(cells) + " |")

    L += ["", "## Whole-task wall, same full-chain rows", "",
          "| tool | service mean ms | queue mean ms | wall mean ms | queue share of wall |",
          "|---|---:|---:|---:|---:|"]
    for tool, s in stats:
        z = s["zones"]
        wall = z["service_mean_ms"] + z["queue_mean_ms"]
        L.append(f"| {tool} | {z['service_mean_ms']:.3f} | {z['queue_mean_ms']:.3f} | "
                 f"{wall:.3f} | {100 * z['queue_mean_ms'] / wall:.1f}% |")

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"rtt-report: syz_rows={stats[0][1]['rows_parsed']} "
          f"rfz_rows={stats[1][1]['rows_parsed']} report={out_md}", flush=True)
    return 0


def main() -> int:
    args = parse_args()
    # Before any path resolution or preflight: this mode runs nothing and needs
    # none of the benchmark's inputs.
    if args.rtt_report:
        return write_rtt_zone_report(*(p.resolve() for p in args.rtt_report))
    for attr in ("refuzz_root", "syzkaller_root", "refuzz_build_dir", "base_config",
                 "pseudo_manifest", "pseudo_allowlist", "out_dir", "seed_corpus_db",
                 "seeds_dir", "corpus_cache_dir", "refuzz_config",
                 "refuzz_seed_corpus", "syz_config", "vmlinux", "pc_set_compare", "filter_pcs"):
        v = getattr(args, attr)
        if isinstance(v, list):
            setattr(args, attr, [p.resolve() for p in v])
        elif v is not None:  # seed_corpus_db / corpus_cache_dir optional
            setattr(args, attr, v.resolve())
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    for a in arms:
        if a not in ARMS:
            raise SystemExit(f"unknown arm {a!r}; valid: {', '.join(ARMS)}")

    install_signal_handlers()
    if not args.no_cleanup_stale:
        cleanup_stale_for_out_dir(args.out_dir)
    mkdir(args.out_dir)
    preflight(args, arms)
    configure_pc_filters(args)

    base = load_json(args.base_config)

    # [--check-decode] STANDALONE reFuzz decoder health test — decode the full
    # corpus and report failures, then exit. Not part of a measured run; runs
    # only when asked. Execution paths never pre-filter on decodability.
    if args.check_decode:
        if not args.skip_build and args.only in ("both", "refuzz"):
            build_refuzz(args, args.out_dir)  # builds the replayer (-decode-check) + syzgen
        prep_all = prepare_corpus(args, args.out_dir)  # full corpus (no filter)
        ok = run_decode_check(args, prep_all)
        print("decode-check: "
              + ("ALL programs decode+encode OK" if ok
                 else "FAILURES — investigate reFuzz decoder (programs are NOT filtered out)"),
              flush=True)
        return 0 if ok else 8

    csv_path = args.out_dir / "results.csv"
    md_path = args.out_dir / "summary.md"

    if not args.skip_build:
        if args.only in ("both", "refuzz"):
            build_refuzz(args, args.out_dir)
        if args.only in ("both", "syzkaller"):
            build_syzkaller(args, args.out_dir)

    # cov-compare (arm D coverage-over-time) — tiny standalone Go build (<1s),
    # so build it whenever D is in the matrix, even under --skip-build.
    args.cov_compare_bin = None
    if "D" in arms:
        args.cov_compare_bin = build_cov_compare(args, args.out_dir)

    # Stage 1: corpus (fixed cache, reused) — default = built-in sys/<os>/test seeds.
    prep = prepare_corpus(args, args.out_dir)
    write_json(args.out_dir / "corpus_manifest.json", prep.manifest)

    # Per-side rootfs copies (FIXED cache, reused). reFuzz config builders read
    # args.refuzz_image; syz uses the image in its own config verbatim.
    args.refuzz_image, _ = prepare_vm_images(args, base, args.out_dir)

    for arm_name in arms:
        spec = ARMS[arm_name]
        for run_id in range(1, args.runs + 1):
            print(f"== arm {arm_name} run {run_id}/{args.runs} ==", flush=True)
            # Only arm D (full fuzz loop) remains.
            if args.d_parallel:
                run_d_parallel(args, base, run_id, csv_path, prep)
            else:
                if args.only in ("both", "refuzz"):
                    r = run_refuzz_fuzz(args, base, run_id, csv_path, prep)
                    print(f"  reFuzz D: {r.status} {r.programs_per_sec:.2f} prog/s "
                          f"{r.syz_calls_per_sec:.2f} call/s", flush=True)
                if args.only in ("both", "syzkaller"):
                    r = run_syz_manager(args, base, run_id, csv_path, prep)
                    print(f"  syz    D: {r.status} {r.programs_per_sec:.2f} prog/s "
                          f"{r.syz_calls_per_sec:.2f} call/s", flush=True)
            run_coverage_compare(args, run_id)
            # [PC-set 对比] arm D: reFuzz corpus_pc 导出 + syz /rawcover(+ --coverage-domains
            # 时 raw-vs-raw / edge 域),对比(探索力视图)。
            if args.only == "both":
                run_pc_set_compare_d(args, base, run_id)
                # [RTT trace, coarse comparison phase] needs both tools' trace
                # logs from this run_id; no-op unless --rtt-trace-sample-rate.
                run_rtt_compare(args, run_id, csv_path)

    write_summary(args, csv_path, md_path, prep.manifest)
    print(f"results: {csv_path}", flush=True)
    print(f"summary: {md_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
