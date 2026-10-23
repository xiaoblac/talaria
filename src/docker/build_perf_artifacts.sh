#!/usr/bin/env bash
# Build the dedicated reFuzz performance-sampling image.
#
# The image contains everything perf_sampling.sh replay needs:
#   - current refuzz/worker binaries + syzkaller bins/sys (for code.id only)
#   - guest perf rootfs + 6.19.13 kernel bzImage/vmlinux
#   - W1 (syz-a) and W2 (rfz-a) fixed streams
#   - four reuse syz baselines (W1/W2 x w6/w7)
#   - container-rewritten configs and the in-image launcher
#
# Usage:
#   bash docker/build_perf_artifacts.sh
#   SKIP_DOCKER=1 bash docker/build_perf_artifacts.sh   # stage only
set -euo pipefail

REFUZZ_ROOT="${REFUZZ_ROOT:-/workspace/talaria}"
SYZ_ROOT="${SYZ_ROOT:-/workspace/syzkaller}"
STAGE="${STAGE:-/tmp/refuzz-perf-stage}"
IMAGE="${IMAGE:-refuzz-perf:latest}"
SSH_KEY="${SSH_KEY:-/workspace/images-test-linux5.14/bookworm.id_rsa}"
LLVM_LIBDIR="${LLVM_LIBDIR:-/usr/lib/llvm-20/lib}"

die() { echo "build_perf_artifacts: $*" >&2; exit 1; }

cd "$REFUZZ_ROOT"

# ── 1. source paths / preflight ──────────────────────────────────────────
RFZ_BIN="$REFUZZ_ROOT/build-llvm20/control/orchestrator/refuzz"
RFZ_WORKER="$REFUZZ_ROOT/build-llvm20/executor/channel/worker/ivshmem_worker"
RFZ_EXECUTOR="$REFUZZ_ROOT/build-llvm20/executor/channel/worker/refuzz_executor"
SYZ_MANAGER="$SYZ_ROOT/bin/syz-manager"
SYZ_CONVERTER="$SYZ_ROOT/bin/syz-stream-from-jsonl"
KERNEL_BZ="$SYZ_ROOT/kernel/build-kasan-clang/arch/x86/boot/bzImage"
KERNEL_VMLINUX="$SYZ_ROOT/kernel/build-kasan-clang/vmlinux"
PERF_ROOTFS="$REFUZZ_ROOT/run/speed_compare/images/refuzz_rootfs_perf.img"
SEED_BASE="$REFUZZ_ROOT/run/seed_base"
PERF_SCRIPT="$REFUZZ_ROOT/scripts/perf_compare/perf_sampling.sh"
SPEED_SCRIPT="$REFUZZ_ROOT/scripts/speed_compare/speed_compare.py"
CODEVER="$REFUZZ_ROOT/run/perf/CODEVER.json"

for f in "$RFZ_BIN" "$RFZ_WORKER" "$RFZ_EXECUTOR" "$SYZ_MANAGER" "$SYZ_CONVERTER" \
         "$KERNEL_BZ" "$KERNEL_VMLINUX" "$PERF_ROOTFS" "$SEED_BASE" \
         "$PERF_SCRIPT" "$SPEED_SCRIPT" "$CODEVER" "$SSH_KEY"; do
    [ -e "$f" ] || die "missing: $f"
done
[ -d "$SYZ_ROOT/sys" ] || die "missing: $SYZ_ROOT/sys"

# ── 2. stage layout ───────────────────────────────────────────────────────
rm -rf "$STAGE"
mkdir -p "$STAGE/opt/perf"
mkdir -p "$STAGE/opt/perf/build/control/orchestrator"
mkdir -p "$STAGE/opt/perf/build/executor/channel/worker"
mkdir -p "$STAGE/opt/perf/syzkaller/bin"
mkdir -p "$STAGE/opt/perf/syzkaller/sys"
mkdir -p "$STAGE/opt/perf/scripts/speed_compare"
mkdir -p "$STAGE/opt/perf/scripts/perf_compare"
mkdir -p "$STAGE/opt/perf/kernel"
mkdir -p "$STAGE/opt/perf/images"
mkdir -p "$STAGE/opt/perf/seed_base"
mkdir -p "$STAGE/opt/perf/configs"
mkdir -p "$STAGE/opt/perf/streams/syz-a"
mkdir -p "$STAGE/opt/perf/streams/rfz-a"
for reuse in W1w6 W1w7 W2w6 W2w7; do
    mkdir -p "$STAGE/opt/perf/reuse/$reuse/syz"
done
mkdir -p "$STAGE/libcxx"

# ── 3. binaries ───────────────────────────────────────────────────────────
cp "$RFZ_BIN" "$STAGE/opt/perf/build/control/orchestrator/refuzz"
cp "$RFZ_WORKER" "$STAGE/opt/perf/build/executor/channel/worker/ivshmem_worker"
cp "$RFZ_EXECUTOR" "$STAGE/opt/perf/build/executor/channel/worker/refuzz_executor"
cp "$SYZ_MANAGER" "$STAGE/opt/perf/syzkaller/bin/syz-manager"
cp "$SYZ_CONVERTER" "$STAGE/opt/perf/syzkaller/bin/syz-stream-from-jsonl"
cp -a "$SYZ_ROOT/sys/." "$STAGE/opt/perf/syzkaller/sys/"

# ── 4. scripts ────────────────────────────────────────────────────────────
cp -a "$REFUZZ_ROOT/scripts/speed_compare/." "$STAGE/opt/perf/scripts/speed_compare/"
cp -a "$REFUZZ_ROOT/scripts/perf_compare/." "$STAGE/opt/perf/scripts/perf_compare/"
cp "$REFUZZ_ROOT/docker/perf_run_replay.sh" "$STAGE/opt/perf/run_replay.sh"

# host perf used for `perf report` inside the container must not drag in the
# build machine's libpython/libLLVM/icu; use the guest-compatible minimal perf
# (libm/libz/libelf/libc only) so the bookworm image can run it.
GUEST_PERF="$REFUZZ_ROOT/build-guest-perf/perf"
if [ ! -x "$GUEST_PERF" ]; then
    (cd "$REFUZZ_ROOT" && bash scripts/perf_compare/build_guest_perf.sh >/dev/null)
fi
[ -x "$GUEST_PERF" ] || die "missing built guest-compatible perf: $GUEST_PERF"
cp "$GUEST_PERF" "$STAGE/opt/perf/scripts/perf_compare/perf"

# ── 5. kernel / rootfs / seed / ssh key ───────────────────────────────────
cp "$KERNEL_BZ" "$STAGE/opt/perf/kernel/bzImage"
cp "$KERNEL_VMLINUX" "$STAGE/opt/perf/kernel/vmlinux"
cp "$PERF_ROOTFS" "$STAGE/opt/perf/images/refuzz_rootfs_perf.img"
cp -a "$SEED_BASE/." "$STAGE/opt/perf/seed_base/"
cp "$SSH_KEY" "$STAGE/opt/perf/id_rsa"
chmod 600 "$STAGE/opt/perf/id_rsa"

for so in libc++.so.1.0 libc++abi.so.1.0 libunwind.so.1.0; do
    [ -f "$LLVM_LIBDIR/$so" ] || die "missing $LLVM_LIBDIR/$so"
    cp "$LLVM_LIBDIR/$so" "$STAGE/libcxx/"
done

# ── 6. streams ────────────────────────────────────────────────────────────
cp "$REFUZZ_ROOT/run/perf/streams/syz-a/stream.bin" "$STAGE/opt/perf/streams/syz-a/stream.bin"
cp "$REFUZZ_ROOT/run/perf/streams/syz-a/STREAM.json" "$STAGE/opt/perf/streams/syz-a/STREAM.json"
cp "$REFUZZ_ROOT/run/perf/streams/rfz-a/stream.bin" "$STAGE/opt/perf/streams/rfz-a/stream.bin"
cp "$REFUZZ_ROOT/run/perf/streams/rfz-a/STREAM.json" "$STAGE/opt/perf/streams/rfz-a/STREAM.json"

# ── 7. reuse syz baselines ────────────────────────────────────────────────
# W1 = syz-a, W2 = rfz-a. Each reuse dir gets the old syz capture artifacts;
# request_stream.bin is a symlink into /opt/perf/streams so the 668MB/950MB
# stream is stored once per workload.
copy_reuse() { # copy_reuse NAME SOURCE_SYZ STREAM
    local name="$1" src="$2" stream="$3"
    [ -d "$src" ] || die "reuse source missing: $src"
    cp -a "$src/." "$STAGE/opt/perf/reuse/$name/syz/"
    ln -sfn "/opt/perf/streams/$stream/stream.bin" \
        "$STAGE/opt/perf/reuse/$name/syz/request_stream.bin"
}

copy_reuse W1w6 \
    "$REFUZZ_ROOT/run/perf/_superseded/e2-replay/both__on-syz-a__20260726T062313Z/syz" \
    syz-a
copy_reuse W1w7 \
    "$REFUZZ_ROOT/run/perf/_superseded/e2-replay/both__on-syz-a__20260726T062313Z/syz" \
    syz-a
copy_reuse W2w6 \
    "$REFUZZ_ROOT/run/perf/e2-replay/rfz__on-rfz-a__20260727T092602Z/syz" \
    rfz-a
copy_reuse W2w7 \
    "$REFUZZ_ROOT/run/perf/e2-replay/rfz__on-rfz-a__20260727T092602Z/syz" \
    rfz-a

# ── 8. container-rewritten configs ────────────────────────────────────────
python3 - "$REFUZZ_ROOT" "$STAGE" <<'PY'
import json, sys

root, stage = sys.argv[1], sys.argv[2]

def rewrite_refuzz(src, dst):
    with open(src, encoding="utf-8") as f:
        c = json.load(f)
    c["channel"]["vm"]["image"] = "/opt/perf/images/refuzz_rootfs_perf.img"
    c["channel"]["vm"]["kernel"] = "/opt/perf/kernel/bzImage"
    c["channel"]["vm"]["ssh_key"] = "/opt/perf/id_rsa"
    c["persistence"]["corpus"]["dir"] = "/opt/perf/seed_base"
    c["phase0_worker_bin"] = "/opt/perf/build/executor/channel/worker/ivshmem_worker"
    c["repro"]["vmlinux_path"] = "/opt/perf/kernel/vmlinux"
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(c, f, indent=2, ensure_ascii=False)
        f.write("\n")

def rewrite_syz(src, dst):
    with open(src, encoding="utf-8") as f:
        c = json.load(f)
    c["syzkaller"] = "/opt/perf/syzkaller"
    c["sshkey"] = "/opt/perf/id_rsa"
    c["image"] = "/opt/perf/images/refuzz_rootfs_perf.img"
    c["kernel_obj"] = "/opt/perf/kernel"
    c["kernel_src"] = "/opt/perf/kernel"
    c["workdir"] = "/tmp/syz_work"
    c["vm"]["kernel"] = "/opt/perf/kernel/bzImage"
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(c, f, indent=2, ensure_ascii=False)
        f.write("\n")

rewrite_refuzz(f"{root}/run/speed_compare/configs/refuzz_mabB_perf.json",
               f"{stage}/opt/perf/configs/refuzz_mabB_perf.json")
rewrite_refuzz(f"{root}/run/speed_compare/configs/refuzz_mabB_perf_w7.json",
               f"{stage}/opt/perf/configs/refuzz_mabB_perf_w7.json")
rewrite_syz(f"{root}/run/speed_compare/configs/syz_6proc_cpu_closure.json",
            f"{stage}/opt/perf/configs/syz_6proc_cpu_closure.json")
rewrite_syz(f"{root}/run/speed_compare/configs/syz_7proc_cpu_closure.json",
            f"{stage}/opt/perf/configs/syz_7proc_cpu_closure.json")
PY

# ── 9. code fingerprint ───────────────────────────────────────────────────
python3 - "$STAGE" "$SYZ_ROOT" "$REFUZZ_ROOT" "$CODEVER" <<'PY'
import hashlib, json, subprocess, sys

stage, syz_root, rfz_root, expected_path = sys.argv[1:5]

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def git(root, *args):
    try:
        return subprocess.run(["git", "-C", root, *args], capture_output=True,
                              text=True, timeout=10, check=True).stdout.strip()
    except Exception:
        return None

bins = {
    "refuzz": sha(f"{stage}/opt/perf/build/control/orchestrator/refuzz"),
    "ivshmem_worker": sha(f"{stage}/opt/perf/build/executor/channel/worker/ivshmem_worker"),
    "syz-manager": sha(f"{stage}/opt/perf/syzkaller/bin/syz-manager"),
}
scripts = {
    "perf_sampling.sh": sha(f"{stage}/opt/perf/scripts/perf_compare/perf_sampling.sh"),
    "speed_compare.py": sha(f"{stage}/opt/perf/scripts/speed_compare/speed_compare.py"),
}
digest = hashlib.sha256("|".join(
    f"{k}={v}" for k, v in list(bins.items()) + list(scripts.items())).encode()).hexdigest()[:12]
code = {
    "id": digest,
    "refuzz_git": git(rfz_root, "rev-parse", "--short", "HEAD"),
    "refuzz_dirty": bool(git(rfz_root, "status", "--porcelain")),
    "syzkaller_git": git(syz_root, "rev-parse", "--short", "HEAD"),
    "syzkaller_dirty": bool(git(syz_root, "status", "--porcelain")),
    "bins": bins,
    "scripts": scripts,
}
with open(f"{stage}/opt/perf/CODEVER.json", "w", encoding="utf-8") as f:
    json.dump(code, f, indent=2, ensure_ascii=False)
    f.write("\n")

with open(expected_path, encoding="utf-8") as f:
    expected = json.load(f)
if code["id"] != expected["id"]:
    sys.stderr.write(
        f"code.id mismatch: staged={code['id']} expected={expected['id']}\n"
        "binaries/scripts changed since run/perf/CODEVER.json; update it first\n")
    sys.exit(1)
print(f"code.id={code['id']} verified")
PY

echo "stage ready: $STAGE"
du -sh "$STAGE" | sed 's/^/  /'

# ── 10. docker image ──────────────────────────────────────────────────────
if [[ "${SKIP_DOCKER:-0}" == "1" ]]; then
    echo "SKIP_DOCKER=1; image build skipped"
    exit 0
fi

docker build --network=host -t "$IMAGE" \
    -f "$REFUZZ_ROOT/docker/Dockerfile.perf" "$STAGE"
echo "image: $IMAGE"
docker images "$IMAGE" --format '  {{.Size}}'
