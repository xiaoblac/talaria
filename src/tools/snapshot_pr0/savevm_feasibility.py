#!/usr/bin/env python3
# PR0 task 0 feasibility spike: prove that the syzkaller-compatible snapshot disk
# setup works on THIS box (AMD + stock KVM, QEMU 6.2):
#
#   - qcow2 overlay over the raw base image (so savevm has a writable qcow2 to
#     store the internal VM-state snapshot, and the base stays immutable)
#   - NO `-snapshot` flag (that temp-overlay mode is incompatible with savevm)
#   - `-cpu host,migratable=on,tsc=off` (migratable required for savevm; tsc=off
#     so the guest doesn't see a TSC jump on restore)
#
# Then boot the real KASAN kernel + rootfs, and via QMP run one `savevm syz`
# followed by N `loadvm syz` restores, timing each. This is the disk-blocker
# validation from docs/plans/snapshot-mode.md PR0 task 0 — does savevm/loadvm
# work at all here, and what is the rough restore latency (KASAN floor)?
#
# Usage: python3 savevm_feasibility.py [--mem 2048] [--smp 1] [--restores 5]

import argparse
import json
import os
import socket
import subprocess
import sys
import time

ROOT = "/workspace/syzkaller"
KERNEL = f"{ROOT}/kernel/build-kasan/arch/x86/boot/bzImage"
BASE_IMG = "/workspace/images-test-linux5.14/bookworm.img"
RUNDIR = f"{ROOT}/reFuzz/tools/snapshot_pr0/run"
APPEND = "root=/dev/sda console=ttyS0 net.ifnames=0 biosdevname=0 nokaslr panic=1 oops=panic"
SNAP = "syz"  # snapshot tag


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class Qmp:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.f = self.sock.makefile("rw")
        greeting = self.f.readline()  # {"QMP": {...}}
        log(f"QMP greeting: {greeting.strip()[:80]}")
        self.cmd("qmp_capabilities")

    def cmd(self, execute, **args):
        msg = {"execute": execute}
        if args:
            msg["arguments"] = args
        self.f.write(json.dumps(msg) + "\n")
        self.f.flush()
        # Read until we get a return/error (skip async events).
        while True:
            line = self.f.readline()
            if not line:
                raise RuntimeError("QMP closed")
            obj = json.loads(line)
            if "return" in obj or "error" in obj:
                return obj

    def hmp(self, command_line):
        r = self.cmd("human-monitor-command", **{"command-line": command_line})
        if "error" in r:
            raise RuntimeError(f"hmp {command_line!r} error: {r['error']}")
        return r["return"]

    def close(self):
        try:
            self.cmd("quit")
        except Exception:
            pass
        self.sock.close()


def wait_for_boot(serial_path, marker, timeout):
    """Poll serial log until marker appears or timeout (seconds)."""
    deadline = time.time() + timeout
    last_size = 0
    while time.time() < deadline:
        try:
            with open(serial_path, "rb") as fh:
                data = fh.read()
        except FileNotFoundError:
            data = b""
        if marker in data:
            return True, len(data)
        if len(data) != last_size:
            last_size = len(data)
        time.sleep(1.0)
    return False, last_size


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mem", type=int, default=2048)
    ap.add_argument("--smp", type=int, default=1)
    ap.add_argument("--restores", type=int, default=5)
    ap.add_argument("--boot-timeout", type=int, default=240)
    a = ap.parse_args()

    os.makedirs(RUNDIR, exist_ok=True)
    overlay = f"{RUNDIR}/overlay.qcow2"
    serial = f"{RUNDIR}/serial.log"
    qmp_sock = f"{RUNDIR}/qmp.sock"
    for p in (overlay, serial, qmp_sock):
        if os.path.exists(p):
            os.remove(p)

    # 1. qcow2 overlay over the raw base (base stays immutable, savevm state
    #    lands in the overlay's internal snapshot table).
    log("creating qcow2 overlay over raw base ...")
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", BASE_IMG, overlay],
        check=True, capture_output=True,
    )
    fmt = subprocess.run(["qemu-img", "info", overlay], capture_output=True, text=True)
    log("overlay: " + fmt.stdout.replace("\n", " | "))

    # 2. launch QEMU — syz-compatible snapshot disk/cpu flags, NO -snapshot.
    cmd = [
        "qemu-system-x86_64",
        "-m", str(a.mem), "-smp", str(a.smp), "-display", "none", "-no-reboot",
        "-name", "pr0-savevm",
        "-serial", f"file:{serial}",
        "-qmp", f"unix:{qmp_sock},server,nowait",
        "-enable-kvm", "-cpu", "host,migratable=on,tsc=off",
        "-drive", f"file={overlay},if=ide,index=0,media=disk",
        "-kernel", KERNEL, "-append", APPEND,
    ]
    log("launching QEMU:\n  " + " ".join(cmd))
    qemu = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    verdict = {"savevm": False, "loadvm": False, "restores_ms": [], "snap_info": "", "booted": False}
    try:
        # 3. wait for boot to a login prompt (KASAN is slow).
        log(f"waiting for boot marker 'login:' (timeout {a.boot_timeout}s) ...")
        booted, sz = wait_for_boot(serial, b"login:", a.boot_timeout)
        verdict["booted"] = booted
        log(f"boot marker {'FOUND' if booted else 'NOT found'} (serial {sz} bytes) — proceeding")
        # small settle so userspace quiesces
        time.sleep(3)

        if qemu.poll() is not None:
            raise RuntimeError(f"QEMU exited early rc={qemu.returncode}")

        # 4. QMP: savevm then N× loadvm, timed.
        q = Qmp(qmp_sock)
        t0 = time.time()
        out = q.hmp(f"savevm {SNAP}")
        dt = (time.time() - t0) * 1000
        verdict["savevm"] = True
        log(f"savevm {SNAP} OK in {dt:.0f} ms (out={out.strip()!r})")

        verdict["snap_info"] = q.hmp("info snapshots").strip()
        log("info snapshots:\n" + verdict["snap_info"])

        for i in range(a.restores):
            t0 = time.time()
            out = q.hmp(f"loadvm {SNAP}")
            dt = (time.time() - t0) * 1000
            verdict["loadvm"] = True
            verdict["restores_ms"].append(round(dt, 1))
            log(f"loadvm {SNAP} #{i+1} OK in {dt:.0f} ms (out={out.strip()!r})")

        q.close()
    finally:
        try:
            qemu.terminate()
            qemu.wait(timeout=10)
        except Exception:
            qemu.kill()

    # 5. verdict
    print("\n================ PR0 task-0 verdict ================")
    print(f"booted to login: {verdict['booted']}")
    print(f"savevm works   : {verdict['savevm']}")
    print(f"loadvm works   : {verdict['loadvm']}")
    if verdict["restores_ms"]:
        r = verdict["restores_ms"]
        print(f"restore latency: {r} ms  (min={min(r)} median={sorted(r)[len(r)//2]})")
    print(f"snapshot store : qcow2 overlay (base immutable), no -snapshot flag")
    print("snapshots:\n" + verdict["snap_info"])
    ok = verdict["savevm"] and verdict["loadvm"]
    print(f"\nDISK BLOCKER RESOLVED: {ok}  (savevm/loadvm on qcow2 + KVM, AMD, vendor-neutral)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
