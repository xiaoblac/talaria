#!/usr/bin/env python3
# PR0 footprint sweep: how small/fast can the syz-compatible savevm/loadvm get
# on this AMD box by shrinking the snapshot footprint?
#
# Baseline (savevm_feasibility.py): full Debian boot + KASAN + -m2048 = 820 MiB
# snapshot, ~1.7s restore. snapshot.h says a *quiet* VM is 132-260 MB -> 150-275ms.
# Two levers isolated here:
#   1. userspace boot cost: full systemd boot  vs  init=/bin/sh (proxy for
#      "executor as init" per snapshot.h:29 -> no systemd/sshd/udevd/klogd)
#   2. RAM cap: -m 2048 -> 512 -> 256 (also shrinks KASAN shadow, 1/8 of RAM)
#   3. fewer devices (snapshot.h recommended cmdline)
#
# Each config: fresh qcow2 overlay, boot, savevm syz, loadvm syz x3 (timed),
# record snapshot VM size + median restore. Tabulate.

import json
import os
import re
import socket
import subprocess
import time

ROOT = "/workspace/syzkaller"
KERNEL = f"{ROOT}/kernel/build-kasan/arch/x86/boot/bzImage"
BASE_IMG = "/workspace/images-test-linux5.14/bookworm.img"
RUNDIR = f"{ROOT}/reFuzz/tools/snapshot_pr0/run_sweep"
BASE_APPEND = "root=/dev/sda console=ttyS0 net.ifnames=0 biosdevname=0 nokaslr panic=1 oops=panic"
FEWDEV = ("loop.max_loop=1 dummy_hcd.num=1 vivid.n_devs=2 vivid.multiplanar=1,2 "
          "netrom.nr_ndevs=1 rose.rose_ndevs=1")
SNAP = "syz"


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def qmp_cmd(f, execute, **args):
    msg = {"execute": execute}
    if args:
        msg["arguments"] = args
    f.write(json.dumps(msg) + "\n")
    f.flush()
    while True:
        line = f.readline()
        if not line:
            raise RuntimeError("QMP closed")
        obj = json.loads(line)
        if "return" in obj or "error" in obj:
            if "error" in obj:
                raise RuntimeError(f"{execute} {args}: {obj['error']}")
            return obj["return"]


def hmp(f, cl):
    return qmp_cmd(f, "human-monitor-command", **{"command-line": cl})


def wait_marker(serial, marker, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(serial, "rb") as fh:
                if marker in fh.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(1.0)
    return False


def parse_size_mib(info):
    # "--   syz   820 MiB 2026-..."  or  "245 MiB"
    m = re.search(r"(\d+(?:\.\d+)?)\s*(KiB|MiB|GiB)", info)
    if not m:
        return None
    v = float(m.group(1))
    return {"KiB": v / 1024, "MiB": v, "GiB": v * 1024}[m.group(2)]


def run_config(name, mem, smp, append, marker, boot_timeout=220, settle=4, restores=3):
    d = f"{RUNDIR}/{name}"
    os.makedirs(d, exist_ok=True)
    overlay, serial, qmp_sock = f"{d}/o.qcow2", f"{d}/serial.log", f"{d}/qmp.sock"
    for p in (overlay, serial, qmp_sock):
        if os.path.exists(p):
            os.remove(p)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", BASE_IMG, overlay],
                   check=True, capture_output=True)
    cmd = ["qemu-system-x86_64", "-m", str(mem), "-smp", str(smp), "-display", "none",
           "-no-reboot", "-name", f"pr0-{name}", "-serial", f"file:{serial}",
           "-qmp", f"unix:{qmp_sock},server,nowait", "-enable-kvm",
           "-cpu", "host,migratable=on,tsc=off",
           "-drive", f"file={overlay},if=ide,index=0,media=disk",
           "-kernel", KERNEL, "-append", append]
    res = {"name": name, "mem": mem, "booted": False, "snap_mib": None,
           "savevm_ms": None, "restore_ms": [], "err": None}
    qemu = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        res["booted"] = wait_marker(serial, marker, boot_timeout)
        log(f"  [{name}] boot marker {'ok' if res['booted'] else 'MISS'}")
        if not res["booted"]:
            res["err"] = "no boot marker"
            return res
        time.sleep(settle)
        if qemu.poll() is not None:
            res["err"] = f"qemu exited rc={qemu.returncode}"
            return res
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(qmp_sock)
        f = s.makefile("rw")
        f.readline()  # greeting
        qmp_cmd(f, "qmp_capabilities")
        t0 = time.time()
        hmp(f, f"savevm {SNAP}")
        res["savevm_ms"] = round((time.time() - t0) * 1000)
        res["snap_mib"] = parse_size_mib(hmp(f, "info snapshots"))
        for _ in range(restores):
            t0 = time.time()
            hmp(f, f"loadvm {SNAP}")
            res["restore_ms"].append(round((time.time() - t0) * 1000))
        qmp_cmd(f, "quit")
        s.close()
    except Exception as e:
        res["err"] = str(e)
    finally:
        try:
            qemu.terminate(); qemu.wait(timeout=10)
        except Exception:
            qemu.kill()
    return res


CONFIGS = [
    # name, mem, smp, append, boot-marker
    ("c1_fullboot_m2048", 2048, 1, BASE_APPEND, b"login:"),
    ("c2_shinit_m2048", 2048, 1, BASE_APPEND + " init=/bin/sh", b"Freeing unused kernel image"),
    ("c3_shinit_m512", 512, 1, BASE_APPEND + " init=/bin/sh", b"Freeing unused kernel image"),
    ("c4_shinit_m256_fewdev", 256, 1, BASE_APPEND + " " + FEWDEV + " init=/bin/sh", b"Freeing unused kernel image"),
]


def main():
    os.makedirs(RUNDIR, exist_ok=True)
    results = []
    for name, mem, smp, append, marker in CONFIGS:
        log(f"=== config {name} (mem={mem}) ===")
        results.append(run_config(name, mem, smp, append, marker))
    print("\n================ footprint sweep ================")
    print(f"{'config':24} {'mem':>5} {'boot':>5} {'snapMiB':>8} {'savevm':>7} {'restore(med ms)':>16}")
    base = None
    for r in results:
        med = sorted(r["restore_ms"])[len(r["restore_ms"]) // 2] if r["restore_ms"] else None
        snap = f"{r['snap_mib']:.0f}" if r["snap_mib"] else "-"
        sv = f"{r['savevm_ms']}" if r["savevm_ms"] else "-"
        meds = f"{med} {r['restore_ms']}" if med is not None else (r["err"] or "-")
        print(f"{r['name']:24} {r['mem']:>5} {str(r['booted']):>5} {snap:>8} {sv:>7} {meds:>16}")
        if r["name"].startswith("c1") and med:
            base = (r["snap_mib"], med)
    if base:
        print(f"\nbaseline c1 = {base[0]:.0f} MiB / {base[1]} ms")
        print("target (snapshot.h quiet VM) = 132-260 MiB / 150-275 ms")
    print("================================================")


if __name__ == "__main__":
    main()
