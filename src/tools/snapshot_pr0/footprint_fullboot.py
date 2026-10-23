#!/usr/bin/env python3
# Complement to footprint_mfloor.py: does reFuzz's REAL snapshot path (FULL Debian
# boot, systemd, then worker deployed over SSH) survive at reduced -m + fewer
# devices? This is the NO-REFACTOR ceiling -- if full boot survives at low -m, the
# 2x footprint win is just a config change (cmdline -m + device args), no
# worker-as-init refactor. Marker = "login:" (systemd reached getty = full boot OK).

import json, os, re, socket, subprocess, time

ROOT = "/workspace/syzkaller"
KERNEL = f"{ROOT}/kernel/build-kasan/arch/x86/boot/bzImage"
BASE_IMG = "/workspace/images-test-linux5.14/bookworm.img"
RUNDIR = f"{ROOT}/reFuzz/tools/snapshot_pr0/run_fullboot"
BASE_APPEND = "root=/dev/sda console=ttyS0 net.ifnames=0 biosdevname=0 nokaslr panic=1 oops=panic"
FEWDEV = ("loop.max_loop=1 dummy_hcd.num=1 vivid.n_devs=2 vivid.multiplanar=1,2 "
          "netrom.nr_ndevs=1 rose.rose_ndevs=1")
SNAP = "syz"
OK_MARKER = b"login:"
FAIL_MARKERS = [b"Kernel panic", b"kasan_populate_shadow", b"Failed to allocate",
                b"Out of memory", b"Killed process"]


def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def qmp_cmd(f, execute, **args):
    msg = {"execute": execute}
    if args: msg["arguments"] = args
    f.write(json.dumps(msg) + "\n"); f.flush()
    while True:
        line = f.readline()
        if not line: raise RuntimeError("QMP closed")
        obj = json.loads(line)
        if "return" in obj or "error" in obj:
            if "error" in obj: raise RuntimeError(f"{execute}: {obj['error']}")
            return obj["return"]


def hmp(f, cl): return qmp_cmd(f, "human-monitor-command", **{"command-line": cl})


def wait_boot(serial, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(serial, "rb") as fh: blob = fh.read()
            if OK_MARKER in blob: return "ok", ""
            for fm in FAIL_MARKERS:
                if fm in blob: return "fail", fm.decode()
        except FileNotFoundError: pass
        time.sleep(0.5)
    return "timeout", ""


def parse_size_mib(info):
    m = re.search(r"(\d+(?:\.\d+)?)\s*(KiB|MiB|GiB)", info)
    if not m: return None
    v = float(m.group(1))
    return {"KiB": v/1024, "MiB": v, "GiB": v*1024}[m.group(2)]


def run_config(name, mem, append, boot_timeout=200, settle=6, restores=5):
    d = f"{RUNDIR}/{name}"; os.makedirs(d, exist_ok=True)
    overlay, serial, qmp_sock = f"{d}/o.qcow2", f"{d}/serial.log", f"{d}/qmp.sock"
    for p in (overlay, serial, qmp_sock):
        if os.path.exists(p): os.remove(p)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", BASE_IMG, overlay],
                   check=True, capture_output=True)
    cmd = ["qemu-system-x86_64", "-m", str(mem), "-smp", "1", "-display", "none",
           "-no-reboot", "-name", f"pr0-{name}", "-serial", f"file:{serial}",
           "-qmp", f"unix:{qmp_sock},server,nowait", "-enable-kvm",
           "-cpu", "host,migratable=on,tsc=off",
           "-drive", f"file={overlay},if=ide,index=0,media=disk",
           "-kernel", KERNEL, "-append", append]
    res = {"name": name, "mem": mem, "boot": None, "snap_mib": None,
           "savevm_ms": None, "restore_ms": [], "err": None}
    qemu = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        status, detail = wait_boot(serial, boot_timeout)
        res["boot"] = status; log(f"  [{name}] boot={status} {detail}")
        if status != "ok":
            res["err"] = f"boot {status}: {detail}"; return res
        time.sleep(settle)
        if qemu.poll() is not None:
            res["err"] = f"qemu exited rc={qemu.returncode}"; return res
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(qmp_sock)
        f = s.makefile("rw"); f.readline()
        qmp_cmd(f, "qmp_capabilities")
        hmp(f, "migrate_set_capability x-ignore-shared on")
        t0 = time.time(); hmp(f, f"savevm {SNAP}")
        res["savevm_ms"] = round((time.time()-t0)*1000)
        res["snap_mib"] = parse_size_mib(hmp(f, "info snapshots"))
        for _ in range(restores):
            t0 = time.time(); hmp(f, f"loadvm {SNAP}")
            res["restore_ms"].append(round((time.time()-t0)*1000))
        qmp_cmd(f, "quit"); s.close()
    except Exception as e:
        res["err"] = str(e)
    finally:
        try: qemu.terminate(); qemu.wait(timeout=10)
        except Exception: qemu.kill()
    return res


CONFIGS = [
    ("f1_fullboot_m1536",        1536, BASE_APPEND),
    ("f2_fullboot_m1024",        1024, BASE_APPEND),
    ("f3_fullboot_m1024_fewdev", 1024, BASE_APPEND + " " + FEWDEV),
    ("f4_fullboot_m768_fewdev",  768,  BASE_APPEND + " " + FEWDEV),
]


def main():
    os.makedirs(RUNDIR, exist_ok=True)
    results = []
    for name, mem, append in CONFIGS:
        log(f"=== {name} (mem={mem}) ===")
        results.append(run_config(name, mem, append))
    print("\n========== full-boot at reduced -m (no-refactor ceiling) ==========")
    print(f"{'config':28} {'mem':>5} {'boot':>8} {'snapMiB':>8} {'savevm':>7} {'restore med ms':>16}")
    for r in results:
        med = sorted(r["restore_ms"])[len(r["restore_ms"])//2] if r["restore_ms"] else None
        snap = f"{r['snap_mib']:.0f}" if r["snap_mib"] else "-"
        sv = f"{r['savevm_ms']}" if r["savevm_ms"] else "-"
        meds = f"{med}  {r['restore_ms']}" if med is not None else (r["err"] or "-")
        print(f"{r['name']:28} {r['mem']:>5} {str(r['boot']):>8} {snap:>8} {sv:>7} {meds}")
    print("ref: full boot m2048 = 831 MiB / 2267 ms  |  shinit+fewdev m768 = 462 MiB / 1109 ms")
    print("===================================================================")


if __name__ == "__main__":
    main()
