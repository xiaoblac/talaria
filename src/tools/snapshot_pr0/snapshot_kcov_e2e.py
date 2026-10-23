#!/usr/bin/env python3
# PR0 increment 2 (B): run a REAL program in snapshot mode and collect KCOV.
#
# This is the production-execution end-to-end (minus the full reFuzz worker):
# a minimal guest KCOV agent (snap_kcov_agent) is the guest agent; it executes a
# real syscall program under KCOV from the restored snapshot and reports the PC
# count + a coverage hash. We then check the two properties that matter for a
# production snapshot engine:
#   - coverage is REAL    (n > 0 PCs collected for the program)
#   - coverage is STABLE  (same program from the same S0 -> same hash each restore)
#
# Agent delivery = a read-only vvfat disk (QEMU exposes a host dir as a FAT disk;
# no root / base64 / network). Agent signal = serial console (PR0 bootstrap).
# savevm/loadvm via QMP. This is NOT a syscall-parity oracle -- it proves the
# snapshot engine can fuzz (execute + cover), which is why snapshot mode exists.

import json
import os
import re
import select
import shutil
import socket
import subprocess
import time
import uuid

ROOT = "/workspace/syzkaller"
KERNEL = f"{ROOT}/kernel/build-kasan/arch/x86/boot/bzImage"
BASE_IMG = "/workspace/images-test-linux5.14/bookworm.img"
HERE = f"{ROOT}/reFuzz/tools/snapshot_pr0"
RUNDIR = f"{HERE}/run_kcov"
APPEND = ("root=/dev/sda rw console=ttyS0 net.ifnames=0 biosdevname=0 nokaslr "
          "panic=1 oops=panic init=/bin/sh")
SNAP = "S0"


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


class Serial:
    def __init__(self, path, logfile):
        for _ in range(80):
            try:
                self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.s.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.5)
        else:
            raise RuntimeError("serial socket never appeared")
        self.logf = open(logfile, "wb")
        self.buf = b""

    def _pump(self, secs):
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([self.s], [], [], 0.2)
            if r:
                d = self.s.recv(65536)
                if d:
                    self.buf += d
                    self.logf.write(d)
                    self.logf.flush()

    def send(self, line):
        self.s.sendall(line.encode() + b"\n")

    def drain(self, secs=0.5):
        self._pump(secs)
        self.buf = b""

    def wait_for(self, pat, timeout):
        rx = re.compile(pat)
        end = time.time() + timeout
        while time.time() < end:
            m = rx.search(self.buf)
            if m:
                return m
            self._pump(0.3)
        return rx.search(self.buf)

    def shell_ready(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            n = uuid.uuid4().hex[:8]
            self.send(f"echo RDY={n}")
            if self.wait_for(rf"RDY={n}".encode(), 4):
                return True
        return False


class Qmp:
    def __init__(self, path):
        for _ in range(80):
            try:
                self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.s.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.5)
        self.f = self.s.makefile("rw")
        self.f.readline()
        self.cmd("qmp_capabilities")

    def cmd(self, execute, **args):
        msg = {"execute": execute}
        if args:
            msg["arguments"] = args
        self.f.write(json.dumps(msg) + "\n")
        self.f.flush()
        while True:
            line = self.f.readline()
            if not line:
                raise RuntimeError("QMP closed")
            o = json.loads(line)
            if "return" in o:
                return o["return"]
            if "error" in o:
                raise RuntimeError(f"{execute}: {o['error']}")

    def hmp(self, cl):
        return self.cmd("human-monitor-command", **{"command-line": cl})

    def resume(self):
        if self.cmd("query-status").get("status") != "running":
            try:
                self.cmd("cont")
            except Exception:
                pass


def main():
    iters = 5
    os.makedirs(RUNDIR, exist_ok=True)
    stage = f"{RUNDIR}/stage"
    os.makedirs(stage, exist_ok=True)
    shutil.copy(f"{HERE}/snap_kcov_agent", f"{stage}/AGENT")
    # Deliver the agent via a read-only ISO CD-ROM: CD media is read-only so
    # `savevm` skips it (only the rootfs qcow2 is snapshotted), and it is a normal
    # block device (no vvfat internal-snapshot problem that silently broke savevm).
    agent_iso = f"{RUNDIR}/agent.iso"
    subprocess.run(["genisoimage", "-quiet", "-R", "-o", agent_iso, stage],
                   check=True, capture_output=True)

    overlay = f"{RUNDIR}/o.qcow2"
    ser_sock = f"{RUNDIR}/serial.sock"
    qmp_sock = f"{RUNDIR}/qmp.sock"
    ser_log = f"{RUNDIR}/serial.log"
    for p in (overlay, ser_sock, qmp_sock):
        if os.path.exists(p):
            os.remove(p)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", BASE_IMG, overlay],
                   check=True, capture_output=True)

    cmd = ["qemu-system-x86_64", "-m", "2048", "-smp", "1", "-display", "none",
           "-no-reboot", "-name", "pr0-kcov",
           "-chardev", f"socket,id=ser0,path={ser_sock},server=on,wait=off",
           "-serial", "chardev:ser0",
           "-qmp", f"unix:{qmp_sock},server,nowait",
           "-enable-kvm", "-cpu", "host,migratable=on,tsc=off",
           "-drive", f"file={overlay},if=ide,index=0,media=disk",
           "-drive", f"file={agent_iso},format=raw,if=ide,index=1,media=cdrom",
           "-kernel", KERNEL, "-append", APPEND]
    qlog = open(f"{RUNDIR}/qemu.log", "wb")
    log("launching QEMU (vvfat agent disk) ...")
    qemu = subprocess.Popen(cmd, stdout=qlog, stderr=subprocess.STDOUT)

    rows = []
    cov_ok = stable = False
    try:
        ser = Serial(ser_sock, ser_log)
        q = Qmp(qmp_sock)
        log("waiting for /bin/sh ...")
        if not ser.shell_ready(200):
            raise RuntimeError("shell never ready")
        ser.drain(1.0)
        # turn OFF tty echo (else regexes match the echoed command text, not the
        # command OUTPUT -- that produced the bogus XFER=FAIL last run). Mount proc.
        n = uuid.uuid4().hex[:8]
        ser.send("export PATH=/usr/bin:/bin:/usr/sbin:/sbin; stty -echo 2>/dev/null; "
                 "mount -t proc proc /proc 2>/dev/null; echo SETUP=" + n)
        if not ser.wait_for(rf"SETUP={n}".encode(), 10):
            raise RuntimeError("setup/stty failed")
        ser.drain(0.5)

        # clean diagnostics: block devices + vfat support
        n = uuid.uuid4().hex[:8]
        ser.send(f"ls -1 /dev/sd* /dev/sr* 2>&1; echo ISO_SUPPORT; grep iso9660 /proc/filesystems; echo ENDDIAG={n}")
        ser.wait_for(rf"ENDDIAG={n}".encode(), 10)
        log("diag:\n" + ser.buf.decode(errors="replace").strip())
        ser.buf = b""

        # mount the agent CD-ROM (iso9660, /dev/sr0), stage agent, report REAL rc.
        n = uuid.uuid4().hex[:8]
        ser.send("mkdir -p /mnt; rm -f /tmp/me; "
                 "mount -t iso9660 -o ro /dev/sr0 /mnt 2>/tmp/me; "
                 "MR=$?; cp /mnt/AGENT /tmp/agent 2>>/tmp/me; CR=$?; chmod +x /tmp/agent 2>/dev/null; "
                 f"echo XRES mr=$MR cr=$CR sz=$(wc -c < /tmp/agent 2>/dev/null) N={n}; "
                 "echo MERRBEG; cat /tmp/me 2>/dev/null; echo MERREND")
        m = ser.wait_for(rf"XRES mr=(\d+) cr=(\d+) sz=(\d*) N={n}".encode(), 20)
        if not m:
            raise RuntimeError("no XRES reply")
        mr, cr, sz = m.group(1).decode(), m.group(2).decode(), m.group(3).decode()
        e = ser.wait_for(rb"MERRBEG\n([\s\S]*?)MERREND", 5)
        log(f"transfer: mount_rc={mr} cp_rc={cr} sz={sz}  err={(e.group(1).decode().strip() if e else '')!r}")
        if cr != "0" or not sz or sz == "0":
            raise RuntimeError("agent transfer failed (see diag/err above)")
        log("agent staged OK")
        ser.buf = b""

        # run the agent (foreground child of the shell -> owns ttyS0).
        ser.drain(0.5)
        ser.send("/tmp/agent")
        m = ser.wait_for(rb"AGENT_(READY|ERR)[^\n]*", 20)
        if not m or b"READY" not in m.group(0):
            raise RuntimeError(f"agent did not become ready: {m.group(0) if m else None}")
        log(f"agent ready: {m.group(0).decode()}")

        t0 = time.time()
        sv = q.hmp(f"savevm {SNAP}")
        q.resume()
        snaps = q.hmp("info snapshots").strip()
        log(f"savevm {SNAP} ({(time.time()-t0)*1000:.0f} ms) out={sv.strip()!r}; {snaps.splitlines()[-1]}")
        if SNAP not in snaps or not re.search(r"\d+\s*(MiB|GiB)", snaps):
            raise RuntimeError(f"savevm did NOT create a snapshot (vvfat blocking it?): "
                               f"out={sv!r} snaps={snaps!r}")

        for i in range(1, iters + 1):
            dt = 0.0
            if i > 1:
                t0 = time.time()
                q.hmp(f"loadvm {SNAP}")
                dt = (time.time() - t0) * 1000
                q.resume()
                ser.drain(0.4)
            n = uuid.uuid4().hex[:8]
            ser.send("RUN")
            m = ser.wait_for(rb"COV n=(\d+) hash=([0-9a-f]+)", 15)
            if not m:
                rows.append((i, None, None, dt))
                log(f"iter {i}: NO COV reply")
                break
            pcs, h = int(m.group(1)), m.group(2).decode()
            rows.append((i, pcs, h, dt))
            log(f"iter {i}: KCOV n={pcs} hash={h} (loadvm {dt:.0f} ms)")
            ser.buf = b""  # clear so next iter's COV match is fresh

        good = [r for r in rows if r[1] is not None]
        cov_ok = bool(good) and all(r[1] > 0 for r in good) and len(good) == iters
        stable = cov_ok and len({r[2] for r in good}) == 1
    finally:
        try:
            qemu.terminate(); qemu.wait(timeout=10)
        except Exception:
            qemu.kill()

    print("\n============ snapshot KCOV end-to-end ============")
    print(f"{'iter':>4} {'KCOV PCs':>9} {'hash':>18} {'loadvm ms':>10}")
    for i, pcs, h, dt in rows:
        print(f"{i:>4} {('-' if pcs is None else pcs):>9} {(h or '-'):>18} {dt:>10.0f}")
    print(f"\nreal coverage collected (all n>0): {cov_ok}")
    print(f"coverage STABLE across restores  : {stable}")
    print("=> snapshot mode executed a REAL program and produced "
          + ("real, stable KCOV." if stable else "KCOV (see above)."))
    print("==================================================")
    return 0 if cov_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
