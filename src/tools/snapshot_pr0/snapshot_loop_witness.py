#!/usr/bin/env python3
# PR0 increment 1: the syzkaller-style snapshot LOOP, host side, proven with a
# state-isolation witness (the doc PR1 correctness gate).
#
# Mechanism (mirrors vm/qemu/snapshot_linux.go, minus ivshmem):
#   boot VM -> shell ready at a clean point -> `savevm S0`
#   per iteration:  [run a state-mutating+checking command]  then  `loadvm S0`
#   isolation holds IFF every iteration sees the post-S0 state as PRISTINE
#   (the mutation from the previous iteration was wiped by the restore).
#
# Agent transport here = the serial console (PR0 bootstrap; doc §7 allows
# virtio-serial/stdout for the agent ABI before ivshmem is wired). This also
# answers a real PR0 design question: does a serial-based agent survive `loadvm`,
# or do we need ivshmem? (syzkaller uses ivshmem; we test the cheap path first.)
#
# Witness command each iter:
#   P=lines(/tmp/W before append);  append one line;  report PRE=P POST=after N=<nonce>
# Isolation  => every iter PRE=0 POST=1.
# Leak       => PRE grows 0,1,2,...  (restore did not wipe guest state)

import json
import os
import re
import select
import socket
import subprocess
import time
import uuid

ROOT = "/workspace/syzkaller"
KERNEL = f"{ROOT}/kernel/build-kasan/arch/x86/boot/bzImage"
BASE_IMG = "/workspace/images-test-linux5.14/bookworm.img"
RUNDIR = f"{ROOT}/reFuzz/tools/snapshot_pr0/run_witness"
APPEND = ("root=/dev/sda rw console=ttyS0 net.ifnames=0 biosdevname=0 nokaslr "
          "panic=1 oops=panic init=/bin/sh")
SNAP = "S0"


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


class Serial:
    """Client to QEMU's serial chardev unix socket: drain + run_cmd via nonce."""

    def __init__(self, path, logfile):
        self.path = path
        self.logf = open(logfile, "wb")
        for _ in range(60):
            try:
                self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.s.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.5)
        else:
            raise RuntimeError("serial socket never appeared")
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

    def wait_for(self, pattern, timeout):
        """Pump serial until regex `pattern` (bytes) seen; return match or None."""
        rx = re.compile(pattern)
        end = time.time() + timeout
        while time.time() < end:
            m = rx.search(self.buf)
            if m:
                return m
            self._pump(0.3)
        return rx.search(self.buf)

    def shell_ready(self, timeout):
        """Probe the /bin/sh on ttyS0 until it echoes our nonce back."""
        end = time.time() + timeout
        while time.time() < end:
            n = uuid.uuid4().hex[:8]
            self.send(f"echo RDY={n}")
            if self.wait_for(rf"RDY={n}".encode(), 4):
                return True
        return False


class Qmp:
    def __init__(self, path):
        for _ in range(60):
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

    def status(self):
        return self.cmd("query-status").get("status", "?")

    def resume(self):
        if self.status() != "running":
            try:
                self.cmd("cont")
            except Exception:
                pass
        return self.status()


def witness_cmd(nonce):
    return (f"P=$(wc -l < /tmp/W 2>/dev/null || echo 0); echo x >> /tmp/W; "
            f"echo RES PRE=$P POST=$(wc -l < /tmp/W) N={nonce}")


def main():
    iters = 6
    os.makedirs(RUNDIR, exist_ok=True)
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
           "-no-reboot", "-name", "pr0-witness",
           "-chardev", f"socket,id=ser0,path={ser_sock},server=on,wait=off",
           "-serial", "chardev:ser0",
           "-qmp", f"unix:{qmp_sock},server,nowait",
           "-enable-kvm", "-cpu", "host,migratable=on,tsc=off",
           "-drive", f"file={overlay},if=ide,index=0,media=disk",
           "-kernel", KERNEL, "-append", APPEND]
    log("launching QEMU (serial-agent snapshot loop) ...")
    qemu = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    rows = []
    ok = False
    try:
        ser = Serial(ser_sock, ser_log)
        q = Qmp(qmp_sock)
        log("waiting for /bin/sh on ttyS0 ...")
        if not ser.shell_ready(200):
            raise RuntimeError("shell never became ready on serial")
        log("shell ready. setting PATH + clean state (baked into S0) ...")
        ser.drain(1.0)
        n = uuid.uuid4().hex[:8]
        ser.send("export PATH=/usr/bin:/bin:/usr/sbin:/sbin; rm -f /tmp/W; echo SETUP=" + n)
        if not ser.wait_for(rf"SETUP={n}".encode(), 10):
            raise RuntimeError("setup echo not seen")

        # pre-savevm sanity: does the witness command work on the LIVE guest?
        # If this fails it's a guest-env issue (PATH/tools/rw), NOT snapshot.
        n = uuid.uuid4().hex[:8]
        ser.send(witness_cmd(n))
        m = ser.wait_for(rf"RES PRE=(\d+) POST=(\d+) N={n}".encode(), 12)
        if not m:
            raise RuntimeError("pre-savevm witness gave no parseable reply "
                               "=> guest env issue (PATH/tools/rw), not snapshot")
        log(f"pre-savevm sanity: PRE={m.group(1).decode()} POST={m.group(2).decode()} (env OK)")
        n = uuid.uuid4().hex[:8]
        ser.send(f"rm -f /tmp/W; echo RST={n}")
        ser.wait_for(rf"RST={n}".encode(), 10)

        t0 = time.time()
        q.hmp(f"savevm {SNAP}")
        log(f"savevm {SNAP} OK ({(time.time()-t0)*1000:.0f} ms), runstate={q.resume()}; VM SIZE:")
        log(q.hmp("info snapshots").strip().splitlines()[-1])

        for i in range(1, iters + 1):
            if i > 1:
                t0 = time.time()
                q.hmp(f"loadvm {SNAP}")
                dt = (time.time() - t0) * 1000
                st = q.resume()
                ser.drain(0.4)  # toss stale post-restore bytes
            else:
                dt = 0.0
                st = q.status()
            n = uuid.uuid4().hex[:8]
            ser.send(witness_cmd(n))
            m = ser.wait_for(rf"RES PRE=(\d+) POST=(\d+) N={n}".encode(), 12)
            if not m:
                rows.append((i, None, None, dt, f"no reply (runstate={st})"))
                log(f"iter {i}: NO reply (runstate={st})")
                if i > 1:
                    break
                continue
            pre, post = int(m.group(1)), int(m.group(2))
            rows.append((i, pre, post, dt, f"runstate={st}"))
            log(f"iter {i}: PRE={pre} POST={post} (loadvm {dt:.0f} ms, {st})")

        good = [r for r in rows if r[1] is not None]
        ok = bool(good) and all(r[1] == 0 and r[2] == 1 for r in good) and len(good) == iters
    finally:
        try:
            qemu.terminate(); qemu.wait(timeout=10)
        except Exception:
            qemu.kill()

    print("\n============ snapshot loop witness ============")
    print(f"{'iter':>4} {'PRE':>4} {'POST':>4} {'loadvm ms':>10}  note")
    for i, pre, post, dt, note in rows:
        pres = "-" if pre is None else pre
        posts = "-" if post is None else post
        print(f"{i:>4} {str(pres):>4} {str(posts):>4} {dt:>10.0f}  {note}")
    print("\nExpected if state-isolated: every iter PRE=0 POST=1")
    print("  PRE growing 0,1,2.. => restore did NOT wipe state (leak)")
    print("  missing replies after iter1 => serial agent did NOT survive loadvm")
    print(f"\nSTATE ISOLATION WITNESS PASS: {ok}")
    print("===============================================")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
