#!/usr/bin/env python3
# VMI probe — does reading guest RAM at a wedge surface more than the console?
#
# syz snapshot crash detection (verified upstream master) = mgr.reporter.
# ContainsCrash(console output); ssh dies once restores start. So a SILENT hang
# (no console output) is invisible to syz, and console is the only window.
#
# This probe shows host-only VMI (no ssh / no agent / no guest cooperation) reads:
#   (1) the printk ring __log_buf straight from guest RAM (QMP memsave), and
#   (2) the live kernel PC (QMP info registers), resolved via System.map,
# on a FROZEN guest (HMP `stop` = simulate the wedge / snapshot-pause), and
# compares the printk message set recovered from RAM vs what reached the console.
#
# Knobs: console loglevel=4 -> kernel sends only <4 (EMERG..ERR) to the serial
# console; INFO/NOTICE/etc stay in __log_buf but never hit console = a clean,
# attributable "RAM has it, console doesn't" delta.

import json, os, re, socket, subprocess, time

ROOT = "/workspace/syzkaller"
KERNEL = f"{ROOT}/kernel/build-kasan/arch/x86/boot/bzImage"
SYSMAP = f"{ROOT}/kernel/build-kasan/System.map"
BASE_IMG = "/workspace/images-test-linux5.14/bookworm.img"
RUNDIR = f"{ROOT}/reFuzz/tools/snapshot_pr0/run_vmi"
APPEND = ("root=/dev/sda console=ttyS0 net.ifnames=0 biosdevname=0 nokaslr "
          "panic=1 oops=panic loglevel=4")
LOG_BUF_VADDR = 0xffffffff9aee8d00   # nm vmlinux __log_buf
DUMP_SIZE = 0x200000                  # 2 MiB (covers LOG_BUF_SHIFT <= 21)


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


def wait_marker(serial, marker, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(serial, "rb") as fh:
                if marker in fh.read(): return True
        except FileNotFoundError: pass
        time.sleep(0.5)
    return False


def load_sysmap():
    syms = []  # (addr, name)
    with open(SYSMAP) as fh:
        for ln in fh:
            p = ln.split()
            if len(p) >= 3 and p[1] in "tT":
                try: syms.append((int(p[0], 16), p[2]))
                except ValueError: pass
    syms.sort()
    return syms


def resolve(syms, addr):
    import bisect
    addrs = [a for a, _ in syms]
    i = bisect.bisect_right(addrs, addr) - 1
    if i < 0: return "?"
    a, n = syms[i]
    return f"{n}+0x{addr - a:x}"


def console_msgs(serial):
    # printk lines on the console look like "[   12.345678] message".
    msgs = set()
    try:
        data = open(serial, "rb").read().decode("utf-8", "replace")
    except FileNotFoundError:
        return msgs
    for ln in data.splitlines():
        m = re.search(r"\]\s*(.*)$", ln)
        txt = (m.group(1) if m else ln).strip()
        # strip ANSI
        txt = re.sub(r"\x1b\[[0-9;]*m", "", txt).strip()
        if len(txt) >= 8:
            msgs.add(txt)
    return msgs


def rambuf_msgs(dump):
    # __log_buf text data ring: message bodies stored as plain text. `strings`
    # recovers them. Filter to plausible kernel-message lines.
    out = subprocess.run(["strings", "-n", "8", dump], capture_output=True, text=True)
    msgs = set()
    for s in out.stdout.splitlines():
        s = s.strip()
        if 8 <= len(s) <= 400 and re.search(r"[a-zA-Z]", s):
            msgs.add(s)
    return msgs


def main():
    os.makedirs(RUNDIR, exist_ok=True)
    overlay, serial, qmp_sock = f"{RUNDIR}/o.qcow2", f"{RUNDIR}/serial.log", f"{RUNDIR}/qmp.sock"
    dump = f"{RUNDIR}/logbuf.bin"
    for p in (overlay, serial, qmp_sock, dump):
        if os.path.exists(p): os.remove(p)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", BASE_IMG, overlay],
                   check=True, capture_output=True)
    cmd = ["qemu-system-x86_64", "-m", "2048", "-smp", "1", "-display", "none",
           "-no-reboot", "-serial", f"file:{serial}",
           "-qmp", f"unix:{qmp_sock},server,nowait", "-enable-kvm",
           "-cpu", "host", "-drive", f"file={overlay},if=ide,index=0,media=disk",
           "-kernel", KERNEL, "-append", APPEND]
    qemu = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    res = {"booted": False, "rip": None, "rip_sym": None}
    try:
        res["booted"] = wait_marker(serial, b"login:", 200)
        log(f"boot={'ok' if res['booted'] else 'MISS'}")
        if not res["booted"]:
            return res
        time.sleep(4)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(qmp_sock)
        f = s.makefile("rw"); f.readline()
        qmp_cmd(f, "qmp_capabilities")
        # Freeze the guest = simulate a wedge / the snapshot-pause. Console now
        # silent; ssh would be dead. VMI must work purely from the host.
        hmp(f, "stop")
        # (1) printk ring from guest RAM. Translate __log_buf vaddr->gpa via HMP
        # gva2gpa, then read physical RAM via NATIVE QMP pmemsave (typed JSON
        # args — avoids the HMP expression lexer choking on the '/home' path).
        r_g = hmp(f, f"gva2gpa 0x{LOG_BUF_VADDR:x}")
        log(f"gva2gpa ret: {r_g.strip()[:200]!r}")
        mg = re.search(r"gpa:\s*0x([0-9a-fA-F]+)", r_g)
        if mg:
            gpa = int(mg.group(1), 16)
            res["gpa"] = gpa
            try:
                qmp_cmd(f, "pmemsave", val=gpa, size=DUMP_SIZE, filename=dump)
                log(f"pmemsave OK gpa=0x{gpa:x} size={DUMP_SIZE} -> {dump}")
            except Exception as e:
                log(f"pmemsave ERR {e}")
        # (2) live kernel PC
        regs = hmp(f, "info registers")
        m = re.search(r"RIP=([0-9a-fA-F]+)", regs)
        if m: res["rip"] = int(m.group(1), 16)
        qmp_cmd(f, "quit"); s.close()
    except Exception as e:
        res["err"] = str(e); log(f"ERR {e}")
    finally:
        try: qemu.terminate(); qemu.wait(timeout=10)
        except Exception: qemu.kill()

    # ---- analysis ----
    if res["rip"]:
        VMLINUX = f"{ROOT}/kernel/build-kasan/vmlinux"
        try:
            a2l = subprocess.run(["addr2line", "-e", VMLINUX, "-f", f"0x{res['rip']:x}"],
                                 capture_output=True, text=True, timeout=30)
            res["rip_sym"] = " ".join(a2l.stdout.split())
        except Exception as e:
            res["rip_sym"] = f"<addr2line failed: {e}>"
    cmsgs = console_msgs(serial)
    rmsgs = rambuf_msgs(dump) if os.path.exists(dump) else set()
    # RAM-only = recovered from __log_buf but never reached the console.
    ram_only = sorted(rmsgs - cmsgs)
    print("\n================ VMI probe result ================")
    print(f"boot={res['booted']}  dump={os.path.getsize(dump) if os.path.exists(dump) else 0} bytes")
    print(f"console printk messages (serial.log)      : {len(cmsgs)}")
    print(f"printk messages recovered from RAM(__log_buf): {len(rmsgs)}")
    print(f"RAM-only (in __log_buf, NEVER on console)  : {len(ram_only)}")
    print(f"live kernel PC (frozen guest): RIP=0x{res['rip']:x} -> {res['rip_sym']}"
          if res["rip"] else "RIP: <unread>")
    print("\n-- sample of messages VMI recovered that console NEVER showed --")
    for s in ram_only[:25]:
        print(f"   {s}")
    print("==================================================")


if __name__ == "__main__":
    main()
