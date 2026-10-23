#!/usr/bin/env python3
"""Build the syz-manager config for one -mode stream-replay run.

Applies exactly the three per-run overrides speed_compare.py's
make_syz_manager_config applies to a capture run -- private empty workdir,
private http port, no corpus carried across runs -- so a replay starts from the
identical machine shape as the capture that produced its stream. Anything else
in the operator's config is left untouched.

The one substitution that matters for measurement is `<run_dir>` inside
qemu_args: that placeholder is what routes the guest's [SyzTL] timeline records
to THIS run's serial file. Without it a replay would append its timeline to the
capture's log and the two would be indistinguishable afterwards.

Prints the config's `syzkaller` root on stdout so the caller can locate
bin/syz-manager without re-parsing the JSON.
"""
import json
import sys


def main(argv):
    if len(argv) != 6:
        sys.exit("usage: materialize_syz_replay_config.py SRC DST WORKDIR RUN_DIR HTTP_ADDR")
    src, dst, workdir, run_dir, http_addr = argv[1:]

    with open(src, encoding="utf-8") as f:
        cfg = json.load(f)

    cfg["workdir"] = workdir
    cfg["http"] = http_addr
    cfg["preserve_corpus"] = False

    vm = cfg.setdefault("vm", {})
    qemu_args = vm.get("qemu_args")
    if not qemu_args:
        sys.exit("syz config has no vm.qemu_args: the guest [SyzTL] timeline would go nowhere")
    qemu_args = str(qemu_args).replace("<run_dir>", run_dir)
    # Both checks guard silent measurement loss rather than a crash: without KVM
    # the replay runs at a different speed than the capture it is compared with,
    # and without the serial chardev the guest timeline is simply never written.
    if "-enable-kvm" not in qemu_args:
        sys.exit(f"syz qemu_args lost -enable-kvm: {qemu_args!r}")
    if "-chardev" not in qemu_args:
        sys.exit("syz qemu_args has no serial chardev: the guest [SyzTL] timeline would go nowhere")
    vm["qemu_args"] = qemu_args

    syz_root = cfg.get("syzkaller")
    if not syz_root:
        sys.exit("syz config has no `syzkaller` root; cannot locate bin/syz-manager")

    with open(dst, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    print(syz_root)


if __name__ == "__main__":
    main(sys.argv)
