#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# s4 PROOF MODEL: decompose every s4_no_anchor variant (has a specific fd/sock but no anchor).
#
# Important invariant: cmd coverage is NOT production-path evidence.  A cmd row proves that some dispatch
# code exists in this kernel; it does not prove that this resource's producer path installs the relevant
# fops/proto_ops.  Therefore DEVNODE resources are only recoverable here when the producer path has a
# registration/fops structural signal.  Otherwise they remain TBD instead of being called honest gaps.
#
# Classification signals (all structural, never binding):
#   - fops-named: the syz auto-name encodes a kernel ops symbol that IS a REG row -> compiled, recoverable
#     (the fd's dispatch table exists; we need the production recognizer, e.g. fs-inode-fops or a cdev idiom)
#   - dev-registered: the producer's /dev path appears in a known device registration (misc/cdev/devnode)
#
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model.variant import build_reg_rows, resource_kind_map, specific_predicate
from provenance.devnode import load_open_variant_devpaths, norm_devpath
from provenance.fd import _load_facts, _fops_rows

SH = "run/seed_horizon"


def main():
    hm = json.load(open(f"{SH}/horizon_model.json"))
    reg_rows = build_reg_rows(SH)
    specific = specific_predicate(hm)
    res_kinds = resource_kind_map(hm)
    opd = load_open_variant_devpaths(hm)
    misc, anon = _load_facts(".")
    by_fops = _fops_rows(reg_rows)
    # every kernel ops symbol that has a dispatch-bearing REG row = "exists/compiled"
    ops_symbols = {ops for ops in by_fops}
    ops_symbols |= {reg_rows[i][2] for i in range(len(reg_rows))
                    if reg_rows[i][0] in ("fops", "proto_ops", "proto", "cdev", "anon", "misc", "chrdev",
                                          "bdev", "drm", "snd", "usb") and reg_rows[i][2] not in ("-", "")}
    # device paths we DO have a registration for (misc + cdev-path)
    registered_paths = {norm_devpath("/dev/" + name) for name in misc}
    registered_paths.discard(None)
    if os.path.exists(f"{SH}/cdev_paths.tsv"):
        cdev_leaf = collections.defaultdict(set)
        for ln in open(f"{SH}/cdev_paths.tsv"):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "DEVPATH" and len(c) >= 3:
                registered_paths.add(c[1])
                cdev_leaf[c[1].rsplit("/", 1)[-1]].add(c[2])
        registered_paths.update("/leaf/" + leaf for leaf, fops in cdev_leaf.items() if len(fops) == 1)

    # fops with no REAL handler (every field '-'): a registered device that is a pure capability token
    # (/dev/sgx_provision is opened only to pass the fd to SGX_IOC_ENCLAVE_PROVISION -- it has no ops of its
    # own).  Fully modeled, nothing to dispatch -> honest, not a recoverable gap.
    empty_fops = {reg_rows[i][2] for i in range(len(reg_rows))
                  if reg_rows[i][2] and reg_rows[i][2] != "-"
                  and not any(v and v != "-" for v in (reg_rows[i][3] or {}).values())}

    prod = collections.defaultdict(list)
    for s in hm["syscalls"]:
        for r in (s.get("produces") or []):
            prod[r].append(s["name"])

    def mech(r, paths):
        ps = prod.get(r, [])
        bases = {p.split("$", 1)[0] for p in ps}
        if bases & {"openat", "syz_open_dev", "open", "openat2"}:
            if any(p.startswith("/dev/") for p in paths):
                return "DEVNODE"
            if any(p.startswith("/sys/kernel/debug/") for p in paths):
                return "DEBUGFS"
            return "FS"
        if bases & {"socket", "socketpair", "syz_init_net_socket"}:
            return "SOCKET"
        if any("CREATE" in p or p.split("$", 1)[0] in (
                "io_uring_setup", "eventfd", "eventfd2", "signalfd", "timerfd_create", "userfaultfd",
                "memfd_create", "perf_event_open", "bpf", "fanotify_init", "inotify_init",
                "epoll_create", "epoll_create1", "pidfd_open", "fsopen", "fspick") for p in ps):
            return "ANON"
        return "OTHER"

    def fops_named(r):
        # the syz auto-name fd_<ops>_<struct> encodes the kernel ops symbol as the LEADING token; match it
        # as a prefix, not a substring, so an unrelated ops that merely appears mid-name (dev_fops inside
        # bch_chardev_fops, whose real bch_chardev_fops is NOT compiled) is rejected -- otherwise an honest
        # not-compiled device is miscounted as recoverable.  If the leading ops IS a REG row the device is
        # compiled and its dispatch table exists -> recoverable (NOT used for binding).
        body = r[3:] if r.startswith("fd_") else r
        cands = [o for o in ops_symbols if body == o or body.startswith(o + "_")]
        return max(cands, key=len) if cands else None

    def devpaths(r):
        out = set()
        for p in prod.get(r, []):
            out |= opd.get(p, set())
        return out

    # --- Verified OUT-OF-TREE drivers (absent from THIS build's bitcode) -> HONEST, not TBD -------------
    # PowerVR (/dev/img-rogue) and ARM Mali (/dev/bifrost, /dev/mali#, and the kbase hwcnt/kinstr ioctl
    # nodes) ship out-of-tree: syzkaller describes their ioctls, but the driver source is NOT compiled into
    # this kernel, so no producer path or fops can EVER be recovered -- a proven gap, not a model gap.
    # Re-verify absence (must stay 0 batches each) with:
    #   grep -rlIa 'img-rogue\|PVRSRV\|rogue\|bifrost\|mali_kbase\|KBASE' run/seed_horizon/kernel_linked/batches/*.bc
    # (the naive "kbase" substring hits ~293 batches, but they are unrelated noise: mali_kbase/KBASE/bifrost
    #  all resolve to 0.)  Matched on the /dev path token + the fd_<token> resource so it survives renames.
    _OOT_PATH = ("img-rogue", "bifrost", "mali", "tlk_device")  # distinctive /dev path substrings
    _OOT_RES = ("rogue", "bifrost", "mali", "hwcnt", "kinstr",  # fd_<token> for the devpath-less kbase nodes
                "tlk")                                          # Tegra Trusted Little Kernel (te_handle_command=0)

    def is_out_of_tree(r, dp):
        body = r[3:] if r.startswith("fd_") else r
        if any(body == tok or body.startswith(tok + "_") for tok in _OOT_RES):
            return True
        if any(any(tok in p for tok in _OOT_PATH) for p in dp):
            return True
        # a devpath-less anon fd produced ONLY by out-of-tree syscalls (Mali kbase fence/stream fds, whose
        # producing KBASE_* ioctl is absent from this build) can never be created here -> proven gap, not a
        # recoverable anon-chain: its fops does not exist in the bitcode.
        prods = prod.get(r, [])
        return bool(prods) and all(any(t in p for t in ("KBASE", "kbase", "mali", "bifrost")) for p in prods)

    # --- Verified NOT-IN-BUILD: mainline drivers whose code is absent from THIS build's built-in bitcode --
    # (config=n, or =m module -- the batch set is built-in only, so a .ko's bitcode is never analyzed).
    # Distinct from out-of-tree: these ARE in the kernel tree, but the fuzzed kernel did not compile them
    # in, so no producer path/fops can be recovered here.  Recovering the =m ones would require Phase-2
    # module-bitcode ingestion; =n ones are proven gaps.  Verified 0 batches define the driver's functions:
    #   grep -rlIa 'floppy_check_events\|bch2_fs_open\|capi20_isinstalled\|ublk_add_dev\|msm_drm_init\|
    #     acpi_thermal_rel_open\|ashmem_ioctl\|smk_load_ops\|sel_write_load' run/seed_horizon/.../batches/*.bc
    _NIB_DEV = ("/dev/fd#", "/dev/bcachefs-ctl", "/dev/capi#", "/dev/msm",
                "/dev/ublk-control", "/dev/ublkc#", "/dev/ublkb#", "/dev/ashmem",
                "/dev/acpi_thermal_rel", "/dev/vfio/vfio",       # vfio container (vfio_fops=0, =m module)
                "/dev/vtpmx",                                    # vTPM proxy driver (vtpmx_fops=0 batches)
                "/dev/sev",                                      # AMD SEV (sev_ioctl/sev_misc_dev=0 batches)
                "/dev/trusty-ipc-dev#")                          # Trusty TEE ipc (trusty_ipc/tipc_open=0)
    _NIB_PFX = ("/sys/fs/smackfs/", "/selinux/")   # SMACK/SELinux LSM fs -- their own filesystems, =n here

    # Verified NOT-IN-BUILD by RESOURCE NAME (these carry no devpath, so the _NIB_DEV/_NIB_PFX devpath match
    # cannot fire).  Matched on the fd_<token> body substring, each backed by a 0-batch symbol grep:
    #   smackfs / smk_ : SMACK LSM securityfs -- smk_open_load/smack_net4addr/smk_write_load/smack_fill_super
    #                    = 0 batches; SMACK is not the built LSM, so its /sys/fs/smackfs/* file ops never
    #                    exist.  (NOT bare "smack": fd_smack_current is /proc/self/attr/current, a proc_pid_attr
    #                    file that exists under any LSM -- recovered by the proc TFOP path join.)
    #   damon          : DAMON debugfs interface was REMOVED upstream (v6.9+); damon_dbgfs = 0 batches,
    #                    so /sys/kernel/debug/damon/* has no producer here (a proven gap, not TBD).
    #   selinux        : SELinux LSM securityfs (/sys/fs/selinux/*) -- sel_write_load/sel_make_dir/
    #                    selinux_fs_info = 0 batches (not the built LSM).  fd_selinux_attr is EXCLUDED: it is
    #                    /proc/self/attr/*, a proc_pid_attr file recovered by the proc TFOP path join.
    #   trusty         : Trusty TEE (ARM, /dev/trusty-ipc-dev*) -- trusty_ipc_open/trusty_dev_init = 0 batches.
    _NIB_RES = ("smackfs", "smk_", "damon", "selinux", "trusty")

    # Verified COMPILED but not yet anchored: the dispatch table exists in this build, but the production
    # recognizer for its registration idiom is not written.  Recoverable model gap (not honest, not TBD-unknown):
    #   cgroup : the fd_cgroup DIRECTORY fd only (kernfs dir ops -- coarse, low value); the control-file
    #            resources are recovered by provenance/cgroup.py and no longer reach s4.
    # Now-recovered idioms (gone from s4, kept here as provenance): cgroup control files (cgroup.py),
    # binfmt_misc register/entry + dma_heap (structural mount-relative/dynamic-dentry/runtime-name methods).
    _RECOVER_KNOWN = {"cgroup": "kernfs-dir-ops (cgroup dir fd)"}

    def is_not_in_build(dp):
        return any(p in _NIB_DEV or any(p.startswith(x) for x in _NIB_PFX) for p in dp)

    def res_body(r):
        return r[3:] if r.startswith("fd_") else r

    # s4 variants from the funnel
    s4 = []
    with open(f"{SH}/candidate_trace.tsv") as f:
        header = f.readline().lstrip("#").rstrip("\n").split("\t")
        for ln in f:
            c = ln.rstrip("\n").split("\t")
            row = dict(zip(header, c))
            if row.get("fail_stage") == "s4_no_anchor":
                s4.append((row["variant"], [x.rstrip("…") for x in row["ctx_res"].split(",")
                                             if x and x != "-"]))

    res_n = collections.Counter()
    res_var = {}
    for v, rs in s4:
        for r in rs:
            res_n[r] += 1
            res_var.setdefault(r, v)

    def classify(r):
        dp = devpaths(r)
        body = res_body(r)
        if is_out_of_tree(r, dp):
            return "HONEST:out-of-tree", ",".join(sorted(dp))[:34] or "-"
        if is_not_in_build(dp) or any(tok in body for tok in _NIB_RES):
            return "HONEST:not-in-build", ",".join(sorted(dp))[:34] or "-"
        for tok, ev in _RECOVER_KNOWN.items():
            if body == tok or body.startswith(tok):
                return "RECOVER:known-compiled", ev
        # a bare directory fd (openat$dir / openat$auto / the syz_mount_image$* root) has no single dispatch
        # table: its ->ioctl (FS_IOC_* fscrypt/fileattr) is resolved per-mounted-filesystem at runtime, and
        # several producing filesystems (reiserfs/sysv/v7) are not built here -- not a recoverable static anchor.
        if r == "fd_dir":
            return "HONEST:generic-dir", "-"
        # fd_binfmt is not a binfmt_misc control file: openat$binfmt opens a runtime filename that
        # write$binfmt_elf*/execveat drive the execve binary-loader (search_binary_handler) through -- a
        # linux_binfmt dispatch, not an fd fops.  No recoverable fd-fops anchor.
        if r == "fd_binfmt":
            return "HONEST:execve-binfmt", "-"
        # verified-honest residual (0-batch or runtime dispatch, not an fd-fops the analysis can recover):
        if body.startswith("char_usb"):     # /dev char major 180: the fops is the per-driver minor's, runtime
            return "HONEST:runtime-char", "-"
        if r == "sock_hf":                   # AF_HF Hafnium hypervisor socket -- 0 batches (out-of-tree)
            return "HONEST:out-of-tree", "AF_HF"
        if r == "nvme_sock":                 # plain inet TCP socket; NVMe/TCP is a userspace protocol over it
            return "HONEST:generic-socket", "-"
        if r == "sock_algconn":              # AF_ALG accept() installs the alg-type ops at runtime (hash/skcipher)
            return "HONEST:runtime-socket", "-"
        m = mech(r, dp)
        fn = fops_named(r)
        if fn:
            # the dispatch table exists in this kernel -> recoverable; which production?
            kind = next((reg_rows[i][0] for i in by_fops.get(fn, [])), "?")
            if m == "DEBUGFS" or "debugfs" in r:
                return "RECOVER:debugfs-fops", fn
            if (m == "FS" or "inode" in r or kind in ("bdev",) or "_dir_" in fn or "_file_" in fn
                    or r.endswith(("_fs", "_inode"))):
                return "RECOVER:fs-inode-fops", fn
            if m == "DEVNODE":
                return "RECOVER:device-cdev", fn
            if m == "ANON":
                return "RECOVER:anon-chain", fn
            return "RECOVER:ops-symbol", fn
        if m == "SOCKET":
            return "SOCKET:family", "-"
        if m == "ANON":
            return "RECOVER:anon-chain", "-"
        if m == "FS":
            return "TBD:fs-open", ",".join(sorted(dp))[:34] or "-"
        if m == "DEBUGFS":
            return "TBD:debugfs-unregistered", ",".join(sorted(dp))[:34] or "-"
        if m == "DEVNODE":
            dp_leaf = {"/leaf/" + p.rsplit("/", 1)[-1] for p in dp}
            if dp & registered_paths or dp_leaf & registered_paths:
                if any(misc.get(p.rsplit("/", 1)[-1]) in empty_fops for p in dp):
                    return "HONEST:token-device", ",".join(sorted(dp))[:34] or "-"
                return "RECOVER:dev-registered", ",".join(sorted((dp & registered_paths) | (dp_leaf & registered_paths)))
            return "TBD:devnode-unregistered", ",".join(sorted(dp))[:34] or "-"
        return "OTHER:" + m, "-"

    bucket = collections.Counter()
    bucket_res = collections.defaultdict(list)
    for r, n in res_n.items():
        cls, ev = classify(r)
        bucket[cls] += n
        bucket_res[cls].append((r, n, ev))

    print(f"# s4 proof model: {len(s4)} variants, {len(res_n)} distinct resources, {sum(res_n.values())} slots\n")
    print("# CLASS  (RECOVER = model gap, keep recovering; HONEST = proven gap):")
    for cls, n in bucket.most_common():
        tag = "RECOVER" if cls.startswith("RECOVER") else ("HONEST" if cls.startswith("HONEST") else "TBD")
        print(f"   [{tag:7}] {cls:26} {n:5}")
    recover = sum(n for c, n in bucket.items() if c.startswith("RECOVER"))
    honest = sum(n for c, n in bucket.items() if c.startswith("HONEST"))
    tbd = sum(res_n.values()) - recover - honest
    print(f"\n#   RECOVERABLE: {recover}   HONEST(proven): {honest}   TBD(socket/other): {tbd}")
    for cls in sorted(bucket, key=lambda c: -bucket[c]):
        print(f"\n# {cls} — top resources:")
        for r, n, ev in sorted(bucket_res[cls], key=lambda x: -x[1])[:8]:
            print(f"    {r:42} {n:4}  ev={ev[:34]}  e.g. {res_var[r][:30]}")


if __name__ == "__main__":
    main()
