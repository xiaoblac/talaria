#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Pure syzkaller variant parsing/classification and linked-fact loading helpers.
import collections
import json
import os
import re

from model.schema import VariantSpec
from model.generated import fixed_const_syscall_args

SH = "run/seed_horizon"

CMD_BASES = {"ioctl", "setsockopt", "getsockopt"}
CMD_FIELD = {"ioctl": "ioctl", "setsockopt": "setsockopt", "getsockopt": "getsockopt"}
FS_BASES = {"mount", "syz_mount_image", "fsopen", "fspick", "fsmount"}
DIRECT_FIELD = {
    "read": "read", "readv": "read", "pread64": "read", "preadv": "read",
    "write": "write", "writev": "write", "pwrite64": "write", "pwritev": "write",
    "sendmsg": "sendmsg", "sendmmsg": "sendmsg", "sendto": "sendmsg",
    "recvmsg": "recvmsg", "recvmmsg": "recvmsg", "recvfrom": "recvmsg",
}
OPEN_BASES = {"openat", "syz_open_dev", "open", "openat2"}

OPCODE_PREFIX = {
    "bpf": ("BPF_", "MAP_", "PROG_", "LINK_", "ITER_", "ENABLE_STATS"),
    "keyctl": ("KEYCTL_",),
    "prctl": ("PR_",),
    "ptrace": ("PTRACE_",),
    "arch_prctl": ("ARCH_",),
    "fcntl": ("F_",),
    "fsconfig": ("FSCONFIG_",),
    "io_uring_register": ("IORING_REGISTER_", "IORING_UNREGISTER_", "IORING_REGISTER", "IORING_UNREGISTER"),
    "ioprio_get": ("IOPRIO_",),
    "ioprio_set": ("IOPRIO_",),
    "getpriority": ("PRIO_",),
    "setpriority": ("PRIO_",),
    "getrusage": ("RUSAGE_",),
    "getitimer": ("ITIMER_",),
    "setitimer": ("ITIMER_",),
    "epoll_ctl": ("EPOLL_CTL_",),
    "waitid": ("P_",),
}

AMBIENT = {"fd", "sock", "pid", "uid", "gid", "tid", "sid", "pgid", "ifindex",
           "time_sec", "time_nsec", "time_usec"}


def fact_files(sh, kind):
    linked = os.path.join(sh, "kernel_facts_linked", f"{kind}.tsv")
    if os.path.exists(linked) and os.path.getsize(linked) > 0:
        return [linked]
    raise FileNotFoundError(f"missing linked kernel fact file: {linked}")


def fact_source(path, kind):
    if os.path.join("kernel_facts_linked", f"{kind}.tsv") in path:
        return "kernel_linked"
    return "unknown"


def load_consts():
    consts = {}
    with open("program/include/refuzz/program/syz/generated/consts.gen.hpp") as f:
        for ln in f:
            m = re.search(r"kSyzConst_(\w+)\s*=\s*(-?\d+)", ln)
            if m:
                consts[m.group(1)] = int(m.group(2)) & 0xFFFFFFFF
    return consts


def load_variant_consts(sh=SH):
    out = {}
    with open(os.path.join(sh, "variant_grammar.jsonl")) as f:
        for ln in f:
            d = json.loads(ln)
            out[d["name"]] = [int(x) & 0xFFFFFFFF for x in d.get("consts") or []]
    return out


def cval(suf, consts, base=None):
    if not suf:
        return None
    if suf in consts:
        return consts[suf]
    parts = suf.split("_")
    for i in range(1, len(parts)):
        c = "_".join(parts[i:])
        if c in consts:
            return consts[c]
    if base:
        c = base.upper() + "_" + suf
        if c in consts:
            return consts[c]
    return None


def cmd_discriminant(name, base, variant_consts):
    vals = variant_consts.get(name, [])
    if base == "ioctl":
        return vals[0] if vals else None
    if base in ("setsockopt", "getsockopt"):
        return vals[1] if len(vals) >= 2 else None
    return None


def syscall_base(handler):
    for pfx in ("__do_sys_", "__se_sys_", "__x64_sys_", "__sys_"):
        if handler.startswith(pfx):
            return handler[len(pfx):]
    return None


def split_variant(name):
    if "$" not in name:
        return name, "", "base", ""
    base, suf = name.split("$", 1)
    if suf == "auto":
        return base, suf, "auto_generic", ""
    if suf.startswith("auto_"):
        return base, suf, "auto_wrapped", suf[len("auto_"):]
    return base, suf, "named", suf


def build_cmd_syscall_bases(sh=SH):
    bases = set()
    for f in fact_files(sh, "cmd"):
        with open(f) as inp:
            for ln in inp:
                c = ln.rstrip("\n").split("\t")
                if len(c) >= 2 and c[0] == "CMD":
                    b = syscall_base(c[1])
                    if b:
                        bases.add(b)
    return bases


def build_cmd_rows(sh=SH):
    rows = collections.defaultdict(list)
    details = collections.defaultdict(list)
    for f in fact_files(sh, "cmd"):
        with open(f) as inp:
            for ln in inp:
                c = ln.rstrip("\n").split("\t")
                if len(c) >= 8 and c[0] == "CMD":
                    cv = int(c[2]) & 0xFFFFFFFF
                    origin = None
                    for extra in c[8:]:
                        if extra.startswith("origin="):
                            origin = extra.split("=", 1)[1]
                    m = re.match(r"d(\d+)$", c[6])
                    rows[cv].append(c[1])
                    details[cv].append({
                        "handler": c[1],
                        "depth": int(m.group(1)) if m else -1,
                        "origin": origin,
                    })
    return rows, details


def build_reg_rows(sh=SH):
    reg_rows = []
    for f in fact_files(sh, "reg"):
        subsystem = fact_source(f, "reg")
        with open(f) as inp:
            for ln in inp:
                c = ln.rstrip("\n").split("\t")
                if c[0] != "REG" or len(c) < 5:
                    continue
                fields = {fm.group(1): fm.group(2)
                          for fm in re.finditer(r"(\w+)=(\S+)", c[4]) if fm.group(2) != "-"}
                reg_rows.append((c[1], c[2], c[3], fields, subsystem))
    return reg_rows


def specific_predicate(hm):
    prod = collections.defaultdict(set)
    cons = collections.defaultdict(set)
    for s in hm["syscalls"]:
        for r in s.get("produces") or []:
            prod[r].add(s["name"])
        for r in set(s.get("consumes") or []) | set(s.get("uses") or []):
            cons[r].add(s["name"])
    generic = {r for r in (set(prod) | set(cons)) if len(prod[r]) > 25} | AMBIENT
    return lambda r: r not in generic


def resource_kind_map(hm):
    return {r["name"]: set(r.get("kind") or []) for r in hm.get("resources", [])}


def ops_context_resource(resource, res_kinds):
    kinds = res_kinds.get(resource, set())
    return "fd" in kinds or "sock" in kinds or resource.startswith(("fd_", "sock_"))


def intent_of(base, suffix, auto_kind, inner, syscall_bases):
    if base in CMD_BASES:
        return "cmd_dispatch"
    if base == "sendmsg" and "_CMD_" in (inner or suffix):
        return "genl_cmd"
    if base in FS_BASES:
        return "fs_dispatch"
    if base in DIRECT_FIELD or base in OPEN_BASES:
        return "direct_fd_op"
    if base in syscall_bases or base in OPCODE_PREFIX:
        return "syscall_multiplexer"
    if base.startswith("syz_"):
        return "syz_helper"
    return "base_or_unknown"


def field_for_base(base):
    return CMD_FIELD.get(base) or DIRECT_FIELD.get(base) or ("open" if base in OPEN_BASES else None)


def build_variant_specs(hm, variant_consts, syscall_bases, specific, res_kinds, root="."):
    specs = {}
    fixed_args = fixed_const_syscall_args(hm, root, {"flags"})
    o_path = load_consts().get("O_PATH")
    for s in hm["syscalls"]:
        name = s["name"]
        base, suffix, auto_kind, inner = split_variant(name)
        intent = intent_of(base, suffix, auto_kind, inner, syscall_bases)
        resources = frozenset(set(s.get("produces") or []) |
                              set(s.get("consumes") or []) |
                              set(s.get("uses") or []))
        produced = frozenset(s.get("produces") or [])
        used = frozenset(set(s.get("consumes") or []) | set(s.get("uses") or []))
        specific_resources = tuple(sorted(r for r in resources
                                          if specific(r) and ops_context_resource(r, res_kinds)))
        flags = fixed_args.get(name, {}).get("flags")
        no_dispatch_reason = None
        if base in {"open", "openat"} and o_path is not None and flags is not None and flags & o_path:
            no_dispatch_reason = "open_o_path"
        specs[name] = VariantSpec(
            name=name,
            base=base,
            suffix=suffix,
            auto_kind=auto_kind,
            inner=inner,
            intent=intent,
            resources=resources,
            produced_resources=produced,
            used_resources=used,
            specific_resources=specific_resources,
            field=None if no_dispatch_reason else field_for_base(base),
            discriminant=cmd_discriminant(name, base, variant_consts),
            no_dispatch_reason=no_dispatch_reason,
        )
    return specs


def taxonomy_reason(spec, consts):
    suffix_const = cval(spec.suffix, consts, spec.base)
    inner_const = cval(spec.inner, consts, spec.base) if spec.inner else None
    if spec.intent == "cmd_dispatch":
        return "runtime_cmd" if spec.auto_kind == "auto_generic" else "cmd_variant"
    if spec.intent == "direct_fd_op":
        if spec.auto_kind == "auto_generic":
            return "runtime_fd_op"
        return "auto_fd_context" if spec.auto_kind == "auto_wrapped" else "fd_op_variant"
    if spec.intent == "syscall_multiplexer":
        if spec.auto_kind == "auto_generic":
            return "runtime_opcode"
        if spec.auto_kind == "auto_wrapped" and inner_const is not None:
            return "auto_arg_constant"
        return "named_opcode" if suffix_const is not None else "opcode_or_base"
    if spec.intent == "genl_cmd":
        return "genl_family_cmd"
    if spec.intent == "fs_dispatch":
        return "runtime_fs" if spec.auto_kind == "auto_generic" else "fs_name"
    if spec.intent == "syz_helper":
        return "syz_helper"
    return "base_or_unknown"
