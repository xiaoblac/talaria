#!/usr/bin/env python3
#
# Structural devnode binding:
#   syzkaller open variant -> normalized /dev path
#   kernel IR devnode/cdev proof -> normalized /dev path -> file_operations REG row
#
# This module deliberately avoids resource-name aliases.  A resource is anchored
# only when the open path and the kernel-side devnode path meet on the same
# normalized device path.

import collections
import os
import re

from model.generated import fixed_buffer_values, generated_syscall_fields


def norm_devpath(path):
    if not path:
        return None
    p = path.split("\0", 1)[0].strip()
    p = p.replace("\\000", "").replace("\\00", "").strip()
    if not p:
        return None

    p = re.sub(r"%0?\d*[diu]", "#", p)
    if p.startswith("dev/"):
        p = "/" + p
    elif not p.startswith("/"):
        p = "/dev/" + p.lstrip("/")

    p = re.sub(r"(?<=\D)0*#(?=/|$)", "#", p)
    p = re.sub(r"(?<=\D)\d+(?=/|$)", "#", p)
    p = re.sub(r"/+", "/", p)
    return p


def norm_open_path(path):
    if not path:
        return None
    p = path.split("\0", 1)[0].strip()
    p = p.replace("\\000", "").replace("\\00", "").strip()
    if not p:
        return None
    if p.startswith("./"):
        p = p[2:]
        p = re.sub(r"%0?\d*[diu]", "#", p)
        p = re.sub(r"(?<=\D)0*#(?=/|$)", "#", p)
        p = re.sub(r"(?<=\D)\d+(?=/|$)", "#", p)
        p = re.sub(r"/+", "/", p)
        return p
    return norm_devpath(p)


def _norm_proc_pid_relpath(path):
    if not path:
        return None
    rel = path.split("\0", 1)[0].strip()
    rel = rel.replace("\\000", "").replace("\\00", "").strip()
    rel = re.sub(r"/+", "/", rel).lstrip("/")
    while rel.startswith("./"):
        rel = rel[2:]
    if not rel or rel == ".." or rel.startswith("../") or "/../" in rel:
        return None
    return rel


def load_procfs_variant_relpaths(hm, root="."):
    """Return the fixed path domain relative to a /proc/<pid> root for syz_open_procfs variants.

    The generated syzkaller type graph supplies the file argument's fixed BufferType values; the pseudo
    syscall's call_name supplies the path-constructor semantics.  The result remains a typed proc-pid-root
    relative path rather than being materialized as an arbitrary /proc/self string.
    """
    out = collections.defaultdict(set)
    for name, call_name, _field_name, type_id in generated_syscall_fields(
            hm, root, {"file"}):
        if call_name != "syz_open_procfs":
            continue
        for val in fixed_buffer_values(type_id, root):
            rel = _norm_proc_pid_relpath(val)
            if rel:
                out[name].add(rel)
    return out


def load_open_variant_devpaths(hm, root="."):
    out = collections.defaultdict(set)
    for name, _call_name, _field_name, type_id in generated_syscall_fields(
            hm, root, {"file", "dev"}):
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        for val in fixed_buffer_values(type_id, root):
            if not val.startswith(("/", "./")):
                continue
            n = norm_open_path(val)
            if n:
                out[name].add(n)
    return out


class _FnSummary:
    __slots__ = ("name", "path", "patterns", "ops", "calls", "has_cdev_add", "path_strings")

    def __init__(self, name, path):
        self.name = name
        self.path = path
        self.patterns = set()
        self.ops = set()
        self.calls = set()
        self.has_cdev_add = False
        self.path_strings = set()


def _has_drm_minor_devnode_proof(root):
    """The DRM-core /dev/dri minor-node proof, from ir_defuse's DRMMINOR fact (no Python disassembly).
    ir_defuse verifies the registration chain (drm_dev_register -> drm_minor_register -> drm_sysfs_minor_alloc
    + drm_devnode/drm_stub_open/@drm_stub_fops), the card%d/renderD%d/controlD%d/dri/%s node-name literals,
    dev_set_name, and the minor types {0,2,32} in the drm-core batch, emitting DRMMINOR there.  We read it
    from fields.by_tu.tsv; the unit (object_rel) reconstructs the batch path for the evidence src."""
    path = os.path.join(root, "run/seed_horizon/kernel_facts_linked", "fields.by_tu.tsv")
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if len(c) >= 2 and c[1] == "DRMMINOR":
                return True, os.path.join("run/seed_horizon/kernel_linked/batches", c[0] + ".bc")
    return False, ""


def _ir_function_summaries(reg_rows, root):
    """Per-function devnode summaries from ir_defuse's DEVN* facts (no Python disassembly): DEVNPAT (the
    dev_set_name node-name formats), DEVNOPS (cdev_init ops), DEVNADD (cdev_add), DEVNCALL (defined-callee
    edges, for the one_hop/rtc joins), DEVNSTR (usb_devnode path strings), DEVNFILE (DISubprogram source).
    norm_devpath + the REG-ops intersection stay here; build_kernel_devpath_rows's idioms are unchanged."""
    ops_names = {ops for _kind, _dev, ops, fields, _subsystem in reg_rows
                 if ops and ops != "-" and fields}
    fpath = os.path.join(root, "run/seed_horizon/kernel_facts_linked", "fields.by_tu.tsv")
    if not os.path.exists(fpath):
        return []
    summ = {}                                            # (unit, fn) -> _FnSummary

    def get(unit, fn):
        s = summ.get((unit, fn))
        if s is None:
            s = summ[(unit, fn)] = _FnSummary(fn, "")
        return s

    for ln in open(fpath):
        c = ln.rstrip("\n").split("\t")
        if len(c) < 3 or not c[1].startswith("DEVN"):
            continue
        unit, typ, fn = c[0], c[1], c[2]
        s = get(unit, fn)
        if typ == "DEVNPAT" and len(c) >= 4:
            n = norm_devpath(c[3])
            if n:
                s.patterns.add(n)
        elif typ == "DEVNOPS" and len(c) >= 4:
            if c[3] in ops_names:
                s.ops.add(c[3])
        elif typ == "DEVNADD":
            s.has_cdev_add = True
        elif typ == "DEVNCALL" and len(c) >= 4:
            s.calls.add(c[3])
        elif typ == "DEVNSTR" and len(c) >= 4:
            n = norm_devpath(c[3])
            if n:
                s.path_strings.add(n)
        elif typ == "DEVNFILE" and len(c) >= 4:
            s.path = c[3]
    return list(summ.values())


def _row_signature(reg_rows, row):
    _kind, _dev, ops_name, fields, _subsystem = reg_rows[row]
    return ops_name, tuple(sorted(fields.items()))


def _unique_logical_row(reg_rows, rows):
    if not rows:
        return None
    if len({_row_signature(reg_rows, row) for row in rows}) != 1:
        return None
    return min(rows)


def build_kernel_devpath_rows(reg_rows, root="."):
    by_ops = collections.defaultdict(set)
    for idx, (_kind, _dev, ops_name, fields, _subsystem) in enumerate(reg_rows):
        if ops_name and ops_name != "-" and fields:
            by_ops[ops_name].add(idx)

    path_ops = collections.defaultdict(set)
    evidence = []
    summaries = _ir_function_summaries(reg_rows, root)
    by_name = collections.defaultdict(list)
    for s in summaries:
        by_name[s.name].append(s)

    def add(path, ops, kind, src):
        if not path or not ops:
            return
        path_ops[path].add(ops)
        evidence.append((path, ops, kind, src))

    for s in summaries:
        if len(s.patterns) == 1 and len(s.ops) == 1 and s.has_cdev_add:
            add(next(iter(s.patterns)), next(iter(s.ops)), "same_fn_dev_set_name_cdev", s.path)

    for caller in summaries:
        if len(caller.patterns) != 1:
            continue
        candidates = []
        for callee_name in caller.calls:
            for callee in by_name.get(callee_name, ()):
                if len(callee.ops) == 1 and (caller.has_cdev_add or callee.has_cdev_add):
                    candidates.append((next(iter(callee.ops)), callee.path))
        if len({op for op, _path in candidates}) == 1:
            op, callee_path = candidates[0]
            add(next(iter(caller.patterns)), op, "one_hop_dev_set_name_cdev", caller.path + "->" + callee_path)

    usb_paths = {p for s in by_name.get("usb_devnode", ())
                 for p in s.path_strings if p == norm_devpath("bus/usb/%03d/%03d")}
    usb_ops = {op for s in summaries if s.has_cdev_add for op in s.ops
               if op == "usbdev_file_operations"}
    if usb_paths and usb_ops == {"usbdev_file_operations"}:
        for p in usb_paths:
            add(p, "usbdev_file_operations", "device_type_devnode_cdev", "drivers/usb/core/usb.c->drivers/usb/core/devio.c")

    rtc_class_pattern = any(
        s.path.endswith("drivers/rtc/class.c") and norm_devpath("rtc%d") in s.patterns
        for s in summaries)
    rtc_register_add = any(
        s.path.endswith("drivers/rtc/class.c") and s.has_cdev_add and "rtc_dev_prepare" in s.calls
        for s in summaries)
    rtc_prepare_ops = any(
        s.path.endswith("drivers/rtc/dev.c") and s.name == "rtc_dev_prepare" and
        s.ops == {"rtc_dev_fops"}
        for s in summaries)
    if rtc_class_pattern and rtc_register_add and rtc_prepare_ops:
        add(norm_devpath("rtc%d"), "rtc_dev_fops", "rtc_class_prepare_cdev",
            "drivers/rtc/class.c->drivers/rtc/dev.c")

    path_rows = collections.defaultdict(set)
    for path, ops_set in path_ops.items():
        for ops in ops_set:
            path_rows[path].update(by_ops.get(ops, ()))

    drm_ok, drm_src = _has_drm_minor_devnode_proof(root)
    if drm_ok:
        drm_rows = {
            idx for idx, (kind, _dev, _ops_name, fields, _subsystem) in enumerate(reg_rows)
            if kind == "drm" and fields.get("open") == "drm_open" and
            fields.get("read") == "drm_read" and fields.get("ioctl")
        }
        for path in (norm_devpath("dri/card%d"),
                     norm_devpath("dri/renderD%d"),
                     norm_devpath("dri/controlD%d")):
            for row in sorted(drm_rows):
                ops_name = reg_rows[row][2]
                path_rows[path].add(row)
                evidence.append((path, ops_name, "drm_minor_devnode_driver_fops",
                                 drm_src + ":drm_dev_register->drm_minor_register->drm_sysfs_minor_alloc"))
    return path_rows, evidence


def build_devpath_resource_anchors(hm, reg_rows, specific, ops_context_resource, root="."):
    open_paths = load_open_variant_devpaths(hm, root)
    kernel_rows, evidence = build_kernel_devpath_rows(reg_rows, root)
    resource_rows = collections.defaultdict(set)
    matches = []

    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        paths = open_paths.get(name, set())
        rows = set()
        for path in paths:
            rows.update(kernel_rows.get(path, ()))
        if not rows:
            continue
        for r in s.get("produces") or []:
            if specific(r) and ops_context_resource(r):
                resource_rows[r].update(rows)
                for path in sorted(paths):
                    if kernel_rows.get(path):
                        matches.append((name, r, path, sorted(kernel_rows[path])))

    anchors = collections.defaultdict(set)
    for r, rows in resource_rows.items():
        row = _unique_logical_row(reg_rows, rows)
        if row is not None:
            anchors[r].add(row)
            continue
        drm_rows = {row for row in rows if reg_rows[row][0] == "drm"}
        if drm_rows and drm_rows == rows and r == "fd_dri":
            anchors[r].update(row for row in drm_rows
                              if reg_rows[row][3].get("ioctl") == "drm_ioctl")
    return anchors, matches, open_paths, kernel_rows, evidence
