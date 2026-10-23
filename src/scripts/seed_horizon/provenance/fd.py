#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# FD-PROVENANCE recognizers. FD binding = resource provenance: identify how an fd is PRODUCED, recover
# the kernel context (struct bindings) it carries, then hand that context to the recursive dispatch
# resolver. devnode (open /dev/X cdev) and socket (proto_ops + sk_prot) are two instances already; this
# module adds two more idioms, each resolving a CLASS of fds rather than one variant:
#
#   misc      : open("/dev/<name>") where <name> is a misc_register'd miscdevice -> its file_operations.
#               The devnode recognizer only catches cdev_add; misc devices share one cdev, so the path
#               -> fops link is the miscdevice's {name, fops} initializer. (Bootstraps e.g. /dev/kvm.)
#   anon_inode: an fd created by anon_inode_getfd/getfile(name, &fops, ...) inside the producer's handler.
#               The fd's context is that &fops. This CHAINS: the producer (ioctl$KVM_CREATE_VM) must be
#               bound first (needs its parent fd's provenance), which the provenance fixpoint provides.
#
# These facts come from ir_defuse (no Python disassembly), in fields.tsv: misc device name -> fops from
# MISC rows (miscdevice global .name/.fops scan); anon_inode creator/syscall-handler fn -> fops from ANON
# rows (call-graph lift: anon_inode_get{fd,file}(name, &fops, ...) attributed to the syscall handlers).
import collections
import os
import re

from model.recognizer import InstallSeed

SH = "run/seed_horizon"


# cdev-path provenance: a device-registration function that (a) cdev_add's a cdev carrying a known shared
# fops and (b) names the device "<base>%d" -> /dev/<base># uses that fops. Catches V4L
# (__video_register_device + v4l2_fops + video/radio/vbi/... names) and similar cdev idioms the generic
# devnode recognizer misses. The path is matched to the syz open variant's devpath (sound). The structural
# IR facts (which fn calls which device-registration API, with which fops global / name-format string) come
# from ir_defuse's CDEV* rows in fields.by_tu.tsv (no Python disassembly); this module keeps only the join
# + name-normalization logic (_devpath_from_format / _subst_format / norm_devpath), unchanged.
_DEVNAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,14}$")
_DEVPATH_RE = re.compile(r"^/dev/[A-Za-z0-9_.#/*:-]+$")
CDEV_PATHS_HEADER = "#devpath\tfops"


def _devpath_from_format(fmt):
    from provenance.devnode import norm_devpath

    raw = (fmt or "").split("\\")[0].strip()
    if not raw or any(ch.isspace() for ch in raw):
        return None
    path = norm_devpath(raw)
    if not path or not _DEVPATH_RE.match(path):
        return None
    return path


def _devpath_pattern_from_format(fmt):
    """Convert a class/devnode printf format to a normalized /dev path pattern.

    Numeric substitutions become '#'. A runtime string substitution becomes '*',
    but only when the format has a static directory/name component such as
    "bsg/%s"; a bare "%s" is too unconstrained to be a useful kernel-side path.
    """
    from provenance.devnode import norm_devpath

    raw = (fmt or "").split("\\")[0].strip()
    if not raw or any(ch.isspace() for ch in raw):
        return None
    if "%s" not in raw:
        return _devpath_from_format(raw)
    static = re.sub(r"%[-+ #0-9.]*[hlLzjt]*s", "", raw)
    if "/" not in raw and len(static.strip("-_.")) < 2:
        return None
    out, i = [], 0
    while i < len(raw):
        if raw[i] == "%" and i + 1 < len(raw):
            j = i + 1
            while j < len(raw) and raw[j] in "0123456789.+-# hlLzjt":
                j += 1
            conv = raw[j] if j < len(raw) else ""
            if conv == "s":
                out.append("*")
            elif conv in "diu":
                out.append("#")
            else:
                out.append(raw[i:j + 1])
            i = j + 1
        else:
            out.append(raw[i])
            i += 1
    path = norm_devpath("".join(out))
    if not path or not _DEVPATH_RE.match(path):
        return None
    return path


def _devpath_pattern_matches(pattern, path):
    if "*" not in pattern:
        return pattern == path
    rx = re.escape(pattern).replace(r"\*", r"[^/]+")
    return re.match(rx + r"\Z", path) is not None


def _subst_format(fmt, lits):
    """Substitute a printf device-name format's %s with its string-literal args, keeping %d/%i for later
    #-normalization: device_create(class, ..., "%s%d", "hidraw", minor) -> "hidraw%d". Returns None if any
    %s has no string-literal arg (a runtime-built name we cannot statically reconstruct, e.g. roccat's
    "%s%s%d" where the 2nd %s is a driver field)."""
    raw = (fmt or "").split("\\")[0]
    out, li, i = [], 0, 0
    while i < len(raw):
        if raw[i] == "%" and i + 1 < len(raw):
            j = i + 1
            while j < len(raw) and raw[j] in "0123456789.+-# lh":
                j += 1
            conv = raw[j] if j < len(raw) else ""
            if conv == "s":
                lit = lits[li].split("\\")[0] if li < len(lits) else ""
                if not lit or "%" in lit:
                    return None
                out.append(lit)
                li += 1
            else:
                out.append(raw[i:j + 1])
            i = j + 1
        else:
            out.append(raw[i])
            i += 1
    return "".join(out)


def _cdev_state():
    return {
        "cdev_in_fn": set(),                                    # fns that call cdev_add/cdev_device_add
        "cdev_init_primary": collections.defaultdict(set),     # fn -> {primary fops passed to cdev_init}
        "cdev_init_order": collections.defaultdict(list),      # fn -> [primary fops in cdev_init order]
        "setname_in_fn": collections.defaultdict(set),         # fn -> {device path from dev_set_name fmt}
        "formatted_names_in_fn": collections.defaultdict(set),  # fn -> {path} from sprintf(name, "<base>%d")
        "devcreate_direct_names": collections.defaultdict(set),  # fn -> {path} from device_create(..., fmt)
        "devcreate_direct_order": collections.defaultdict(list),  # fn -> [path in device_create order]
        "devcreate_string_name": set(),                        # fns with device_create(..., "%s", dynamic)
        "devnode_paths": collections.defaultdict(set),         # devnode fn -> {/dev/path patterns} (kasprintf)
        "chrdev_region_name": collections.defaultdict(set),    # fn -> {(alloc|register)_chrdev_region name}
        "chrdev_fops_in_fn": collections.defaultdict(set),     # fn -> {fops from __register_chrdev}
        "chrdev_pending": [],                                  # (name, fops) from __register_chrdev
        "memdev_pending": [],                                  # (name, fops) from drivers/char/mem.c devlist
        "class_devnodes": collections.defaultdict(set),        # class global -> {devnode fn refs}
        "class_refs_in_fn": collections.defaultdict(set),      # fn -> {class globals it registers/uses}
        "fops_in_fn": collections.defaultdict(set),            # fn -> {known fops referenced} (cdev_add fns)
        "func_file": {},                                       # fn -> source file (DISubprogram)
        "file_cdev_fops": set(),                               # unique cdev fops anywhere in this link unit
        "file_devcreate_paths": set(),                         # direct device_create("<base>%d") paths in unit
        "v4l2_ok": False,                                      # __video_register_device family idiom proven
        "v4l2_names": set(),                                   # video/radio/vbi/... names present in the unit
    }


def _cdev_load_units(root, known_fops):
    """Read ir_defuse's CDEV* facts from fields.by_tu.tsv, grouped by link-unit (object_rel = one batch).
    The known_fops filter (on the fops-bearing facts) and the name normalization (_devpath_from_format /
    _subst_format / _devpath_pattern_from_format) are applied AS the facts are read, so each unit's state
    matches what the old per-.bc llvm-dis pass produced -- the join tail (_cdev_unit_rows) is then identical.
    Emission order is preserved within a unit (write_fact_outputs writes each batch's lines contiguously in
    ir_defuse order), so cdev_init_order / devcreate_direct_order keep their instruction order."""
    units = {}
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.by_tu.tsv")
    if not os.path.exists(path):
        return units

    def st(unit):
        s = units.get(unit)
        if s is None:
            s = units[unit] = _cdev_state()
        return s

    with open(path) as f:
        for ln in f:
            c = ln.rstrip("\n").split("\t")
            if len(c) < 2:
                continue
            typ = c[1]
            if typ == "CDEVADD" and len(c) >= 3:
                st(c[0])["cdev_in_fn"].add(c[2])
            elif typ == "CDEVINIT" and len(c) >= 4:
                cands = [x for x in c[3].split(",") if x in known_fops]
                if cands:                                       # first known fops = primary device fops
                    s, fn = st(c[0]), c[2]
                    s["cdev_init_primary"][fn].add(cands[0])
                    s["cdev_init_order"][fn].append(cands[0])
                    s["file_cdev_fops"].add(cands[0])
            elif typ == "REGCHRDEV" and len(c) >= 5:
                fn, name, fops = c[2], c[3], c[4]
                if fops in known_fops:
                    s = st(c[0])
                    s["chrdev_pending"].append((name, fops))
                    s["chrdev_fops_in_fn"][fn].add(fops)
            elif typ == "CDEVNAME" and len(c) >= 5:
                fn, api, fmt = c[2], c[3], c[4]
                s = st(c[0])
                if api == "set_name":
                    dp = _devpath_from_format(fmt)
                    if dp:
                        s["setname_in_fn"][fn].add(dp)
                elif api == "sprintf":
                    dp = _devpath_from_format(fmt)
                    if dp:
                        s["formatted_names_in_fn"][fn].add(dp)
                elif api == "kasprintf":
                    dp = _devpath_pattern_from_format(fmt)
                    if dp:
                        s["devnode_paths"][fn].add(dp)
                elif api == "device_create":
                    # device_create(class, parent, devt, drvdata, fmt, ...): substitute the %s string args
                    # so the "%s%d"+"hidraw" idiom (base as a literal arg) is recovered, not just "hidraw%d".
                    sub = _subst_format(fmt, c[5:])
                    if sub is None and fmt.split("\\")[0].startswith("%s"):
                        s["devcreate_string_name"].add(fn)      # fully runtime name -> use sprintf'd names
                    else:
                        dp = _devpath_from_format(sub if sub is not None else fmt)
                        if dp:
                            s["devcreate_direct_names"][fn].add(dp)
                            s["devcreate_direct_order"][fn].append(dp)
                            s["file_devcreate_paths"].add(dp)
            elif typ == "CHRDEVREGION" and len(c) >= 4:
                st(c[0])["chrdev_region_name"][c[2]].add(c[3])
            elif typ == "CLASSDEV" and len(c) >= 4:
                st(c[0])["class_devnodes"][c[2]].add(c[3])
            elif typ == "CLASSREF" and len(c) >= 4:
                st(c[0])["class_refs_in_fn"][c[2]].add(c[3])
            elif typ == "CDEVFOPS" and len(c) >= 4:
                if c[3] in known_fops:
                    st(c[0])["fops_in_fn"][c[2]].add(c[3])
            elif typ == "CDEVFILE" and len(c) >= 4:
                st(c[0])["func_file"][c[2]] = c[3]
            elif typ == "MEMDEV" and len(c) >= 4:
                if c[3] in known_fops:
                    st(c[0])["memdev_pending"].append((c[2], c[3]))
            elif typ == "V4L2OK":
                st(c[0])["v4l2_ok"] = True
            elif typ == "V4L2NAME" and len(c) >= 3:
                st(c[0])["v4l2_names"].add(c[2])
    return units


def _cdev_unit_rows(st, known_fops):
    """The cdev path<->fops joins for ONE link-unit -- the old per-.bc tail verbatim, fed by ir_defuse facts
    instead of an llvm-dis stream."""
    cdev_in_fn = st["cdev_in_fn"]
    cdev_init_primary = st["cdev_init_primary"]
    cdev_init_order = st["cdev_init_order"]
    setname_in_fn = st["setname_in_fn"]
    formatted_names_in_fn = st["formatted_names_in_fn"]
    devcreate_direct_names = st["devcreate_direct_names"]
    devcreate_direct_order = st["devcreate_direct_order"]
    devcreate_string_name = st["devcreate_string_name"]
    devnode_paths = st["devnode_paths"]
    chrdev_region_name = st["chrdev_region_name"]
    chrdev_fops_in_fn = st["chrdev_fops_in_fn"]
    chrdev_pending = st["chrdev_pending"]
    memdev_pending = st["memdev_pending"]
    class_devnodes = st["class_devnodes"]
    class_refs_in_fn = st["class_refs_in_fn"]
    fops_in_fn = st["fops_in_fn"]
    func_file = st["func_file"]
    file_cdev_fops = st["file_cdev_fops"]
    file_devcreate_paths = st["file_devcreate_paths"]
    rows = []
    # class.devnode path: a class global supplies .devnode(), while the registration function installs
    # the chrdev/cdev fops. This is the structural link for cpu/%u/msr and bsg/%s style devices.
    for fn, classes in class_refs_in_fn.items():
        paths = set()
        for cls in classes:
            for devnode_fn in class_devnodes.get(cls, ()):
                paths.update(devnode_paths.get(devnode_fn, ()))
        if not paths:
            continue
        fopss = set(chrdev_fops_in_fn.get(fn, ())) | set(cdev_init_primary.get(fn, ()))
        for fops in fopss:
            for devpath in paths:
                rows.append((devpath, fops))
    for fn in cdev_in_fn:
        for fops in fops_in_fn.get(fn, set()):     # candidate set: keep ALL same-fn cdev fops, not unique-only
            for devpath in devcreate_direct_names.get(fn, ()):
                rows.append((devpath, fops))
            if fn in devcreate_string_name:
                for devpath in formatted_names_in_fn.get(fn, ()):
                    rows.append((devpath, fops))
    # Ordered same-function pairing: one init function may register several cdevs in sequence
    # (tty_init: tty_fops -> "tty", console_fops -> "console"). This is still structural evidence:
    # both sides are registration API calls in the same function and their order matches.
    for fn in cdev_in_fn:
        fops_order = cdev_init_order.get(fn, [])
        path_order = devcreate_direct_order.get(fn, [])
        if fops_order and len(fops_order) == len(path_order):
            for fops, devpath in zip(fops_order, path_order):
                rows.append((devpath, fops))
    # ADDITIVE path: a registration fn whose cdev_init carries ONE primary fops + names the device via a
    # dev_set_name("<base>%d") format string (e.g. ib_uverbs_add_one: cdev uverbs_fops, "uverbs%d"). The
    # old path misses these (the fn references >1 fops via the mmap select; the name has a %d format).
    for fn in cdev_in_fn:
        for fops in cdev_init_primary.get(fn, set()):   # candidate set: all cdev_init fops, not unique-only
            for devpath in setname_in_fn.get(fn, ()):
                rows.append((devpath, fops))
    # chrdev-region + cdev_init co-located: an init fn registers the numbered region AND inits the cdev
    # with its fops (hidraw_init: alloc_chrdev_region "hidraw" + cdev_init @hidraw_ops). The /dev node is
    # named elsewhere (hidraw_connect's device_create "%s%d","hidraw"), but the region name IS the node
    # base, joined to the fops by same-function co-location. Recovers hidraw/ublk/... (split registration).
    for fn, prim in cdev_init_primary.items():
        for fops in prim:                                 # candidate set: all cdev_init fops, not unique-only
            for nm in chrdev_region_name.get(fn, ()):
                base = nm.split("\\")[0].strip()
                if not base or not _DEVNAME_RE.match(base.rsplit("/", 1)[-1]):
                    continue
                if base.startswith("/dev/"):
                    rows.append((base, fops))                 # full path, single device (pty.c "/dev/ptmx")
                else:
                    rows.append(("/dev/" + base + "#", fops))  # bare name, numbered family (hidraw)
    # Split registration path: one function initializes/adds a single global cdev fops, while another
    # function in the same linked unit creates the /dev node via device_create("<base>%d").
    if cdev_in_fn and len(file_cdev_fops) == 1:
        fops = next(iter(file_cdev_fops))
        for devpath in file_devcreate_paths:
            rows.append((devpath, fops))
    for name, fops in chrdev_pending:
        if name and _DEVNAME_RE.match(name.split("\\")[0]):
            rows.append(("/dev/" + name.split("\\")[0] + "#", fops))
    for name, fops in memdev_pending:
        devpath = _devpath_from_format(name)
        if devpath:
            rows.append((devpath, fops))
    # V4L2 core registers several device-node families through __video_register_device(): v4l2_fops +
    # cdev_add + dev_set_name("%s%d") + the video/radio/vbi/... name strings (ir_defuse V4L2OK/V4L2NAME).
    # Emit every proven family as a candidate-set anchor under the same DEVPATH schema.
    if "v4l2_fops" in known_fops and st["v4l2_ok"]:
        for name in st["v4l2_names"]:
            rows.append((f"/dev/{name}#", "v4l2_fops"))
    # Per-source-file join (debug-info): the device-NODE name (device_create/dev_set_name) and the cdev
    # FOPS (cdev_init) often live in DIFFERENT functions of the same .c (tap.c: device_create "tap%d" in
    # the per-device fn, cdev_init @tap_fops in tap_init). Group by DIFile (ir_defuse CDEVFILE) and emit
    # name x cdev-fops as the candidate set (over-approx within one file is fine; the context filter prunes).
    file_names = collections.defaultdict(set)
    file_cdev = collections.defaultdict(set)
    for fn in (set(devcreate_direct_names) | set(setname_in_fn) | set(formatted_names_in_fn)
               | set(cdev_init_primary) | set(devnode_paths)):
        f = func_file.get(fn)
        if not f:
            continue
        # devnode_paths = a class's .devnode() kasprintf path (dma_heap/%s -> /dev/dma_heap/*), already
        # None-filtered to subdir-qualified patterns (a bare "%s" is dropped upstream, so no /dev/* wildcard).
        # For a DYNAMIC class (class_create + runtime .devnode store, e.g. dma_heap) the static class.devnode
        # join misses the link; the devnode fn and the cdev_init still share the .c, so co-locate them here.
        file_names[f] |= (devcreate_direct_names.get(fn, set()) | setname_in_fn.get(fn, set())
                          | formatted_names_in_fn.get(fn, set()) | devnode_paths.get(fn, set()))
        file_cdev[f] |= cdev_init_primary.get(fn, set())
    for f, names_ in file_names.items():
        for path in names_:
            for fops in file_cdev[f]:
                rows.append((path, fops))
    return rows


def extract_cdev_paths(root=".", out=None, known_fops=None, bcs=None):
    """Emit DEVPATH <normalized-/dev/path> <fops>: a char/block device whose /dev node maps to a known fops,
    via (a) a registration fn that cdev_add's a cdev carrying that fops + names the device, (b) a
    register_chrdev(name, fops) call, or (c) class.devnode returning a device path while the same
    registration path installs cdev/chrdev fops. The structural IR facts come from ir_defuse (CDEV* rows in
    fields.by_tu.tsv, per batch); this keeps only the join + norm_devpath logic, no Python disassembly.
    `bcs` is accepted for signature compatibility but ignored (the facts are pre-extracted per batch)."""
    out = out or os.path.join(root, SH, "cdev_paths.tsv")
    known_fops = known_fops or set()
    rows = []
    for st in _cdev_load_units(root, known_fops).values():     # one link-unit (batch) at a time
        rows.extend(_cdev_unit_rows(st, known_fops))
    with open(out, "w") as f:
        f.write(CDEV_PATHS_HEADER + "\n")
        for devpath, fops in sorted(set(rows)):
            f.write(f"DEVPATH\t{devpath}\t{fops}\n")
    return out


def build_cdev_path_anchors(hm, reg_rows, specific, ops_context_resource, open_devpaths, root="."):
    """resource -> {fops REG row}: open("/dev/<path>") of a cdev whose registration fn carries a unique
    known shared fops. Mirrors build_misc_anchors. Recovers fd_video (v4l2_fops) etc."""
    by_fops = _fops_rows(reg_rows)
    known = {ops for ops in by_fops}                  # only fops that have an ops-table REG row
    path = os.path.join(root, SH, "cdev_paths.tsv")
    if not os.path.exists(path) or not os.path.getsize(path):
        extract_cdev_paths(root, path, known_fops=known)
    path_fops = collections.defaultdict(set)
    leaf_fops = collections.defaultdict(set)
    pattern_fops = []
    for ln in open(path):
        c = ln.rstrip("\n").split("\t")
        if c[0] == "DEVPATH" and len(c) >= 3:
            path_fops[c[1]].add(c[2])
            if "*" in c[1]:
                pattern_fops.append((c[1], c[2]))
                continue
            if c[1].endswith("#") and not c[1].endswith("-#") and not c[1].endswith("/#"):
                path_fops[c[1][:-1]].add(c[2])
            leaf_fops[c[1].rsplit("/", 1)[-1]].add(c[2])
    name_fops = {leaf: set(fops) for leaf, fops in leaf_fops.items() if len(fops) == 1}
    anchors = collections.defaultdict(set)
    evidence = []
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        for p in open_devpaths.get(name, ()):
            # de-# is symmetric: a cdev entry "/dev/video#" already also indexes "/dev/video"; here a syz
            # path "/dev/tty#" must also match a cdev "/dev/tty" (the # is syz's instance placeholder).
            fopss = set()
            for pp in ({p, p[:-1]} if p.endswith("#") else {p}):
                fopss |= path_fops.get(pp, set())
                fopss |= name_fops.get(pp.rsplit("/", 1)[-1], set())
            for patt, fops in pattern_fops:
                if _devpath_pattern_matches(patt, p):
                    fopss.add(fops)
            if not fopss:
                continue
            for fops in fopss:
                for r in (s.get("produces") or []):
                    if specific(r) and ops_context_resource(r):
                        rows = by_fops.get(fops, set())
                        anchors[r].update(rows)
                        if rows:
                            evidence.append((name, r, p, fops, sorted(rows)))
    return anchors, evidence


# fs-inode-fops provenance: a file opened on a mounted fs gets inode->i_fop = the fs's dir/file
# operations. syz encodes this as openat$auto_<fops>_<struct> producing fd_<fops>_<struct>. The binding
# is FOUND, not name-matched: a fops is accepted ONLY if proven stored into the inode i_fop FIELD -- a
# `store ptr @<fops>, ptr %g` where %g is an i8 byte-offset GEP at the i_fop offset. Opaque-pointer IR
# erases the %struct.inode type, so the offset is the robust structural signal; it is SELF-CALIBRATED as
# the byte offset where the most distinct known file_operations are stored (= i_fop).
def build_inode_fops_anchors(hm, reg_rows, specific, ops_context_resource, root="."):
    """resource fd_<fops>_<struct> (openat$auto_-produced) -> the REG row of its proven i_fop fops."""
    fops_rows = collections.defaultdict(set)
    for i, (kind, _d, ops, fld, _s) in enumerate(reg_rows):
        # open counts as a real entry handler: pseudo-fs files (configfs/kernfs) expose only .open, and the
        # openat$auto_ variant IS bound once its .open is the entry -- gated by proven-installed (IFOP) below.
        if kind == "fops" and ops not in ("-", "") and any(fld.get(x) for x in ("ioctl", "read", "write", "open")):
            fops_rows[ops].add(i)
    proven = set()       # installed file_operations, from ir_defuse's IFOP facts (fields.tsv)
    fpath = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    if os.path.exists(fpath):
        for ln in open(fpath):
            if ln.startswith("IFOP\t"):
                proven.add(ln.rstrip("\n").split("\t")[1])
    # a REG row from a device-registration CALL (misc_register/cdev_add/__register_chrdev/usb/drm/snd, which
    # analyzeReg emits with a device kind) IS install proof -- the fops lives in a static miscdevice/drm_driver
    # struct so IFOP's instruction-address-taken scan misses it, but the registration call installs it.  The
    # enumOpsTables type-only rows are kind=='fops'/'bdev'/'proto' and are NOT added here.
    for _kind, _dev, _ops, _fld, _s in reg_rows:
        if _kind in ("misc", "cdev", "chrdev", "usb", "drm", "snd") and _ops not in ("-", ""):
            proven.add(_ops)
    cand = sorted((o for o in fops_rows if o in proven), key=len, reverse=True)
    auto_res = set()
    for s in hm.get("syscalls", []):
        if "auto" in s["name"] and s["name"].split("$", 1)[0] in ("openat", "syz_open_dev", "open"):
            for r in (s.get("produces") or []):
                if specific(r) and ops_context_resource(r):
                    auto_res.add(r)
    anchors = collections.defaultdict(set)
    evidence = []
    for r in auto_res:
        # the syz auto-name encodes the fops as the LEADING token: fd_<fops>_<struct>.  Match it as a
        # prefix, not a substring -- a substring match both lets a short fops (tap_fops) be masked by a
        # len gate and wrongly attaches an unrelated fops that merely appears mid-name (device_fops inside
        # vga_arb_device_fops).  Longest-first picks the most specific leading fops.
        body = r[3:] if r.startswith("fd_") else r
        for o in cand:
            if body == o or body.startswith(o + "_"):
                anchors[r].update(fops_rows[o])
                evidence.append((r, o))
                break
    return anchors, evidence


def _load_facts(root="."):
    """(misc, anon) from ir_defuse's facts in fields.tsv (no Python disassembly): misc device name -> fops
    from MISC rows (miscdevice global scan); anon creator/syscall-handler fn -> {fops} from ANON rows
    (ir_defuse's call-graph lift)."""
    misc, anon = {}, collections.defaultdict(set)
    fields = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    if os.path.exists(fields):
        for ln in open(fields):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "MISC" and len(c) >= 3:
                misc.setdefault(c[1], c[2])
            elif c[0] == "ANON" and len(c) >= 3:
                anon[c[1]].add(c[2])
    return misc, anon


def _fops_rows(reg_rows):
    by = collections.defaultdict(set)
    for idx, (kind, _dev, ops_name, fields, _sub) in enumerate(reg_rows):
        if kind in ("fops", "anon", "cdev", "misc", "chrdev") and ops_name and ops_name != "-" and fields:
            by[ops_name].add(idx)
    return by


def build_misc_anchors(hm, reg_rows, specific, ops_context_resource, open_devpaths, root="."):
    """resource -> {fops REG row}: open("/dev/<name>") of a misc_register device -> its file_operations.
    open_devpaths maps an open variant -> {normalized /dev path} (reused from provenance.devnode)."""
    misc, _anon = _load_facts(root)
    for kind, dev, ops_name, fields, _sub in reg_rows:
        if kind == "misc" and dev and dev != "-" and ops_name and ops_name != "-" and fields:
            misc.setdefault(dev, ops_name)
    by_fops = _fops_rows(reg_rows)
    # normalized "/dev/<nodepath>" -> fops.  The MISC fact now carries miscdevice.nodename (the ACTUAL /dev
    # node path, e.g. "net/tun", "infiniband/rdma_cm"), not just the bare .name identifier, so the syz devpath
    # matches EXACTLY.  There is deliberately NO basename fallback: matching /proc/sys/kernel/watchdog to the
    # /dev/watchdog misc device by the shared leaf "watchdog" is a cross-namespace name-guess, not a bind.
    path_fops = {}
    for name, fops in misc.items():
        bare = name.split("\0")[0].strip()
        p = re.sub(r"(?<=\D)\d+(?=/|$)", "#", "/dev/" + bare)
        path_fops[p] = fops
    anchors = collections.defaultdict(set)
    evidence = []
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        for p in open_devpaths.get(name, ()):
            fops = path_fops.get(p)   # exact devnode path only
            if not fops:
                continue
            for r in (s.get("produces") or []):
                if specific(r) and ops_context_resource(r):
                    rows = by_fops.get(fops, set())
                    anchors[r].update(rows)
                    if rows:
                        evidence.append((name, r, p, fops, sorted(rows)))
    return anchors, evidence


def load_tfop(root="."):
    """relpath -> fops, from ir_defuse's TFOP facts (each = a pid_entry / tree_descr entry's {path relative
    to its fs root -> its installed file_operations}, read from the bitcode fill table by DWARF type; a
    pident SUB-table entry carries its parent-dir prefix, e.g. "attr/current").  Uniqueness-gated: a relpath
    is usable only when it maps to ONE fops across all tables, so an ambiguous leaf never guesses."""
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    by = collections.defaultdict(set)
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "TFOP" and len(c) >= 3 and c[1] and c[2]:
                by[c[1]].add(c[2])
    return {rel: next(iter(f)) for rel, f in by.items() if len(f) == 1}


def load_magiclink_fops(root="."):
    """proc-relative directory prefix -> fops reached through a magic-link path resolver.

    MAGICCALL identifies a call whose argument is the same SSA path passed to nd_jump_link by a fill-table
    directory's installed get_link callback; PATHFOP identifies the matching function argument that is
    passed to path_from_stashed under a mount whose typed inode initializer installs one fops.  Joining on
    (function, path-argument-index) is the cross-batch bridge.  Both sides and the final prefix are
    uniqueness-gated, so unrelated get_link calls or ambiguous mount contexts cannot bind a resource.
    """
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    calls = collections.defaultdict(set)
    fops_by_function = collections.defaultdict(set)
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "MAGICCALL" and len(c) >= 4 and c[1] and c[2] and c[3]:
                calls[c[1]].add((c[2], c[3]))
            elif c[0] == "PATHFOP" and len(c) >= 4 and c[1] and c[2] and c[3]:
                fops_by_function[(c[1], c[2])].add(c[3])
    unique_path_fops = {
        function: next(iter(fops))
        for function, fops in fops_by_function.items()
        if len(fops) == 1
    }
    out = {}
    for relroot, functions in calls.items():
        fops = {unique_path_fops[function]
                for function in functions if function in unique_path_fops}
        if len(fops) == 1:
            out[relroot] = next(iter(fops))
    return out


_PROC_PID_RE = re.compile(r"^/proc/(?:self|thread-self)/(.+)$")


def build_proc_table_anchors(hm, reg_rows, specific, ops_context_resource, opd, root="."):
    """resource -> {fops REG row}: a syz open of a /proc pid_entry / tree_descr file, anchored by joining the
    open PATH to the fops the kernel's own fill table installs for it (TFOP) -- a STRUCTURAL derivation from
    the bitcode, not a hardcoded resource->fops map.  For syz_open_procfs, the generated type graph supplies
    the fixed relative file domain and the pseudo syscall call_name supplies the proc-pid-root constructor.
    The join matches the FULL path relative to /proc/<pid>/ (not a bare basename), so a leaf that recurs
    across dirs never collides:
      /proc/self/attr/current   -> rel "attr/current" -> proc_pid_attr_operations
      /proc/self/ns/cgroup      -> rel "ns/cgroup"    -> MAGICCALL/PATHFOP -> ns_file_operations
      /proc/self/cgroup         -> rel "cgroup"       -> proc_single_file_operations
    (tree_descr files on their own fs -- binfmt_misc's register/status -- need the fs mount point to form the
    relative path, a separate idiom handled by build_mount_relative_anchors.)"""
    from provenance.devnode import load_procfs_variant_relpaths

    tfop = load_tfop(root)
    magiclink_fops = load_magiclink_fops(root)
    procfs_relpaths = load_procfs_variant_relpaths(hm, root)
    by_fops = _fops_rows(reg_rows)
    anchors = collections.defaultdict(set)
    for s in hm.get("syscalls", []):
        name = s["name"]
        relpaths = set(procfs_relpaths.get(name, ()))
        for p in opd.get(name, ()):
            m = _PROC_PID_RE.match(p)
            if m:
                relpaths.add(m.group(1))
        for relpath in relpaths:
            fops = tfop.get(relpath)                         # exact path relative to /proc/<pid>/
            if not fops:
                candidates = {
                    candidate_fops
                    for relroot, candidate_fops in magiclink_fops.items()
                    if relpath.startswith(relroot + "/")
                }
                if len(candidates) == 1:
                    fops = next(iter(candidates))
            if not fops:
                continue
            for r in (s.get("produces") or []):
                if specific(r) and ops_context_resource(r):
                    anchors[r].update(by_fops.get(fops, set()))
    return anchors, {}


def load_subtree(root="."):
    """subtree-root name -> blanket fops, from ir_defuse's SUBTREE facts (each = proc_mkdir(NAME) whose
    dir inode-ops lookup instantiates EVERY child with one file_operations -- the ① subtree-blanket method).
    Uniqueness-gated across batches, so an ambiguous root never guesses."""
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    by = collections.defaultdict(set)
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "SUBTREE" and len(c) >= 3 and c[1] and c[2]:
                by[c[1]].add(c[2])
    return {name: next(iter(f)) for name, f in by.items() if len(f) == 1}


def load_subtree_holes(root="."):
    """sysctl-root-relative mount-point paths (register_sysctl_mount_point(REL) -> "fs/binfmt_misc"), from the
    SUBTREEHOLE facts.  /proc/sys/REL is where a DIFFERENT fs mounts (binfmt_misc, fuse), so the sysctl blanket
    fops does NOT apply below it -- these carve holes out of the subtree join."""
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    holes = set()
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "SUBTREEHOLE" and len(c) >= 2 and c[1]:
                holes.add(c[1])
    return holes


def build_subtree_anchors(hm, reg_rows, specific, ops_context_resource, opd, root="."):
    """resource -> {fops REG row}: a syz open of a file UNDER a proc blanket subtree, anchored by joining the
    path's subtree ROOT to the blanket fops the kernel installs on every inode of that subtree (SUBTREE) --
    the ① subtree-blanket ObjectId method, STRUCTURAL (recovered from proc_mkdir -> IOPS.lookup -> make-inode
    i_fop), not a hardcoded path->fops map:
      /proc/sys/net/ipv#/tcp_mem            -> subtree "sys" -> proc_sys_file_operations
      /proc/sys/fs/binfmt_misc/register     -> HOLE (register_sysctl_mount_point) -> NOT sysctl -> skipped
    Every leaf below the root shares the fops EXCEPT under a mount-point hole where another fs is mounted, so
    the whole prefix binds (sysctl fd_sysctl / fd_tcp_mem / fd_tcp_congestion / fd_yama_ptrace_scope) without
    wrongly claiming the binfmt_misc files below /proc/sys/fs/binfmt_misc."""
    subtree = load_subtree(root)
    holes = load_subtree_holes(root)
    by_fops = _fops_rows(reg_rows)
    anchors = collections.defaultdict(set)
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "open$", "openat2$", "syz_open_dev$")):
            continue
        for p in opd.get(name, ()):
            fops = next((f for rn, f in subtree.items()
                         if p.startswith("/proc/" + rn + "/")
                         and not any(p.startswith("/proc/" + rn + "/" + h + "/") for h in holes)), None)
            if not fops:
                continue
            for r in (s.get("produces") or []):
                if specific(r) and ops_context_resource(r):
                    anchors[r].update(by_fops.get(fops, set()))
    return anchors, {}


def load_dynchild(root="."):
    """write/create-handler fn -> the SINGLE file_operations it installs on inodes it spawns (DYNCHILD).  A
    static file's .write (binfmt_misc register -> bm_register_write) creates the fs's runtime-named children;
    this types those dynamic siblings."""
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    out = {}
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "DYNCHILD" and len(c) >= 3 and c[1] and c[2]:
                out[c[1]] = c[2]
    return out


def _tfop_known_relpaths(root="."):
    """EVERY relpath present in a pid/tree fill table, gated or ambiguous -- lets the caller tell a genuinely
    DYNAMIC leaf (absent from all tables) from a known-but-ambiguous static one (binfmt_misc "status")."""
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    known = set()
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "TFOP" and len(c) >= 2 and c[1]:
                known.add(c[1])
    return known


def build_mount_relative_anchors(hm, reg_rows, specific, ops_context_resource, opd, root="."):
    """resource -> {fops REG row}: a syz open of a file on a FS mounted INSIDE a proc subtree (binfmt_misc at
    /proc/sys/fs/binfmt_misc, a SUBTREEHOLE), anchored by stripping the mount prefix to get the path RELATIVE
    to that fs's own root, then joining to the fops its own fill table installs (TFOP) -- the ① fs-mount-
    relative ObjectId method, STRUCTURAL:
      /proc/sys/fs/binfmt_misc/register -> mount /proc/sys/fs/binfmt_misc, rel "register" -> bm_register_operations
      /proc/sys/fs/binfmt_misc/<name>   -> rel absent from ALL tables (a runtime dentry) -> bm_entry_operations
    The mount lives at /proc/<subtree-root>/<hole> (register_sysctl_mount_point holes hang under the sysctl
    root).  A DYNAMIC child (a runtime-named entry, so its relpath is in NO fill table) is typed by DYNCHILD:
    the fops the mount's static file .write handler (register -> bm_register_write) installs on the entries it
    creates.  A known-but-ambiguous static leaf (status) is NOT treated as dynamic (it IS in a table), so it
    never mis-binds to the dynamic fops."""
    tfop = load_tfop(root)
    dynchild = load_dynchild(root)
    known = _tfop_known_relpaths(root)
    mounts = ["/proc/" + rn + "/" + h for rn in load_subtree(root) for h in load_subtree_holes(root)]
    by_fops = _fops_rows(reg_rows)
    # per mount, the dynamic-child fops = the unique DYNCHILD across the .write handlers of its STATIC entries
    fops_write = {ops: fields.get("write") for _k, _n, ops, fields, _s in reg_rows
                  if ops and fields and fields.get("write") not in (None, "-")}
    mount_dyn = {}
    for m in mounts:
        dyns = set()
        for s in hm.get("syscalls", []):
            for p in opd.get(s["name"], ()):
                if p.startswith(m + "/"):
                    sf = tfop.get(p[len(m) + 1:])            # a static entry's fops
                    d = dynchild.get(fops_write.get(sf)) if sf else None
                    if d:
                        dyns.add(d)
        if len(dyns) == 1:
            mount_dyn[m] = next(iter(dyns))
    anchors = collections.defaultdict(set)
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "open$", "openat2$", "syz_open_dev$")):
            continue
        for p in opd.get(name, ()):
            m = next((mt for mt in mounts if p.startswith(mt + "/")), None)
            if not m:
                continue
            rel = p[len(m) + 1:]
            fops = tfop.get(rel)                             # a static entry (unique in the fill tables)
            if not fops and rel not in known:                # a runtime dentry (absent from ALL tables)
                fops = mount_dyn.get(m)
            if not fops:
                continue
            for r in (s.get("produces") or []):
                if specific(r) and ops_context_resource(r):
                    anchors[r].update(by_fops.get(fops, set()))
    return anchors, {}


def build_drm_driver_cmd_anchors(hm, reg_rows, specific, ops_context_resource, already=None, root="."):
    """resource -> {DRM REG row}: driver-specific DRM resources anchored by the driver's ioctl table.

    The structural chain is:
      drm driver fops REG row -> fops.ioctl
      driver-specific CMD facts -> table name (e.g. i915_ioctls[N]) -> cmd values
      resource's ioctl variants -> cmd values

    We only use tables whose CMD facts have a dominant unique table for the resource and whose table stem
    matches a compiled DRM driver fops stem. This is a table/fops relation check, not a resource-name
    fallback: the resource name never selects the row.
    """
    from provenance.socket import _load_variant_consts
    already = already or set()
    drm_rows = collections.defaultdict(set)          # driver stem -> {REG row}
    for idx, (kind, _dev, ops, fields, _sub) in enumerate(reg_rows):
        if kind != "drm" or fields.get("ioctl") != "drm_ioctl":
            continue
        if not ops or ops == "-":
            continue
        stem = re.sub(r"_(?:driver_)?fops$", "", ops)
        if stem:
            drm_rows[stem].add(idx)

    table_cmds = collections.defaultdict(set)        # table stem -> {cmd values}
    for ln in open(os.path.join(root, SH, "kernel_facts_linked", "cmd.tsv")):
        c = ln.rstrip("\n").split("\t")
        if c[0] != "CMD" or len(c) < 4:
            continue
        m = re.match(r"([A-Za-z0-9_]+)_ioctls\[\d+\]$", c[3])
        if not m:
            continue
        stem = m.group(1)
        if stem in drm_rows:
            table_cmds[stem].add(int(c[2]) & 0xFFFFFFFF)

    vconsts = _load_variant_consts(root)
    res_cmds = collections.defaultdict(set)
    for s in hm["syscalls"]:
        if s["name"].split("$", 1)[0] != "ioctl":
            continue
        v = vconsts.get(s["name"], [])
        if not v:
            continue
        for r in (set(s.get("consumes") or []) | set(s.get("uses") or [])):
            res_cmds[r].add(v[0])

    anchors = collections.defaultdict(set)
    evidence = []
    for r, rc in res_cmds.items():
        if r in already or not (specific(r) and ops_context_resource(r)) or not rc:
            continue
        scored = sorted(((len(rc & cmds), stem) for stem, cmds in table_cmds.items() if rc & cmds),
                        reverse=True)
        if not scored:
            continue
        best, stem = scored[0]
        second = scored[1][0] if len(scored) > 1 else 0
        if best >= max(3, 0.5 * len(rc)) and best >= 2 * second:
            anchors[r].update(drm_rows[stem])
            evidence.append((r, stem, best, second, len(rc), sorted(drm_rows[stem])))
    return anchors, evidence


def read_cdrom_block_dops(root="."):
    """[(producer_fn, ops_global, ioctl_handler, rel_bc)] for block disks registered as CD-ROM devices.

    Structural proof pattern:
      - a probe/init function installs a block_device_operations table into gendisk->fops,
      - calls register_cdrom(gendisk, cdi),
      - then calls device_add_disk(gendisk).

    This intentionally returns candidate evidence only.  It does not by itself prove a command-specific
    point binding; it only recovers the block-driver context behind a CD-ROM fd.
    """
    cache = os.path.join(root, SH, "block_cdrom_dops.tsv")
    if os.path.exists(cache) and os.path.getsize(cache) > 0:
        out = []
        for ln in open(cache):
            if not ln.startswith("CDROMBDOPS\t"):
                continue
            c = ln.rstrip("\n").split("\t")
            if len(c) >= 5:
                out.append((c[1], c[2], c[3], c[4]))
        return out

    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from resolve.fixpoint import read_block_dops_tables

    table_handlers = read_block_dops_tables(root)         # {block_device_operations: {ioctl handler}}
    block_ops = set(table_handlers)
    out = []
    # ir_defuse's CDROMBDOPS facts: a fn that calls register_cdrom + device_add_disk and references a
    # block_device_operations global (its gendisk->fops); join that ops to its .ioctl handlers.
    fpath = os.path.join(root, SH, "kernel_facts_linked", "fields.by_tu.tsv")
    if os.path.exists(fpath):
        for ln in open(fpath):
            c = ln.rstrip("\n").split("\t")
            if len(c) < 4 or c[1] != "CDROMBDOPS":
                continue
            unit, fn, ops = c[0], c[2], c[3]
            if ops not in block_ops:
                continue
            rel = os.path.join("run/seed_horizon/kernel_linked/batches", unit + ".bc")
            for h in sorted(table_handlers.get(ops, ())):
                out.append((fn, ops, h, rel))

    out = sorted(set(out))
    with open(cache, "w") as f:
        f.write("#producer_fn\tops\thandler\tbc\n")
        for producer, ops, h, rel in out:
            f.write(f"CDROMBDOPS\t{producer}\t{ops}\t{h}\t{rel}\n")
    return out


def build_block_dops_context(hm, reg_rows, specific, ops_context_resource, root=".",
                             include_candidates=False, with_evidence=False):
    """resource -> [{'ioctl': H}]: the SPECIFIC block-driver ioctl a block fd carries (VARIANT-SPECIFIC
    block_device_operations context, like sock_proto_ctx for sk_prot -- NOT the global union of all block
    ioctl handlers). Block-device provenance grounded by cmd dispatch: among the real block-driver .ioctl
    handlers (read_block_dops_ioctls), the one whose cmd table covers the resource's consumer cmds is that
    resource's gendisk fops.ioctl. fd_loop->lo_ioctl, fd_nbd->nbd_ioctl (each 11/11); driver-agnostic
    fd_block matches none (its generic BLK cmds go to blkdev_ioctl, handled there) -> empty, no fanout."""
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from resolve.dispatch import load_dispatch_graph
    from resolve.fixpoint import read_block_dops_ioctls
    from provenance.socket import _load_variant_consts
    from provenance.devnode import load_open_variant_devpaths
    block_ioctls = read_block_dops_ioctls(root)
    cmd_by_origin = load_dispatch_graph(os.path.join(root, SH))[0]
    htbl = {h: set(cmd_by_origin.get(h, {}).keys()) for h in block_ioctls}
    vconsts = _load_variant_consts(root)
    res_cmds = collections.defaultdict(set)
    for s in hm["syscalls"]:
        if s["name"].split("$", 1)[0] != "ioctl":
            continue
        v = vconsts.get(s["name"], [])
        cv = v[0] if v else None
        if cv is None:
            continue
        for r in (set(s.get("consumes") or []) | set(s.get("uses") or [])):
            res_cmds[r].add(cv)
    out = collections.defaultdict(list)
    evidence = []

    def add(resource, handler, confidence, score=0, second=0, total=0, detail="-"):
        if handler not in {fd.get("ioctl") for fd in out.get(resource, ())}:
            out[resource].append({"ioctl": handler})
        evidence.append({
            "resource": resource,
            "handler": handler,
            "confidence": confidence,
            "score": score,
            "second": second,
            "total": total,
            "detail": detail,
        })

    for r, rc in res_cmds.items():
        if not (specific(r) and ops_context_resource(r)):
            continue
        scored = [(len(rc & ct), h) for h, ct in htbl.items() if rc & ct]
        if not scored:
            continue
        best = max(s for s, _ in scored)
        if best >= max(3, 0.5 * len(rc)):          # the driver whose ioctl handles a majority of R's cmds
            second = max((s for s, _h in scored if s != best), default=0)
            for s, h in scored:
                if s == best:
                    add(r, h, "cmd_majority", best, second, len(rc), "block-dops-cmd-coverage")

    if include_candidates:
        cdrom_handlers = read_cdrom_block_dops(root)
        if cdrom_handlers:
            open_devpaths = load_open_variant_devpaths(hm, root)
            cdrom_resources = collections.defaultdict(set)
            for s in hm.get("syscalls", []):
                name = s.get("name", "")
                if not name.startswith(("openat$", "syz_open_dev$")):
                    continue
                paths = {p for p in open_devpaths.get(name, ())
                         if p == "/dev/cdrom" or p.startswith("/dev/cdrom#")}
                if not paths:
                    continue
                for r in s.get("produces") or []:
                    if specific(r) and ops_context_resource(r):
                        cdrom_resources[r].update(paths)
            for r, paths in cdrom_resources.items():
                for producer, ops, h, rel in cdrom_handlers:
                    detail = f"{producer}:{ops}:{','.join(sorted(paths))}:{rel}"
                    add(r, h, "cdrom_register", 1, 0, len(paths), detail)

    out = dict(out)
    if with_evidence:
        return out, evidence
    return out


def build_usb_dev_anchors(hm, reg_rows, specific, ops_context_resource, open_devpaths, root="."):
    """resource -> {fops REG row}: a usb_register_dev'd character device fd. usb_register_dev registers a
    usb_class_driver {name '<base>%d', fops} and creates /dev/usb/<base># — the cdev recognizer misses it
    because it is not a cdev_add. The REG extraction already records these as kind 'usb' rows
    {device '<base>%d', ops}; match the open variant's /dev/.../<base># devpath to that device name by
    base, the SAME registered-device-name mechanism as misc/cdev. Recovers fd_hiddev (/dev/usb/hiddev# ->
    hiddev_fops, ioctl=hiddev_ioctl)."""
    by_fops = _fops_rows(reg_rows)
    base_rows = collections.defaultdict(set)
    for i, (kind, dev, ops, _fld, _s) in enumerate(reg_rows):
        if kind == "usb" and dev and dev != "-" and ops and ops != "-":
            base = re.sub(r"%.*$", "", dev).rstrip("0123456789").strip("/")
            if base:
                base_rows[base] |= (by_fops.get(ops) or {i})
    anchors = collections.defaultdict(set)
    evidence = []
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        for p in open_devpaths.get(name, ()):
            base = p.rsplit("/", 1)[-1].rstrip("#").rstrip("0123456789")
            rows = base_rows.get(base)
            if not rows:
                continue
            for r in (s.get("produces") or []):
                if specific(r) and ops_context_resource(r):
                    anchors[r].update(rows)
                    evidence.append((name, r, p, base, sorted(rows)))
    return anchors, evidence


def _snd_fmt_to_regex(fmt):
    """A printf device-node format ('pcmC%iD%i%c') -> compiled regex matching a syz /dev/snd/ leaf, where
    %d/%i/%u accept a number OR the syz '#' wildcard, %c a single letter, %s an alnum run."""
    out, i = [], 0
    while i < len(fmt):
        if fmt[i] == "%" and i + 1 < len(fmt):
            j = i + 1
            while j < len(fmt) and fmt[j] in "0123456789.+-# lh":  # printf flags/width
                j += 1
            spec = fmt[j] if j < len(fmt) else ""
            if spec in "diu":
                out.append(r"[0-9#]+")
            elif spec in "xX":
                out.append(r"[0-9a-fA-F#]+")
            elif spec == "c":
                out.append(r"[A-Za-z]")
            elif spec == "s":
                out.append(r"[0-9A-Za-z#_]+")
            else:
                out.append(re.escape(fmt[i:j + 1]))
            i = j + 1
        else:
            out.append(re.escape(fmt[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def load_snd_devnodes(root="."):
    """ALSA (fops, devname-format) pairs recovered from snd.bc by snd_devnodes.py (per-source-file join of
    dev_set_name node-name + snd_register_device fops). Honest-empty if the fact file is absent."""
    out = []
    path = os.path.join(root, SH, "snd_devnodes.tsv")
    if not os.path.exists(path):
        return out
    for ln in open(path):
        c = ln.rstrip("\n").split("\t")
        if len(c) >= 3 and c[0] == "DEVNODE" and c[1] and c[2]:
            out.append((c[1], c[2]))           # (fops_global, devname_format)
    return out


def build_snd_dev_anchors(hm, reg_rows, specific, ops_context_resource, open_devpaths, root="."):
    """resource -> {fops REG row}: an ALSA character device fd opened as /dev/snd/<node>. ALSA splits its
    registration — the file_operations is passed to snd_register_device() while the device-node NAME is set
    by dev_set_name() in the same source file — so neither the .tsv REG row nor the misc/cdev/usb devpath
    recognizers carry a devpath for it. snd_devnodes.py recovers the (fops, node-name-format) pair by
    per-file co-location (the registration mechanism, not the resource name); here we match the kernel's own
    node-name format ('controlC%d', 'pcmC%iD%i%c', ...) to the syz /dev/snd/ devpath and anchor the produced
    fd to that fops' REG row. Recovers fd_snd_ctl/seq/timer/hwdep/rawmidi + pcm playback/capture.

    PRECISION NOTE: snd_pcm_f_ops is a [2 x file_operations] array (elem0=playback, elem1=capture) that
    differ ONLY in .open (snd_pcm_playback_open vs snd_pcm_capture_open); .ioctl is snd_pcm_ioctl for both.
    ir_defuse materializes only elem0, and the syz capture/playback opens both produce the shared fd_snd_dsp
    resource, so the 2 capture-open variants (sndpcmc/pcm1) over-approximate to snd_pcm_playback_open (the
    sibling element of the SAME fops). All pcm IOCTL bindings are exact. A precise capture-open needs
    ir_defuse to emit snd_pcm_f_ops[1] (its real struct offsets) — a Python re-parse would be an offset-guess."""
    pairs = load_snd_devnodes(root)
    if not pairs:
        return collections.defaultdict(set), []
    by_ops = collections.defaultdict(set)      # ops_name -> {row idxs} across ALL kinds (snd_pcm only kind=snd)
    for i, (_kind, _dev, ops_name, fields, _s) in enumerate(reg_rows):
        if ops_name and ops_name != "-" and fields:
            by_ops[ops_name].add(i)
    matchers = [(_snd_fmt_to_regex(fmt), fops, fmt) for (fops, fmt) in pairs]
    anchors = collections.defaultdict(set)
    evidence = []
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        for p in open_devpaths.get(name, ()):
            if not p.startswith("/dev/snd/"):     # OSS nodes (/dev/dsp,/dev/mixer) use other fops; exclude
                continue
            leaf = p[len("/dev/snd/"):]
            for rx, fops, fmt in matchers:
                if not rx.match(leaf):
                    continue
                rows = by_ops.get(fops)
                if not rows:
                    continue
                for r in (s.get("produces") or []):
                    if specific(r) and ops_context_resource(r):
                        anchors[r].update(rows)
                        evidence.append((name, r, p, fops, fmt, sorted(rows)))
    return anchors, evidence


def _norm_devpath_local(path):
    from provenance.devnode import norm_devpath
    return norm_devpath(path)


def _oss_unit_paths(base):
    return {_norm_devpath_local(base), _norm_devpath_local(base + "1")}


def _snd_oss_paths(oss_type, dev):
    """ALSA OSS type/dev -> kernel soundcore devnodes.

    This mirrors sound/core/sound_oss.c:snd_oss_kernel_minor plus
    sound/sound_core.c:register_sound_special_device. Per-card devices can
    appear as the bare node for card0 and as <node>N for later cards; both are
    normalized before matching against syz open paths.
    """
    if oss_type == 0:      # SNDRV_OSS_DEVICE_TYPE_MIXER
        return _oss_unit_paths("mixer") if dev == 0 else set()
    if oss_type == 1:      # SNDRV_OSS_DEVICE_TYPE_SEQUENCER
        return {_norm_devpath_local("sequencer")}
    if oss_type == 6:      # SNDRV_OSS_DEVICE_TYPE_MUSIC -> sequencer2
        return {_norm_devpath_local("sequencer2")}
    if oss_type == 2:      # SNDRV_OSS_DEVICE_TYPE_PCM
        if dev == 0:
            return _oss_unit_paths("dsp") | _oss_unit_paths("audio")
        if dev == 1:
            return _oss_unit_paths("adsp")
        return set()
    if oss_type == 3:      # SNDRV_OSS_DEVICE_TYPE_MIDI
        if dev == 0:
            return _oss_unit_paths("midi") | _oss_unit_paths("dmmidi")
        if dev == 1:
            return _oss_unit_paths("amidi") | _oss_unit_paths("admmidi")
        return set()
    if oss_type == 4:      # SNDRV_OSS_DEVICE_TYPE_DMFM
        return _oss_unit_paths("dmfm")
    return set()


def extract_snd_oss_devnodes(root=".", bcs=None):
    """Recover ALSA OSS devnode -> fops pairs from ir_defuse's SNDOSS facts (no Python disassembly).

    Structural chain:
      snd_register_oss_device(type, card, dev, fops, private)
        -> sound_oss.c:snd_oss_kernel_minor(type, card, dev)
        -> sound_core.c:register_sound_special_device(fops, minor, ...)
        -> sound_core.c:sound_insert_unit(..., name)

    ir_defuse emits SNDOSS <type> <dev> <fops> for each constant-type/dev call; `_snd_oss_paths` maps the
    (type, dev) constants to the soundcore node names (the kernel-constant mapping).  This deliberately does
    not use resource names or fops names to infer paths.  `bcs` is accepted for compatibility but ignored.
    """
    rows = set()  # (devpath, fops, type, dev, unit)
    fpath = os.path.join(root, SH, "kernel_facts_linked", "fields.by_tu.tsv")
    if not os.path.exists(fpath):
        return rows
    for ln in open(fpath):
        c = ln.rstrip("\n").split("\t")
        if len(c) < 5 or c[1] != "SNDOSS":
            continue
        try:
            oss_type, dev = int(c[2]), int(c[3])
        except ValueError:
            continue
        fops = c[4]
        if not fops:
            continue
        for path in _snd_oss_paths(oss_type, dev):
            if path:
                rows.add((path, fops, oss_type, dev, c[0]))
    return rows


def build_snd_oss_dev_anchors(hm, reg_rows, specific, ops_context_resource, open_devpaths, root="."):
    """resource -> {fops REG row}: ALSA OSS nodes such as /dev/dsp, /dev/audio,
    /dev/sequencer and /dev/mixer. The node names come from the kernel OSS
    minor/type registration path, while fops come from snd_register_oss_device().
    """
    pairs = extract_snd_oss_devnodes(root)
    if not pairs:
        return collections.defaultdict(set), []
    by_ops = collections.defaultdict(set)
    for i, (_kind, _dev, ops_name, fields, _s) in enumerate(reg_rows):
        if ops_name and ops_name != "-" and fields:
            by_ops[ops_name].add(i)
    path_fops = collections.defaultdict(set)
    src = collections.defaultdict(set)
    for path, fops, oss_type, dev, bc in pairs:
        path_fops[path].add(fops)
        src[(path, fops)].add(f"{bc}:snd_register_oss_device(type={oss_type},dev={dev})")

    anchors = collections.defaultdict(set)
    evidence = []
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        for p in open_devpaths.get(name, ()):
            for fops in sorted(path_fops.get(p, ())):
                rows = by_ops.get(fops, set())
                if not rows:
                    continue
                for r in (s.get("produces") or []):
                    if specific(r) and ops_context_resource(r):
                        anchors[r].update(rows)
                        evidence.append((name, r, p, fops, sorted(rows), sorted(src[(p, fops)])))
    return anchors, evidence


def load_dvb_devnodes(root="."):
    """DVB (fops, devnode-typename) pairs recovered from dvb-core by dvb_devnodes.py (dvb_register_device
    template.fops + the @dnames type->name table). Honest-empty if the fact file is absent."""
    out = []
    path = os.path.join(root, SH, "dvb_devnodes.tsv")
    if not os.path.exists(path):
        return out
    for ln in open(path):
        c = ln.rstrip("\n").split("\t")
        if len(c) >= 3 and c[0] == "DVBNODE" and c[1] and c[2]:
            out.append((c[1], c[2]))           # (fops_global, devnode_typename)
    return out


def build_dvb_dev_anchors(hm, reg_rows, specific, ops_context_resource, open_devpaths, root="."):
    """resource -> {fops REG row}: a DVB char device fd opened as /dev/dvb/adapter#/<type>#. DVB registers
    via dvb_register_device(template, type) — the fops is the template's .fops, the node name is the
    @dnames[type] string ("frontend"/"demux"/"dvr"/"ca"). dvb_devnodes.py recovers the (fops, typename)
    pair (registration mechanism, not name); here we match the syz /dev/dvb/.../<typename># devpath leaf to
    that typename and anchor the produced fd to the fops' REG row. Recovers fd_dvb_frontend/demux/dvr/ca."""
    pairs = load_dvb_devnodes(root)
    if not pairs:
        return collections.defaultdict(set), []
    by_ops = collections.defaultdict(set)
    for i, (_kind, _dev, ops_name, fields, _s) in enumerate(reg_rows):
        if ops_name and ops_name != "-" and fields:
            by_ops[ops_name].add(i)
    type_fops = {tn: fops for (fops, tn) in pairs}
    anchors = collections.defaultdict(set)
    evidence = []
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        for p in open_devpaths.get(name, ()):
            if not p.startswith("/dev/dvb/"):
                continue
            leaf = re.sub(r"[#0-9]+$", "", p.rsplit("/", 1)[-1])     # "demux#" -> "demux"
            fops = type_fops.get(leaf)
            if not fops:
                continue
            rows = by_ops.get(fops)
            if not rows:
                continue
            for r in (s.get("produces") or []):
                if specific(r) and ops_context_resource(r):
                    anchors[r].update(rows)
                    evidence.append((name, r, p, fops, leaf, sorted(rows)))
    return anchors, evidence


def _clean_path_component(s):
    raw = (s or "").split("\\")[0].split("\0")[0].strip("/")
    if not raw or raw in {".", ".."}:
        return None
    if "/" in raw:
        return None
    return raw


def _debugfs_child(parent, name, root="/sys/kernel/debug", dynamic=False):
    name = _clean_path_component(name)
    if not name and dynamic:
        name = "*"
    if not name:
        return None
    parent = parent.rstrip("/") if parent else root
    return parent + "/" + name


# Structural dentry-path recovery, run as a recognizer/resolver FIXPOINT (same model as run_fixpoint in
# resolve/fixpoint.py and the `for _ in range(4)` loop in build_full_res2rows below).  The dentry lattice
# has levels -- root globals -> struct-field dirs -> sub-dirs -> files -- whose parents are created/stored
# in one function or .bc and loaded in another, so a single ordered pass under-approximates.  ir_defuse emits
# the per-function dentry-dataflow events (DBGFS* in fields.by_tu.tsv); we iterate a cheap in-memory resolve
# over a MODULE-GLOBAL, monotone context until no new binding is learned, resolving multi-level AND
# cross-translation-unit chains (e.g. dev->debugfs_root written in drm-core, read in i915).  No Python
# disassembly: the IR understanding (field-GEP offsets/names, the create-call args, the NULL-parent edge) is
# done in ir_defuse; this side keeps only the fixpoint resolution + path normalization.
#
# A field dentry is keyed by (normalized field name, byte offset), FALLING BACK to byte-offset alone when the
# GEP result is unnamed.  The name disambiguates distinct structs that reuse the same offset; the offset
# fallback links a numeric store to a named load.  All lattices are set-valued and hold only already-resolved
# dentry paths; propagation requires a UNIQUE path for the key (_unique), so any clash is a conservative
# miss, never a wrong path.  Resolution is SCOPED: globals (internal linkage) and field bindings resolve
# per-.bc FIRST; only struct fields fall back to a module-global map, since the struct INSTANCE -- not the
# symbol -- is what is shared across .bc.
_DEBUGFS_MAX_ROUNDS = 6                  # chain depth root->devdir->subdir->file ~4, + cross-.bc/order slack


def _unique(paths):
    """The sole path of a lattice cell, or None if absent/ambiguous (the soundness guard)."""
    return next(iter(paths)) if paths and len(paths) == 1 else None


def _debugfs_load_units(root):
    """Read ir_defuse's DBGFS* facts from fields.by_tu.tsv -> [(bc_rel, {@str: literal}, [(fn, params,
    [event, ...]), ...]), ...], one entry per link-unit (batch).  The event tuples are byte-for-byte what the
    old llvm-dis _debugfs_scan_unit produced, so the resolution (_debugfs_resolve_*) below is unchanged.  A
    "-"/"null" ref maps to None (a NULL / absent operand -> fs root, or a runtime/dynamic name)."""
    fpath = os.path.join(root, SH, "kernel_facts_linked", "fields.by_tu.tsv")
    if not os.path.exists(fpath):
        return []
    raw = {}                                            # unit -> {"strings": {...}, "fns": {fn: [params, evs]}}

    def _ref(t):
        return None if t in ("null", "-") else t

    with open(fpath) as f:
        for ln in f:
            c = ln.rstrip("\n").split("\t")
            if len(c) < 4 or c[1] not in ("DBGFS", "DBGFSSTR"):
                continue
            u = raw.setdefault(c[0], {"strings": {}, "fns": {}})
            if c[1] == "DBGFSSTR":
                u["strings"][c[2]] = c[3]
                continue
            fn, ev = c[2], c[3]
            slot = u["fns"].setdefault(fn, [[], []])    # [params, events]
            if ev == "PARAMS":
                slot[0] = c[4].split(",") if len(c) >= 5 and c[4] else []
            elif ev == "GEP" and len(c) >= 7:
                slot[1].append(("GEP", c[4], int(c[5]), None if c[6] == "-" else c[6]))
            elif ev in ("LDG", "LDF", "STG", "STF") and len(c) >= 6:
                slot[1].append((ev, c[4], c[5]))
            elif ev == "PHI" and len(c) >= 6:
                slot[1].append(("PHI", c[4], c[5].split(",")))
            elif ev == "CDIR" and len(c) >= 8:
                slot[1].append(("CDIR", c[4], _ref(c[5]), _ref(c[6]), c[7]))
            elif ev == "CFILE" and len(c) >= 8:
                slot[1].append(("CFILE", _ref(c[4]), _ref(c[5]), c[6].split(","), c[7]))
            elif ev == "CALL" and len(c) >= 6:
                slot[1].append(("CALL", c[4], [int(x) for x in c[5].split(",") if x != ""]))
    units = []
    for unit, u in raw.items():
        fns = [(fn, p, evs) for fn, (p, evs) in u["fns"].items()]
        names = {fn for fn, _, _ in fns}                # keep only CALLs into THIS unit's own functions
        kept = []
        for fn, params, events in fns:
            evs = [e for e in events if e[0] != "CALL" or e[1] in names]
            if any(e[0] in ("CDIR", "CFILE", "STG", "STF", "CALL") for e in evs):
                kept.append((fn, params, evs))
        bc_rel = os.path.join(SH, "kernel_linked", "batches", unit + ".bc")
        units.append((bc_rel, u["strings"], kept))
    return units


def _debugfs_resolve_fn(fn, params, events, strings, loc, g_no, g_off, emit=None):
    """Resolve one function's events under SCOPED context.  loc = the per-.bc maps (global, field-by-
    (name,off), field-by-off, null-param).  Globals are file-local (internal linkage).  Field dentries
    resolve LOCAL-FIRST then fall back to the MODULE-GLOBAL maps (g_no/g_off) for cross-.bc shared structs
    (dev->debugfs_root written in drm-core, read in i915).  THE CALL EDGE: a parameter that some caller
    passes NULL is the fs root, so a create whose parent is that parameter roots at the mount -- proven
    interprocedurally, not guessed.  A non-NULL parent that stays unresolved makes a dir DEFER and a file
    NOT emit (no shallow-root fallback).  Returns True if a LOCAL binding grew (drives the inner fixpoint).
    ssa_paths/field_gep are function-local; emit=(known_fops, rows, bc_rel) emits create_file rows."""
    loc_global, loc_no, loc_off, loc_null = loc
    ssa_paths, field_gep, grew = {}, {}, False
    null_ssa = {params[i] for i in loc_null.get(fn, ()) if i < len(params) and params[i]}

    def _field(off, name):                       # local (name,off) -> local off -> global (name,off) -> off
        return ((name and _unique(loc_no.get((name, off)))) or _unique(loc_off.get(off))
                or (name and _unique(g_no.get((name, off)))) or _unique(g_off.get(off)))

    def _parent(pref):                           # -> (parent, ok); parent None == top-level; ok False == defer
        if not pref or pref == "@NULL" or pref in null_ssa:
            return None, True                    # NULL literal, or a parameter the caller passes NULL = root
        p = ssa_paths.get(pref) or _unique(loc_global.get(pref))
        return p, (p is not None)

    for ev in events:
        k = ev[0]
        if k == "GEP":
            field_gep[ev[1]] = (ev[2], ev[3])                # (byte_offset, normalized field name or None)
        elif k == "LDG":
            p = _unique(loc_global.get(ev[2]))
            if p:
                ssa_paths[ev[1]] = p
        elif k == "LDF":
            fg = field_gep.get(ev[2])
            if fg is not None:
                p = _field(*fg)
                if p:
                    ssa_paths[ev[1]] = p
        elif k == "PHI":
            cand = {v for op in ev[2] if op != "null"
                    for v in (ssa_paths.get(op) or _unique(loc_global.get(op)),) if v}
            if len(cand) == 1:
                ssa_paths[ev[1]] = next(iter(cand))
        elif k == "STG":
            v = ssa_paths.get(ev[1]) or _unique(loc_global.get(ev[1]))
            if v and v not in loc_global.setdefault(ev[2], set()):
                loc_global[ev[2]].add(v)
                grew = True
        elif k == "STF":
            fg = field_gep.get(ev[2])
            if fg is not None:
                off, name = fg
                v = ssa_paths.get(ev[1]) or _unique(loc_global.get(ev[1]))
                if v:
                    if v not in loc_off.setdefault(off, set()):
                        loc_off[off].add(v)
                        grew = True
                    if name and v not in loc_no.setdefault((name, off), set()):
                        loc_no[(name, off)].add(v)
                        grew = True
        elif k == "CALL":                        # the call edge: caller's NULL arg -> callee parameter is root
            seen = loc_null.setdefault(ev[1], set())
            for i in ev[2]:
                if i not in seen:
                    seen.add(i)
                    grew = True
        elif k == "CDIR":
            dst, nref, pref, rootp = ev[1], ev[2], ev[3], ev[4]
            parent, ok = _parent(pref)
            if not ok:
                continue                         # non-NULL parent unresolved -> defer (no pollution)
            name = strings.get(nref)
            dynamic = bool(parent and name is None and nref and nref != "@NULL")
            path = _debugfs_child(parent, name, rootp, dynamic)
            if path and dst:
                ssa_paths[dst] = path
        elif k == "CFILE" and emit is not None:
            known_fops, rows, bc_rel = emit
            nref, pref, fops_refs, rootp = ev[1], ev[2], ev[3], ev[4]
            parent, ok = _parent(pref)
            if not ok:
                continue                         # unresolved non-NULL parent -> do NOT emit (no fallback)
            path = _debugfs_child(parent, strings.get(nref), rootp)
            for ref in fops_refs:
                fops = ref[1:] if ref and ref.startswith("@") else None
                if path and fops in known_fops:
                    rows.add((path, fops, bc_rel, fn))
    return grew


def _debugfs_resolve_unit(strings, fns, g_no, g_off, emit=None):
    """Run a per-.bc inner fixpoint: converge file-local globals, local field bindings, and NULL-passed
    parameters (the call edge), using the module-global field maps as fallback; then optionally emit
    create_file rows.  Returns this unit's learned local field maps (loc_no, loc_off) for the merge."""
    loc = ({}, {}, {}, {})                       # global, field-by-(name,off), field-by-off, null-param
    for _ in range(_DEBUGFS_MAX_ROUNDS):
        grew = False
        for fn, params, events in fns:
            if _debugfs_resolve_fn(fn, params, events, strings, loc, g_no, g_off):
                grew = True
        if not grew:
            break
    if emit is not None:
        for fn, params, events in fns:
            _debugfs_resolve_fn(fn, params, events, strings, loc, g_no, g_off, emit=emit)
    return loc[1], loc[2]


def extract_debugfs_paths(root=".", out=None, known_fops=None, bcs=None):
    """Emit DEBUGFSPATH <absolute debugfs/tracefs path> <fops>.

    This is a structural debugfs/tracefs registration recognizer:
      debugfs_create_dir("sync", NULL) -> /sys/kernel/debug/sync
      debugfs_create_file("sw_sync", ..., parent, ..., &fops)
        -> /sys/kernel/debug/sync/sw_sync carries fops.
      tracefs_create_file("trace_pipe_raw", ..., parent, ..., &fops)
        -> /sys/kernel/tracing/.../trace_pipe_raw carries fops.

    Parents reached through globals or struct fields are stored in one
    function or .bc and loaded in another, so this runs as a fixpoint over a
    module-global dentry context (see the comment above _DEBUGFS_MAX_ROUNDS)
    until it quiesces.  If a directory name is runtime-computed but the parent
    is known, it emits a single-segment wildcard; file names must still be
    static.  The per-function dentry-dataflow events come from ir_defuse's DBGFS*
    facts (no Python disassembly); `bcs` is accepted but ignored.
    """
    out = out or os.path.join(root, SH, "debugfs_paths.tsv")
    known_fops = known_fops or set()
    units = _debugfs_load_units(root)            # ir_defuse DBGFS* facts, grouped by link-unit (batch)
    g_no, g_off = {}, {}                         # MODULE-GLOBAL field lattices (cross-.bc fallback)
    for _ in range(_DEBUGFS_MAX_ROUNDS):         # outer fixpoint: accumulate cross-.bc field bindings
        grew = False
        for _bc_rel, strings, fns in units:
            loc_no, loc_off = _debugfs_resolve_unit(strings, fns, g_no, g_off)
            for key, ps in loc_no.items():       # merge this unit's local fields into the module-global maps
                d = g_no.setdefault(key, set())
                if not ps <= d:
                    d |= ps
                    grew = True
            for off, ps in loc_off.items():
                d = g_off.setdefault(off, set())
                if not ps <= d:
                    d |= ps
                    grew = True
        if not grew:
            break
    rows = set()                                 # emit per-.bc against the converged module-global fields
    for bc_rel, strings, fns in units:
        _debugfs_resolve_unit(strings, fns, g_no, g_off, emit=(known_fops, rows, bc_rel))
    with open(out, "w") as f:
        f.write("#path\tfops\tbc\tfn\n")
        for path, fops, bc, fn in sorted(rows):
            f.write(f"DEBUGFSPATH\t{path}\t{fops}\t{bc}\t{fn}\n")
    return out


def build_debugfs_anchors(hm, reg_rows, specific, ops_context_resource, open_devpaths, root="."):
    """resource -> {fops REG row}: an fd opened from a debugfs file whose path/fops
    pair is proven by debugfs_create_dir/debugfs_create_file IR.
    """
    by_fops = _fops_rows(reg_rows)
    known = {ops for ops in by_fops}
    path = os.path.join(root, SH, "debugfs_paths.tsv")
    if not os.path.exists(path) or not os.path.getsize(path):
        extract_debugfs_paths(root, path, known_fops=known)
    path_fops = collections.defaultdict(set)
    pattern_fops = []
    src = collections.defaultdict(set)

    def aliases(p):
        out = {p}
        if p.startswith("/sys/kernel/tracing/"):
            out.add("/sys/kernel/debug/tracing/" + p[len("/sys/kernel/tracing/"):])
        return out

    for ln in open(path):
        c = ln.rstrip("\n").split("\t")
        if c[0] == "DEBUGFSPATH" and len(c) >= 4:
            for p in aliases(c[1]):
                if "*" in p:
                    pattern_fops.append((p, c[2]))
                else:
                    path_fops[p].add(c[2])
                src[(p, c[2])].add(":".join(c[3:]))

    anchors = collections.defaultdict(set)
    evidence = []
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        for p in open_devpaths.get(name, ()):
            fopss = set(path_fops.get(p, ()))
            for patt, fops in pattern_fops:
                if _devpath_pattern_matches(patt, p):
                    fopss.add(fops)
            for fops in sorted(fopss):
                rows = by_fops.get(fops, set())
                if not rows:
                    continue
                for r in (s.get("produces") or []):
                    if specific(r) and ops_context_resource(r):
                        anchors[r].update(rows)
                        evidence.append((name, r, p, fops, sorted(rows), sorted(src[(p, fops)])))
    return anchors, evidence


def _binderfs_segment(path):
    parts = [p for p in path.strip("/").split("/") if p]
    for i, part in enumerate(parts):
        if part.startswith("binderfs"):
            return parts[i + 1:]
    return []


def build_binderfs_anchors(hm, reg_rows, specific, ops_context_resource, open_devpaths, root="."):
    """resource -> {fops REG row}: files opened from a binderfs mount.

    Full userspace mount paths are syz-model artifacts (./binderfs,
    ./binderfs2, /dev/binderfs).  The kernel proof is binderfs' own inode
    creation: the root control file carries binder_ctl_fops, and root-level
    binder device files carry binder_fops.
    """
    proven = set()       # fops on a persistent pseudo-fs dentry, from ir_defuse's PERSISTFOP facts; the
    fpath = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")   # binder leaf check filters to binderfs
    if os.path.exists(fpath):
        for ln in open(fpath):
            if ln.startswith("PERSISTFOP\t"):
                proven.add(ln.rstrip("\n").split("\t")[1])
    by_fops = _fops_rows(reg_rows)
    anchors = collections.defaultdict(set)
    evidence = []
    for s in hm.get("syscalls", []):
        name = s["name"]
        if not name.startswith(("openat$", "syz_open_dev$")):
            continue
        for p in open_devpaths.get(name, ()):
            rest = _binderfs_segment(p)
            if len(rest) != 1:
                continue
            leaf = rest[0].rstrip("#")
            fops = "binder_ctl_fops" if leaf == "binder-control" else "binder_fops"
            if fops not in proven:
                continue
            rows = by_fops.get(fops, set())
            if not rows:
                continue
            for r in (s.get("produces") or []):
                if specific(r) and ops_context_resource(r):
                    anchors[r].update(rows)
                    evidence.append((name, r, p, fops, sorted(rows)))
    return anchors, evidence


def build_anon_anchors(hm, reg_rows, specific, ops_context_resource, handler_of, root="."):
    """resource -> {fops REG row}: an fd produced by variant V whose bound handler region creates it via
    anon_inode_get*(&fops). handler_of(variant) -> set of region functions (the resolved leaf + roots).
    CHAIN: only fires once V is bound, so it runs inside the provenance fixpoint after each bind pass."""
    _misc, anon = _load_facts(root)
    by_fops = _fops_rows(reg_rows)
    anchors = collections.defaultdict(set)
    evidence = []
    for s in hm.get("syscalls", []):
        produced = [r for r in (s.get("produces") or []) if specific(r) and ops_context_resource(r)]
        if not produced:
            continue
        region = handler_of(s["name"])
        if not region:
            continue
        fopss = set()
        for fn in region:
            fopss |= anon.get(fn, set())
        if len(fopss) != 1:                       # unique anon fops in the producer region -> sound
            continue
        fops = next(iter(fopss))
        rows = by_fops.get(fops, set())
        for r in produced:
            anchors[r].update(rows)
            if rows:
                evidence.append((s["name"], r, fops, sorted(rows)))
    return anchors, evidence


class _CmdRootIndex:
    def __init__(self):
        self.exact = collections.defaultdict(lambda: collections.defaultdict(set))
        self.masked = collections.defaultdict(
            lambda: collections.defaultdict(
                lambda: collections.defaultdict(lambda: collections.defaultdict(set))))

    def add(self, origin, value, roots, depth, mask=None):
        self.exact[(origin, value)][depth].update(roots)
        if mask is not None:
            self.masked[origin][mask][value & mask][depth].update(roots)

    def get(self, key, default=None):
        origin, value = key
        levels = self.exact.get((origin, value))
        roots = set(levels[min(levels)]) if levels else set()
        for mask, table in self.masked.get(origin, {}).items():
            masked_levels = table.get(value & mask)
            if masked_levels:
                roots.update(masked_levels[min(masked_levels)])
        return roots if roots else default

    def __len__(self):
        return len(self.exact)


def _cmd_roots(root="."):
    """(handler, value) -> {region funcs} from the CMD facts — the value-narrowed callees a producer's
    cmd reaches (used by the anon fixpoint to find anon_inode_get* in a deeper cmd-scoped callee)."""
    out = _CmdRootIndex()
    linked = os.path.join(root, SH, "kernel_facts_linked", "cmd.tsv")
    if not os.path.exists(linked) or not os.path.getsize(linked):
        raise FileNotFoundError(f"missing linked kernel fact file: {linked}")
    files = [linked]
    for f in files:
        for ln in open(f):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "CMD" and len(c) > 7:
                try:
                    val = int(c[2]) & 0xFFFFFFFF
                except ValueError:
                    continue
                try:
                    depth = int(c[6][1:]) if c[6].startswith("d") else 0
                except ValueError:
                    depth = 0
                roots = {x for x in c[7].split(",") if x}
                origin = c[1]
                key_kind = ""
                # ALSO key by the DISPATCHER (origin): a producer's fops.ioctl IS the origin, so a cmd handled
                # via an ops table (media_ioctl -> media_device_request_alloc) is reachable as (origin, cmd) --
                # this lets the anon fixpoint descend to the cmd's leaf roots (media_request_alloc -> request_fops).
                for extra in c[8:]:
                    if extra.startswith("origin="):
                        origin = extra[len("origin="):]
                    elif extra.startswith("key_kind="):
                        key_kind = extra[len("key_kind="):]
                mask = None
                if key_kind == "iocnr":
                    mask = 0x3FFFFFFF
                elif key_kind.startswith("mask:"):
                    try:
                        mask = int(key_kind.split(":", 1)[1], 0) & 0xFFFFFFFF
                    except ValueError:
                        pass
                out.add(c[1], val, roots, depth, mask)
                if origin != c[1]:
                    out.add(origin, val, roots, depth, mask)
    return out


# special-inode (block/char device) provenance. A device node's inode gets its i_fop from
# init_special_inode (S_ISBLK -> def_blk_fops, S_ISCHR -> def_chr_fops), NOT from cdev_add/misc_register,
# so the devnode/cdev recognizers miss it (e.g. fd_block from openat$nullb is unanchored). We ground the
# fops by the MECHANISM (a `store @fops` inside init_special_inode) and pick which one a resource carries
# by CMD DISPATCH (the special-inode fops whose .ioctl dispatches the majority of the resource's
# consumer-ioctl cmds), never by name. def_blk_fops.ioctl=blkdev_ioctl dispatches the BLK* cmds, so
# fd_block/fd_loop/fd_nbd -> def_blk_fops; def_chr_fops has no .ioctl so it anchors nothing here.
def build_special_inode_anchors(hm, reg_rows, specific, ops_context_resource, root="."):
    """resource -> {REG row}: a special-device fd anchored to its init_special_inode fops, chosen by cmd
    dispatch (the special-inode fops whose .ioctl handles the majority of the resource's consumer cmds)."""
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from resolve.dispatch import load_dispatch_graph
    from provenance.socket import _load_variant_consts
    special = set()       # init_special_inode fops, from ir_defuse's SPECIALFOP facts (fields.tsv)
    fpath = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    if os.path.exists(fpath):
        for ln in open(fpath):
            if ln.startswith("SPECIALFOP\t"):
                special.add(ln.rstrip("\n").split("\t")[1])
    cmd_by_origin = load_dispatch_graph(os.path.join(root, SH))[0]
    frow, ctab = {}, {}                      # special-inode fops with a dispatching .ioctl -> REG row + cmd table
    for i, (kind, _d, ops, fld, _s) in enumerate(reg_rows):
        if kind == "fops" and ops in special and fld.get("ioctl") and fld["ioctl"] != "-":
            frow.setdefault(ops, i)
            ctab[ops] = set(cmd_by_origin.get(fld["ioctl"], {}).keys())
    vconsts = _load_variant_consts(root)
    res_cmds = collections.defaultdict(set)
    for s in hm["syscalls"]:
        if s["name"].split("$", 1)[0] != "ioctl":
            continue
        v = vconsts.get(s["name"], [])
        cv = v[0] if v else None
        if cv is None:
            continue
        for r in (set(s.get("consumes") or []) | set(s.get("uses") or [])):
            res_cmds[r].add(cv)
    anchors = collections.defaultdict(set)
    evidence = []
    for r, rc in res_cmds.items():
        if not (specific(r) and ops_context_resource(r)) or not rc:
            continue
        best, bcov = None, 0
        for ops, ct in ctab.items():
            cov = len(rc & ct)
            if cov > bcov:
                bcov, best = cov, ops
        if best and bcov >= max(3, 0.5 * len(rc)):   # majority of consumer cmds dispatched by this i_fop
            anchors[r].add(frow[best])
            evidence.append((r, best, bcov, len(rc)))
    # block-kind propagation: def_blk_fops is carried by EVERY block-device fd (init_special_inode S_ISBLK
    # is universal), but a block fd whose cmds are mostly driver-specific (fd_loop: LOOP_* -> lo_ioctl,
    # fd_nbd: NBD_* -> nbd_ioctl, reached via the block_device_operations forward) falls below the
    # cmd-dispatch majority. A cmd-confirmed member establishes the syz block-fd KIND for this fops;
    # propagate to siblings sharing that specific kind tag -- BUT NOT to a resource that has its OWN
    # registered device fops (fd_sg -> sg_ioctl=sg_fops.ioctl, fd_bsg -> bsg_ioctl): those are char
    # devices that only share the broad fd_block_trace category and must anchor to their own fops, not
    # def_blk_fops. Guard = the resource's cmds do not majority-dispatch to a registered fops .ioctl.
    from model.variant import AMBIENT
    res_kind = {r["name"]: set(r.get("kind") or []) for r in hm.get("resources", [])}
    own_fops_ioctl = {fld.get("ioctl") for (kind, _d, _o, fld, _s) in reg_rows
                      if kind in ("fops", "cdev", "misc", "chrdev", "usb")
                      and fld.get("ioctl") and fld["ioctl"] != "-"}
    cmd_handlers = collections.defaultdict(set)
    for origin, tbl in cmd_by_origin.items():
        for cvv in tbl:
            cmd_handlers[cvv].add(origin)

    def has_own_fops(rc):
        h = collections.Counter()
        for cvv in rc:
            for hd in cmd_handlers.get(cvv, ()):
                if hd in own_fops_ioctl:
                    h[hd] += 1
        return bool(h) and max(h.values()) >= max(3, 0.5 * len(rc))

    fops_tags = collections.defaultdict(set)          # fops REG row -> {specific kind tag of confirmed res}
    for r, rows in list(anchors.items()):
        tags = {t for t in res_kind.get(r, ()) if t not in AMBIENT and t != "fd"}
        for row in rows:
            fops_tags[row] |= tags
    for r in res_cmds:
        if not (specific(r) and ops_context_resource(r)) or r in anchors or has_own_fops(res_cmds[r]):
            continue
        rtags = res_kind.get(r, set())
        for row, tags in fops_tags.items():
            if rtags & tags:
                anchors[r].add(row)
                evidence.append((r, "block-kind-propagated", 0, len(res_cmds[r])))
                break
    # CD-ROM block devices mostly dispatch CDROM_* commands through block_device_operations, so they do not
    # satisfy the generic blkdev_ioctl majority test above. Once block_dops_context proves the resource is a
    # register_cdrom/device_add_disk block device, the special inode entry fops is still the universal
    # def_blk_fops; the driver-specific ioctl remains a separate recursive block_device_operations context.
    def_blk_row = frow.get("def_blk_fops")
    if def_blk_row is not None:
        try:
            _block_ctx, block_ev = build_block_dops_context(
                hm, reg_rows, specific, ops_context_resource, root,
                include_candidates=True, with_evidence=True)
        except Exception:
            block_ev = []
        for ev in block_ev:
            if ev.get("confidence") != "cdrom_register":
                continue
            r = ev.get("resource")
            if not r or not (specific(r) and ops_context_resource(r)):
                continue
            anchors[r].add(def_blk_row)
            evidence.append((r, "cdrom-special-inode", 1, ev.get("total", 0)))
    return anchors, evidence


# RETIRED: resolve_subops_icalls / load_subops_icalls (the flat global sub-ops type-scan) is replaced by
# the grounded ContextProvider-in-fixpoint (resolve/fixpoint.py: read_struct_offsets + run_fixpoint). The
# type-scan pre-injected (from -> targets) edges before resolve, so it could not chain to the next
# struct-kind, was not demand-driven, and was ungrounded. The fixpoint demands a struct-kind only when
# the walk reaches it, satisfies it once per round (batched, cached), and re-resolves one level deeper.


def propagate_parent_kind_anchors(hm, res2rows, specific, ops_context_resource):
    """Propagate anchored concrete resources to abstract parent-kind resources.

    syz resources encode hierarchy through the `kind` list: a concrete producer like `vhost_net` can have
    kind [`fd`, `fd_vhost`, `vhost_net`], while consumers may use the abstract parent `fd_vhost`. The
    concrete resource's REG rows are therefore candidates for the parent, not a point binding. This is a
    structural syz-model relation; it never matches by suffix/name and never chooses a single handler.
    """
    res_kind = {r["name"]: set(r.get("kind") or []) for r in hm.get("resources", [])}
    res_producer_count = {r["name"]: int(r.get("producer_count") or 0) for r in hm.get("resources", [])}
    res_names = set(res_kind)
    evidence = []  # (parent, child, row)
    changed = True
    while changed:
        changed = False
        snapshot = {resource: set(rows) for resource, rows in res2rows.items() if rows}
        for child, rows in sorted(snapshot.items()):
            if child not in res_names:
                continue
            if not (specific(child) and ops_context_resource(child)):
                continue
            for parent in sorted(res_kind.get(child, ())):
                if parent == child or parent not in res_names:
                    continue
                if res_producer_count.get(parent, 0) != 0:
                    continue
                if not (specific(parent) and ops_context_resource(parent)):
                    continue
                old = res2rows.get(parent, set())
                new = rows - old
                if not new:
                    continue
                res2rows.setdefault(parent, set()).update(new)
                evidence.extend((parent, child, row) for row in sorted(new))
                changed = True
    return res2rows, evidence


def build_full_provenance_rows(
        hm, reg_rows, specific, ops_context_resource, root=".", seed_sink=None):
    """Build the structural entry context for resources and individual variants.

    Most install facts persist on a typed syzkaller resource and belong in ``res2rows``.  Some producers
    return a generic resource even though the producing variant has a precise object identity; those facts
    belong in ``variant2rows`` and must not contaminate every user of that generic resource.
    """
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from provenance.devnode import build_devpath_resource_anchors, load_open_variant_devpaths
    from provenance.socket import build_sock_resource_anchors, _load_variant_consts
    from provenance.cgroup import build_cgroup_cftype_anchors

    res2rows = collections.defaultdict(set)
    variant2rows = collections.defaultdict(set)

    def merge(target, root_kind, root_key, rows, method, source, parent_root="-"):
        target[root_key].update(rows)
        if seed_sink is None:
            return
        for row in rows:
            seed_sink(InstallSeed(
                relation="entry_install",
                root_kind=root_kind,
                root=root_key,
                method=method,
                reg_row=row,
                source=source,
                parent_root=parent_root,
            ))

    dev = build_devpath_resource_anchors(hm, reg_rows, specific, ops_context_resource, root)[0]
    for r, rows in dev.items():
        merge(res2rows, "resource", r, rows, "devpath-registration",
              "build_devpath_resource_anchors")
    sock = build_sock_resource_anchors(hm, reg_rows, specific, ops_context_resource, root)[0]
    for r, rows in sock.items():
        merge(res2rows, "resource", r, rows, "socket-constructor",
              "build_sock_resource_anchors")
    opd = load_open_variant_devpaths(hm, root)
    builders = (
        ("misc-registration", build_misc_anchors),
        ("cdev-registration", build_cdev_path_anchors),
        ("usb-registration", build_usb_dev_anchors),
        ("sound-registration", build_snd_dev_anchors),
        ("oss-registration", build_snd_oss_dev_anchors),
        ("dvb-registration", build_dvb_dev_anchors),
        ("debugfs-fill", build_debugfs_anchors),
        ("binderfs-persistent", build_binderfs_anchors),
        ("fs-fill-table", build_proc_table_anchors),
        ("subtree-blanket", build_subtree_anchors),
        ("fs-mount-relative", build_mount_relative_anchors),
    )
    for method, builder in builders:
        anc = builder(hm, reg_rows, specific, ops_context_resource, opd, root)[0]
        for r, rows in anc.items():
            merge(res2rows, "resource", r, rows, method, builder.__name__)
    cgroup_resources, cgroup_variants = build_cgroup_cftype_anchors(
        hm, reg_rows, specific, ops_context_resource, opd, root)
    for resource, rows in cgroup_resources.items():
        merge(res2rows, "resource", resource, rows, "typed-key-table",
              "build_cgroup_cftype_anchors")
    for variant, rows in cgroup_variants.items():
        merge(variant2rows, "variant", variant, rows, "typed-key-table",
              "build_cgroup_cftype_anchors")
    for r, rows in build_inode_fops_anchors(hm, reg_rows, specific, ops_context_resource, root)[0].items():
        merge(res2rows, "resource", r, rows, "inode-direct-install",
              "build_inode_fops_anchors")
    for r, rows in build_special_inode_anchors(hm, reg_rows, specific, ops_context_resource, root)[0].items():
        merge(res2rows, "resource", r, rows, "special-inode-install",
              "build_special_inode_anchors")

    # anon fixpoint: each anchored fd -> its producer's handler region -> anon_inode_get*(&fops) -> next fd
    cmd_roots = _cmd_roots(root)
    name2s = {s["name"]: s for s in hm["syscalls"]}
    vconsts = _load_variant_consts(root)

    def disc(vname, base):
        v = vconsts.get(vname, [])
        return v[0] if base == "ioctl" and v else None

    def handler_of(vname):
        s = name2s.get(vname)
        if s is None:
            return set()
        region = set()
        base = vname.split("$", 1)[0]
        if base.startswith(("read", "write", "ioctl", "sendmsg", "recvmsg")):
            cv = disc(vname, base)
            for r in (set(s.get("consumes") or []) | set(s.get("uses") or [])):
                if specific(r) and ops_context_resource(r):
                    for row in res2rows.get(r, ()):
                        h = reg_rows[row][3].get("ioctl")
                        if h and h != "-":
                            region.add(h)
                            if cv is not None:
                                region |= cmd_roots.get((h, cv), set())
        else:
            sys_fns = {p + base for p in ("__se_sys_", "__do_sys_", "__x64_sys_", "__sys_")}
            vc = vconsts.get(vname, [])             # cmd-multiplexed direct syscall (bpf/fsconfig): the anon
            cv = vc[0] if vc else None              # creator lives in the arg0-cmd's region, NOT __sys_bpf,
            narrowed = set()                        # which aggregates EVERY cmd's fops -> never unique.
            if cv is not None:
                for h in sys_fns:
                    narrowed |= cmd_roots.get((h, cv), set())
            region |= narrowed or sys_fns           # prefer the cmd-scoped creator; else the bare syscall fn
        return region

    for _ in range(4):
        anon = build_anon_anchors(hm, reg_rows, specific, ops_context_resource, handler_of, root)[0]
        grew = False
        for r, rows in anon.items():
            if rows - res2rows.get(r, set()):
                merge(res2rows, "resource", r, rows, "anon-producer",
                      "build_anon_anchors")
                grew = True
        if not grew:
            break

    # socket-family: non-inet families (ax25/x25/packet/rose/netrom/can/...) -> their proto_ops, matched
    # by proto_ops.family == the syz socket domain const (the inet protosw scan covers only inet families).
    from provenance.socket import build_sock_family_anchors
    for r, rows in build_sock_family_anchors(hm, reg_rows, specific, ops_context_resource,
                                             set(res2rows), root)[0].items():
        merge(res2rows, "resource", r, rows, "socket-family",
              "build_sock_family_anchors")

    _res2rows, parent_evidence = propagate_parent_kind_anchors(
        hm, res2rows, specific, ops_context_resource)
    if seed_sink is not None:
        for parent, child, row in parent_evidence:
            seed_sink(InstallSeed(
                relation="entry_install",
                root_kind="resource",
                root=parent,
                method="resource-kind-propagation",
                reg_row=row,
                source="propagate_parent_kind_anchors",
                parent_root=child,
            ))

    for r, rows in build_drm_driver_cmd_anchors(hm, reg_rows, specific, ops_context_resource,
                                                set(res2rows), root)[0].items():
        merge(res2rows, "resource", r, rows, "drm-driver-table",
              "build_drm_driver_cmd_anchors")

    return res2rows, variant2rows


def build_full_res2rows(hm, reg_rows, specific, ops_context_resource, root="."):
    """Compatibility view for callers that only consume persistent resource provenance."""
    return build_full_provenance_rows(
        hm, reg_rows, specific, ops_context_resource, root)[0]
