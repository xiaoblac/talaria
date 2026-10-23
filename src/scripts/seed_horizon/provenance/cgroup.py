#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# cgroup kernfs cftype recognizer.
#
# cgroup control files (cgroup.procs, cpu.weight, memory.high, ...) are not char/misc devices and do not
# dispatch through a file_operations of their own: every cgroup file shares kernfs_file_fops, and the
# per-file behaviour is a SECOND-level indirection through a `struct cftype`:
#
#     struct cftype { char name[64]; ...; int (*seq_show)(...); ...; ssize_t (*write)(...); ... }
#
# So the static handler for `write$cgroup_type` is cft->write for the cftype whose .name == "cgroup.type"
# (== @cgroup_type_write), and for a read it is cft->seq_show (== @cgroup_type_show).  This recognizer
# recovers the (visible filename -> typed callbacks) relation from Bitcode facts and joins it to the fixed
# file domains in syzkaller's generated model.  No resource name participates in the join.
#
# Name keying: cgroup CORE files carry the full name in the cftype (.name = "cgroup.type"); per-controller
# files carry only the BARE leaf (.name = "high" for memory.high, "state" for freezer.state, "allow" for
# devices.allow).  CFTOWNER + CGNAME/CGLEGACY reconstruct that prefix before the exact join, keeping equal
# leaves such as cpu.max, memory.max and pids.max in separate dispatch domains.
import collections
import os

from model.generated import fixed_buffer_values, generated_syscall_fields

SH = "run/seed_horizon"


def load_cgroup_cftype(root="."):
    """Load complete visible cgroup keys from typed Bitcode facts.

    CFTYPE rows are scoped by translation-unit because local table symbols such as ``files`` repeat.
    CFTOWNER links a table to its cgroup subsystem and hierarchy mode; CGNAME/CGLEGACY provide the prefix
    installed by cgroup core.  Unowned core tables already carry complete keys such as ``cgroup.type``.
    """
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.by_tu.tsv")
    callbacks = collections.defaultdict(set)
    owners = collections.defaultdict(set)
    names = collections.defaultdict(set)
    legacy_names = collections.defaultdict(set)
    if not os.path.exists(path):
        return {}, {}, {}
    for line in open(path):
        cols = line.rstrip("\n").split("\t")
        if len(cols) < 2:
            continue
        unit, kind = cols[:2]
        if kind == "CFTYPE" and len(cols) >= 6:
            table, key, role, handler = cols[2:6]
            if table and key and role and handler:
                callbacks[(unit, table, key, role)].add(handler)
        elif kind == "CFTOWNER" and len(cols) >= 5:
            table, mode, subsystem = cols[2:5]
            if table and mode in {"dfl", "legacy"} and subsystem:
                owners[(unit, table)].add((mode, subsystem))
        elif kind == "CGNAME" and len(cols) >= 4:
            names[cols[2]].add(cols[3])
        elif kind == "CGLEGACY" and len(cols) >= 4:
            legacy_names[cols[2]].add(cols[3])

    by_role = {
        "write": collections.defaultdict(set),
        "read": collections.defaultdict(set),
        "open": collections.defaultdict(set),
    }
    for (unit, table, raw_key, role), handlers in callbacks.items():
        table_owners = owners.get((unit, table), set())
        visible_keys = set()
        if table_owners:
            for mode, subsystem in table_owners:
                if mode == "legacy":
                    prefixes = legacy_names.get(subsystem) or names.get(subsystem, set())
                else:
                    prefixes = names.get(subsystem, set())
                visible_keys.update(f"{prefix}.{raw_key}" for prefix in prefixes)
        else:
            visible_keys.add(raw_key)
        for key in visible_keys:
            by_role[role][key].update(handlers)
    return by_role["write"], by_role["read"], by_role["open"]


def _lookup(table, fname):
    """Exact userspace-visible dispatch key lookup; no basename or suffix fallback."""
    return set(table.get(fname, ()))


def _fixed_file_domains(hm, root="."):
    domains = collections.defaultdict(set)
    for name, call_name, _field_name, type_id in generated_syscall_fields(
            hm, root, {"file"}):
        if call_name != "openat":
            continue
        for value in fixed_buffer_values(type_id, root):
            filename = value.split("\0", 1)[0].strip()
            if filename and "/" not in filename:
                domains[name].add(filename)
    return domains


def _kernfs_open_rows(reg_rows, root="."):
    """A projected REG row for the uniquely recovered kernfs file-open installation."""
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    installs = set()
    if os.path.exists(path):
        for line in open(path):
            cols = line.rstrip("\n").split("\t")
            if cols[0] == "KERNFSOPEN" and len(cols) >= 3 and cols[1] and cols[2]:
                installs.add((cols[1], cols[2]))
    if len(installs) != 1:
        return set()
    fops, handler = next(iter(installs))
    if not any(row[2] == fops and row[3].get("open") == handler for row in reg_rows):
        return set()
    reg_rows.append(("fops", "-", fops, {"open": handler}, "kernfs"))
    return {len(reg_rows) - 1}


def build_cgroup_cftype_anchors(hm, reg_rows, specific, ops_context_resource, _opd, root="."):
    """Derive cgroup control-file provenance from two independent semantic domains.

    The syzkaller generated model supplies each open variant's fixed ``file`` value domain.  The kernel
    bitcode supplies the cftype key table and its typed callbacks.  Their key join identifies the opened
    control-file object; the variant's produced resource inherits those rows for later read/write calls.
    A generic produced resource is deliberately not polluted: every opening variant also receives its own
    rows through the returned variant map.

    A cftype with a custom ``open`` callback resolves to that callback.  Otherwise the VFS open reaches the
    outer kernfs file fops recovered by KERNFSOPEN.  This is dispatch semantics, not a name fallback.
    """
    write, read, opn = load_cgroup_cftype(root)
    file_domains = _fixed_file_domains(hm, root)
    kernfs_open = _kernfs_open_rows(reg_rows, root)
    syscall_by_name = {syscall["name"]: syscall for syscall in hm.get("syscalls", [])}
    resource_anchors = collections.defaultdict(set)
    variant_anchors = collections.defaultdict(set)
    row_cache = {}

    def callback_row(filename, field, handler):
        key = filename, field, handler
        if key not in row_cache:
            reg_rows.append(("cgroup_cft", filename, "-", {field: handler}, "cgroup"))
            row_cache[key] = len(reg_rows) - 1
        return row_cache[key]

    for variant, filenames in sorted(file_domains.items()):
        syscall = syscall_by_name.get(variant)
        if not syscall:
            continue
        produced = set(syscall.get("produces") or [])
        context_resources = (
            set(syscall.get("consumes") or []) | set(syscall.get("uses") or [])
        ) - produced
        context_resources = {
            resource for resource in context_resources
            if specific(resource) and ops_context_resource(resource)
        }
        if len(context_resources) != 1:
            continue

        rows = set()
        matched_files = 0
        for filename in sorted(filenames):
            callbacks = {
                "write": _lookup(write, filename),
                "read": _lookup(read, filename),
                "open": _lookup(opn, filename),
            }
            if not any(callbacks.values()):
                continue
            matched_files += 1
            for field in ("write", "read"):
                for handler in sorted(callbacks[field]):
                    rows.add(callback_row(filename, field, handler))
            if callbacks["open"]:
                for handler in sorted(callbacks["open"]):
                    rows.add(callback_row(filename, "open", handler))
            else:
                rows.update(kernfs_open)
        if not matched_files or not rows:
            continue

        variant_anchors[variant].update(rows)
        for resource in produced:
            if specific(resource) and ops_context_resource(resource):
                resource_anchors[resource].update(rows)

    return resource_anchors, variant_anchors
