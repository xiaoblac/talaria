#!/usr/bin/env python3
"""Extract ALSA device-node bindings from ir_defuse's SND* facts (no Python disassembly).

ALSA does NOT register its fops with a device name in one call: the file_operations is registered via
`snd_register_device(type, card, dev, f_ops, ...)` (in sound/core/<x>.c's *_dev_register), while the
device node *name* is set separately via `dev_set_name(dev, "<fmt>", ...)` (in the same file's *_new /
init path). Neither carries the other's datum, so the .tsv REG extraction records the snd fops with
dev='-' and the cdev/misc/usb devpath recognizers miss them.

The structural link is SOURCE-FILE co-location: within one translation unit (e.g. sound/core/pcm.c) there
is exactly one node-name format (`pcmC%iD%i%c`) and one registered fops (`@snd_pcm_f_ops`). ir_defuse emits
the raw facts (SNDREG <fn> <fops> <type>, SNDSET <fn> <fmt>, SNDFILE <fn> <basename>); we join them by
DIFile co-location. This is the registration mechanism, NOT name-grep: the node name is the kernel's own
`dev_set_name` literal, the fops is the argument the kernel passes to snd_register_device. Emits one DEVNODE
row per (fops, devname-format).

Output: run/seed_horizon/snd_devnodes.tsv
    DEVNODE\t<fops_global>\t<devname_format>\t<file>\t<register_types>
"""
import collections
import os
import sys

SH = "run/seed_horizon"
OUT = "snd_devnodes.tsv"


def extract(root="."):
    """(fops, devname-fmt, file, register_types) rows from ir_defuse's SND* facts, joined per (link-unit,
    source file): a file's snd_register_device fops paired with its dev_set_name node-name formats."""
    fpath = os.path.join(root, SH, "kernel_facts_linked", "fields.by_tu.tsv")
    if not os.path.exists(fpath):
        return []
    fn_file = {}                               # (unit, fn) -> source-file basename
    fn_set = collections.defaultdict(set)      # (unit, fn) -> {dev_set_name format}
    fn_reg = collections.defaultdict(set)      # (unit, fn) -> {(fops, type)}
    for ln in open(fpath):
        c = ln.rstrip("\n").split("\t")
        if len(c) < 4:
            continue
        unit, typ = c[0], c[1]
        if typ == "SNDSET":
            fn_set[(unit, c[2])].add(c[3])
        elif typ == "SNDREG" and len(c) >= 5:
            fn_reg[(unit, c[2])].add((c[3], c[4]))
        elif typ == "SNDFILE":
            fn_file[(unit, c[2])] = c[3]
    devset = collections.defaultdict(set)      # (unit, file) -> {fmt}
    sndreg = collections.defaultdict(set)      # (unit, file) -> {(fops, type)}
    for key, fmts in fn_set.items():
        f = fn_file.get(key)
        if f:
            devset[(key[0], f)] |= fmts
    for key, regs in fn_reg.items():
        f = fn_file.get(key)
        if f:
            sndreg[(key[0], f)] |= regs
    rows = []                                  # (fops, devfmt, file, types)
    for (unit, f), regs in sndreg.items():
        fmts = devset.get((unit, f), set())
        if not fmts:
            continue
        for fops, _ty in regs:
            types = ",".join(sorted({t for (fo, t) in regs if fo == fops}))
            for fmt in sorted(fmts):
                rows.append((fops, fmt, f, types))
    return rows


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    rows = sorted(set(extract(root)))
    out = os.path.join(root, SH, OUT)
    with open(out, "w") as fh:
        fh.write("#kind\tfops\tdevname_fmt\tfile\tregister_types\n")
        for fops, fmt, f, types in rows:
            fh.write(f"DEVNODE\t{fops}\t{fmt}\t{f}\t{types}\n")
    print(f"wrote {len(rows)} DEVNODE rows -> {out}")
    for fops, fmt, f, types in rows:
        print(f"  {fops:22} <- {fmt:16} ({f}, types {types})")


if __name__ == "__main__":
    main()
