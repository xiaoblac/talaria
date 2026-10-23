#!/usr/bin/env python3
"""Extract DVB device-node bindings from ir_defuse's DVBNODE facts (no Python disassembly).

DVB registers char devices via `dvb_register_device(adap, &pdvbdev, template, priv, type, ...)` — the
file_operations is the `.fops` field of the dvb_device TEMPLATE (arg2), and the device-node name is
`dvb/adapter%d/<dnames[type]>%d`. ir_defuse resolves, per call: the template's .fops (the first real
@global in the template initializer, or the runtime @<x>_fops stored in the registering fn) and the
typename from the kernel's @dnames[type] table, emitting DVBNODE <fops> <typename>. This is the
registration mechanism, not name-grep.

Output: run/seed_horizon/dvb_devnodes.tsv   ->   DVBNODE\t<fops>\t<typename>
"""
import os
import sys

SH = "run/seed_horizon"
OUT = "dvb_devnodes.tsv"


def extract(root="."):
    fpath = os.path.join(root, SH, "kernel_facts_linked", "fields.by_tu.tsv")
    rows = set()                               # (fops, typename)
    if os.path.exists(fpath):
        for ln in open(fpath):
            c = ln.rstrip("\n").split("\t")
            if len(c) >= 4 and c[1] == "DVBNODE" and c[2] and c[3]:
                rows.add((c[2], c[3]))
    return sorted(rows)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    rows = extract(root)
    out = os.path.join(root, SH, OUT)
    with open(out, "w") as fh:
        fh.write("#kind\tfops\ttypename\n")
        for fops, typename in rows:
            fh.write(f"DVBNODE\t{fops}\t{typename}\n")
    print(f"wrote {len(rows)} DVBNODE rows -> {out}")
    for fops, typename in rows:
        print(f"  {fops:22} <- {typename}")


if __name__ == "__main__":
    main()
