# Copyright 2026 reFuzz project author -------youngkk.
# Generic (angle-independent): the syzkaller resource model. Loads horizon_model.json, builds the
# producer/consumer maps, and the SPECIFIC predicate (hub-deflatten of ambient resources — untyped
# fd/sock, pid/uid/gid, ifindex, time, and any resource with >25 producers form a fully-connected
# blob, not real dependencies). This is the fact source for the resource angle (E1) and the resource
# context other angles can read.
import collections
import json

AMBIENT = {"fd", "sock", "pid", "uid", "gid", "tid", "sid", "pgid", "ifindex",
           "time_sec", "time_nsec", "time_usec"}


def load_model(SH, producer_hub=25):
    hm = json.load(open(f"{SH}/horizon_model.json"))
    prod = collections.defaultdict(set)
    cons = collections.defaultdict(set)
    for s in hm["syscalls"]:
        for r in s.get("produces") or []:
            prod[r].add(s["name"])
        for r in set(s.get("consumes") or []) | set(s.get("uses") or []):
            cons[r].add(s["name"])
    generic = {r for r in (set(prod) | set(cons)) if len(prod[r]) > producer_hub} | AMBIENT

    def specific(r):
        return r not in generic

    return hm, prod, cons, specific
