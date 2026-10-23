#!/usr/bin/env python3
# Sweep the region_audit no-context variants: group by the fd resource they consume and classify each
# resource by the most-recoverable anchoring mechanism, to rank the next anchoring gaps.
import sys, os, json, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from resolve.dispatch import load_dispatch_graph
from provenance.devnode import load_open_variant_devpaths
from model.variant import (build_reg_rows, specific_predicate, resource_kind_map,
                           ops_context_resource, load_variant_consts)
SH = "run/seed_horizon"
hm = json.load(open(f"{SH}/horizon_model.json"))
reg_rows = build_reg_rows(SH); specific = specific_predicate(hm); rk = resource_kind_map(hm)
opd = load_open_variant_devpaths(hm)
cbo = load_dispatch_graph(SH)[0]
vconsts = load_variant_consts(SH)
def opc(r): return ops_context_resource(r, rk)
# no-context variants from the audit
nc = set()
for ln in open(f"{SH}/region_audit.tsv"):
    if ln.startswith("#"): continue
    c = ln.rstrip("\n").split("\t")
    if c[2] == "no-context": nc.add(c[0])
name2s = {s["name"]: s for s in hm["syscalls"]}
# fops .ioctl set (registered device fops) + cmd -> dispatchers
fops_ioctl = {fld.get("ioctl"): ops for (k,_d,ops,fld,_s) in reg_rows
              if k in ("fops","cdev","misc","chrdev","usb","anon") and fld.get("ioctl") and fld["ioctl"]!="-"}
cmd_disp = collections.defaultdict(set)
for o,tbl in cbo.items():
    for v in tbl: cmd_disp[v].add(o)
# group no-context by consumed fd resource
res_vars = collections.defaultdict(list); fdless = []
for v in nc:
    s = name2s[v]
    rs = set(s.get("consumes") or []) | set(s.get("uses") or [])
    fds = [r for r in rs if specific(r) and opc(r)]
    if fds:
        for r in fds: res_vars[r].append(v)
    else:
        fdless.append(v)
# classify each resource
def producers(r):
    return [s["name"] for s in hm["syscalls"] if r in (s.get("produces") or [])]
def cls(r, vs):
    # cmd-dispatch: do this resource's ioctl cmds majority-dispatch to a registered fops .ioctl?
    cmds = set()
    for v in vs:
        if v.split("$",1)[0] != "ioctl": continue
        cc = vconsts.get(v, []); 
        if cc: cmds.add(cc[0])
    hit = collections.Counter()
    for cv in cmds:
        for h in cmd_disp.get(cv, ()):
            if h in fops_ioctl: hit[h]+=1
    prods = producers(r)
    dp = set()
    for p in prods: dp |= opd.get(p, set())
    if cmds and hit and max(hit.values()) >= max(2, 0.4*len(cmds)):
        h,_ = hit.most_common(1)[0]
        return "RECOVER:cmd-dispatch-fops", f"{fops_ioctl[h]}.{h} ({hit[h]}/{len(cmds)})"
    if dp:
        return "RECOVER:devpath", ",".join(sorted(dp))[:30]
    pbases={p.split('$',1)[0] for p in prods}
    if pbases & {"socket","socketpair","syz_init_net_socket","accept","accept4"}:
        return "RECOVER:socket-family", ",".join(sorted(pbases))
    if any("CREATE" in p or p.split('$',1)[0] in ("io_uring_setup","eventfd2","signalfd","timerfd_create","memfd_create","bpf","fsopen","userfaultfd","epoll_create1","inotify_init1") for p in prods):
        return "RECOVER:anon", ",".join(sorted(pbases))[:30]
    return "OTHER", ",".join(sorted(pbases))[:30] or "no-producer"
buckets = collections.Counter(); bres = collections.defaultdict(list)
for r, vs in res_vars.items():
    k, ev = cls(r, vs)
    buckets[k] += len(vs); bres[k].append((r, len(vs), ev))
print(f"# no-context: {len(nc)} variants = {sum(len(v) for v in res_vars.values())} fd-slots over {len(res_vars)} resources + {len(fdless)} fd-less\n")
for k,n in buckets.most_common():
    print(f"  {k:28} {n:5} slots")
print(f"  {'HONEST:fd-less':28} {len(fdless):5} (prctl/bpf/keyctl/...)\n")
for k in sorted(buckets, key=lambda x:-buckets[x]):
    print(f"# {k} top resources:")
    for r,n,ev in sorted(bres[k], key=lambda x:-x[1])[:10]:
        print(f"    {r:34} {n:4}  {ev}")
