#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Structural socket -> proto_ops anchoring (stage-4 anchor for sock_* resources).
#
# A socket fd's dispatch table is `sock->ops` (struct proto_ops), installed at socket(2) time by the
# address family's .create. We recover which proto_ops a `socket$VARIANT` installs WITHOUT name
# heuristics, from two structural facts already present in the kernel IR:
#
#   1. struct inet_protosw initializers: { hlist, i16 type, i16 protocol, ptr prot, ptr OPS, i8 } —
#      the (type, protocol) -> ops map that inet_create / inet6_create looks up. Each entry's address
#      family is read from the OPS struct's own field 0 (proto_ops.family == PF_INET/PF_INET6/...),
#      so v4 vs v6 entries that share a .bc are attributed by the ops they point at, not by name.
#   2. families with a single direct `sock->ops = &X_ops` (netlink): every proto_ops global carries
#      its family in field 0, so a family with no inet_protosw entries anchors to all proto_ops of
#      that family value.
#
# The OPS pointer is a named LLVM global; the REG row's ops_name is the SAME global. Joining them is an
# IDENTITY join (same object), not a name-similarity guess. The variant's (domain[,type][,protocol])
# come from variant_grammar consts (integers), so the (type,protocol) match is an integer join too.
#
# Anchoring returns a SET of REG rows per resource (uniqueness is proven downstream at stage 8); when
# the variant underspecifies (proto=0 wildcard, or only the domain is fixed) the set is an honest
# superset of the family's candidate ops, never a guessed single row.
#
# inet_protosw entries + proto_ops families come from ir_defuse's facts in fields.tsv (PROTOSW + OPSFIELD
# proto_ops.family); no Python disassembly.
import collections
import os

SH = "run/seed_horizon"

SOCK_TYPE_MASK = 0xf   # kernel: sock->type = type & SOCK_TYPE_MASK (strips SOCK_NONBLOCK/SOCK_CLOEXEC)


def _load_protosw_facts(root="."):
    """(entries, fam_ops, families_with_protosw, default_proto) from ir_defuse facts in fields.tsv, no Python
    disassembly: PROTOSW entries (type,proto,ops,prot,core/ext) with family joined from OPSFIELD
    proto_ops.family (which also gives fam_ops, every proto_ops by family).  ir_defuse keeps the inet_protosw
    array order, so the first core entry of each type is that type's default protocol."""
    fpath = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    ops_fam = {}                               # proto_ops global -> family
    fam_ops = collections.defaultdict(set)     # family -> {ops}
    protosw = []                               # (type, proto, ops, prot, src) in ir_defuse array order
    if os.path.exists(fpath):
        for ln in open(fpath):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "OPSFIELD" and len(c) >= 4 and c[2] == "proto_ops.family":
                try:
                    fam = int(c[3]) & 0xFFFFFFFF
                except ValueError:
                    continue
                ops_fam[c[1]] = fam
                fam_ops[fam].add(c[1])
            elif c[0] == "PROTOSW" and len(c) >= 6:
                try:
                    protosw.append((int(c[1]), int(c[2]), c[3], c[4], c[5]))
                except ValueError:
                    continue
    entries = collections.defaultdict(list)    # family -> [(type, proto, ops, prot, src)]
    families_with_protosw = set()
    default_proto = {}                         # type -> default protocol (first core entry, array order)
    for typ, proto, ops, prot, src in protosw:
        fam = ops_fam.get(ops)
        if fam is None:                        # ops with no proto_ops.family -> not an inet family; skip
            continue
        entries[fam].append((typ, proto, ops, prot, src))
        families_with_protosw.add(fam)
        if src == "core" and typ not in default_proto:
            default_proto[typ] = proto
    return entries, fam_ops, families_with_protosw, default_proto


def _load_variant_consts(root="."):
    import json
    out = {}
    with open(os.path.join(root, SH, "variant_grammar.jsonl")) as f:
        for ln in f:
            d = json.loads(ln)
            out[d["name"]] = [int(x) & 0xFFFFFFFF for x in d.get("consts") or []]
    return out


def match_entries(domain, consts, entries, fam_ops, families_with_protosw, default_proto):
    """CONSTRUCTOR-SEMANTICS NORMALIZATION: resolve a socket(domain,type,protocol) constructor to the
    inet_protosw entries the kernel actually installs, recovering implicit/default values BEFORE matching.
    consts = [domain, type?, protocol?]. Returns ([(type,proto,ops,prot,src)], why).

    The kernel (inet_create) does not treat protocol=0 as a wildcard: it is the DETERMINISTIC default for
    the socket type (the first registered entry of that type). We recover that default from the core
    inetsw_array's registration order (default_proto[type]); protocol numbers are family-independent, so
    it applies to v6 too. SOCK_NONBLOCK/SOCK_CLOEXEC are masked off the type. This fixes the whole class
    of proto=0 sockets (socket$inet_tcp -> tcp not {tcp,sctp}), not one variant."""
    if domain not in families_with_protosw:
        return [(None, None, o, "-", "ext") for o in fam_ops.get(domain, ())], "family-direct"
    ents = entries.get(domain, [])
    if len(consts) < 2:                                  # only the domain is fixed -> generic socket
        return list(ents), "family-all"
    typ = consts[1] & SOCK_TYPE_MASK
    if len(consts) >= 3:
        proto = consts[2]
    else:                                                # [domain, X]: X is a protocol if it looks like one
        x = consts[1]
        if (x & SOCK_TYPE_MASK) != x:                    # not a small type value -> X is the protocol
            return [e for e in ents if e[1] == x], "protocol"
        proto = 0
    if proto == 0:                                       # constructor default for this type
        proto = default_proto.get(typ, 0)
    if proto:
        M = [e for e in ents if e[1] == proto and e[0] == typ]
        if not M:
            M = [e for e in ents if e[1] == proto]
        if M:
            return M, "resolved"
    return [e for e in ents if e[0] == typ], "type"      # type known, protocol unresolved -> honest set


def match_ops(domain, consts, entries, fam_ops, families_with_protosw, default_proto):
    """Return ({ops_name}, why) — the proto_ops globals (sock->ops) this socket installs."""
    ents, why = match_entries(domain, consts, entries, fam_ops, families_with_protosw, default_proto)
    return {e[2] for e in ents}, why


def build_sock_family_anchors(hm, reg_rows, specific, ops_context_resource, already=None, root="."):
    """sock_X -> {proto_ops REG rows of family X}: a socket fd anchored to its family's proto_ops, matched
    by proto_ops.family (field-0) == the syz socket$X domain const. Covers the non-inet families the inet
    protosw scan misses (ax25/x25/packet/rose/netrom/can/llc/qrtr/rds/kcm/...). Grounded by family NUMBER,
    never by name. Skips `already`-anchored resources (inet, handled type-precise by the protosw scan).

    proto_ops.family per global comes from ir_defuse's OPSFIELD facts (ir_defuse reads the field at its
    DWARF offset); the Python side never disassembles or reads an offset."""
    already = already or set()
    ops_fam = collections.defaultdict(set)                # proto_ops global -> {family int} (from OPSFIELD)
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "OPSFIELD" and len(c) >= 4 and c[2] == "proto_ops.family":
                try:
                    ops_fam[c[1]].add(int(c[3]) & 0xFFFFFFFF)   # a global may collide across TUs -> >1 family
                except ValueError:
                    pass
    fam_rows = collections.defaultdict(set)               # family -> {proto_ops REG rows}
    by_ops_name = collections.defaultdict(set)            # proto_ops name -> {REG rows}  (protocol-precise)
    for i, (k, _d, ops, fld, _s) in enumerate(reg_rows):
        if k == "proto_ops" and fld:
            if ops and ops != "-":
                by_ops_name[ops].add(i)
            if ops in ops_fam:
                for famv in ops_fam[ops]:
                    fam_rows[famv].add(i)
    # SOCKOPS<family><protocol><proto_ops>: the specific proto_ops a (family,protocol) installs, recovered
    # from the per-protocol registration (bt_sock_register(BTPROTO_L2CAP)->l2cap_sock_create->l2cap_sock_ops)
    # -- so a bt_l2cap socket anchors to l2cap_sock_ops ALONE, not all bluetooth proto_ops.
    _sockops_fam, sockops_fp = _load_sock_binding(root, "SOCKOPS")
    vconsts = _load_variant_consts(root)
    sock_fam = {}                                         # produced sock resource -> consts [domain,type?,proto?]
    for s in hm["syscalls"]:
        if s["name"].split("$", 1)[0] in ("socket", "socketpair", "syz_init_net_socket"):
            v = vconsts.get(s["name"], [])
            if v:
                for r in (s.get("produces") or []):
                    sock_fam.setdefault(r, v)
    anchors = collections.defaultdict(set)
    evidence = []
    for r, c in sock_fam.items():
        if r in already or not (specific(r) and ops_context_resource(r)):
            continue
        dom = c[0]
        opnames = None                                    # protocol at arg2 [domain,type,proto], some at arg1
        for pos in (2, 1):
            if len(c) > pos and (dom, c[pos]) in sockops_fp:
                opnames = sockops_fp[(dom, c[pos])]
                break
        rows = set().union(*(by_ops_name.get(o, set()) for o in opnames)) if opnames else fam_rows.get(dom)
        if rows:
            anchors[r].update(rows)
            evidence.append((r, dom, sorted({reg_rows[i][2] for i in rows})))
    return anchors, evidence


def build_sock_resource_anchors(hm, reg_rows, specific, ops_context_resource, root="."):
    """resource -> {REG row idx}, evidence list. Mirrors build_devpath_resource_anchors' contract."""
    entries, fam_ops, fams, default_proto = _load_protosw_facts(root)
    sockops_fp = _load_sock_binding(root, "SOCKOPS")[1]   # (family,protocol) -> {proto_ops} (protocol-precise)
    vconsts = _load_variant_consts(root)

    by_ops = collections.defaultdict(set)             # ops_name -> {proto_ops REG row idxs}
    for idx, (kind, _dev, ops_name, fields, _sub) in enumerate(reg_rows):
        if kind == "proto_ops" and ops_name and ops_name != "-" and fields:
            by_ops[ops_name].add(idx)

    # resource -> the socket-producing variant(s) that fix its (domain,type,proto)
    res_consts = collections.defaultdict(list)
    for s in hm.get("syscalls", []):
        name = s["name"]
        base = name.split("$", 1)[0]
        if base not in ("socket", "syz_init_net_socket", "socketpair") or "$" not in name:
            continue
        c = vconsts.get(name)
        if not c:
            continue
        for r in (s.get("produces") or []):
            if specific(r) and ops_context_resource(r):
                res_consts[r].append((name, c))

    anchors = collections.defaultdict(set)
    evidence = []
    for r, producers in res_consts.items():
        for name, c in producers:
            # protocol-precise proto_ops from the per-protocol registration (bt(31,BTPROTO_L2CAP=0) ->
            # l2cap_sock_ops ALONE); protocol is normally arg2, some 2-arg variants carry it at arg1.
            opnames, why = None, "sockops"
            for pos in (2, 1):
                if len(c) > pos and (c[0], c[pos]) in sockops_fp:
                    opnames = sockops_fp[(c[0], c[pos])]
                    break
            if opnames is None:                # else the family-level (or inet type-precise) match_ops set
                opnames, why = match_ops(c[0], c, entries, fam_ops, fams, default_proto)
            for ops in opnames:
                rows = by_ops.get(ops, set())
                anchors[r].update(rows)
                if rows:
                    evidence.append((name, r, c[0], why, ops, sorted(rows)))
    return anchors, evidence


def _load_sock_binding(root, tag):
    """ir_defuse <tag><family><protocol><name> for NON-inet families -- tag=SOCKPROTO (sk_prot) or SOCKOPS
    (proto_ops).  Returns (fam, famproto): fam[family]={name} is the family-level fallback (protocol -1,
    from the sk_alloc slice), famproto[(family,protocol)]={name} is protocol-precise (from the per-protocol
    registration, e.g. bt_sock_register(BTPROTO_L2CAP)->l2cap_sock_ops)."""
    fam = collections.defaultdict(set)
    famproto = collections.defaultdict(set)
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if c[0] == tag and len(c) >= 4 and c[3]:
                try:
                    f, p = int(c[1]), int(c[2])
                except ValueError:
                    continue
                (fam[f] if p == -1 else famproto[(f, p)]).add(c[3])
    return fam, famproto


def build_sock_proto_context(hm, reg_rows, specific, ops_context_resource, root="."):
    """resource -> {proto REG row idx} = the sk_prot (struct proto) this socket installs.  inet is recovered
    from inet_protosw.prot; non-inet families (Phonet/WPAN/Bluetooth/AF_ALG) have no such table -- they set
    sk_prot imperatively in .create, recovered as SOCKPROTO<family><proto> (family-level).  This is the
    context struct the resolver hops to when a generic socket dispatcher (sock_common_setsockopt) forwards
    through struct.proto+off (sk->sk_prot->field); without it the forward has no scope and falls back to the
    un-scoped cross-family collapse."""
    entries, fam_ops, fams, default_proto = _load_protosw_facts(root)
    fam_sp, famproto_sp = _load_sock_binding(root, "SOCKPROTO")
    vconsts = _load_variant_consts(root)
    by_proto = collections.defaultdict(set)           # prot_name -> {proto REG row idxs}
    for idx, (kind, _dev, ops_name, fields, _sub) in enumerate(reg_rows):
        if kind == "proto" and ops_name and ops_name != "-" and fields:
            by_proto[ops_name].add(idx)

    res_consts = collections.defaultdict(list)
    for s in hm.get("syscalls", []):
        name = s["name"]
        if name.split("$", 1)[0] not in ("socket", "syz_init_net_socket", "socketpair") or "$" not in name:
            continue
        c = vconsts.get(name)
        if not c:
            continue
        for r in (s.get("produces") or []):
            if specific(r) and ops_context_resource(r):
                res_consts[r].append(c)

    ctx = collections.defaultdict(set)
    for r, clist in res_consts.items():
        for c in clist:
            ents, _why = match_entries(c[0], c, entries, fam_ops, fams, default_proto)   # inet: protosw.prot
            for (_t, _p, _ops, prot, _src) in ents:
                if prot and prot != "-":
                    ctx[r].update(by_proto.get(prot, set()))
            # non-inet: protocol-precise (family, protocol) if the registration bound it, else family-level.
            # protocol is normally arg2 [domain,type,protocol]; some 2-arg variants (bt_l2cap = [31, 0])
            # carry it at arg1 -- try arg2 first, then arg1, using it only when it IS a registered protocol.
            protos = None
            for pos in (2, 1):
                if len(c) > pos and (c[0], c[pos]) in famproto_sp:
                    protos = famproto_sp[(c[0], c[pos])]
                    break
            for prot in (protos or fam_sp.get(c[0], ())):
                ctx[r].update(by_proto.get(prot, set()))
    return ctx
