#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Structural context construction.
#
# This layer does not resolve dispatch and does not bind variants. It only builds
# candidate context from syzkaller resources:
#   resource -> {REG rows}
#   producing variant -> {REG rows}             (precise object, generic return resource)
#   socket resource -> {proto REG rows}        (sk_prot recursive context)
#   block resource -> [{ioctl: handler}]       (variant-specific block dops context)
from dataclasses import dataclass

from model.recognizer import InstallSeed
from model.variant import ops_context_resource, resource_kind_map, specific_predicate
from provenance.fd import build_block_dops_context, build_full_provenance_rows
from provenance.socket import build_sock_proto_context


@dataclass
class ProvenanceContext:
    hm: dict
    reg_rows: list
    specific: object
    res_kinds: dict
    res2rows: dict
    variant2rows: dict
    sock_proto_ctx: dict
    block_dops_ctx: dict
    install_seeds: tuple[InstallSeed, ...]

    def ops_ctx(self, resource):
        return ops_context_resource(resource, self.res_kinds)

    def context_rows(self, resources, variant=None):
        rows = set()
        for r in resources:
            if self.specific(r) and self.ops_ctx(r):
                for row in self.res2rows.get(r, ()):
                    if self.reg_rows[row][3]:
                        rows.add(row)
        for row in self.variant2rows.get(variant, ()):
            if self.reg_rows[row][3]:
                rows.add(row)
        return rows

    def entry_handlers(self, resources, field, variant=None):
        if not field:
            return set()
        return {self.reg_rows[row][3].get(field)
                for row in self.context_rows(resources, variant)
                if self.reg_rows[row][3].get(field)}


def build_provenance_context(hm, reg_rows, root="."):
    specific = specific_predicate(hm)
    res_kinds = resource_kind_map(hm)
    install_seeds = set()

    def ops_ctx(resource):
        return ops_context_resource(resource, res_kinds)

    res2rows, variant2rows = build_full_provenance_rows(
        hm, reg_rows, specific, ops_ctx, root, install_seeds.add)
    sock_proto_ctx = build_sock_proto_context(hm, reg_rows, specific, ops_ctx, root)
    for resource, rows in sock_proto_ctx.items():
        for row in rows:
            install_seeds.add(InstallSeed(
                relation="context_install",
                root_kind="resource",
                root=resource,
                method="socket-protocol",
                reg_row=row,
                source="build_sock_proto_context",
                parent_root="-",
            ))
    block_dops_ctx = build_block_dops_context(hm, reg_rows, specific, ops_ctx, root)
    return ProvenanceContext(
        hm=hm,
        reg_rows=reg_rows,
        specific=specific,
        res_kinds=res_kinds,
        res2rows=res2rows,
        variant2rows=variant2rows,
        sock_proto_ctx=sock_proto_ctx,
        block_dops_ctx=block_dops_ctx,
        install_seeds=tuple(sorted(install_seeds)),
    )
