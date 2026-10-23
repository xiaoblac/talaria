import collections
from dataclasses import dataclass
import json
import os

from model.generated import (
    fixed_buffer_values,
    fixed_descendant_fields,
    fixed_scalar_domain,
    generated_syscall_signatures,
    generated_type_info,
)
from model.variant import (
    CMD_BASES,
    FS_BASES,
    OPEN_BASES,
    OPCODE_PREFIX,
    build_cmd_syscall_bases,
    field_for_base,
)


SYSCALL_SELECTOR_FIELDS = {
    "arch_prctl": ("code", "cmd", "option"),
    "bpf": ("cmd",),
    "epoll_ctl": ("op",),
    "fcntl": ("cmd",),
    "fsconfig": ("cmd",),
    "getitimer": ("which",),
    "getpriority": ("which",),
    "getrusage": ("who",),
    "io_uring_register": ("opcode",),
    "ioprio_get": ("which",),
    "ioprio_set": ("which",),
    "keyctl": ("code", "option"),
    "prctl": ("option", "opt", "cmd"),
    "ptrace": ("request", "req", "code", "cmd"),
    "quotactl": ("cmd",),
    "quotactl_fd": ("cmd",),
    "setitimer": ("which",),
    "setpriority": ("which",),
    "waitid": ("which",),
}
GENERIC_SELECTOR_FIELDS = {
    "cmd", "command", "opcode", "op", "request", "req", "code", "option", "opt", "which",
}
SOCKET_CONSTRUCTOR_FIELDS = {
    "domain": "socket_family",
    "family": "socket_family",
    "type": "socket_type",
    "proto": "socket_protocol",
    "protocol": "socket_protocol",
}
PATH_FIELDS = {"file", "filename", "path", "dev"}
FS_SELECTOR_FIELDS = {
    "mount": {"type"},
    "syz_mount_image": {"fs"},
    "fsopen": {"type", "_fs_name"},
}


@dataclass
class VariantQueryInput:
    name: str
    call_name: str
    query_kind: str
    operation_field: str | None
    operation_status: str
    input_resources: tuple[str, ...]
    output_resources: tuple[str, ...]
    all_resources: tuple[str, ...]
    grammar_consts: tuple[int, ...]
    constraints: list[dict]
    gaps: list[dict]
    producer_branch_count: int = 0


@dataclass
class VariantInputModel:
    hm: dict
    queries: dict[str, VariantQueryInput]
    compatible_producers: dict[str, tuple[tuple[str, str], ...]]


def load_grammar_consts(sh):
    out = {}
    with open(os.path.join(sh, "variant_grammar.jsonl")) as source:
        for line in source:
            row = json.loads(line)
            out[row["name"]] = tuple(int(value) for value in row.get("consts") or [])
    return out


def build_compatible_producers(hm):
    resource_kinds = {
        resource["name"]: set(resource.get("kind") or ()) | {resource["name"]}
        for resource in hm.get("resources", [])
    }
    exact = collections.defaultdict(set)
    for syscall in hm.get("syscalls", []):
        for resource in syscall.get("produces") or ():
            exact[resource].add(syscall["name"])

    compatible = collections.defaultdict(set)
    for produced_resource, producers in exact.items():
        for accepted_resource in resource_kinds.get(produced_resource, {produced_resource}):
            compatible[accepted_resource].update(
                (produced_resource, producer) for producer in producers
            )
    return {
        resource: tuple(sorted(producers))
        for resource, producers in compatible.items()
    }


def _json_value(value):
    if isinstance(value, str):
        return value.rstrip("\0")
    return value


def _grammar_evidence(value, grammar_consts):
    if not isinstance(value, int):
        return "not-applicable"
    masked = value & 0xFFFFFFFF
    return "present" if any((candidate & 0xFFFFFFFF) == masked for candidate in grammar_consts) else "absent"


def _constraint(role, selector, field_path, value_kind, value, status, source, type_id,
                type_name, grammar_consts, bitmask=False):
    return {
        "role": role,
        "selector": selector,
        "field_path": field_path,
        "value_kind": value_kind,
        "value": _json_value(value),
        "status": status,
        "source": source,
        "type_id": type_id,
        "type_name": type_name or "-",
        "grammar_evidence": _grammar_evidence(value, grammar_consts),
        "bitmask": bitmask,
    }


def _gap(stage, subject, status, detail, source):
    return {
        "stage": stage,
        "subject": subject,
        "status": status,
        "detail": detail,
        "source": source,
    }


def _top_level_domain(type_id, root):
    scalar = fixed_scalar_domain(type_id, root)
    if scalar:
        value_kind, values, bitmask = scalar
        return value_kind, tuple(values), bitmask
    buffers = tuple(sorted(fixed_buffer_values(type_id, root)))
    if buffers:
        return "buffer", buffers, False
    return None


def _genl_cmd_fields(fields, root):
    rows = []
    for top_field, type_id in fields:
        for fixed in fixed_descendant_fields(type_id, root):
            if not fixed.owner_name.startswith("genlmsghdr_t[") or fixed.field_name != "cmd":
                continue
            rows.append((top_field, fixed))
    return rows


def _selector_fields(call_name, query_kind, fields, root):
    if call_name in {"setsockopt", "getsockopt"}:
        if len(fields) < 3:
            return {}
        return {
            fields[1][0]: ("dispatch_selector", "level"),
            fields[2][0]: ("dispatch_selector", "optname"),
        }
    if call_name == "ioctl":
        if len(fields) < 2:
            return {}
        return {fields[1][0]: ("dispatch_selector", "cmd")}
    if call_name in SYSCALL_SELECTOR_FIELDS:
        available = {field for field, _type_id in fields}
        return {
            field: ("dispatch_selector", field)
            for field in SYSCALL_SELECTOR_FIELDS[call_name]
            if field in available
        }
    if query_kind != "syscall_multiplexer":
        return {}
    semantic = {
        field: ("dispatch_selector_candidate", field)
        for field, _type_id in fields
        if field in GENERIC_SELECTOR_FIELDS
    }
    if semantic:
        return semantic
    finite = [
        field for field, type_id in fields
        if fixed_scalar_domain(type_id, root) is not None
    ]
    if len(finite) == 1:
        return {finite[0]: ("dispatch_selector_candidate", finite[0])}
    return {}


def _query_kind(call_name, operation_field, syscall_bases, expects_genl):
    if expects_genl:
        return "genl_dispatch"
    if call_name in CMD_BASES:
        return "cmd_dispatch"
    if call_name in FS_BASES:
        return "fs_dispatch"
    if call_name in syscall_bases or call_name in OPCODE_PREFIX:
        return "syscall_multiplexer"
    if operation_field:
        return "direct_operation"
    if call_name.startswith("syz_"):
        return "syz_helper"
    return "no_dispatch_model"


def build_variant_input_model(hm, sh, root="."):
    grammar = load_grammar_consts(sh)
    signatures = {
        name: (call_name, tuple(fields))
        for name, call_name, fields in generated_syscall_signatures(hm, root)
    }
    syscall_bases = build_cmd_syscall_bases(sh)
    compatible = build_compatible_producers(hm)
    queries = {}

    for syscall in sorted(hm.get("syscalls", []), key=lambda row: row["name"]):
        name = syscall["name"]
        fallback_call = name.split("$", 1)[0]
        signature = signatures.get(name)
        call_name, fields = signature if signature else (fallback_call, ())
        field_map = dict(fields)
        produced = set(syscall.get("produces") or ())
        consumed = set(syscall.get("consumes") or ())
        used = set(syscall.get("uses") or ())
        input_resources = tuple(sorted(consumed | (used - produced)))
        output_resources = tuple(sorted(produced))
        all_resources = tuple(sorted(produced | consumed | used))
        grammar_consts = grammar.get(name, ())
        operation_field = field_for_base(call_name)
        genl_rows = _genl_cmd_fields(fields, root) if call_name in {"sendmsg", "sendmmsg"} else []
        expects_genl = call_name in {"sendmsg", "sendmmsg"} and any(
            resource.startswith("genl_") and "_family_id" in resource
            for resource in all_resources
        )
        query_kind = _query_kind(call_name, operation_field, syscall_bases, expects_genl)
        operation_status = "known" if operation_field else "not-applicable"
        constraints = []
        gaps = []

        if not signature:
            gaps.append(_gap(
                "catalog", "generated_signature", "unknown", "variant is absent from generated syscall tables",
                "horizon_model.json:syscalls.name",
            ))

        selector_fields = _selector_fields(call_name, query_kind, fields, root)
        selected_top_fields = set(selector_fields)
        for field_name, (role, selector_name) in sorted(selector_fields.items()):
            type_id = field_map[field_name]
            info = generated_type_info(type_id, root) or {}
            domain = _top_level_domain(type_id, root)
            if not domain:
                gaps.append(_gap(
                    "selector", field_name, "non-finite",
                    f"generated type {info.get('kind', 'unknown')}:{info.get('name', '-')} has no fixed finite domain",
                    f"generated_syscall:{name}:{field_name}:type[{type_id}]",
                ))
                continue
            value_kind, values, bitmask = domain
            status = "bitmask-atoms" if bitmask else ("fixed-set" if len(values) > 1 else "fixed")
            for value in values:
                constraints.append(_constraint(
                    role, selector_name, field_name, value_kind, value, status,
                    f"generated_syscall:{name}:{field_name}", type_id, info.get("name"), grammar_consts, bitmask,
                ))
            if bitmask:
                gaps.append(_gap(
                    "selector", field_name, "domain-not-expanded",
                    "FlagsType is a bitmask; listed atoms are not the complete combination domain",
                    f"generated_type[{type_id}]",
                ))

        for top_field, fixed in genl_rows:
            info = generated_type_info(fixed.type_id, root) or {}
            status = "bitmask-atoms" if fixed.bitmask else (
                "fixed-set" if len(fixed.values) > 1 else "fixed"
            )
            field_path = ".".join((top_field,) + fixed.path)
            for value in fixed.values:
                constraints.append(_constraint(
                    "dispatch_selector", "genl_cmd", field_path, fixed.value_kind, value, status,
                    f"generated_type:{fixed.owner_name}.{fixed.field_name}", fixed.type_id,
                    info.get("name"), grammar_consts, fixed.bitmask,
                ))

        if query_kind == "syscall_multiplexer" and not selector_fields:
            gaps.append(_gap(
                "selector", "syscall_opcode", "unknown",
                "no ABI-mapped or uniquely identifiable top-level selector field",
                f"generated_syscall:{name}",
            ))
        if query_kind == "genl_dispatch" and not genl_rows:
            gaps.append(_gap(
                "selector", "genl_cmd", "unknown", "no fixed genlmsghdr_t.cmd field found",
                f"generated_syscall:{name}",
            ))

        if call_name in {"socket", "socketpair"}:
            for field_name, selector in SOCKET_CONSTRUCTOR_FIELDS.items():
                if field_name not in field_map:
                    continue
                type_id = field_map[field_name]
                info = generated_type_info(type_id, root) or {}
                domain = _top_level_domain(type_id, root)
                if not domain:
                    gaps.append(_gap(
                        "constructor", selector, "non-finite", "constructor field has no fixed finite domain",
                        f"generated_syscall:{name}:{field_name}:type[{type_id}]",
                    ))
                    continue
                value_kind, values, bitmask = domain
                status = "fixed-set" if len(values) > 1 else "fixed"
                for value in values:
                    constraints.append(_constraint(
                        "constructor_constraint", selector, field_name, value_kind, value, status,
                        f"generated_syscall:{name}:{field_name}", type_id, info.get("name"), grammar_consts, bitmask,
                    ))

        path_call = call_name in OPEN_BASES or call_name.startswith("syz_open_") or call_name == "fspick"
        if path_call:
            for field_name, type_id in fields:
                if field_name not in PATH_FIELDS:
                    continue
                info = generated_type_info(type_id, root) or {}
                values = tuple(sorted(fixed_buffer_values(type_id, root)))
                if values:
                    for value in values:
                        constraints.append(_constraint(
                            "path_constraint", "path", field_name, "buffer", value,
                            "fixed-set" if len(values) > 1 else "fixed",
                            f"generated_syscall:{name}:{field_name}", type_id, info.get("name"),
                            grammar_consts,
                        ))
                else:
                    gaps.append(_gap(
                        "path", field_name, "runtime-or-non-finite", "path field has no fixed BufferType domain",
                        f"generated_syscall:{name}:{field_name}:type[{type_id}]",
                    ))

        for field_name in sorted(FS_SELECTOR_FIELDS.get(call_name, ())):
            if field_name not in field_map or field_name in selected_top_fields:
                continue
            type_id = field_map[field_name]
            info = generated_type_info(type_id, root) or {}
            values = tuple(sorted(fixed_buffer_values(type_id, root)))
            if not values:
                gaps.append(_gap(
                    "selector", "fs_type", "runtime-or-non-finite",
                    f"field {field_name} has no fixed BufferType domain",
                    f"generated_syscall:{name}:{field_name}:type[{type_id}]",
                ))
                continue
            for value in values:
                constraints.append(_constraint(
                    "dispatch_selector", "fs_type", field_name, "buffer", value,
                    "fixed-set" if len(values) > 1 else "fixed",
                    f"generated_syscall:{name}:{field_name}", type_id, info.get("name"), grammar_consts,
                ))

        numeric_selectors = {
            constraint["value"] & 0xFFFFFFFF
            for constraint in constraints
            if constraint["role"].startswith("dispatch_selector") and
            isinstance(constraint["value"], int)
        }
        if query_kind in {"cmd_dispatch", "genl_dispatch", "syscall_multiplexer"} and \
                not numeric_selectors and grammar_consts:
            gaps.append(_gap(
                "selector", "grammar_constants", "unmapped",
                "variant grammar has constants, but none is mapped to a semantic selector field",
                "variant_grammar.jsonl:consts",
            ))

        if query_kind in {"cmd_dispatch", "direct_operation", "genl_dispatch"} and not operation_field:
            operation_status = "unknown"
            gaps.append(_gap(
                "operation", call_name, "unknown", "syscall operation has no dispatch-field mapping",
                "model.variant.field_for_base",
            ))

        producer_branch_count = len(output_resources)
        for resource in input_resources:
            producer_branch_count += max(1, len(compatible.get(resource, ())))
            if resource not in compatible:
                gaps.append(_gap(
                    "producer", resource, "no-catalog-producer",
                    "no produced resource is compatible through resource.kind inheritance",
                    "horizon_model.json:resources.kind+syscalls.produces",
                ))

        constraints.sort(key=lambda row: (
            row["role"], row["selector"], row["field_path"], row["value_kind"],
            json.dumps(row["value"], sort_keys=True, ensure_ascii=True), row["type_id"],
        ))
        gaps.sort(key=lambda row: (row["stage"], row["subject"], row["status"], row["detail"]))
        queries[name] = VariantQueryInput(
            name=name,
            call_name=call_name,
            query_kind=query_kind,
            operation_field=operation_field,
            operation_status=operation_status,
            input_resources=input_resources,
            output_resources=output_resources,
            all_resources=all_resources,
            grammar_consts=grammar_consts,
            constraints=constraints,
            gaps=gaps,
            producer_branch_count=producer_branch_count,
        )

    return VariantInputModel(hm=hm, queries=queries, compatible_producers=compatible)
