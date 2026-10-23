#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.

import collections
from dataclasses import dataclass
import functools
import glob
import os
import re


def _read(path):
    try:
        with open(path, errors="ignore") as stream:
            return stream.read()
    except OSError:
        return ""


def _decode_c_string(raw):
    try:
        return bytes(raw, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return raw


@dataclass(frozen=True)
class GeneratedFixedField:
    path: tuple[str, ...]
    owner_kind: str
    owner_name: str
    field_name: str
    value_kind: str
    values: tuple
    type_id: int
    bitmask: bool = False


_TYPE_BLOCK_RE = re.compile(
    r"\{\s*auto\* t = static_cast<(?P<kind>\w+Type)\*>\(types\[(?P<id>\d+)\]\);"
    r"(?P<body>.*?)\n    \}",
    re.S,
)
_TYPE_NAME_RE = re.compile(
    r't->set_name\(std::string\("((?:\\.|[^"\\])*)",\s*\d+\)\)'
)
_TYPE_FIELD_RE = re.compile(
    r'Field fld\(std::string\("((?:\\.|[^"\\])*)",\s*\d+\),\s*types\[(\d+)\]\)'
)


@functools.lru_cache(maxsize=4)
def _generated_type_infos(root):
    infos = {}
    pattern = os.path.join(
        root,
        "program/src/syz/generated/target_linux_amd64_types_part_*.gen.cpp",
    )
    for path in sorted(glob.glob(pattern)):
        text = _read(path)
        for match in _TYPE_BLOCK_RE.finditer(text):
            type_id = int(match.group("id"))
            kind = match.group("kind")
            body = match.group("body")
            name_match = _TYPE_NAME_RE.search(body)
            name = _decode_c_string(name_match.group(1)) if name_match else ""
            children = []
            if kind in {"StructType", "UnionType"}:
                children.extend(
                    (_decode_c_string(field.group(1)), int(field.group(2)))
                    for field in _TYPE_FIELD_RE.finditer(body)
                )
            elif kind in {"PtrType", "ArrayType"}:
                elem = re.search(r"t->set_elem\(types\[(\d+)\]\)", body)
                if elem:
                    children.append(("*" if kind == "PtrType" else "[]", int(elem.group(1))))

            values = ()
            bitmask = False
            if kind == "ConstType":
                value = re.search(r"t->set_val\((\d+)uLL\)", body)
                if value:
                    values = (int(value.group(1)),)
            elif kind == "FlagsType":
                value_list = re.search(
                    r"t->set_vals\(std::vector<uint64_t>\{(?P<body>.*?)\}\)",
                    body,
                    re.S,
                )
                if value_list:
                    values = tuple(
                        int(value.group(1))
                        for value in re.finditer(r"(\d+)uLL", value_list.group("body"))
                    )
                bitmask_match = re.search(r"t->set_bitmask\((true|false)\)", body)
                bitmask = bool(bitmask_match and bitmask_match.group(1) == "true")
            elif kind == "BufferType":
                value_list = re.search(
                    r"t->set_values\(std::vector<std::string>\{(?P<body>.*?)\}\)",
                    body,
                    re.S,
                )
                if value_list:
                    values = tuple(sorted({
                        _decode_c_string(value.group(1))
                        for value in re.finditer(
                            r'std::string\("((?:\\.|[^"\\])*)",\s*\d+\)',
                            value_list.group("body"),
                        )
                    }))

            infos[type_id] = {
                "kind": kind,
                "name": name,
                "children": tuple(children),
                "values": values,
                "bitmask": bitmask,
                "source": os.path.relpath(path, root),
            }
    return infos


@functools.lru_cache(maxsize=4)
def _generated_type_maps(root):
    ptr_elem = {}
    buffer_values = collections.defaultdict(set)
    const_values = {}
    for type_id, info in _generated_type_infos(root).items():
        if info["kind"] == "PtrType" and info["children"]:
            ptr_elem[type_id] = info["children"][0][1]
        elif info["kind"] == "BufferType":
            buffer_values[type_id].update(info["values"])
        elif info["kind"] == "ConstType" and info["values"]:
            const_values[type_id] = info["values"][0]
    return (
        ptr_elem,
        {type_id: frozenset(values) for type_id, values in buffer_values.items()},
        const_values,
    )


@functools.lru_cache(maxsize=4)
def _generated_syscall_signatures(root):
    rows = []
    block_re = re.compile(
        r"\{\s*auto\* m = target\.add_syscall\(\);(?P<body>.*?)\n    \}",
        re.S,
    )
    name_re = re.compile(r'm->set_name\(std::string\("([^"]+)",\s*\d+\)\)')
    call_name_re = re.compile(r'm->set_call_name\(std::string\("([^"]+)",\s*\d+\)\)')
    field_re = re.compile(
        r'Field fld\(std::string\("([^"]+)",\s*\d+\),\s*types\[(\d+)\]\)'
    )
    pattern = os.path.join(
        root,
        "program/src/syz/generated/target_linux_amd64_syscalls_part_*.gen.cpp",
    )
    for path in sorted(glob.glob(pattern)):
        text = _read(path)
        for block in block_re.finditer(text):
            body = block.group("body")
            name = name_re.search(body)
            call_name = call_name_re.search(body)
            if not name or not call_name:
                continue
            fields = tuple(
                (field.group(1), int(field.group(2)))
                for field in field_re.finditer(body)
            )
            rows.append((name.group(1), call_name.group(1), fields))
    return tuple(rows)


@functools.lru_cache(maxsize=4)
def _generated_syscall_fields(root):
    return tuple(
        (name, call_name, field_name, type_id)
        for name, call_name, fields in _generated_syscall_signatures(root)
        for field_name, type_id in fields
    )


def generated_syscall_signatures(hm, root="."):
    root = os.path.abspath(root)
    model_names = {syscall["name"] for syscall in hm.get("syscalls", [])}
    for name, call_name, fields in _generated_syscall_signatures(root):
        if name in model_names:
            yield name, call_name, fields


def generated_syscall_fields(hm, root=".", field_names=None):
    root = os.path.abspath(root)
    model_names = {syscall["name"] for syscall in hm.get("syscalls", [])}
    wanted = set(field_names) if field_names is not None else None
    for name, call_name, field_name, type_id in _generated_syscall_fields(root):
        if name not in model_names or (wanted is not None and field_name not in wanted):
            continue
        yield name, call_name, field_name, type_id


def fixed_buffer_values(type_id, root="."):
    ptr_elem, buffer_values, _const_values = _generated_type_maps(os.path.abspath(root))
    values = set()
    seen = set()
    while type_id not in seen:
        seen.add(type_id)
        values.update(buffer_values.get(type_id, ()))
        if type_id not in ptr_elem:
            break
        type_id = ptr_elem[type_id]
    return values


def fixed_const_value(type_id, root="."):
    _ptr_elem, _buffer_values, const_values = _generated_type_maps(os.path.abspath(root))
    return const_values.get(type_id)


def generated_type_info(type_id, root="."):
    return _generated_type_infos(os.path.abspath(root)).get(type_id)


def fixed_scalar_domain(type_id, root="."):
    """Return a finite scalar domain without inventing a value for runtime scalar types."""
    infos = _generated_type_infos(os.path.abspath(root))
    seen = set()
    while type_id not in seen:
        seen.add(type_id)
        info = infos.get(type_id)
        if not info:
            return None
        if info["kind"] == "ConstType" and info["values"]:
            return "const", info["values"], False
        if info["kind"] == "FlagsType" and info["values"]:
            return "flags", info["values"], info["bitmask"]
        if info["kind"] != "PtrType" or not info["children"]:
            return None
        type_id = info["children"][0][1]
    return None


def fixed_descendant_fields(type_id, root=".", max_depth=32, max_results=4096):
    """Enumerate fixed Const/Flags/Buffer fields reachable through the generated type graph."""
    infos = _generated_type_infos(os.path.abspath(root))
    results = []

    def domain(child_id):
        info = infos.get(child_id)
        seen = set()
        while info and info["kind"] == "PtrType" and info["children"] and child_id not in seen:
            seen.add(child_id)
            child_id = info["children"][0][1]
            info = infos.get(child_id)
        if not info or not info["values"]:
            return None
        if info["kind"] == "ConstType":
            return child_id, "const", info["values"], False
        if info["kind"] == "FlagsType":
            return child_id, "flags", info["values"], info["bitmask"]
        if info["kind"] == "BufferType":
            return child_id, "buffer", info["values"], False
        return None

    def walk(current_id, path, stack, depth):
        if depth > max_depth or current_id in stack or len(results) >= max_results:
            return
        info = infos.get(current_id)
        if not info:
            return
        next_stack = stack | {current_id}
        for field_name, child_id in info["children"]:
            if len(results) >= max_results:
                return
            transparent = field_name in {"*", "[]"}
            child_path = path if transparent else path + (field_name or "<anon>",)
            fixed = domain(child_id)
            if fixed:
                leaf_id, value_kind, values, bitmask = fixed
                results.append(GeneratedFixedField(
                    path=child_path,
                    owner_kind=info["kind"],
                    owner_name=info["name"],
                    field_name=field_name,
                    value_kind=value_kind,
                    values=tuple(values),
                    type_id=leaf_id,
                    bitmask=bitmask,
                ))
            else:
                walk(child_id, child_path, next_stack, depth + 1)

    walk(type_id, (), set(), 0)
    return tuple(results)


def fixed_const_syscall_args(hm, root=".", field_names=None):
    out = collections.defaultdict(dict)
    for name, _call_name, field_name, type_id in generated_syscall_fields(
            hm, root, field_names):
        value = fixed_const_value(type_id, root)
        if value is not None:
            out[name][field_name] = value
    return out
