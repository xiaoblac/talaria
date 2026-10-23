#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SYSCALL_PROG_MAGIC = 0x50535953
SYZ_EXEC_MAGIC = 0x53595A50
SYZ_EXEC_VERSION = 2

SYZ_ARG_CONST = 0
SYZ_ARG_RESULT = 1
SYZ_ARG_PTR_IN = 2
SYZ_ARG_PTR_OUT = 3
SYZ_ARG_DATA = 4

FLAT_HEADER = struct.Struct('<II')
FLAT_OP = struct.Struct('<7Q')
TYPED_HEADER = struct.Struct('<IHHIIII')
TYPED_CALL = struct.Struct('<IHBBI')
TYPED_ARG = struct.Struct('<B3xIQ')

SUICIDE_CALLS = {
    'exit',
    'exit_group',
    'kill',
    'clone',
    'fork',
    'vfork',
    'execve',
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_syscall_table() -> tuple[list[dict[str, Any]], dict[int, str]]:
    """Build syscall meta order (meta_idx) + NR→name map.

    V2 codegen emits per-part C++ under ``program/src/syz/generated/``; the wire
    meta_idx is the SyscallMeta insertion order in Target::finalize(). Legacy
    fuzzer ``syscall_table.gen.hpp`` may still exist in older trees.
    """
    root = repo_root()
    entries: list[dict[str, Any]] = []
    by_nr: dict[int, str] = {}

    part_paths = sorted(root.glob('program/src/syz/generated/target_linux_amd64_syscalls_part_*.gen.cpp'))
    name_re = re.compile(r'm->set_name\(std::string\("([^"]+)"')
    nr_re = re.compile(r'm->set_nr\((\d+)uLL\)')

    for path in part_paths:
        pending_name: str | None = None
        with path.open(encoding='utf-8') as fh:
            for line in fh:
                if 'target.add_syscall()' in line:
                    pending_name = None
                    continue
                nm = name_re.search(line)
                if nm:
                    pending_name = nm.group(1)
                    continue
                rm = nr_re.search(line)
                if rm and pending_name is not None:
                    nr = int(rm.group(1))
                    meta_idx = len(entries)
                    entries.append({
                        'meta_idx': meta_idx,
                        'nr': nr,
                        'name': pending_name,
                        'arg_count': 0,
                    })
                    by_nr.setdefault(nr, pending_name)
                    pending_name = None

    if entries:
        return entries, by_nr

    legacy = root / 'fuzzer/include/refuzz/fuzzer/syz/generated/syscall_table.gen.hpp'
    if legacy.is_file():
        text = legacy.read_text(encoding='utf-8')
        pattern = re.compile(r'^\s*\{\s*(\d+),\s*"([^"]+)",\s*(\d+),', re.MULTILINE)
        for match in pattern.finditer(text):
            nr = int(match.group(1))
            name = match.group(2)
            arg_count = int(match.group(3))
            meta_idx = len(entries)
            entries.append({
                'meta_idx': meta_idx,
                'nr': nr,
                'name': name,
                'arg_count': arg_count,
            })
            by_nr.setdefault(nr, name)
        return entries, by_nr

    raise FileNotFoundError(
        'decode_prog: no syscall metadata (expected '
        f'{root}/program/src/syz/generated/target_linux_amd64_syscalls_part_*.gen.cpp '
        'after V2 codegen)'
    )


def preview_bytes(data: bytes, limit: int = 24) -> str:
    if not data:
        return '""'
    head = data[:limit]
    printable = ''.join(chr(b) if 32 <= b < 127 and chr(b) not in {'\\', '"'} else '.' for b in head)
    suffix = '' if len(data) <= limit else '...'
    return f'len={len(data)} hex={head.hex()}{suffix} ascii="{printable}{suffix}"'


def resolve_syscall(call_nr: int, meta_idx: int | None, meta_table: list[dict[str, Any]], by_nr: dict[int, str]) -> dict[str, Any]:
    meta_entry = None
    if meta_idx is not None and 0 <= meta_idx < len(meta_table):
        meta_entry = meta_table[meta_idx]
    nr_name = by_nr.get(call_nr, f'sys_{call_nr}')
    meta_name = meta_entry['name'] if meta_entry is not None else None
    meta_nr = meta_entry['nr'] if meta_entry is not None else None
    mismatch = meta_entry is not None and meta_nr != call_nr
    name = nr_name
    if name.startswith('sys_') and meta_name is not None:
        name = str(meta_name)
    return {
        'name': name,
        'meta_name': meta_name,
        'meta_nr': meta_nr,
        'meta_mismatch': mismatch,
    }


def decode_typed_arg(blob: bytes, data_base: bytes) -> dict[str, Any]:
    kind, type_idx, value = TYPED_ARG.unpack(blob)
    out: dict[str, Any] = {
        'kind': kind,
        'type_idx': type_idx,
        'value': value,
    }
    if kind in {SYZ_ARG_PTR_IN, SYZ_ARG_DATA}:
        data_offset = (value >> 32) & 0xFFFFFFFF
        data_len = value & 0xFFFFFFFF
        end = data_offset + data_len
        if end > len(data_base):
            raise ValueError(f'arg data out of range: off={data_offset} len={data_len} data_len={len(data_base)}')
        out['data_offset'] = data_offset
        out['data_len'] = data_len
        out['data'] = data_base[data_offset:end]
    elif kind == SYZ_ARG_RESULT:
        out['ref_call_idx'] = (value >> 32) & 0xFFFFFFFF
    elif kind == SYZ_ARG_PTR_OUT:
        out['alloc_size'] = value
    return out


def typed_arg_text(arg: dict[str, Any]) -> str:
    kind = arg['kind']
    type_idx = arg['type_idx']
    if kind == SYZ_ARG_CONST:
        return f'const(type={type_idx}, value=0x{arg["value"]:x})'
    if kind == SYZ_ARG_RESULT:
        return f'result(type={type_idx}, call={arg.get("ref_call_idx", 0)})'
    if kind == SYZ_ARG_PTR_IN:
        return f'ptr_in(type={type_idx}, {preview_bytes(arg.get("data", b""))})'
    if kind == SYZ_ARG_PTR_OUT:
        return f'ptr_out(type={type_idx}, size={arg.get("alloc_size", 0)})'
    if kind == SYZ_ARG_DATA:
        return f'data(type={type_idx}, {preview_bytes(arg.get("data", b""))})'
    return f'arg(kind={kind}, type={type_idx}, value=0x{arg["value"]:x})'


def detect_format(data: bytes) -> str:
    if len(data) >= TYPED_HEADER.size:
        magic, version, n_calls, calls_offset, data_offset, data_len, _reserved = TYPED_HEADER.unpack_from(data, 0)
        if (
            magic == SYZ_EXEC_MAGIC
            and version == SYZ_EXEC_VERSION
            and n_calls > 0
            and calls_offset >= TYPED_HEADER.size
            and data_offset >= calls_offset
            and data_offset <= len(data)
            and data_offset + data_len <= len(data)
        ):
            return 'syz_exec_v2'
    if len(data) >= FLAT_HEADER.size:
        magic, count = FLAT_HEADER.unpack_from(data, 0)
        expected = FLAT_HEADER.size + count * FLAT_OP.size
        if magic == SYSCALL_PROG_MAGIC and expected <= len(data):
            return 'flat_v1'
    return 'unknown'


def looks_like_syz_canonical_text(data: bytes) -> bool:
    """Corpus v2 stores canonical syz programs as UTF-8 text in payload.bin."""
    if not data:
        return False
    probe = data[:4096]
    if b'\x00' in probe:
        return False
    try:
        head = probe.decode('utf-8')
    except UnicodeDecodeError:
        return False
    return bool(re.search(r'^\s*r\d+\s*=', head, re.MULTILINE))


def decode_syz_canonical_text(data: bytes) -> dict[str, Any]:
    text = data.decode('utf-8')
    stripped = text.strip()
    lines = [ln.rstrip() for ln in stripped.splitlines() if ln.strip()]
    # Canonical line: rN = ioctl$foo(...)
    call_re = re.compile(r'^r\d+\s*=\s*([^\s(]+)\s*\(')
    calls: list[dict[str, Any]] = []
    for line in lines:
        m = call_re.match(line.strip())
        if not m:
            continue
        name = m.group(1)
        calls.append({
            'index': len(calls),
            'nr': None,
            'name': name,
            'text': line.strip(),
            'meta_idx': None,
            'meta_name': None,
            'meta_nr': None,
            'meta_mismatch': False,
            'args': [],
        })
    return {
        'format': 'syz_canonical_text',
        'header': {
            'encoding': 'utf-8',
            'line_count': len(lines),
            'matched_call_lines': len(calls),
        },
        'calls': calls,
        'source_text': stripped,
    }


def decode_typed(data: bytes, meta_table: list[dict[str, Any]], by_nr: dict[int, str]) -> dict[str, Any]:
    magic, version, n_calls, calls_offset, data_offset, data_len, reserved = TYPED_HEADER.unpack_from(data, 0)
    call_pos = calls_offset
    calls_end = data_offset
    data_base = data[data_offset:data_offset + data_len]
    calls: list[dict[str, Any]] = []
    for call_idx in range(n_calls):
        if call_pos + TYPED_CALL.size > calls_end:
            raise ValueError(f'truncated SyzExecCall at index {call_idx}')
        call_nr, n_args, has_ret, ret_kind, meta_idx = TYPED_CALL.unpack_from(data, call_pos)
        call_pos += TYPED_CALL.size
        args: list[dict[str, Any]] = []
        for arg_idx in range(n_args):
            if call_pos + TYPED_ARG.size > calls_end:
                raise ValueError(f'truncated SyzExecArg at call {call_idx} arg {arg_idx}')
            args.append(decode_typed_arg(data[call_pos:call_pos + TYPED_ARG.size], data_base))
            call_pos += TYPED_ARG.size
        resolved = resolve_syscall(call_nr, meta_idx, meta_table, by_nr)
        name = resolved['name']
        text_value = f'{name}(' + ', '.join(typed_arg_text(arg) for arg in args) + ')'
        if resolved['meta_mismatch']:
            text_value += f' [meta_idx={meta_idx} -> {resolved["meta_name"]}/{resolved["meta_nr"]}]'
        calls.append({
            'index': call_idx,
            'nr': call_nr,
            'name': name,
            'meta_idx': meta_idx,
            'meta_name': resolved['meta_name'],
            'meta_nr': resolved['meta_nr'],
            'meta_mismatch': resolved['meta_mismatch'],
            'n_args': n_args,
            'has_ret': bool(has_ret),
            'ret_kind': ret_kind,
            'args': args,
            'text': text_value,
        })
    return {
        'format': 'syz_exec_v2',
        'header': {
            'magic': magic,
            'version': version,
            'n_calls': n_calls,
            'calls_offset': calls_offset,
            'data_offset': data_offset,
            'data_len': data_len,
            'reserved': reserved,
        },
        'calls': calls,
    }


def decode_flat(data: bytes, _meta_table: list[dict[str, Any]], by_nr: dict[int, str]) -> dict[str, Any]:
    magic, count = FLAT_HEADER.unpack_from(data, 0)
    calls: list[dict[str, Any]] = []
    pos = FLAT_HEADER.size
    for call_idx in range(count):
        if pos + FLAT_OP.size > len(data):
            raise ValueError(f'truncated SyscallOp at index {call_idx}')
        values = FLAT_OP.unpack_from(data, pos)
        pos += FLAT_OP.size
        call_nr = values[0]
        args = list(values[1:])
        name = resolve_syscall(call_nr, None, _meta_table, by_nr)['name']
        text = f'{name}(' + ', '.join(f'0x{arg:x}' for arg in args) + ')'
        calls.append({
            'index': call_idx,
            'nr': call_nr,
            'name': name,
            'args': args,
            'text': text,
        })
    return {
        'format': 'flat_v1',
        'header': {
            'magic': magic,
            'count': count,
        },
        'calls': calls,
    }


def add_summary(decoded: dict[str, Any]) -> dict[str, Any]:
    names = [str(call['name']) for call in decoded['calls']]
    counts = Counter(names)
    decoded['summary'] = {
        'call_count': len(decoded['calls']),
        'top_syscalls': [{'name': name, 'count': count} for name, count in counts.most_common(8)],
        'suicide_candidates': [name for name in names if name in SUICIDE_CALLS],
    }
    return decoded


def decode_program_bytes(data: bytes) -> dict[str, Any]:
    fmt = detect_format(data)
    if fmt == 'syz_exec_v2' or fmt == 'flat_v1':
        meta_table, by_nr = load_syscall_table()
        if fmt == 'syz_exec_v2':
            return add_summary(decode_typed(data, meta_table, by_nr))
        return add_summary(decode_flat(data, meta_table, by_nr))
    if looks_like_syz_canonical_text(data):
        return add_summary(decode_syz_canonical_text(data))
    raise ValueError('unrecognized program format')


def render_text(decoded: dict[str, Any], source: Path | None) -> str:
    lines: list[str] = []
    if source is not None:
        lines.append(f'source: {source}')
    lines.append(f'format: {decoded["format"]}')
    for key, value in decoded.get('header', {}).items():
        lines.append(f'{key}: {value}')
    summary = decoded.get('summary', {})
    lines.append(f'call_count: {summary.get("call_count", len(decoded["calls"]))}')
    top = summary.get('top_syscalls', [])
    if top:
        lines.append('top_syscalls: ' + ', '.join(f'{item["name"]}x{item["count"]}' for item in top))
    suicide = summary.get('suicide_candidates', [])
    if suicide:
        lines.append('suicide_candidates: ' + ', '.join(suicide))
    lines.append('calls:')
    for call in decoded['calls']:
        lines.append(f'  {call["index"]}: {call["text"]}')
    return '\n'.join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Decode reFuzz prog0.bin into readable syscalls')
    parser.add_argument('path', type=Path, help='Path to prog0.bin or payload.bin')
    parser.add_argument('--json', action='store_true', help='Emit structured JSON')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data = args.path.read_bytes()
    decoded = decode_program_bytes(data)
    if args.json:
        print(json.dumps(decoded, indent=2, default=lambda value: value.hex() if isinstance(value, (bytes, bytearray)) else str(value)))
    else:
        print(render_text(decoded, args.path))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'decode_prog.py: {exc}', file=sys.stderr)
        raise SystemExit(1)
