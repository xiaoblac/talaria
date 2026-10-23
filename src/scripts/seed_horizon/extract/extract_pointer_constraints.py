#!/usr/bin/env python3
import argparse
import concurrent.futures
import csv
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time


DEFAULT_ROOT = "."
DEFAULT_BATCHES = "run/seed_horizon/kernel_linked/batches.tsv"
DEFAULT_BINARY = "run/seed_horizon/ir_constraints"
DEFAULT_OUT = "run/seed_horizon"
DEFAULT_TMP = "run/seed_horizon/constraint_tmp"

EXPECTED_COLUMNS = {
    "COBJ": 14,
    "CPT": 18,
    "CMEM": 13,
    "CCALL": 15,
}
OUTPUT_NAMES = {
    "COBJ": "objects.tsv",
    "CPT": "points_to_constraints.tsv",
    "CMEM": "memory_constraints.tsv",
    "CCALL": "call_constraints.tsv",
}
HEADERS = {
    "COBJ": (
        "#object_id\tkind\tscope\tsymbol\tparent_object\tbyte_offset\ttype\t"
        "contained_structs\tsize\tbatch\tfunction\tinstruction\tdebug\tdetail\n"
    ),
    "CPT": (
        "#constraint_id\tkind\tdst_value\tsrc_value\tobject_id\tbyte_offset\t"
        "offset_kind\tstruct_type\tfield_name\tbatch\tfunction\tinstruction\topcode\t"
        "debug\tdetail\tdynamic_base\tdynamic_stride\tdynamic_count\tsource_type\n"
    ),
    "CMEM": (
        "#constraint_id\tkind\tdst_value\tpointer_value\tsrc_value\tobject_id\t"
        "byte_offset\tsize\tbatch\tfunction\tinstruction\topcode\tdebug\tdetail\n"
    ),
    "CCALL": (
        "#constraint_id\tkind\tcallsite\tcaller\tcallee\ttarget_object\tindex\tvalue\t"
        "result_value\tbatch\tfunction\tinstruction\topcode\tattributes\tdebug\tdetail\n"
    ),
}


def digest(path):
    sha256 = hashlib.sha256()
    size = 0
    lines = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            sha256.update(chunk)
            size += len(chunk)
            lines += chunk.count(b"\n")
    return sha256.hexdigest(), size, lines


def qualify(batch_id, identifier):
    if identifier == "-" or identifier.startswith(("sym:", "special:")):
        return identifier
    return f"batch:{batch_id}:{identifier}"


def load_batches(path, root, pattern=None, limit=0):
    matcher = re.compile(pattern) if pattern else None
    rows = []
    with path.open() as source:
        for row in csv.DictReader(source, delimiter="\t"):
            if row.get("status") != "OK":
                continue
            batch_id = row["batch_id"]
            if matcher and not matcher.search(batch_id):
                continue
            bitcode = Path(row["bc_path"])
            if not bitcode.is_absolute():
                bitcode = root / bitcode
            if not bitcode.exists():
                raise FileNotFoundError(f"missing linked batch: {bitcode}")
            rows.append((batch_id, bitcode))
    rows.sort()
    return rows[:limit] if limit else rows


def transform_object(batch_id, columns):
    return "\t".join([
        qualify(batch_id, columns[1]),
        columns[2],
        columns[3],
        columns[4],
        qualify(batch_id, columns[5]),
        columns[6],
        columns[7],
        columns[8],
        columns[9],
        batch_id,
        columns[10],
        columns[11],
        columns[12],
        columns[13],
    ])


def transform_point(batch_id, sequence, columns):
    constraint_id = f"batch:{batch_id}:pt:{sequence}"
    return "\t".join([
        constraint_id,
        columns[1],
        qualify(batch_id, columns[2]),
        qualify(batch_id, columns[3]),
        qualify(batch_id, columns[4]),
        columns[5],
        columns[6],
        columns[7],
        columns[8],
        batch_id,
        columns[9],
        columns[10],
        columns[11],
        columns[12],
        columns[13],
        columns[14],
        columns[15],
        columns[16],
        columns[17],
    ])


def transform_memory(batch_id, sequence, columns):
    constraint_id = f"batch:{batch_id}:mem:{sequence}"
    return "\t".join([
        constraint_id,
        columns[1],
        qualify(batch_id, columns[2]),
        qualify(batch_id, columns[3]),
        qualify(batch_id, columns[4]),
        qualify(batch_id, columns[5]),
        columns[6],
        columns[7],
        batch_id,
        columns[8],
        columns[9],
        columns[10],
        columns[11],
        columns[12],
    ])


def transform_call(batch_id, sequence, columns):
    constraint_id = f"batch:{batch_id}:call:{sequence}"
    return "\t".join([
        constraint_id,
        columns[1],
        qualify(batch_id, columns[2]),
        columns[3],
        columns[4],
        qualify(batch_id, columns[5]),
        columns[6],
        qualify(batch_id, columns[7]),
        qualify(batch_id, columns[8]),
        batch_id,
        columns[9],
        columns[10],
        columns[11],
        columns[12],
        columns[13],
        columns[14],
    ])


TRANSFORMS = {
    "COBJ": transform_object,
    "CPT": transform_point,
    "CMEM": transform_memory,
    "CCALL": transform_call,
}


def extract_batch(binary, batch_id, bitcode, tmp_dir):
    start = time.monotonic()
    paths = {tag: tmp_dir / f"{batch_id}.{tag.lower()}.tsv.gz" for tag in OUTPUT_NAMES}
    marker_path = tmp_dir / f"{batch_id}.done.json"
    stderr_path = tmp_dir / f"{batch_id}.stderr"
    counts = {tag: 0 for tag in OUTPUT_NAMES}
    malformed = []
    writers = {
        tag: gzip.open(path, "wt", compresslevel=1, encoding="utf-8", newline="")
        for tag, path in paths.items()
    }
    try:
        with stderr_path.open("w") as stderr:
            process = subprocess.Popen(
                [str(binary), str(bitcode)],
                stdout=subprocess.PIPE,
                stderr=stderr,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1024 * 1024,
            )
            assert process.stdout is not None
            for line_number, line in enumerate(process.stdout, 1):
                columns = line.rstrip("\n").split("\t")
                tag = columns[0] if columns else ""
                if tag not in EXPECTED_COLUMNS or len(columns) != EXPECTED_COLUMNS[tag]:
                    if len(malformed) < 20:
                        malformed.append(
                            f"line={line_number} tag={tag!r} columns={len(columns)} text={line[:200]!r}"
                        )
                    continue
                sequence = counts[tag]
                transform = TRANSFORMS[tag]
                if tag == "COBJ":
                    output = transform(batch_id, columns)
                else:
                    output = transform(batch_id, sequence, columns)
                writers[tag].write(output + "\n")
                counts[tag] += 1
            returncode = process.wait()
    finally:
        for writer in writers.values():
            writer.close()

    stderr_text = stderr_path.read_text(errors="replace") if stderr_path.exists() else ""
    if returncode != 0 or malformed:
        reason = f"exit={returncode}"
        if malformed:
            reason += " malformed=" + " | ".join(malformed)
        if stderr_text:
            reason += " stderr=" + stderr_text[-2000:].replace("\n", " ")
        return {
            "batch_id": batch_id,
            "bitcode": str(bitcode),
            "ok": False,
            "reason": reason,
            "counts": counts,
            "paths": paths,
            "marker": marker_path,
            "seconds": time.monotonic() - start,
        }
    if stderr_path.exists():
        stderr_path.unlink()
    result = {
        "batch_id": batch_id,
        "bitcode": str(bitcode),
        "ok": True,
        "reason": "",
        "counts": counts,
        "paths": paths,
        "marker": marker_path,
        "seconds": time.monotonic() - start,
    }
    marker_tmp = marker_path.with_suffix(".tmp")
    with marker_tmp.open("w") as out:
        json.dump({"batch_id": batch_id, "counts": counts}, out, sort_keys=True)
        out.write("\n")
    marker_tmp.replace(marker_path)
    return result


def recover_batch(batch_id, bitcode, tmp_dir):
    paths = {tag: tmp_dir / f"{batch_id}.{tag.lower()}.tsv.gz" for tag in OUTPUT_NAMES}
    marker_path = tmp_dir / f"{batch_id}.done.json"
    final_columns = {"COBJ": 14, "CPT": 19, "CMEM": 14, "CCALL": 16}
    if not all(path.exists() for path in paths.values()):
        return None
    counts = {}
    try:
        for tag, path in paths.items():
            count = 0
            with gzip.open(path, "rt", encoding="utf-8") as source:
                for line in source:
                    if len(line.rstrip("\n").split("\t")) != final_columns[tag]:
                        raise ValueError(f"invalid resumed {tag} row")
                    count += 1
            counts[tag] = count
    except (OSError, EOFError, ValueError):
        for path in paths.values():
            path.unlink(missing_ok=True)
        marker_path.unlink(missing_ok=True)
        return None
    marker_tmp = marker_path.with_suffix(".tmp")
    with marker_tmp.open("w") as out:
        json.dump({"batch_id": batch_id, "counts": counts}, out, sort_keys=True)
        out.write("\n")
    marker_tmp.replace(marker_path)
    return {
        "batch_id": batch_id,
        "bitcode": str(bitcode),
        "ok": True,
        "reason": "resumed",
        "counts": counts,
        "paths": paths,
        "marker": marker_path,
        "seconds": 0.0,
    }


def merge_results(results, out_dir, keep_temp):
    temp_outputs = {
        tag: out_dir / f".{name}.tmp"
        for tag, name in OUTPUT_NAMES.items()
    }
    writers = {tag: path.open("w") for tag, path in temp_outputs.items()}
    merged_counts = {tag: 0 for tag in OUTPUT_NAMES}
    duplicate_objects = 0
    seen_objects = set()
    try:
        for tag, writer in writers.items():
            writer.write(HEADERS[tag])
        for result in sorted(results, key=lambda row: row["batch_id"]):
            for tag, path in result["paths"].items():
                with gzip.open(path, "rt", encoding="utf-8") as source:
                    if tag == "COBJ":
                        for line in source:
                            object_id = line.split("\t", 1)[0]
                            if object_id in seen_objects:
                                duplicate_objects += 1
                                continue
                            seen_objects.add(object_id)
                            writers[tag].write(line)
                            merged_counts[tag] += 1
                    else:
                        for line in source:
                            writers[tag].write(line)
                            merged_counts[tag] += 1
                if not keep_temp:
                    path.unlink()
            if not keep_temp:
                result["marker"].unlink(missing_ok=True)
    finally:
        for writer in writers.values():
            writer.close()

    for tag, name in OUTPUT_NAMES.items():
        temp_outputs[tag].replace(out_dir / name)
    return merged_counts, duplicate_objects


def write_log(path, results):
    with path.open("w") as out:
        out.write("#status\tbatch_id\tbitcode\tobjects\tpoints\tmemory\tcalls\tseconds\treason\n")
        for result in sorted(results, key=lambda row: row["batch_id"]):
            counts = result["counts"]
            out.write("\t".join([
                "OK" if result["ok"] else "FAIL",
                result["batch_id"],
                result["bitcode"],
                str(counts["COBJ"]),
                str(counts["CPT"]),
                str(counts["CMEM"]),
                str(counts["CCALL"]),
                f"{result['seconds']:.3f}",
                result["reason"].replace("\t", " ").replace("\n", " "),
            ]) + "\n")


def write_manifest(path, root, binary, batches_path, outputs, counts, batch_count,
                   duplicate_objects):
    source_path = root / "scripts/seed_horizon/extract/ir_constraints.cpp"
    extractor_path = root / "scripts/seed_horizon/extract/extract_pointer_constraints.py"
    artifacts = {}
    for role, artifact in {
        "binary": binary,
        "source": source_path,
        "driver": extractor_path,
        "batches": batches_path,
        **{f"output_{tag.lower()}": output for tag, output in outputs.items()},
    }.items():
        sha256, size, lines = digest(artifact)
        try:
            shown = str(artifact.relative_to(root))
        except ValueError:
            shown = str(artifact)
        artifacts[role] = {
            "path": shown,
            "sha256": sha256,
            "bytes": size,
            "lines": lines,
        }
    manifest = {
        "schema_version": 3,
        "batch_count": batch_count,
        "counts": {OUTPUT_NAMES[tag]: counts[tag] for tag in sorted(counts)},
        "duplicate_object_rows_removed": duplicate_objects,
        "artifacts": artifacts,
    }
    with path.open("w") as out:
        json.dump(manifest, out, indent=2, sort_keys=True)
        out.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=DEFAULT_ROOT)
    parser.add_argument("--batches", default=DEFAULT_BATCHES)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--out-dir", default=DEFAULT_OUT)
    parser.add_argument("--tmp-dir", default=DEFAULT_TMP)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--batch-pattern")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    def rooted(path):
        value = Path(path)
        return value if value.is_absolute() else root / value

    batches_path = rooted(args.batches)
    binary = rooted(args.binary)
    out_dir = rooted(args.out_dir)
    tmp_dir = rooted(args.tmp_dir)
    if not binary.exists():
        raise FileNotFoundError(f"missing constraint extractor: {binary}")
    rows = load_batches(batches_path, root, args.batch_pattern, args.limit)
    if not rows:
        raise RuntimeError("no linked batches selected")

    out_dir.mkdir(parents=True, exist_ok=True)
    if tmp_dir.exists() and not args.resume:
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    results = []
    pending = []
    if args.resume:
        for batch_id, bitcode in rows:
            recovered = recover_batch(batch_id, bitcode, tmp_dir)
            if recovered:
                results.append(recovered)
            else:
                pending.append((batch_id, bitcode))
    else:
        pending = rows
    print(
        f"constraint batches={len(rows)} jobs={max(1, args.jobs)} "
        f"resumed={len(results)} pending={len(pending)}"
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as executor:
        futures = {
            executor.submit(extract_batch, binary, batch_id, bitcode, tmp_dir): batch_id
            for batch_id, bitcode in pending
        }
        for completed, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            results.append(result)
            if not result["ok"] or completed % 25 == 0 or completed == len(pending):
                status = "OK" if result["ok"] else "FAIL"
                print(
                    f"[{completed}/{len(pending)}] {status} {result['batch_id']} "
                    f"rows={sum(result['counts'].values())} seconds={result['seconds']:.2f}",
                    flush=True,
                )

    log_path = out_dir / "constraint_extract.log.tsv"
    write_log(log_path, results)
    failures = [result for result in results if not result["ok"]]
    if failures:
        print(f"constraint extraction failed batches={len(failures)} log={log_path}")
        return 1

    counts, duplicate_objects = merge_results(results, out_dir, args.keep_temp)
    if not args.keep_temp:
        shutil.rmtree(tmp_dir)
    outputs = {tag: out_dir / name for tag, name in OUTPUT_NAMES.items()}
    manifest_path = out_dir / "constraint_manifest.json"
    write_manifest(
        manifest_path,
        root,
        binary,
        batches_path,
        outputs,
        counts,
        len(rows),
        duplicate_objects,
    )
    for tag in ("COBJ", "CPT", "CMEM", "CCALL"):
        print(f"{OUTPUT_NAMES[tag]} rows={counts[tag]}")
    print(f"duplicate object rows removed={duplicate_objects}")
    print(f"wrote {manifest_path}")
    print(f"wrote {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
