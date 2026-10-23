#!/usr/bin/env python3
"""Explain guest CPU residuals from full-span proc snapshots and perf reports.

The probe directory is produced by perf_sampling.sh.  The /proc/stat pair
provides the guest-wide CPU envelope.  The complete comm report supplies
per-comm sample proportions, while the thresholded symbol report is used only
to explain hotspots inside those comm groups.  This diagnostic attribution
does not add anything to the CPU ledger.
"""

import re
import sys
from collections import defaultdict
from pathlib import Path


PERCENT_FIELD = re.compile(r"^([0-9]+(?:\.[0-9]+)?)%$")
COUNT_FIELD = re.compile(r"^[0-9][0-9,]*$")


def load_proc_stat(path):
    for line in Path(path).read_text().splitlines():
        if line.startswith("cpu "):
            values = [int(value) for value in line.split()[1:9]]
            return dict(zip(["u", "n", "s", "i", "w", "hi", "si", "st"], values))
    raise ValueError(f"no cpu line in {path}")


def comm_group(comm):
    """Collapse the same per-instance names as the previous attribution tool."""
    if re.match(r"syz\.\d+\.\d+$", comm) or comm.startswith("syz-executor"):
        return "syz-executor/*"
    if re.match(r"kworker/", comm):
        return "kworker/*"
    if re.match(r"(?:rcuop|rcuos|rcuog)/", comm):
        return "rcuo*/*"
    match = re.match(r"(ksoftirqd|migration|idle_inject|cpuhp)/", comm)
    if match:
        return match.group(1) + "/*"
    if re.match(r"irq/", comm):
        return "irq/*"
    if re.match(r"jbd2/", comm):
        return "jbd2/*"
    return comm


def parse_perf_fields(line, minimum_fields):
    fields = [field.strip() for field in line.split(";")]
    if len(fields) < minimum_fields:
        return None
    percent_match = PERCENT_FIELD.match(fields[0])
    if not percent_match or not COUNT_FIELD.match(fields[1]):
        return None
    return float(percent_match.group(1)), int(fields[1].replace(",", "")), fields


def parse_comm_report(path):
    samples_by_comm = defaultdict(int)
    for line in Path(path).read_text(errors="replace").splitlines():
        parsed = parse_perf_fields(line, 3)
        if parsed is None:
            continue
        _, samples, fields = parsed
        if fields[2]:
            samples_by_comm[fields[2]] += samples
    return dict(samples_by_comm)


def parse_symbol_report(path):
    # perf's --field-separator output for --sort comm,dso,symbol is 6
    # fields, not 5: Overhead;Samples;Command;Shared Object;Symbol;IPC. The
    # trailing IPC column is meaningless for a cpu-clock software event and
    # prints as placeholder dashes ("-      -"); fields[4] alone is the
    # symbol, nothing past it belongs in the name.
    rows = []
    for line in Path(path).read_text(errors="replace").splitlines():
        parsed = parse_perf_fields(line, 6)
        if parsed is None:
            continue
        percent, samples, fields = parsed
        rows.append(
            {
                "percent": percent,
                "samples": samples,
                "comm": fields[2],
                "dso": fields[3],
                "symbol": fields[4],
            }
        )
    return rows


def analyze_proc_stat(name, directory):
    directory = Path(directory)
    before = load_proc_stat(directory / "st.before")
    after = load_proc_stat(directory / "st.after")
    delta = {key: after[key] - before[key] for key in before}
    busy = sum(delta[key] for key in ("u", "n", "s", "hi", "si"))
    wall_ticks = sum(delta.values()) / 2

    print(f"\n{'=' * 76}\n{name}: full-span guest CPU attribution  ({directory})\n{'=' * 76}")
    print(
        f"/proc/stat busy delta: {busy} ticks "
        f"(u={delta['u']} n={delta['n']} s={delta['s']} "
        f"hi={delta['hi']} si={delta['si']}); "
        f"idle={delta['i']} iowait={delta['w']} steal={delta['st']}"
    )
    if wall_ticks:
        print(f"wall(core-ticks/core): {wall_ticks:.0f}  busy cores = {busy / wall_ticks:.3f}")


def analyze_perf(name, directory):
    directory = Path(directory)
    comm_path = directory / "gp.comm.report.txt"
    symbol_path = directory / "gp.hot-symbols.report.txt"
    if not comm_path.is_file():
        print(f"[{name}] no complete comm report at {comm_path}")
        return

    raw_comm_samples = parse_comm_report(comm_path)
    grouped_samples = defaultdict(int)
    for comm, samples in raw_comm_samples.items():
        grouped_samples[comm_group(comm)] += samples
    total_samples = sum(grouped_samples.values())

    print(f"\n-- {name} perf cpu-clock attribution ({total_samples} complete comm samples) --")
    print("   by comm (sample-count proportions):")
    for comm, samples in sorted(grouped_samples.items(), key=lambda item: -item[1]):
        share = samples * 100.0 / total_samples if total_samples else 0.0
        print(f"     {comm:<24} {samples:>9d}  {share:6.2f}%")

    if not symbol_path.is_file():
        print(f"[{name}] no hotspot report at {symbol_path}")
        return

    symbol_rows = parse_symbol_report(symbol_path)
    symbols = defaultdict(int)
    group_symbols = defaultdict(lambda: defaultdict(int))
    for row in symbol_rows:
        group = comm_group(row["comm"])
        symbols[row["symbol"]] += row["samples"]
        group_symbols[group][row["symbol"]] += row["samples"]

    print("   top hotspot symbols (thresholded report; explanation only):")
    for symbol, samples in sorted(symbols.items(), key=lambda item: -item[1])[:15]:
        share = samples * 100.0 / total_samples if total_samples else 0.0
        print(f"     {symbol:<52} {samples:>8d}  {share:6.2f}%")
    for group in (
        "kworker/*",
        "(udev-worker)",
        "systemd-udevd",
        "ksoftirqd/*",
        "systemd",
        "pool_workqueue_release",
    ):
        group_rows = group_symbols.get(group)
        if not group_rows:
            continue
        group_total = grouped_samples.get(group, 0)
        print(f"   top hotspot symbols inside {group} (complete comm samples {group_total}):")
        for symbol, samples in sorted(group_rows.items(), key=lambda item: -item[1])[:8]:
            share = samples * 100.0 / total_samples if total_samples else 0.0
            print(f"     {symbol:<52} {samples:>8d}  {share:6.2f}%")


def analyze(name, directory):
    analyze_proc_stat(name, directory)
    analyze_perf(name, directory)


if __name__ == "__main__":
    for argument in sys.argv[1:]:
        system_name, probe_directory = argument.split("=", 1)
        analyze(system_name, probe_directory)
