#!/usr/bin/env python3
# Compare scheduling policies from coverage_PC_series.log:
#   # tick<TAB>all_pc<TAB>corpus_pc
# Reports all-PC cardinality at elapsed checkpoints plus run-summary endpoints.
#
#   python3 scripts/sched_policy_compare.py priority uniform size_weighted rarity_weighted
import csv, glob, json, sys

POLICIES = sys.argv[1:] or ["priority", "uniform", "size_weighted", "rarity_weighted"]
CHECKPOINTS = [60, 300, 600, 1200, 1800]  # seconds


def load_series(path):
    """Return {column: [(elapsed_s, value)]} from coverage_PC_series.log."""
    series = {}
    columns = []
    first_tick = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                columns = line.removeprefix("# ").split("\t")
                continue
            parts = line.split("\t")
            if not columns or len(parts) != len(columns):
                continue
            tick = int(parts[0])
            if first_tick is None:
                first_tick = tick
            for index, name in enumerate(columns[1:], start=1):
                series.setdefault(name, []).append((tick - first_tick, int(parts[index])))
    return series


def main_series(series):
    """The headline metric is the all-execution distinct raw-PC set."""
    return series.get("all_pc", [])


def at(pts, sec):
    """distinct PC at-or-before `sec` (last point with elapsed <= sec)."""
    val = 0
    for e, t in pts:
        if e <= sec:
            val = t
        else:
            break
    return val


def summary_metric(path, *keys):
    try:
        s = json.load(open(path))
        fields = s.get("fields", s)
        for k in keys:
            if k in fields:
                return fields[k]
    except Exception:
        pass
    return None


rows = {}
for pol in POLICIES:
    base = f"/tmp/se_{pol}/out"
    coverage_log = f"{base}/coverage_PC_series.log"
    pts = main_series(load_series(coverage_log)) if glob.glob(coverage_log) else []
    rs = f"{base}/run_summary.json"
    rows[pol] = {
        "pts": pts,
        "final": pts[-1][1] if pts else 0,
        "dur": pts[-1][0] if pts else 0,
        "corpus": summary_metric(rs, "corpus"),
        "cov_unique": summary_metric(rs, "cov_unique"),
        "interesting": summary_metric(rs, "interesting"),
        "generated": summary_metric(rs, "generated"),
        "crash": summary_metric(rs, "crash"),
    }

# Table.
hdr = ["policy"] + [f"t={c}s" for c in CHECKPOINTS] + ["final", "dur_s", "corpus", "cov_unique", "interesting", "crash"]
print("\t".join(hdr))
for pol in POLICIES:
    r = rows[pol]
    cells = [pol] + [str(at(r["pts"], c)) for c in CHECKPOINTS]
    cells += [str(r["final"]), f"{r['dur']:.0f}", str(r["corpus"]), str(r["cov_unique"]),
              str(r["interesting"]), str(r["crash"])]
    print("\t".join(cells))

# Merged CSV for plotting (elapsed_sec grid @1s up to max dur).
maxdur = int(max((r["dur"] for r in rows.values()), default=0))
out_csv = "/tmp/se_compare.csv"
with open(out_csv, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["elapsed_sec"] + POLICIES)
    for sec in range(0, maxdur + 1, 5):
        w.writerow([sec] + [at(rows[p]["pts"], sec) for p in POLICIES])
print(f"\nmerged curve CSV -> {out_csv}")
