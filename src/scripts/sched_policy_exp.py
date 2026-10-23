#!/usr/bin/env python3
# Scheduling-policy experiment runner: run reFuzz once with a chosen selection
# policy (REFUZZ_SCHED_POLICY env), same candidate corpus / kernel profile /
# duration — vary ONLY the policy. Collects coverage metric logs + run_summary.json.
#
#   python3 scripts/sched_policy_exp.py <policy> <duration_seconds>
#
# Outputs under /tmp/se_<policy>/out/.  Run from the reFuzz repo root.
import glob, json, os, shutil, subprocess, sys

REPO = os.getcwd()
POLICY = sys.argv[1]
DURATION = int(sys.argv[2])
ROOT = f"/tmp/se_{POLICY}"
BIN = f"{REPO}/build-llvm20/control/orchestrator/refuzz"
FIXED = f"{REPO}/run/speed_compare/configs/refuzz.json"
SEED_CORPUS = f"{REPO}/run/speed_compare/corpus/refuzz"

shutil.rmtree(ROOT, ignore_errors=True)
for d in ("work", "ipc", "out"):
    os.makedirs(f"{ROOT}/{d}", exist_ok=True)
# Per-run corpus clone — admits persist back, must not pollute the canonical set
# or other policies' runs.
shutil.copytree(SEED_CORPUS, f"{ROOT}/corpus")

cfg = json.load(open(FIXED))
cfg["work_dir"] = f"{ROOT}/work"
cfg.setdefault("channel", {}).setdefault("transport", {})
cfg["channel"]["transport"]["ivshmem_path"] = f"{ROOT}/ipc/r.ivshmem"
cfg["channel"]["transport"]["doorbell_socket_path"] = f"{ROOT}/ipc/r.sock"
cfg.setdefault("persistence", {}).setdefault("corpus", {})
cfg["persistence"]["corpus"].update(enable=True, load_on_start=True, dir=f"{ROOT}/corpus")
cfg.setdefault("coverage", {}).setdefault("export", {})
cfg["coverage"]["export"].update(enabled=True)
# [config-selected scheduling policy] 经 config 的 fuzzer.scheduling_policy 选 policy
# (替代旧 REFUZZ_SCHED_POLICY env)。空串 = engine 默认 priority。
cfg.setdefault("fuzzer", {})["scheduling_policy"] = POLICY
cfg["phase1_run_limit_mode"] = "runtime"
cfg["phase1_runtime_seconds"] = DURATION
cfg_path = f"{ROOT}/config.json"
json.dump(cfg, open(cfg_path, "w"), indent=2)

timeout_s = DURATION + 150  # boot + drain margin
print(f"[{POLICY}] running {DURATION}s (timeout {timeout_s}s)...", flush=True)
with open(f"{ROOT}/run.log", "wb") as log:
    rc = subprocess.run(["timeout", str(timeout_s), BIN, cfg_path],
                        stdout=log, stderr=subprocess.STDOUT, cwd=REPO).returncode

# Collect artifacts (search the whole run tree — paths are auto under work_dir).
found = []
for pat in ("coverage_PC_series.log", "coverage_edge_series.log", "run_summary.json"):
    for f in glob.glob(f"{ROOT}/**/{pat}", recursive=True):
        dst = f"{ROOT}/out/{pat}"
        shutil.copy(f, dst)
        found.append(f)
print(f"[{POLICY}] rc={rc}  collected={found}", flush=True)
