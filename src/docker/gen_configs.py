#!/usr/bin/env python3
"""gen_configs.py — 从本机那两份基线配置生成 3 个内核 × 2 侧 = 6 份容器内配置。

基线（CLAUDE.md 指定 + 用户指定）:
    run/speed_compare/configs/refuzz_mabB.json
    run/speed_compare/configs/syz_6proc.json

只改路径和内核，其余字段逐字保留 —— 这是刻意的。n_workers=6 ↔ procs=6 的对等、
性能采样全关、cover_edges/raw_pc、超时常数，这些都已经在基线里调好了，重写一遍
只会引入分歧。要改基线就去改基线，不要在生成器里打补丁。

生成时不碰的字段（speed_compare.py 运行时会覆盖，写了也白写）:
    refuzz: work_dir, channel.transport.ivshmem_path/doorbell_socket_path,
            phase1_runtime_seconds, coverage.export.*（含 --coverage-domains 注入的）
    syz:    workdir, http, preserve_corpus, disable_syscalls, vm.qemu_args
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

KERNELS = ["v6.12", "v6.18", "v7.1"]

# 容器内布局。和本地同构，只是前缀不同，所以路径替换是纯字符串级的。
C_ART = "/opt/artifacts"
C_REFUZZ = f"{C_ART}/refuzz"
C_SYZ = f"{C_ART}/syzkaller"
C_IMAGES = f"{C_ART}/images"
C_KERNELS = f"{C_ART}/kernels"


def load(p: Path) -> dict:
    with p.open(encoding="utf-8") as f:
        return json.load(f)


def dump(obj: dict, p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def nested(d: dict, *keys: str) -> dict:
    cur = d
    for k in keys:
        nxt = cur.get(k)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[k] = nxt
        cur = nxt
    return cur


def make_refuzz(base: dict, tag: str) -> dict:
    cfg = json.loads(json.dumps(base))  # 深拷贝，别让三个 tag 共享子对象

    vm = nested(cfg, "channel", "vm")
    vm["kernel"] = f"{C_KERNELS}/{tag}/bzImage"
    vm["image"] = f"{C_IMAGES}/refuzz_rootfs.img"
    vm["ssh_key"] = f"{C_IMAGES}/bookworm.id_rsa"

    # phase0_worker_bin 是 guest 里跑的 worker，路径在宿主侧被读取后注入。
    cfg["phase0_worker_bin"] = (
        f"{C_REFUZZ}/build-llvm20/executor/channel/worker/ivshmem_worker")

    # repro.vmlinux_path 是**不被 speed_compare 覆盖的**，基线里它指向本机的
    # build-kasan-clang。留着的话容器里就是一条死路径 —— 覆盖率实验不跑 repro
    # (reproduce=false)，但配置解析阶段可能校验它存在。指向本 tag 的 vmlinux。
    nested(cfg, "repro")["vmlinux_path"] = f"{C_KERNELS}/{tag}/vmlinux"

    # 下面三个都会被 make_refuzz_config() 在运行时覆盖（work_dir → short_root/work，
    # corpus.dir → --seed-corpus，corpus_pc_path → short_root/corpus_pc.txt）。
    # 改成容器内路径不是为了生效，是为了这份 JSON 单独看时不含宿主机路径 ——
    # 一份配置里混着两台机器的路径，出问题时最难排查。
    cfg["work_dir"] = "/results/refuzz_work"
    nested(cfg, "persistence", "corpus")["dir"] = "/results/refuzz_corpus"
    nested(cfg, "coverage", "export")["corpus_pc_path"] = "/tmp/refuzz_corpus_pc.txt"

    return cfg


def make_syz(base: dict, tag: str) -> dict:
    cfg = json.loads(json.dumps(base))

    kdir = f"{C_KERNELS}/{tag}"
    # kernel_obj 要能找到 vmlinux（syz 符号化用）。不需要整个 16G 构建树 ——
    # 我们只放了 vmlinux + bzImage + kernel.config 进去。
    cfg["kernel_obj"] = kdir
    cfg["kernel_src"] = kdir
    cfg["image"] = f"{C_IMAGES}/syz_rootfs.img"
    cfg["sshkey"] = f"{C_IMAGES}/bookworm.id_rsa"
    cfg["syzkaller"] = C_SYZ

    vm = nested(cfg, "vm")
    vm["kernel"] = f"{kdir}/bzImage"

    # qemu_args 删键：syzkaller 从 arch 默认 seed 之后再 unmarshal JSON 覆盖，
    # 设了这个键就是**替换**而非扩展。基线里那串带
    #   -chardev file,...syz_perf_serial.log,append=on -serial chardev:tlchr
    # 是性能采样时抓 guest 串口用的，覆盖率实验要关采样，而且 48h 下 append 模式
    # 会无界增长。删掉键之后 speed_compare.py:969 走
    #   SYZ_QEMU_ARGS_AMD64_DEFAULT = "-enable-kvm -cpu host,migratable=off"
    # 与原值的前半段逐字相同，并会自动补一个截断模式的 -serial file:（VM 重启即
    # 覆盖，不会涨）。少一处重复定义，也不会漏掉 -enable-kvm（:980 有护栏）。
    vm.pop("qemu_args", None)

    # workdir / http 由 speed_compare.py 按 run_id 注入，这里的值不生效；
    # 写成容器内路径只是让这份配置单独可读。
    cfg["workdir"] = "/results/syz_work"

    return cfg


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--refuzz-base", type=Path,
                    default=Path("run/speed_compare/configs/refuzz_mabB.json"))
    ap.add_argument("--syz-base", type=Path,
                    default=Path("run/speed_compare/configs/syz_6proc.json"))
    ap.add_argument("--out", type=Path, required=True,
                    help="输出目录，会被 Dockerfile 收成 /opt/configs")
    args = ap.parse_args()

    rbase = load(args.refuzz_base)
    sbase = load(args.syz_base)

    # 基线体检：这几个值错了，48h 跑完才发现就太晚。校验而不是纠正 —— 基线是
    # 唯一真源，生成器只做路径替换。
    kcov = rbase.get("coverage", {}).get("kcov", {})
    if not kcov.get("cover_edges"):
        raise SystemExit("refuzz 基线 coverage.kcov.cover_edges 不是 true —— "
                         "corpus_signal/all_signal 就不是边集了")
    if not kcov.get("raw_pc"):
        raise SystemExit("refuzz 基线 coverage.kcov.raw_pc 不是 true")
    if rbase.get("fuzzer", {}).get("worker_perf", {}).get("enable"):
        raise SystemExit("refuzz 基线开着 worker_perf —— 覆盖率实验要关性能采样")
    if not rbase.get("fuzzer", {}).get("worker_log", {}).get("enable"):
        raise SystemExit("refuzz 基线 worker_log 不是 true —— 当前诊断实验需要 worker 日志")
    if rbase.get("telemetry", {}).get("logging", {}).get("hot_path_sample_rate"):
        raise SystemExit("refuzz 基线 hot_path_sample_rate 非 0")

    if sbase.get("reproduce"):
        raise SystemExit("syz 基线 reproduce=true —— 会抽走 VM 跑 repro，污染覆盖率曲线")
    for key in ("cover", "raw_cover"):
        if not sbase.get(key):
            raise SystemExit(f"syz 基线 {key} 不是 true")

    for tag in KERNELS:
        dump(make_refuzz(rbase, tag), args.out / f"refuzz_{tag}.json")
        dump(make_syz(sbase, tag), args.out / f"syz_{tag}.json")
        print(f"  {tag}: refuzz_{tag}.json + syz_{tag}.json")

    print(f"6 份配置 → {args.out}")
    n_workers = rbase.get("channel", {}).get("transport", {}).get("n_workers")
    procs = sbase.get("procs")
    print(f"并发配置: refuzz n_workers={n_workers} ↔ syz procs={procs} "
          f"(饱和对等: {n_workers}x28.5% ≈ {procs}x30.3% ≈ 2 vCPU)")


if __name__ == "__main__":
    main()
