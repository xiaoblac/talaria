#!/usr/bin/env bash
# collect.sh — 48h 跑完后清点 9 个 run，出三张聚合图。
#
# 用法: collect.sh [results_dir] [out_dir]
#
# 先清点再画图: 9 个容器无人值守跑 48h，必然有可能某个中途挂了。把"哪些 run
# 完整、哪些没有"明确列出来，比直接画一张少了一条 run 的图要好 —— 后者看起来
# 和 n=3 的图一模一样。
set -euo pipefail

RESULTS="${1:-$HOME/chengyongkang/cov-results}"
OUTDIR="${2:-$RESULTS/figures}"
KERNELS=(v6.12 v6.18 v7.1)
PLOT="${PLOT:-scripts/speed_compare/plot_cov_runs.py}"

die() { echo "collect: $*" >&2; exit 1; }
[[ -d "$RESULTS" ]] || die "$RESULTS 不存在"
[[ -f "$PLOT" ]] || die "找不到 $PLOT（从 reFuzz 根目录跑）"

mkdir -p "$OUTDIR"

echo "=============================================================="
echo "清点 $RESULTS"
echo "=============================================================="
printf '%-14s %-6s %-9s %-8s %s\n' RUN STATUS EXIT CSVs 时长
total_ok=0
for k in "${KERNELS[@]}"; do
    for r in 1 2 3; do
        d="$RESULTS/${k}-r${r}"
        [[ -d "$d" ]] || { printf '%-14s %s\n' "${k}-r${r}" "目录不存在"; continue; }
        st=$(grep -m1 '^status=' "$d/RUN.txt" 2>/dev/null | cut -d= -f2 || echo "?")
        ec=$(grep -m1 '^exit_code=' "$d/RUN.txt" 2>/dev/null | cut -d= -f2 || echo "?")
        n=$(find "$d" -maxdepth 1 -name 'D_cov_*.csv' 2>/dev/null | wc -l)
        s0=$(grep -m1 '^started_utc=' "$d/RUN.txt" 2>/dev/null | cut -d= -f2 || echo "")
        s1=$(grep -m1 '^finished_utc=' "$d/RUN.txt" 2>/dev/null | cut -d= -f2 || echo "")
        dur="?"
        if [[ -n "$s0" && -n "$s1" ]]; then
            dur=$(( ( $(date -u -d "$s1" +%s) - $(date -u -d "$s0" +%s) ) / 3600 ))h
        elif [[ -z "$s1" ]]; then
            dur="未结束"
        fi
        printf '%-14s %-6s %-9s %-8s %s\n' "${k}-r${r}" "${st:-?}" "$ec" "$n" "$dur"
        [[ "$st" == "complete" && "$n" -gt 0 ]] && total_ok=$(( total_ok + 1 ))
    done
done
echo
echo "完整可用: $total_ok / 9"
[[ $total_ok -gt 0 ]] || die "没有可用 run"

# ── 出图: 每个内核 × 每个 domain ──────────────────────────────────────────
echo
echo "=============================================================="
echo "出图 → $OUTDIR"
echo "=============================================================="
for k in "${KERNELS[@]}"; do
    dirs=()
    for r in 1 2 3; do
        d="$RESULTS/${k}-r${r}"
        st=$(grep -m1 '^status=' "$d/RUN.txt" 2>/dev/null | cut -d= -f2 || echo "")
        [[ "$st" == "complete" ]] && dirs+=("$d")
    done
    if [[ ${#dirs[@]} -eq 0 ]]; then
        echo "[$k] 没有完整 run，跳过"
        continue
    fi
    [[ ${#dirs[@]} -lt 3 ]] && \
        echo "[$k] 警告: 只有 ${#dirs[@]}/3 次 run —— 图上的 n= 会如实反映"

    # corpus = PC 视图，edge = 边视图。两个都出，论文里选一个做主图、
    # 另一个进附录。edge 那份依赖 --coverage-domains（已在 entrypoint 里开）。
    for tag in corpus edge; do
        if ! ls "${dirs[0]}"/D_cov_${tag}_run_*.csv >/dev/null 2>&1; then
            echo "[$k/$tag] 无数据，跳过"
            continue
        fi
        python3 "$PLOT" --run-dir "${dirs[@]}" \
            --kernel "$k" --tag "$tag" \
            --out "$OUTDIR/coverage_${k}_${tag}.png" \
            --csv-out "$OUTDIR/coverage_${k}_${tag}.csv" \
            2>&1 | sed "s/^/[$k\/$tag] /"
    done
done

# 身份卡汇总: 三张图各自跑在什么内核、什么二进制上，集中一份好写论文。
{
    echo "# 覆盖率实验汇总"
    echo
    echo "生成于 $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "完整 run: $total_ok / 9"
    echo
    for k in "${KERNELS[@]}"; do
        echo "## $k"
        echo '```'
        cat "$RESULTS/${k}-r1/RUN.txt" 2>/dev/null || echo "(缺 RUN.txt)"
        echo '```'
        echo
    done
} > "$OUTDIR/SUMMARY.md"

echo
echo "图和聚合 CSV 在 $OUTDIR"
ls -1 "$OUTDIR" | sed 's/^/  /'
