#!/bin/bash
# Copyright 2026 reFuzz project author -------youngkk.
# Full-target S/P/R fact sweep: run ir_defuse --gates (GATE facts) + default (WRITE facts, with S)
# over every regenerated clang-KASAN .ll, in parallel, into all_gates.tsv / all_writes.tsv. Per-TU
# temp files avoid append races. Feeds ../model/gate_value.py for the all-syscall read-out.
set -u
OUT=/workspace/syzkaller/kernel/build-kasan-clang
SH=/workspace/talaria/run/seed_horizon
IRD=$SH/ir_defuse
TMP=$SH/sweep_tmp
P=${1:-8}
rm -rf "$TMP"; mkdir -p "$TMP"

sweep() {
  local ll="$OUT/$1"; [ -f "$ll" ] || return
  local id; id=$(echo "$1" | tr '/' '_')
  "$IRD" --gates "$ll" 2>/dev/null | grep '^GATE' > "$TMP/$id.gate"
  "$IRD" "$ll" 2>/dev/null | grep -P '^WRITE\t' > "$TMP/$id.write"
}
export -f sweep; export OUT IRD TMP

n=$(wc -l < "$SH/lllist.txt")
echo "sweeping $n .ll with -P$P (ir_defuse --gates + default each) ..."
xargs -a "$SH/lllist.txt" -P"$P" -I{} bash -c 'sweep "$@"' _ {}
cat "$TMP"/*.gate > "$SH/all_gates.tsv" 2>/dev/null
cat "$TMP"/*.write > "$SH/all_writes.tsv" 2>/dev/null
echo "GATE=$(wc -l < "$SH/all_gates.tsv") WRITE=$(wc -l < "$SH/all_writes.tsv")"

# fptr-install is CROSS-TU (install in one TU, dispatch in another → the per-TU .ll sweep sees neither both
# sides nor the full resolved-callee set R). Supplement from the linked kernel .bc batches: append their
# fptr facts (dispatch GATEs + fptr-install WRITEs). Duplicates with the .ll sweep dedupe in gate_value
# (gates by max value, writers by set).
bcfptr() {
  local bc="$1"; [ -f "$bc" ] || return
  local id; id=$(basename "$bc" .bc)
  "$IRD" --gates "$bc" 2>/dev/null | grep -P '\tdispatch$' > "$TMP/$id.bcgate"
  "$IRD" "$bc" 2>/dev/null | grep -P '\tfptr-install\tfptr$' > "$TMP/$id.bcwrite"
}
export -f bcfptr
nbc=$(find "$SH/kernel_linked" -type f -name '*.bc' 2>/dev/null | wc -l)
echo "supplementing fptr from $nbc .bc (cross-TU) ..."
find "$SH/kernel_linked" -type f -name '*.bc' -print0 2>/dev/null | xargs -0 -P"$P" -I{} bash -c 'bcfptr "$@"' _ {}
cat "$TMP"/*.bcgate >> "$SH/all_gates.tsv" 2>/dev/null
cat "$TMP"/*.bcwrite >> "$SH/all_writes.tsv" 2>/dev/null
echo "  +fptr(bc): GATE=$(wc -l < "$SH/all_gates.tsv") WRITE=$(wc -l < "$SH/all_writes.tsv")  dispatch=$(grep -Pc '\tdispatch$' "$SH/all_gates.tsv") install=$(grep -Pc '\tfptr-install\tfptr$' "$SH/all_writes.tsv")"
rm -rf "$TMP"
