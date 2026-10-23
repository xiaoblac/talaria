#!/usr/bin/env bash
# Session-local regression script — run after every §3.5 milestone to
# catch oracles that should still be green.
#
# Usage: bash tools/run_all_oracles.sh [milestone]
#   milestone: optional tag for the workdir (defaults to "tmp")
#
# Expects:
#   * /tmp/syzgen built (tools/syzgen build)
#   * build-llvm20/refuzz-syz-v2-{gen,mutate,validate,enum,text-batch,
#     exec-wire,exec-wire-roundtrip,wire-driver-smoke,exec-trace} built
#   * L3 corpus at /workspace/syzkaller/sys/linux/test
#
# Each section prints PASS or FAIL with the relevant counts. Set
# ORACLE_QUICK=1 to skip slower oracles (paired-VM, exec-trace).

set -uo pipefail
MILESTONE="${1:-tmp}"
ROOT="/workspace/talaria"
BUILD="${ROOT}/build-llvm20"
SYZGEN="/tmp/syzgen"
L3="/workspace/syzkaller/sys/linux/test"
WORK="/tmp/oracles-${MILESTONE}"
mkdir -p "${WORK}"

cd "${ROOT}" || exit 1
fail=0
pass=0

step() {
    local label="$1" outcome="$2" detail="$3"
    if [[ "${outcome}" == "ok" ]]; then
        printf '  %-44s PASS  %s\n' "${label}" "${detail}"
        pass=$((pass + 1))
    else
        printf '  %-44s FAIL  %s\n' "${label}" "${detail}"
        fail=$((fail + 1))
    fi
}

echo "=== schema (L1 enum diff) ==="
"${SYZGEN}" enum-dump -os linux -arch amd64 \
    -syzkaller-root /workspace/syzkaller > "${WORK}/go_enum.txt" 2>/dev/null
"${BUILD}/refuzz-syz-v2-enum" > "${WORK}/cpp_enum.txt" 2>/dev/null
if diff -q "${WORK}/go_enum.txt" "${WORK}/cpp_enum.txt" > /dev/null; then
    step "L1 enum diff" ok "byte-equal"
else
    step "L1 enum diff" fail "differ — see ${WORK}/{go,cpp}_enum.txt"
fi

echo "=== codec (L3 corpus round-trip) ==="
out=$("${SYZGEN}" corpus-roundtrip \
    -dir "${L3}" \
    -cpp-bin "${BUILD}/refuzz-syz-v2-text-batch" \
    -work "${WORK}/l3-rt" 2>&1 | tail -8)
# corpus-roundtrip writes C++ output under `${WORK}/l3-rt/cpp` and Go
# reference under `${WORK}/l3-rt/go`. The summary block prints
# `match%      : 100.0%  (of considered)` on success.
echo "${out}" | grep -qE "match%[[:space:]]*:[[:space:]]+100\.0%" && \
    step "L3 corpus round-trip" ok "$(echo "${out}" | grep 'match%' | head -1)" || \
    step "L3 corpus round-trip" fail "${out}"

echo "=== exec wire (§3.2/§3.3) ==="
mkdir -p "${WORK}/l3-exec"
# §3.2 takes the L3 corpus directly with default -filter-requires=true
# (syzkaller-equivalent oracle path). The L3 RT cpp output is a
# different artifact (codec roundtrip stability) and is not the input
# to §3.2 / §3.3.
out=$("${SYZGEN}" exec-wire-diff \
    -dir "${L3}" \
    -cpp-bin "${BUILD}/refuzz-syz-v2-exec-wire" \
    -work "${WORK}/l3-exec" 2>&1 | tail -3)
echo "${out}" | grep -qE "match=[0-9]+ .*mismatch=0" && \
    step "exec-wire byte-equal" ok "$(echo "${out}" | tail -1)" || \
    step "exec-wire byte-equal" fail "${out}"

out=$("${BUILD}/refuzz-syz-v2-exec-wire-roundtrip" "${L3}" 2>&1 | tail -1)
echo "${out}" | grep -qE "ok=[0-9]+ mismatch=0 (decode_fail|fail_decode_wire)=0" && \
    step "wire roundtrip" ok "${out}" || \
    step "wire roundtrip" fail "${out}"

out=$("${BUILD}/refuzz-syz-v2-wire-driver-smoke" "${L3}" 2>&1 | tail -1)
total=$(echo "${out}" | grep -oE "total=[0-9]+" | head -1 | cut -d= -f2)
if [[ -n "${total}" ]] && [[ "${total}" -gt 0 ]] && \
   echo "${out}" | grep -qE "count_mismatch=0 nr_mismatch=0 driver_err=0"; then
    step "wire-driver smoke" ok "${out}"
else
    step "wire-driver smoke" fail "${out}"
fi

if [[ "${ORACLE_QUICK:-0}" != "1" ]]; then
    echo "=== exec trace (§3.3 Layer-3 milestone I) ==="
    out=$("${SYZGEN}" exec-trace-diff \
        -dir "${L3}" \
        -cpp-bin "${BUILD}/refuzz-syz-v2-exec-trace" \
        -work "${WORK}/l3-trace" 2>&1 | tail -2)
    echo "${out}" | grep -qE "match=[0-9]+ mismatch=0" && \
        step "trace-equiv" ok "${out}" || \
        step "trace-equiv" fail "${out}"
fi

echo "=== choice table (§3.6) ==="
"${SYZGEN}" choice-ref -os linux -arch amd64 \
    -syzkaller-root /workspace/syzkaller \
    -unpinned -out "${WORK}/go-choice.json" > /dev/null 2>&1
"${BUILD}/refuzz-syz-v2-choice-ref" -out "${WORK}/cpp-choice.json" > /dev/null 2>&1
jq '.anchors' "${WORK}/go-choice.json"  > "${WORK}/go-anchors.json" 2>/dev/null
jq '.anchors' "${WORK}/cpp-choice.json" > "${WORK}/cpp-anchors.json" 2>/dev/null
if cmp -s "${WORK}/go-anchors.json" "${WORK}/cpp-anchors.json"; then
    step "choice-ref byte-equal" ok "$(jq -r '.anchors | length' "${WORK}/cpp-choice.json") anchors"
else
    step "choice-ref byte-equal" fail "diff at ${WORK}"
fi

echo "=== generation (§3.4) ==="
rm -rf "${WORK}/v2-gen"
out=$("${BUILD}/refuzz-syz-v2-gen" -outdir "${WORK}/v2-gen" -count 1000 -ncalls 2:8 -seed 12345 2>&1 | tail -1)
echo "${out}" | grep -qE "ok=1000 gen_or_encode_fail=0" && \
    step "gen 1000 progs" ok "${out}" || \
    step "gen 1000 progs" fail "${out}"

out=$("${BUILD}/refuzz-syz-v2-validate" "${WORK}/v2-gen" 2>&1 | tail -1)
echo "${out}" | grep -qE "validate_ok=1000 validate_fail=0" && \
    step "validate-on-generated" ok "${out}" || \
    step "validate-on-generated" fail "${out}"

out=$("${SYZGEN}" corpus-roundtrip \
    -dir "${WORK}/v2-gen" \
    -cpp-bin "${BUILD}/refuzz-syz-v2-text-batch" \
    -work "${WORK}/v2-gen-rt" -fixed-point 2>&1 | tail -3)
echo "${out}" | grep -qE "C\+\+ fixed-point : stable=1000 drift=0" && \
    step "text-RT-on-generated (C++ fp)" ok "$(echo "${out}" | grep 'C++ fixed-point')" || \
    step "text-RT-on-generated (C++ fp)" fail "${out}"

if [[ "${ORACLE_QUICK:-0}" != "1" ]]; then
    rm -rf "${WORK}/v2-gen-hist"
    out=$("${SYZGEN}" gen-histogram-diff -count 5000 -ncalls 5 \
        -cpp-bin "${BUILD}/refuzz-syz-v2-gen" -work "${WORK}/v2-gen-hist" 2>&1 | grep coverage | tail -1)
    cov=$(echo "${out}" | grep -oE "coverage=[0-9.]+" | head -1 | cut -d= -f2)
    if [[ -n "${cov}" ]] && awk "BEGIN{exit !(${cov} >= 0.80)}"; then
        step "histogram coverage (≥0.80)" ok "${out}"
    else
        step "histogram coverage (≥0.80)" fail "${out}"
    fi
fi

echo "=== mutation (§3.5) ==="
rm -rf "${WORK}/v2-mut"
out=$("${BUILD}/refuzz-syz-v2-mutate" \
    -indir "${L3}" \
    -outdir "${WORK}/v2-mut" \
    -count 100 -seed 1 -policy syz_v2_balanced 2>&1 | tail -1)
echo "${out}" | grep -qE "ok=100 mutate_empty=0" && \
    step "mutate 100 progs" ok "${out}" || \
    step "mutate 100 progs" fail "${out}"

out=$("${BUILD}/refuzz-syz-v2-validate" "${WORK}/v2-mut" 2>&1 | tail -1)
echo "${out}" | grep -qE "validate_fail=0" && \
    step "validate-on-mutated" ok "${out}" || \
    step "validate-on-mutated" fail "${out}"

# Per-op 1k smoke (§3.5 M1/M2/M3 single-op coverage). Runs are cheap;
# they catch a per-op regression even when balanced happens to skip it
# this seed.
for p in syz_v2_mutate_arg syz_v2_splice_heavy syz_v2_insert_call \
         syz_v2_remove_call syz_v2_squash_any; do
    rm -rf "${WORK}/v2-mut-${p}"
    out=$("${BUILD}/refuzz-syz-v2-mutate" \
        -indir "${L3}" \
        -outdir "${WORK}/v2-mut-${p}" \
        -count 1000 -seed 7 -policy "${p}" 2>&1 | tail -1)
    val=$("${BUILD}/refuzz-syz-v2-validate" "${WORK}/v2-mut-${p}" 2>&1 | tail -1)
    if echo "${out}" | grep -qE "ok=1000" && \
       echo "${val}" | grep -qE "validate_fail=0"; then
        step "single-op ${p} 1k" ok "${val}"
    else
        step "single-op ${p} 1k" fail "${val}"
    fi
done

# ──────────────────────────────────────────────────────────────
# §3.10 typed-program-pipeline oracles (#17 / #18 / #19 / #20)
# ──────────────────────────────────────────────────────────────
echo "=== typed pipeline (§3.10 #17-#20) ==="
for t in mutate_typed_codec_free_test smash_repeat_decode_count_test \
         corpus_v2_artifact_roundtrip_test serialize_for_exec_placement_test; do
    bin="${BUILD}/tests/${t}"
    if [[ ! -x "${bin}" ]]; then
        step "${t}" fail "binary not built (${bin})"
        continue
    fi
    out=$("${bin}" 2>&1 | tail -3)
    if echo "${out}" | grep -q "^ALL OK$"; then
        step "${t}" ok "$(echo "${out}" | grep -E 'oracle|after' | head -1)"
    else
        step "${t}" fail "${out}"
    fi
done

# ──────────────────────────────────────────────────────────────
# Epic 3 generation-completeness oracles (#26-#29 + USB coverage)
# ──────────────────────────────────────────────────────────────
echo "=== generation completeness (Epic 3 #26-#29) ==="

bin="${BUILD}/tests/resource_centric_test"
if [[ ! -x "${bin}" ]]; then
    step "oracle #29 resource_centric artifact-first" fail "binary not built (${bin})"
else
    out=$("${bin}" 2>&1)
    detail=$(echo "${out}" | grep 'resource_centric_payload_fallbacks=' | tail -1)
    if echo "${out}" | grep -q "^ALL OK$" && \
       echo "${detail}" | grep -q "resource_centric_payload_fallbacks=0"; then
        step "oracle #29 resource_centric artifact-first" ok "${detail}"
    else
        step "oracle #29 resource_centric artifact-first" fail "$(echo "${out}" | tail -6)"
    fi
fi

bin="${BUILD}/tests/special_type_manifest_test"
if [[ ! -x "${bin}" ]]; then
    step "oracle #28 SpecialType + USB coverage" fail "binary not built (${bin})"
else
    out=$("${bin}" 2>&1)
    manifest=$(echo "${out}" | grep 'produced=' | tail -1)
    usb=$(echo "${out}" | grep 'patched=' | tail -1)
    if echo "${out}" | grep -q "^ALL OK$" && \
       echo "${manifest}" | grep -q "produced=14 skipped=0 failed=0" && \
       echo "${usb}" | grep -qE "patched=[1-9][0-9]*"; then
        step "oracle #28 SpecialType + USB coverage" ok "${manifest}; ${usb}"
    else
        step "oracle #28 SpecialType + USB coverage" fail "$(echo "${out}" | tail -8)"
    fi
fi

if [[ "${ORACLE_QUICK:-0}" != "1" ]]; then
    bin="${BUILD}/tests/epic3_generation_oracle_test"
    if [[ ! -x "${bin}" ]]; then
        step "oracle #26 resource link rate" fail "binary not built (${bin})"
        step "oracle #27 anyres spoof" fail "binary not built (${bin})"
    else
        out=$("${bin}" --resource-link-rate 2>&1)
        if echo "${out}" | grep -q "^ALL OK$"; then
            step "oracle #26 resource link rate" ok "$(echo "${out}" | grep 'oracle #26' | tail -1)"
        else
            step "oracle #26 resource link rate" fail "${out}"
        fi
        out=$("${bin}" --anyres-spoof 2>&1)
        if echo "${out}" | grep -q "^ALL OK$"; then
            step "oracle #27 anyres spoof" ok "$(echo "${out}" | grep 'oracle #27' | tail -1)"
        else
            step "oracle #27 anyres spoof" fail "${out}"
        fi
    fi
fi

echo
echo "summary: PASS=${pass} FAIL=${fail}"
exit "${fail}"
