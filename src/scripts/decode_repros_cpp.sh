#!/usr/bin/env bash
# Decodes each corpus/<seed_id>/payload.bin.
#
# 最终只写一个文本文件(默认 ${REPROS_DIR}/decoded_corpus.log,可由第 2 参数覆盖):
#   前半段 — call_count 分布统计;
#   后半段 — 逐条 corpus 解码正文(与原先 decoded 报告体相同)。
#
# [v1 — Python decode_prog.py: ROLLBACK 时 export REFUZZ_DECODE_USE_PYTHON=1]
#   Python 端自己重建 syscall 表 + 自实现 binary header unpack,有 schema 漂移风险;
#   canonical text 走启发式判断,fail 时只能 raise "unrecognized program format",
#   不打 hex / 不区分 v1 wire / corrupt / 非 canonical。
# [v2 — refuzz-syz-v2-corpus-dump (默认):]
#   走 fuzzer 同源 syz::TextDecoder(target_, kNonStrict),与 CorpusDiskIO::SaveSeed
#   写盘端完全同源;失败时打 payload_len + hex_head_16/64 + decoder line/col。
#   工具 build 不出来时自动回退到 Python(测试机 / 未编译 build dir)。
set -euo pipefail

# 把 call_count 统计写在开头,后面接完整解码正文(raw 解码工具/Python 循环的原始输出)。
finalize_decoded_report() {
  local raw_body="$1"
  local final_out="$2"
  local repros_dir="$3"

  if [[ ! -f "${raw_body}" ]]; then
    echo "[decode_repros_cpp.sh] finalize: missing raw decode body: ${raw_body}" >&2
    return 1
  fi
  local n
  n="$(grep -c '^call_count:' "${raw_body}" 2>/dev/null || true)"
  {
    echo "# =============================================================================="
    echo "# corpus call_count 统计 (syscall 条数 → 该条数下的 corpus 条目数)"
    echo "# generated_at: $(date -Iseconds)"
    echo "# corpus_dir: ${repros_dir}"
    echo "# total_entries: ${n}"
    echo "# =============================================================================="
    echo ""
    if [[ "${n}" -gt 0 ]]; then
      echo "# 列: call_count	corpus条目数"
      grep '^call_count:' "${raw_body}" | sed 's/call_count: //' | sort -n | uniq -c |
        awk '{ printf "%d\t%d\n", $2, $1 }'
    else
      echo "# (无 call_count 行,跳过分布表)"
    fi
    echo ""
    echo "# =============================================================================="
    echo "# 解码正文"
    echo "# =============================================================================="
    echo ""
    cat "${raw_body}"
  } > "${final_out}"
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DECODE_PROG_PY="${REPO_ROOT}/tools/decode_prog.py"
DEFAULT_REPROS_DIR="${REPO_ROOT}/run/state/corpus"

REPROS_DIR="${1:-${DEFAULT_REPROS_DIR}}"
OUTPUT_PATH="${2:-${REPROS_DIR}/decoded_corpus.log}"

if [[ ! -d "${REPROS_DIR}" ]]; then
  echo "[decode_repros_cpp.sh] repros dir not found: ${REPROS_DIR}" >&2
  exit 1
fi

# v2 路径优先:在常见 build dir 里找 refuzz-syz-v2-corpus-dump。
CPP_DUMPER=""
for candidate in \
    "${REPO_ROOT}/build-llvm20/refuzz-syz-v2-corpus-dump" \
    "${REPO_ROOT}/build/refuzz-syz-v2-corpus-dump" \
    "${REPO_ROOT}/build-llvm20/bin/refuzz-syz-v2-corpus-dump" \
    "${REPO_ROOT}/build/bin/refuzz-syz-v2-corpus-dump"; do
  if [[ -x "${candidate}" ]]; then
    CPP_DUMPER="${candidate}"
    break
  fi
done

if [[ -n "${CPP_DUMPER}" && "${REFUZZ_DECODE_USE_PYTHON:-0}" != "1" ]]; then
  echo "[decode_repros_cpp.sh] using C++ dumper: ${CPP_DUMPER}"
  TMP_RAW="$(mktemp "${OUTPUT_PATH}.raw.XXXXXX")"
  trap 'rm -f "${TMP_RAW}"' EXIT
  "${CPP_DUMPER}" "${REPROS_DIR}" "${TMP_RAW}"
  finalize_decoded_report "${TMP_RAW}" "${OUTPUT_PATH}" "${REPROS_DIR}"
  trap - EXIT
  rm -f "${TMP_RAW}"
  echo "[decode_repros_cpp.sh] wrote stats + decode to ${OUTPUT_PATH}"
  exit 0
fi

# v1 fallback:Python decode_prog.py 路径(C++ 工具不存在或显式回退)。
if [[ ! -f "${DECODE_PROG_PY}" ]]; then
  echo "[decode_repros_cpp.sh] missing decoder script: ${DECODE_PROG_PY}" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[decode_repros_cpp.sh] python3 not found on PATH" >&2
  exit 2
fi

extract_field() {
  local report_path="$1"
  local key="$2"
  if [[ ! -f "${report_path}" ]]; then
    return 0
  fi
  sed -n "s/^${key}: //p" "${report_path}" | head -n 1
}

decode_calls() {
  local program_path="$1"
  if [[ ! -f "${program_path}" ]]; then
    echo "missing program: ${program_path}"
    return 0
  fi

  local decoded
  if ! decoded="$(python3 "${DECODE_PROG_PY}" "${program_path}" 2>&1)"; then
    echo "decode failed: ${program_path}"
    echo "${decoded}"
    return 0
  fi

  if ! printf '%s\n' "${decoded}" | sed -n '/^call_count:/,$p'; then
    printf '%s\n' "${decoded}"
  fi
}

mapfile -t CORPUS_DIRS < <(
  find "${REPROS_DIR}" -mindepth 1 -maxdepth 1 -type d | sort -V
)

if [[ "${#CORPUS_DIRS[@]}" -eq 0 ]]; then
  echo "[decode_repros_cpp.sh] no corpus directories found in ${REPROS_DIR}" >&2
  exit 1
fi

TMP_OUTPUT="$(mktemp "${OUTPUT_PATH}.tmp.XXXXXX")"
trap 'rm -f "${TMP_OUTPUT}"' EXIT

{
  echo "decode_corpus_cpp report"
  echo "generated_at: $(date -Iseconds)"
  echo "corpus_dir: ${REPROS_DIR}"
  echo "count: ${#CORPUS_DIRS[@]}"
  echo
} > "${TMP_OUTPUT}"

for corpus_dir in "${CORPUS_DIRS[@]}"; do
  corpus_name="$(basename "${corpus_dir}")"
  payload_path="${corpus_dir}/payload.bin"

  {
    echo "================================================================================"
    echo "corpus_id: ${corpus_name}"
    echo "path: ${corpus_dir}"
    echo
    echo "[syscalls]"
    if [[ -f "${payload_path}" ]]; then
      echo "program: ${payload_path}"
      decode_calls "${payload_path}"
    else
      echo "missing payload.bin"
    fi
    echo
  } >> "${TMP_OUTPUT}"
done

finalize_decoded_report "${TMP_OUTPUT}" "${OUTPUT_PATH}" "${REPROS_DIR}"
trap - EXIT
rm -f "${TMP_OUTPUT}"

echo "[decode_repros_cpp.sh] wrote stats + ${#CORPUS_DIRS[@]} corpus entries to ${OUTPUT_PATH}"
