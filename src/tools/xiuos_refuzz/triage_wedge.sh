#!/usr/bin/env bash
# triage_wedge.sh <wedge_dir>
#
# Replays one archived wedge against XiUOS with QEMU gdbstub enabled, then
# (after the wedge timeout) attaches gdb, reads the trap CSRs $mepc/$mcause,
# addr2line-symbolizes $mepc, and infers the class. Using $mepc/$mcause (not
# the old sp+8 saved_ra heuristic) makes it correct for store/AMO faults too.
#
# Classification uses the LEAF ($mepc) AND the CALLER (saved ra from the trap
# frame), because shared list helpers fault for several distinct bugs. Fault
# kind ($mcause) is reported but is NOT a class discriminator — Class A faults
# as load OR store depending on the uninitialized node's contents.
#
#   - BigMemFree                                 → CLASS_B  (heap coalesce)
#   - _StartRun / KTimerStartRun (leaf)          → CLASS_A2 (sortlist re-insert)
#   - KTaskSetDelay (leaf)                       → CLASS_F  (delay-list dangling)
#   - _Delete / KDeleteTimer (leaf)              → CLASS_A
#   - DoubleLinkListRmNode/Insert leaf, by CALLER:
#       _Delete/KDeleteTimer    → CLASS_A   (softtimer delete, uninit sortlist)
#       _StartRun/KTimerStartRun→ CLASS_A2  (double-start sortlist)
#       CheckTimerList          → CLASS_TIMER_FIRE (timer-fire dispatch path)
#       _KTaskWakeup/WakeupWqueue→ CLASS_WAKEUP_UAF (freed TaskDescriptor wakeup:
#                                  waitqueue stale node OR WorkSubmit freed queue)
#       (no caller recovered)   → UNKNOWN_LIST_<faultkind>
#   - KTaskWakeup / _KTaskWakeup (leaf)          → CLASS_WAKEUP_UAF
#   - mcause interrupt bit set (not a fault)     → LIVELOCK (hang, retry/gdb)
#   - anything else                              → UNKNOWN
#
# fault kind (mcause low bits): 5=load, 7=store/AMO, 1=ifetch, 2=illegal.
#
# Requires: build-llvm20/tests/xiuos_archive_replay_smoke, riscv-none-elf-gdb,
# riscv-none-elf-addr2line in PATH, ELF at $XIUOS_VIRT_RV32_ELF.

set -euo pipefail

WEDGE_DIR="${1:-}"
if [[ -z "${WEDGE_DIR}" || ! -d "${WEDGE_DIR}" ]]; then
    echo "usage: $0 <wedge_dir>" >&2
    exit 2
fi

ELF="${XIUOS_VIRT_RV32_ELF:-/workspace/xiuos-work/xiuos/Ubiquitous/XiZi_IIoT_Macro/build/XiZi-virt-rv32.elf}"
REPLAY_BIN="${REPLAY_BIN:-./build-llvm20/tests/xiuos_archive_replay_smoke}"
GDB_PORT="${GDB_PORT:-12345}"
UART_PORT="${UART_PORT:-33099}"
RV_TOOLCHAIN="${RV_TOOLCHAIN:-/opt/xpack-riscv-none-elf-gcc-15.2.0-1/bin}"
GDB="${GDB:-${RV_TOOLCHAIN}/riscv-none-elf-gdb}"
ADDR2LINE="${ADDR2LINE:-${RV_TOOLCHAIN}/riscv-none-elf-addr2line}"

[[ -x "${REPLAY_BIN}" ]] || { echo "replay binary missing: ${REPLAY_BIN}" >&2; exit 2; }
[[ -f "${ELF}"        ]] || { echo "ELF missing: ${ELF}" >&2; exit 2; }
[[ -x "${GDB}"        ]] || { echo "${GDB} not executable" >&2; exit 2; }
[[ -x "${ADDR2LINE}" ]] || { echo "${ADDR2LINE} not executable" >&2; exit 2; }

# Run replay in background; on wedge it'll spin 8s then exit.
LOG=$(mktemp)
trap 'rm -f "${LOG}"' EXIT

XIUOS_REPLAY_DIRS="${WEDGE_DIR}" \
  XIUOS_PORT="${UART_PORT}" \
  XIUOS_VIRT_RV32_ELF="${ELF}" \
  XIUOS_QEMU_GDBSTUB="${GDB_PORT}" \
  "${REPLAY_BIN}" > "${LOG}" 2>&1 &
REPLAY_PID=$!

# Wait for the replay binary to actually start QEMU + reach the wedge state.
# We'd ideally poll for WEDGE in log, but it appears after the 8s timeout —
# we attach gdb a bit earlier (5s) so we're alive when the trap is in
# HandleTrap busy loop.
sleep 5

# Read the trap CSRs directly. $mepc is the faulting instruction PC and
# $mcause its cause — both reliable for ANY fault type while the CPU spins
# in HandleTrap. The old sp+8 "saved_ra" heuristic only matched the
# load-fault frame layout and read garbage for store/AMO faults (e.g. the
# WorkSubmit-delayed write-UAF), mislabeling them UNKNOWN. We keep sp+8 as a
# secondary cross-check only.
# Besides $mepc/$mcause, recover the CALLER of the faulting leaf. XiUOS'
# save_hw_context builds a trap frame ([0]=mepc, [4]=ra, [8]=mstatus, ...)
# on the faulting task's stack. We locate it by scanning RAM for a word
# equal to $mepc whose [+4] is a kernel code address — that [+4] is the
# saved ra = the caller. (The HandleTrap arg-copy also holds mepc but its
# [+4] is the small mcause int, so the code-address test rejects it.)
# Caller frame is decisive where the leaf is shared, e.g. DoubleLinkListRmNode
# is reached from softtimer _Delete (Class A), _StartRun (A2), CheckTimerList
# (timer-fire), and _KTaskWakeup (write-UAF) — same leaf, different bug.
# gdb command file: multi-line while/if (the trap-frame scan) only parses
# correctly from a script file, not from a single -ex.
GDB_CMDS=$(mktemp)
cat > "${GDB_CMDS}" <<'GDBEOF'
set pagination off
echo === REGS ===\n
info registers pc sp ra
echo === MEPC ===\n
p/x $mepc
echo === MCAUSE ===\n
p/x $mcause
echo === SP+8 ===\n
x/1xw $sp+8
echo === CALLER SCAN ===\n
set $a = 0x80018000
while $a < 0x80030000
  if *(unsigned int *)$a == $mepc
    set $r = *(unsigned int *)($a + 4)
    if $r >= 0x80000000 && $r < 0x80030000
      printf "CALLER_RA 0x%x at_frame 0x%x\n", $r, $a
    end
  end
  set $a = $a + 4
end
detach
GDBEOF
GDB_OUT=$("${GDB}" -batch -nx \
    -ex "target remote :${GDB_PORT}" \
    -x "${GDB_CMDS}" \
    "${ELF}" 2>&1 || true)
rm -f "${GDB_CMDS}"

# Wait for replay to finish (will exit on its own after timeout).
wait "${REPLAY_PID}" 2>/dev/null || true

echo "--- replay log tail ---"
tail -5 "${LOG}"
echo "--- gdb output ---"
echo "${GDB_OUT}"

# Parse $mepc (faulting PC) and $mcause from their `$N = 0x...` lines.
FAULT_PC=$(echo "${GDB_OUT}" | sed -n '/=== MEPC ===/,/=== MCAUSE ===/p' \
            | grep -oE '0x[0-9a-fA-F]+' | tail -1)
MCAUSE=$(echo "${GDB_OUT}" | sed -n '/=== MCAUSE ===/,/=== SP+8 ===/p' \
            | grep -oE '0x[0-9a-fA-F]+' | tail -1)
SAVED_RA=$(echo "${GDB_OUT}" | sed -n '/=== SP+8 ===/,$p' \
            | grep -oE '0x[0-9a-fA-F]{8}' | tail -1)

if [[ -z "${FAULT_PC}" || -z "${MCAUSE}" ]]; then
    echo "TRIAGE_RESULT class=UNKNOWN reason=no_mepc_parsed saved_ra=${SAVED_RA:-none}"
    exit 0
fi

# If mcause bit 31 is set the sample caught an INTERRUPT, not an exception —
# the CPU is NOT spinning in HandleTrap after a fault. That means this wedge
# is a livelock / hang (worker alive but not progressing, e.g. a runaway
# high-prio task or repeated non-fatal faults) rather than a clean fault.
# A single mepc sample can't classify it; report so + suggest manual gdb.
if (( (MCAUSE >> 31) & 1 )); then
    echo "TRIAGE_RESULT class=LIVELOCK fault=interrupt mepc=${FAULT_PC} mcause=${MCAUSE} note=sampled_in_interrupt_not_fault_retry_or_gdb saved_ra=${SAVED_RA:-none}"
    exit 0
fi

# Decode mcause low bits (exception code). RISC-V exception
# codes: 5 = load access fault, 7 = store/AMO access fault, 1 = instr
# access, 2 = illegal instr, 4 = load misaligned, 6 = store misaligned.
MC_LOW=$(( MCAUSE & 0xf ))
case "${MC_LOW}" in
    5) FAULT_KIND="load"  ;;
    7) FAULT_KIND="store" ;;
    1) FAULT_KIND="ifetch" ;;
    2) FAULT_KIND="illegal" ;;
    4) FAULT_KIND="load_misaligned" ;;
    6) FAULT_KIND="store_misaligned" ;;
    *) FAULT_KIND="cause${MC_LOW}" ;;
esac

# Leaf symbol (faulting instruction).
SYM=$("${ADDR2LINE}" -e "${ELF}" -f -C "${FAULT_PC}" 2>&1 | head -2 || true)
FUNC=$(echo "${SYM}" | head -1)
FILE=$(echo "${SYM}" | tail -1)

# Caller symbol (saved ra from the trap frame). The scan may print several
# CALLER_RA lines (e.g. recursive list helpers); take the first whose
# symbol is NOT the leaf itself, so we get the real caller one level up.
CALLER_FUNC="?"
CALLER_RA="none"
while read -r cra; do
    [[ -z "${cra}" ]] && continue
    cf=$("${ADDR2LINE}" -e "${ELF}" -f -C "${cra}" 2>&1 | head -1 || true)
    if [[ "${cf}" != "${FUNC}" && "${cf}" != "??" ]]; then
        CALLER_RA="${cra}"; CALLER_FUNC="${cf}"; break
    fi
done < <(echo "${GDB_OUT}" | sed -n '/=== CALLER SCAN ===/,$p' \
            | grep -oE 'CALLER_RA 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+')

# Classify by (leaf, caller). The caller is decisive when the leaf is a
# shared list helper. Fall back to leaf-only when no caller was recovered.
CLASS="UNKNOWN"
case "${FUNC}" in
    BigMemFree*)                CLASS="CLASS_B"  ;;
    _StartRun*|KTimerStartRun*) CLASS="CLASS_A2" ;;
    KTaskSetDelay*)             CLASS="CLASS_F"  ;;
    _Delete*|KDeleteTimer*)     CLASS="CLASS_A"  ;;
    DoubleLinkListRmNode*|DoubleLinkListInsert*)
        # Shared list helper — decide by caller.
        case "${CALLER_FUNC}" in
            _Delete*|KDeleteTimer*)        CLASS="CLASS_A"  ;;  # softtimer delete on uninit sortlist
            _StartRun*|KTimerStartRun*)    CLASS="CLASS_A2" ;;  # double-start sortlist
            CheckTimerList*)               CLASS="CLASS_TIMER_FIRE" ;; # fire-path list op
            KTaskSetDelay*|KTaskUnSetDelay*) CLASS="CLASS_F" ;;
            _KTaskWakeup*|KTaskWakeup*|WakeupWqueue*) CLASS="CLASS_WAKEUP_UAF" ;; # freed task wakeup
            \?)  # no caller recovered: best-effort by fault kind
                 CLASS="UNKNOWN_LIST_${FAULT_KIND}" ;;
            *)   CLASS="LIST_OP_via_${CALLER_FUNC}" ;;
        esac
        ;;
    KTaskWakeup*|_KTaskWakeup*) CLASS="CLASS_WAKEUP_UAF" ;;
esac

echo "TRIAGE_RESULT class=${CLASS} fault=${FAULT_KIND} mepc=${FAULT_PC} mcause=${MCAUSE} func=${FUNC} caller=${CALLER_FUNC} caller_ra=${CALLER_RA} loc=${FILE}"
