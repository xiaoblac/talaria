#!/usr/bin/env bash
# snapshot_preflight.sh — PR0 host-capability gate for snapshot mode.
#
# Operationalizes the PR0 gate in docs/plans/snapshot-mode.md: host capability is
# a GATE, not an assumption. Snapshot backend selection forks on TWO independent
# sub-gates — they are orthogonal (reset substrate ⊥ coverage backend):
#
#   sub-gate 1  KVM acceleration  (/dev/kvm)         → needed by ALL KVM-backed
#               reset paths (Snapchange-style dirty-page reset, Nyx, kAFL).
#   sub-gate 2  Intel PT          (intel_pt cpu flag) → needed by the kAFL/Nyx
#               hardware-trace COVERAGE path. Intel-only; AMD has no equivalent.
#
# This script is READ-ONLY and needs no sudo. It prints a per-capability report
# and a final VERDICT mapping the host to a backend tier.
#
# Exit codes (encode the tier so CI / PR0 can branch):
#   0   PT-PRODUCTION  : Intel PT + KVM present → kAFL / Nyx eligible
#                        (still verify you may install a patched KVM kernel).
#   10  KVM-NO-PT      : KVM present, no Intel PT → Snapchange-style dirty-page
#                        reset + KCOV/breakpoint coverage; PT path needs an
#                        Intel host.
#   20  WITNESS-ONLY   : no usable /dev/kvm → stock-QEMU savevm/loadvm or TCG
#                        only (checkpoint-witness / slow). Provision an
#                        Intel + KVM host for the real backend.
#   1   script error.

set -u

PASS="[PASS]"; FAIL="[FAIL]"; WARN="[WARN]"; INFO="[INFO]"

say()  { printf '%s %s\n' "$1" "$2"; }
hdr()  { printf '\n=== %s ===\n' "$1"; }

# --- capability globals (filled by checks) -------------------------------------
CPU_VENDOR="unknown"      # GenuineIntel | AuthenticAMD | other
HAS_VTX=0                 # vmx (Intel) or svm (AMD) present
HAS_INTEL_PT=0            # intel_pt cpu flag
HAS_KVM_DEV=0             # /dev/kvm exists
KVM_ACCESSIBLE=0          # /dev/kvm r+w by current user
IN_VM="no"                # detected outer hypervisor (vmware/kvm/...)
NESTED="unknown"          # nested-virt param of the loaded kvm module
QEMU_KVM_ACCEL=0          # qemu reports kvm accelerator

cpuinfo_has_flag() { grep -qiw "$1" /proc/cpuinfo 2>/dev/null; }

# --- sub-gate inputs -----------------------------------------------------------
hdr "CPU"
if [ -r /proc/cpuinfo ]; then
    CPU_VENDOR="$(awk -F': ' '/^vendor_id/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"
    CPU_VENDOR="${CPU_VENDOR:-unknown}"
    MODEL="$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"
    say "$INFO" "vendor=${CPU_VENDOR}  model=${MODEL:-?}"
else
    say "$WARN" "/proc/cpuinfo unreadable — CPU checks degraded"
fi

if cpuinfo_has_flag vmx; then HAS_VTX=1; say "$PASS" "Intel VT-x (vmx) present";
elif cpuinfo_has_flag svm; then HAS_VTX=1; say "$PASS" "AMD-V (svm) present";
else say "$FAIL" "no hardware virtualization flag (vmx/svm) exposed to this host"; fi

if cpuinfo_has_flag intel_pt; then HAS_INTEL_PT=1; say "$PASS" "Intel PT (intel_pt) present — HW-trace coverage possible";
else
    if [ "$CPU_VENDOR" = "AuthenticAMD" ]; then
        say "$FAIL" "Intel PT ABSENT (AMD CPU) — kAFL/Nyx PT coverage architecturally unavailable here"
    else
        say "$FAIL" "Intel PT (intel_pt) flag absent — kAFL/Nyx PT coverage unavailable"
    fi
fi

hdr "KVM"
if [ -e /dev/kvm ]; then
    HAS_KVM_DEV=1
    say "$PASS" "/dev/kvm exists"
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        KVM_ACCESSIBLE=1; say "$PASS" "/dev/kvm is r+w by current user"
    else
        say "$WARN" "/dev/kvm exists but not r+w by you — add user to the 'kvm' group (usermod -aG kvm \$USER)"
    fi
else
    say "$FAIL" "/dev/kvm absent — no KVM acceleration"
fi

# kvm modules loaded?
if command -v lsmod >/dev/null 2>&1; then
    KMODS="$(lsmod 2>/dev/null | awk '/^kvm/{print $1}' | paste -sd, -)"
    [ -n "${KMODS:-}" ] && say "$INFO" "kvm modules loaded: ${KMODS}" || say "$INFO" "no kvm_* module loaded"
fi

# --- are we inside an outer hypervisor? (decides whether nested virt matters) --
hdr "Virtualization context"
if command -v systemd-detect-virt >/dev/null 2>&1; then
    DV="$(systemd-detect-virt 2>/dev/null || true)"
    if [ -n "${DV:-}" ] && [ "$DV" != "none" ]; then IN_VM="$DV"; fi
fi
if [ "$IN_VM" = "no" ] && cpuinfo_has_flag hypervisor; then IN_VM="hypervisor(flag)"; fi
if [ "$IN_VM" != "no" ]; then
    say "$INFO" "running INSIDE a hypervisor: ${IN_VM}"
    # nested-virt of the outer hypervisor must be ON to expose working KVM here.
    for p in /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested; do
        if [ -r "$p" ]; then NESTED="$(cat "$p" 2>/dev/null)"; fi
    done
    say "$INFO" "guest kvm module nested param = ${NESTED}"
    if [ "$HAS_KVM_DEV" -eq 0 ]; then
        say "$WARN" "no /dev/kvm inside this VM → enable nested virt in the OUTER hypervisor"
        say "$WARN" "  (VMware: VM Settings → CPU → 'Virtualize Intel VT-x/EPT or AMD-V/RVI')"
    fi
else
    say "$INFO" "running on bare metal (no outer hypervisor detected)"
fi

# --- does the installed QEMU offer the kvm accelerator? ------------------------
hdr "QEMU accelerator"
QEMU_BIN="$(command -v qemu-system-x86_64 || true)"
if [ -n "${QEMU_BIN:-}" ]; then
    say "$INFO" "qemu: ${QEMU_BIN}"
    ACCELS="$("${QEMU_BIN}" -accel help 2>&1 | tr '\n' ' ' || true)"
    if printf '%s' "$ACCELS" | grep -qiw kvm; then QEMU_KVM_ACCEL=1; say "$PASS" "qemu advertises 'kvm' accelerator"; fi
    printf '%s' "$ACCELS" | grep -qiw tcg && say "$INFO" "qemu has 'tcg' (software) accelerator as fallback"
    [ "$QEMU_KVM_ACCEL" -eq 0 ] && say "$WARN" "qemu does not list 'kvm' accelerator"
else
    say "$WARN" "qemu-system-x86_64 not in PATH — install it or point PATH at the build"
fi

# --- manual-only check the script cannot decide --------------------------------
hdr "Manual checks (script cannot auto-decide)"
say "$INFO" "kAFL/Nyx need a PATCHED host KVM (kafl.linux / KVM-Nyx) + modified QEMU."
say "$INFO" "  This box's stock KVM cannot run the PT path even if intel_pt is present."
say "$INFO" "  Confirm separately whether you may install a patched host kernel here."

# --- VERDICT -------------------------------------------------------------------
hdr "VERDICT"
TIER=""; CODE=1
if [ "$HAS_KVM_DEV" -eq 1 ] && [ "$HAS_INTEL_PT" -eq 1 ]; then
    TIER="PT-PRODUCTION"; CODE=0
    say "$PASS" "Intel PT + KVM present → kAFL / Nyx eligible (production PT-coverage path)."
    say "$INFO" "Next: confirm you may install a patched KVM kernel (kafl.linux / KVM-Nyx)."
elif [ "$HAS_KVM_DEV" -eq 1 ]; then
    TIER="KVM-NO-PT"; CODE=10
    say "$WARN" "KVM present but NO Intel PT → Snapchange-style dirty-page reset + KCOV/breakpoint."
    say "$INFO" "The kAFL/Nyx PT-coverage path needs an Intel host; not available on this box."
else
    TIER="WITNESS-ONLY"; CODE=20
    say "$FAIL" "No usable /dev/kvm → stock-QEMU savevm/loadvm or TCG only (checkpoint-witness / slow)."
    say "$INFO" "Provision an Intel + KVM (patchable) host for the real production backend."
fi
printf '\nTIER=%s  (exit %d)\n' "$TIER" "$CODE"
printf 'sub-gates: kvm=%s  intel_pt=%s  vendor=%s  in_vm=%s\n' \
    "$([ "$HAS_KVM_DEV" -eq 1 ] && echo yes || echo no)" \
    "$([ "$HAS_INTEL_PT" -eq 1 ] && echo yes || echo no)" \
    "${CPU_VENDOR}" "${IN_VM}"
exit "$CODE"
