package main

import (
	"strings"
)

type pseudoSpec struct {
	domain string
	impl   string
	caps   []string
}

func classifyPseudo(name string) pseudoSpec {
	base := pseudoBaseName(name)
	switch {
	case name == "syz_init_net_socket$nl_generic":
		return pseudoSpec{domain: "net", impl: "native"}
	case strings.HasPrefix(base, "syz_create_resource"):
		return pseudoSpec{domain: "core", impl: "native"}
	case strings.HasPrefix(base, "syz_open_procfs"):
		return pseudoSpec{domain: "file", impl: "native"}
	case strings.HasPrefix(base, "syz_open_dev"), strings.HasPrefix(base, "syz_open_pts"):
		return pseudoSpec{domain: "device", impl: "native"}
	case strings.HasPrefix(base, "syz_genetlink_get_family_id"):
		return pseudoSpec{domain: "net", impl: "native"}
	// [v1 net family stub + needs_raw_net cap — ROLLBACK: uncomment below and remove v2]
	// case strings.HasPrefix(base, "syz_emit_ethernet"),
	// 	strings.HasPrefix(base, "syz_extract_tcp_res"),
	// 	strings.HasPrefix(base, "syz_init_net_socket"),
	// 	strings.HasPrefix(base, "syz_80211"):
	// 	return pseudoSpec{domain: "net", impl: "stub", caps: []string{"needs_raw_net"}}

	// [v2 PR-B1/B2/B3 — 当前版本]
	// Lane 2 net stack (PR-B1/B2/B3) — TUN-fd / init-netns-socket /
	// mac80211_hwsim genetlink. All handler-side acquisition + graceful
	// degrade if cap absent (operator-preload extension of plan §10 Q6:
	// handler attempts TUN/socket setup, returns -1 cheap on failure).
	// Cap dropped: handler does the open itself but failure path is
	// tested in CI via direct dispatch; generation unblocked.
	case strings.HasPrefix(base, "syz_emit_ethernet"),
		strings.HasPrefix(base, "syz_extract_tcp_res"),
		strings.HasPrefix(base, "syz_init_net_socket"),
		strings.HasPrefix(base, "syz_80211"):
		return pseudoSpec{domain: "net", impl: "native"}
	// [v1 syz_mount_image 全部 stub — ROLLBACK: uncomment 这块,删除 v2]
	// case strings.HasPrefix(base, "syz_mount_image"):
	// 	return pseudoSpec{domain: "fs", impl: "stub", caps: []string{"needs_root", "needs_mount"}}

	// [v2 PR-D1 foundation batch — REPLACED BY v3 PR-D1.A bulk flip]
	// // case name == "syz_mount_image$ext4" || ... 6 names ...:
	// //     return pseudoSpec{domain: "mount", impl: "native", ...}
	// // case strings.HasPrefix(base, "syz_mount_image"):
	// //     return pseudoSpec{domain: "fs", impl: "stub", ...}
	//
	// [v3 PR-D1.A bulk flip — 当前版本]
	// All 43 syz_mount_image$<fs> variants now route to kMount/kNative.
	// Adjusters for the 4 fs that need them (iso9660 / ext{2,3,4} / xfs /
	// gfs2*) live in mount_helpers.cpp::BuildMountOpts; the other 39 fs
	// are vanilla mount(2) calls with the fs name passed through. PR-D1's
	// foundation 6 fs proved the template; PR-D1.A bulk-flips the
	// remaining 37. Caps stay needs_root|needs_mount per plan §10 Q6
	// rule 3.
	case strings.HasPrefix(base, "syz_mount_image"):
		return pseudoSpec{domain: "mount", impl: "native", caps: []string{"needs_root", "needs_mount"}}
	case strings.HasPrefix(base, "syz_read_part_table"):
		return pseudoSpec{domain: "fs", impl: "native", caps: []string{"needs_root"}}
	// [v1 syz_usb 整族 unsupported — ROLLBACK: uncomment 这块,删除 v2]
	// case strings.HasPrefix(base, "syz_usb"):
	//     return pseudoSpec{domain: "usb", impl: "unsupported", caps: []string{"needs_usb"}}

	// [v2 PR-D4 — 当前版本]
	// 25 syz_usb_* pseudos flipped kUnsupported→kNative under existing kUsb
	// domain. New `pseudo/usb/` subdir replaces deleted `pseudo_usb.cpp`
	// ENOSYS stub (plan §5.2). Caps stay needs_root|needs_usb per plan §10
	// Q6 rule 3 (handler-active + non-degradable — /dev/raw-gadget +
	// device-emulation state machine across multiple pseudos in the same
	// program). PR-CTRL-SANDBOX mount_capable=true unlocks via
	// kMountCapableCaps. Note `syz_usbip_server_init` is in this branch
	// but is a separate USB/IP server family (different from raw-gadget);
	// dispatcher routes it to a separate handler.
	case strings.HasPrefix(base, "syz_usb"):
		return pseudoSpec{domain: "usb", impl: "native", caps: []string{"needs_root", "needs_usb"}}
	// [v1 syz_fuse stub + needs_fuse cap — ROLLBACK: uncomment below and remove v2]
	// case strings.HasPrefix(base, "syz_fuse"):
	// 	return pseudoSpec{domain: "fuse", impl: "unsupported", caps: []string{"needs_fuse"}}

	// [v2 PR-D3 — 当前版本]
	// syz_fuse_handle_req is a stateless reactive handler: caller program
	// owns the /dev/fuse fd and passes it in; handler reads the FUSE
	// request, picks a fuzzer-supplied response by opcode, writes it back.
	// No persistent state, no setup hook, no cap acquisition by handler
	// itself — operator/profile responsibility to load `fuse` kernel
	// module + /dev/fuse node, mirroring PR-B3 hwsim operator-preload
	// (§10 Q6). Caller program will fail at openat(/dev/fuse) if the
	// module is absent → handler receives -1 fd → returns -1.
	// Implemented at executor/channel/worker/src/backend/pseudo/fuse/
	// fuse_dispatcher.cpp (subdir per §5.2).
	case strings.HasPrefix(base, "syz_fuse"):
		return pseudoSpec{domain: "fuse", impl: "native"}
	// [v2 PR-B4 — 当前版本]
	// syz_emit_vhci writes raw HCI bytes to a worker-cached /dev/vhci fd.
	// Lazy open at first call; degraded if hci_vhci kernel module not
	// loaded (operator-preload pattern, plan §10 Q6 generalization).
	// Implemented in pseudo_net.cpp (single pseudo, no subdir per §5.2 budget).
	case strings.HasPrefix(base, "syz_emit_vhci"):
		return pseudoSpec{domain: "net", impl: "native"}
	// [v1 syz_kvm 整族 unsupported — ROLLBACK: uncomment 这块,删除 v2]
	// case strings.HasPrefix(base, "syz_kvm"):
	//     return pseudoSpec{domain: "kvm", impl: "unsupported", caps: []string{"needs_kvm"}}

	// [v2 PR-D2 — 当前版本; PR-D2.A pending — see plan §6 / §11 DoD]
	// 6 syz_kvm pseudos flipped kUnsupported→kNative under existing kKvm
	// domain (no new domain enum needed; pseudo_kvm.cpp ENOSYS stub deleted +
	// replaced by pseudo/kvm/ subdir per plan §5.2). Caps stay
	// needs_root|needs_kvm per plan §10 Q6 rule 3 (handler-active +
	// non-degradable — /dev/kvm + VM/vCPU/guest-memory lifecycle persistence).
	// PR-CTRL-SANDBOX mount_capable=true unlocks via kMountCapableCaps.
	//
	// **Honesty notes per PR-D2 review (2026-05-07)**:
	//
	//   * syz_kvm_setup_cpu$ppc64 — classification kNative but handler
	//     returns ENOSYS at the kvm_dispatcher level. reFuzz worker is
	//     amd64-only. Architectural choice: the gate is at dispatcher
	//     level rather than catalog level so a future cross-arch reFuzz
	//     worker can light it up by adding a handler branch without a
	//     catalog edit. The catalog tells the truth about "this pseudo
	//     is supposed to be implemented"; the runtime tells the truth
	//     about "this worker can't actually do it".
	//
	//   * syz_kvm_setup_cpu$x86 + syz_kvm_setup_syzos_vm$x86 — handlers
	//     are MINIMUM VIABLE: open /dev/kvm + KVM_CREATE_VM + map guest
	//     memory. Full upstream syzOS guest-binary loader (kvm_syz_vm
	//     struct in caller host_mem; multi-region GPA layout matching
	//     common_kvm_amd64.h:220-260; syzOS guest binary install at
	//     SYZOS_ADDR_EXECUTOR_CODE; IDT/TSS/segment regs/page tables) is
	//     **DEFERRED to PR-D2.A** (tracked in plan §6 PR table + §11 DoD
	//     + audit row #18). Without that, KVM_RUN faults immediately on
	//     undefined opcode at GPA 0; downstream assert_syzos_* handlers
	//     therefore always fail (correct behavior — they detect the
	//     missing syzOS guest state).
	//
	//   * syz_kvm_assert_syzos_uexit$x86 + syz_kvm_assert_syzos_kvm_exit$x86
	//     — handler logic is correct per common_kvm_amd64.h:1205-1219 +
	//     common_kvm.h:40-56. Mechanism (b) oracle pins the canonical
	//     KVM_EXIT_MMIO + phys_addr + mmio.data[0]==expect semantics.
	//
	//   * syz_kvm_add_vcpu$x86 — handler accumulates vCPUs via
	//     state.vcpu_slots + next_cpu_id counter, matching upstream
	//     common_kvm_amd64.h:1190-1201.
	//
	// Plan §11 DoD KVM family closure requires: PR-D2 (this PR — gate +
	// lifecycle plumbing + correct assertion handler logic) AND PR-D2.A
	// (full syzOS guest setup). Until PR-D2.A lands, KVM kernel surface
	// that depends on guest execution is unreachable; only the
	// VM-creation / vCPU-creation kernel paths are exercised.
	case strings.HasPrefix(base, "syz_kvm"):
		return pseudoSpec{domain: "kvm", impl: "native", caps: []string{"needs_root", "needs_kvm"}}
	// [v1 io_uring 与 btf_id 共享 stub — ROLLBACK: uncomment below and remove v2]
	// case strings.HasPrefix(base, "syz_btf_id_by_name"),
	// 	strings.HasPrefix(base, "syz_io_uring"):
	// 	return pseudoSpec{domain: "core", impl: "stub"}

	// [v2 io_uring 升 native (PR-A1) — 当前版本]
	// io_uring trio (setup/submit/complete) is now implemented in
	// executor/channel/worker/src/backend/pseudo/pseudo_core.cpp using
	// PseudoRuntimeContext::RegisterNamedRegion for cross-call mmap region
	// sharing. Cap requirement: kCapNone (io_uring_setup is unprivileged
	// for normal users; failure surfaces as syscall errno without needing
	// a cap-gate).
	case strings.HasPrefix(base, "syz_io_uring"):
		return pseudoSpec{domain: "core", impl: "native"}
	// [当前版本 syz 08ab311 ublk 升 native (kCore domain)]
	// ublk family (setup_io_uring / add_dev / setup_queues / process_io) drives
	// the userspace block device control plane over io_uring uring_cmd, which
	// requires SQE128 / CQE32. Implemented in pseudo_core.cpp with a size-aware
	// io_uring path (the generic io_uring trio masks those flags + uses fixed
	// 64/16 sizes). kCapNone: the ops fail gracefully as errno when
	// CONFIG_BLK_DEV_UBLK or privilege is absent (same contract as io_uring).
	case strings.HasPrefix(base, "syz_ublk"):
		return pseudoSpec{domain: "core", impl: "native"}
	// [v3 btf_id_by_name 升 native (PR-A3) — 当前版本]
	// syz_btf_id_by_name$bpf_lsm reads /sys/kernel/btf/vmlinux and scans
	// the BTF type table for the requested name; returns type ID or -1.
	// Implemented in pseudo_core.cpp using a per-worker static cache
	// (mirrors upstream common_linux.h:2168-2197 read_btf_vmlinux).
	case strings.HasPrefix(base, "syz_btf_id_by_name"):
		return pseudoSpec{domain: "core", impl: "native"}
	// [v4 PR-A2 process / memory / kfuzztest 升 native (kCore domain) — 当前版本]
	// process group:
	//   syz_clone   (6 args): wraps clone(2), clears CLONE_VM, child exits via handle_clone_ret
	//   syz_clone3  (2 args): wraps clone3(2), copies clone_args, clears CLONE_VM
	//   syz_pidfd_open (2 args): wraps pidfd_open(2), forces pid=0 if pid==1 (PID-ns parent guard)
	//   syz_pkey_set (2 args): x86 wrpkru with RESERVED_PKEY=15 EINVAL guard
	//   syz_execute_func (1 arg): casts pointer to function and calls; coverage-only
	// memory group:
	//   syz_memcpy_off$* (5 args): memcpy(dest+dest_off, src+src_off, n)
	// kfuzztest group:
	//   syz_kfuzztest_run (4 args): write input buffer to /sys/kernel/debug/kfuzztest/<test>/input
	// All implemented in pseudo_core.cpp; kCapNone (process syscalls + asm + memcpy + debugfs
	// write all unprivileged).
	case strings.HasPrefix(base, "syz_clone"),
		strings.HasPrefix(base, "syz_pidfd_open"),
		strings.HasPrefix(base, "syz_pkey_set"),
		strings.HasPrefix(base, "syz_execute_func"),
		strings.HasPrefix(base, "syz_memcpy_off"),
		strings.HasPrefix(base, "syz_kfuzztest_run"):
		return pseudoSpec{domain: "core", impl: "native"}
	// [v4 PR-A2 nvme socket 升 native (kNet domain) — 当前版本]
	// syz_socket_connect_nvme_tcp (0 args): NVMe-oF/TCP socket+connect to 127.0.0.1:4420.
	// Upstream has two variants — with / without SYZ_NET_INJECTION; reFuzz uses the
	// no-injection fallback (`socket(-1, 0, 0)` → fail-fast) per Q6/Q2 sandbox split.
	// Full init-net-namespace variant blocked on PR-C0+B1 (setup hook) + PR-CTRL-SANDBOX.
	case strings.HasPrefix(base, "syz_socket_connect_nvme_tcp"):
		return pseudoSpec{domain: "net", impl: "native"}
	default:
		return pseudoSpec{domain: "unknown", impl: "unsupported"}
	}
}

func pseudoBaseName(name string) string {
	if idx := strings.IndexByte(name, '$'); idx >= 0 {
		return name[:idx]
	}
	return name
}

func cppPseudoDomain(domain string) string {
	switch domain {
	case "core":
		return "PseudoDomain::kCore"
	case "file":
		return "PseudoDomain::kFile"
	case "fs":
		return "PseudoDomain::kFs"
	case "device":
		return "PseudoDomain::kDevice"
	case "net":
		return "PseudoDomain::kNet"
	case "usb":
		return "PseudoDomain::kUsb"
	case "fuse":
		return "PseudoDomain::kFuse"
	case "kvm":
		return "PseudoDomain::kKvm"
	// [PR-D1 — 加 mount domain,匹配 §5.2 Tier 3 family-per-subdir convention]
	case "mount":
		return "PseudoDomain::kMount"
	default:
		return "PseudoDomain::kUnknown"
	}
}

func cppPseudoImpl(impl string) string {
	switch impl {
	case "native":
		return "PseudoImplKind::kNative"
	case "stub":
		return "PseudoImplKind::kStub"
	default:
		return "PseudoImplKind::kUnsupported"
	}
}

// [syscall-support-detection] capability_mask is no longer emitted; the
// per-family cap classification carried by pseudoSpec.caps is retained as
// catalog documentation but is not lowered into C++. Environment/capability
// gating now lives host-side in control/support, keyed on the syscall name.
