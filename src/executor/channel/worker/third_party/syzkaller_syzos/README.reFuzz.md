# syzkaller syzOS Vendor Copy

This directory vendors the AMD64 syzOS guest sources used by reFuzz's KVM
pseudo handlers.

Source repository: `/workspace/syzkaller`

Source commit: `08ab31164c55f20c7a2653de3186ae333470e2c1`

Copied files:

- `common_kvm_syzos.h`
- `common_kvm_amd64_syzos.h`
- `common_kvm.h`
- `kvm.h`
- `LICENSE.Apache-2.0`

The worker does not include these headers from normal KVM handler code. They
are consumed only by `src/backend/pseudo/kvm/syzos_guest_amd64.cpp`, which
exposes a small reFuzz-owned API for the guest section bytes and key guest
entry GPAs.

Upgrade process:

1. Update the local syzkaller checkout to the desired commit.
2. Re-copy the files listed above from `../executor/`.
3. Update this README's source commit.
4. Rebuild and run the focused pseudo KVM tests.
