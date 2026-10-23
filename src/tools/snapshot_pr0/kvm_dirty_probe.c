// PR0 snapshot-mode feasibility spike — step 1.
//
// Goal: prove on THIS host (stock KVM, nested under VMware, AMD Ryzen) that the
// primitives a Snapchange-style dirty-page snapshot/restore would build on
// actually work, and put a FIRST number on the restore copy-back cost vs
// dirty-set size — i.e. the "heavy mount-image (132 MB inflate) 倒挂" risk.
//
// This deliberately does NOT use savevm/loadvm (full serialize = throughput
// killer, per docs/plans/snapshot-mode.md). It exercises raw /dev/kvm:
//   1. report dirty-log / snapshot KVM capabilities,
//   2. create a VM + 64 KB guest region WITH KVM_MEM_LOG_DIRTY_PAGES,
//   3. run a tiny real-mode guest that writes 3 distinct pages then HLT,
//   4. KVM_GET_DIRTY_LOG and confirm those pages are reported dirty
//      (end-to-end host dirty tracking works here),
//   5. model the restore as a memcpy(baseline -> live) of N pages and time it
//      for dirty-set sizes up to 132 MB, vs the continuous ~16 ms fork+wait.
//
// NOTE: numbers on this box are a PESSIMISTIC FLOOR (stock KVM + nested under
// VMware + AMD has no Intel PML, so dirty tracking uses write-protect faults).
// Bare-metal Intel+PML will be faster. Read accordingly.
//
// Build:  cc -O2 -o kvm_dirty_probe kvm_dirty_probe.c
// Exit:   0 = dirty tracking proven end-to-end;
//         2 = /dev/kvm unusable;
//         3 = VM/vcpu/dirty-log path failed (capability gap on this host).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static void report_cap(int kvm, const char *name, int c) {
    int r = ioctl(kvm, KVM_CHECK_EXTENSION, c);
    printf("  %-28s %s\n", name, r < 0 ? "ERR" : (r == 0 ? "no" : "yes"));
    if (r > 1) printf("    (value=%d)\n", r);
}

int main(void) {
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) {
        printf("[FAIL] open(/dev/kvm) errno=%d (%s)\n", errno, strerror(errno));
        return 2;
    }
    printf("KVM api version = %d (expect 12)\n", ioctl(kvm, KVM_GET_API_VERSION, 0));

    printf("\n== dirty-log / snapshot-relevant capabilities ==\n");
#ifdef KVM_CAP_USER_MEMORY
    report_cap(kvm, "USER_MEMORY", KVM_CAP_USER_MEMORY);
#endif
#ifdef KVM_CAP_IMMEDIATE_EXIT
    report_cap(kvm, "IMMEDIATE_EXIT", KVM_CAP_IMMEDIATE_EXIT);
#endif
#ifdef KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2
    report_cap(kvm, "MANUAL_DIRTY_LOG_PROTECT2", KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2);
#endif
#ifdef KVM_CAP_DIRTY_LOG_RING
    report_cap(kvm, "DIRTY_LOG_RING", KVM_CAP_DIRTY_LOG_RING);
#endif
#ifdef KVM_CAP_DIRTY_LOG_RING_ACQ_REL
    report_cap(kvm, "DIRTY_LOG_RING_ACQ_REL", KVM_CAP_DIRTY_LOG_RING_ACQ_REL);
#endif

    // --- create VM + a 64 KB guest region WITH dirty logging ---
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm < 0) { printf("[FAIL] KVM_CREATE_VM errno=%d (%s)\n", errno, strerror(errno)); return 3; }

    // Intel real-mode entry needs a TSS addr; harmless/ignored on AMD SVM.
    (void)ioctl(vm, KVM_SET_TSS_ADDR, 0xfffbd000UL);

    const size_t MEM = 0x10000; // 64 KB = 16 pages
    void *mem = mmap(NULL, MEM, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { printf("[FAIL] mmap guest mem\n"); return 3; }
    memset(mem, 0, MEM);

    // real-mode guest @0x1000: mov al,'A'; write to phys 0x2000,0x3000,0x5000; hlt
    unsigned char code[] = {
        0xB0, 0x41,                   // mov al, 0x41
        0xBB, 0x00, 0x20, 0x88, 0x07, // mov bx,0x2000 ; mov [bx],al
        0xBB, 0x00, 0x30, 0x88, 0x07, // mov bx,0x3000 ; mov [bx],al
        0xBB, 0x00, 0x50, 0x88, 0x07, // mov bx,0x5000 ; mov [bx],al
        0xF4                          // hlt
    };
    memcpy((char *)mem + 0x1000, code, sizeof(code));

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .flags = KVM_MEM_LOG_DIRTY_PAGES,
        .guest_phys_addr = 0,
        .memory_size = MEM,
        .userspace_addr = (unsigned long)mem,
    };
    if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        printf("[FAIL] SET_USER_MEMORY_REGION (dirty-log) errno=%d (%s)\n", errno, strerror(errno));
        return 3;
    }

    int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    if (vcpu < 0) { printf("[FAIL] KVM_CREATE_VCPU errno=%d (%s)\n", errno, strerror(errno)); return 3; }
    int run_sz = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    struct kvm_run *run = mmap(NULL, run_sz, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
    if (run == MAP_FAILED) { printf("[FAIL] mmap kvm_run\n"); return 3; }

    struct kvm_sregs sregs;
    ioctl(vcpu, KVM_GET_SREGS, &sregs);
    sregs.cs.base = 0; sregs.cs.selector = 0;
    ioctl(vcpu, KVM_SET_SREGS, &sregs);
    struct kvm_regs regs = { .rip = 0x1000, .rflags = 0x2, .rsp = 0xfff0 };
    ioctl(vcpu, KVM_SET_REGS, &regs);

    int hlt = 0;
    for (int i = 0; i < 1000 && !hlt; i++) {
        if (ioctl(vcpu, KVM_RUN, 0) < 0) {
            printf("[FAIL] KVM_RUN errno=%d (%s)\n", errno, strerror(errno));
            return 3;
        }
        switch (run->exit_reason) {
        case KVM_EXIT_HLT: hlt = 1; break;
        case KVM_EXIT_SHUTDOWN:
            printf("[WARN] guest SHUTDOWN (triple fault) — real-mode entry differs on this KVM\n");
            i = 1000; break;
        default:
            printf("[INFO] unexpected exit_reason=%d\n", run->exit_reason);
            break;
        }
    }
    printf("\n== guest ran: hlt=%d ==\n", hlt);

    // --- read dirty log ---
    unsigned long bitmap[8];
    memset(bitmap, 0, sizeof(bitmap));
    struct kvm_dirty_log dl = { .slot = 0 };
    dl.dirty_bitmap = bitmap;
    double t0 = now_ms();
    int dr = ioctl(vm, KVM_GET_DIRTY_LOG, &dl);
    double t_getlog = now_ms() - t0;
    if (dr < 0) {
        printf("[FAIL] KVM_GET_DIRTY_LOG errno=%d (%s) — stock-KVM dirty tracking NOT usable here\n",
               errno, strerror(errno));
        return 3;
    }
    printf("KVM_GET_DIRTY_LOG ok (%.4f ms). dirty pages: ", t_getlog);
    int ndirty = 0;
    for (size_t p = 0; p < MEM / 4096; p++)
        if (bitmap[p / 64] & (1UL << (p % 64))) { printf("%zu ", p); ndirty++; }
    printf("\n  (expected 2 3 5 — guest writes; code-page reads do not dirty)\n");
    int proven = hlt && ndirty > 0;
    printf("[%s] end-to-end host dirty tracking\n", proven ? "PASS" : "FAIL");

    // --- model restore copy-back cost vs dirty-set size ---
    printf("\n== restore copy-back cost model (memcpy baseline->live on this host) ==\n");
    printf("  restore = GET_DIRTY_LOG scan + copy back ONLY dirtied pages.\n");
    printf("  Here we isolate the copy-back half for representative dirty-set sizes:\n");
    const size_t sizes[]  = { 4096UL, 1UL << 20, 16UL << 20, 132UL << 20 };
    const char  *labels[] = { "1 page (4 KB)", "1 MB", "16 MB", "132 MB (mount-image inflate)" };
    const size_t MAXB = 132UL << 20;
    char *base = malloc(MAXB), *live = malloc(MAXB);
    if (base && live) {
        memset(base, 0xAB, MAXB);
        memset(live, 0x00, MAXB);
        for (unsigned i = 0; i < 4; i++) {
            int iters = sizes[i] < (1UL << 20) ? 20000 : 50;
            double b = now_ms();
            for (int k = 0; k < iters; k++) {
                // vary one byte so the copy is not loop-invariant, then a
                // memory clobber so -O2 cannot eliminate/hoist the memcpy.
                base[k % sizes[i]] = (char)k;
                memcpy(live, base, sizes[i]);
                __asm__ __volatile__("" : : "r"(live), "r"(base) : "memory");
            }
            double per = (now_ms() - b) / iters;
            printf("  copy-back %-30s %9.4f ms/restore\n", labels[i], per);
        }
        free(base); free(live);
    }
    printf("\n  baseline to beat: continuous per-program fork+wait ~16 ms (18 exec/s).\n");
    printf("  (numbers above are a PESSIMISTIC FLOOR: stock KVM + nested VMware + AMD/no-PML)\n");
    return proven ? 0 : 3;
}
