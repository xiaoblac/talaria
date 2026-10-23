// PR0 snapshot-mode feasibility spike — step 2.
//
// Measures the OTHER half of per-restore cost that step 1 did not: the
// dirty-TRACKING overhead DURING guest execution. On AMD (no Intel PML) KVM
// tracks dirty pages by write-protecting them and faulting on first write — the
// suspected weak spot. We time a guest that writes N pages WITH vs WITHOUT
// KVM_MEM_LOG_DIRTY_PAGES; the delta ≈ per-page write-protect-fault cost.
//
// We report WARM (steady-state) timing, not just cold: in a real snapshot fuzz
// loop every iteration re-dirties pages that were just reset, so each run
// re-faults. For the logging case we call KVM_GET_DIRTY_LOG between runs (which
// re-write-protects under default, non-manual mode) to reproduce that.
//
// Guest: 32-bit flat protected mode (segment caches set via SREGS, no GDT in
// memory; CR0.PE=1, paging OFF so linear==physical). It writes one byte to each
// of N pages starting at 1 MB, then HLT.  rdi=scratch, rcx=N set by host.
//
// Build:  cc -O2 -o kvm_track_overhead kvm_track_overhead.c
// Exit:   0 ok; 2 /dev/kvm unusable; 3 a measurement run failed.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>

static double now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

#define SCRATCH 0x100000UL    // 1 MB: where the guest starts writing pages
#define CODE    0x1000UL
#define RUNS    6             // run[0]=cold warm-up; avg run[1..] = warm

// 32-bit guest: mov al,'A'; loop { [edi]=al; edi+=0x1000; ecx--; } while ecx; hlt
static const unsigned char GUEST[] = {
    0xB0, 0x41,                         // mov al, 0x41
    0x88, 0x07,                         // L: mov [edi], al
    0x81, 0xC7, 0x00, 0x10, 0x00, 0x00, //    add edi, 0x1000
    0x49,                               //    dec ecx
    0x75, 0xF5,                         //    jnz L
    0xF4                                //    hlt
};

static void seg32(struct kvm_segment *s, uint16_t sel, uint8_t type) {
    memset(s, 0, sizeof(*s));
    s->base = 0; s->limit = 0xffffffff; s->selector = sel;
    s->type = type; s->present = 1; s->dpl = 0; s->db = 1; s->s = 1; s->l = 0; s->g = 1;
}

// run the guest `runs` times; fill *cold (run 0) and *warm (avg of runs 1..).
// returns 1 on success.
static int measure(int kvm, size_t npages, int dirty_flag, double *cold, double *warm) {
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm < 0) return 0;
    (void)ioctl(vm, KVM_SET_TSS_ADDR, 0xfffbd000UL);

    size_t need = SCRATCH + npages * 4096UL + 0x10000UL;
    size_t MEM = (need + 0xfffffUL) & ~0xfffffUL;       // round up to 1 MB
    void *mem = mmap(NULL, MEM, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { close(vm); return 0; }
    memset(mem, 0, MEM);
    memcpy((char *)mem + CODE, GUEST, sizeof(GUEST));

    struct kvm_userspace_memory_region r = {
        .slot = 0, .flags = (uint32_t)dirty_flag,
        .guest_phys_addr = 0, .memory_size = MEM, .userspace_addr = (unsigned long)mem,
    };
    if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &r) < 0) { munmap(mem, MEM); close(vm); return 0; }

    int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    if (vcpu < 0) { munmap(mem, MEM); close(vm); return 0; }
    int run_sz = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    struct kvm_run *run = mmap(NULL, run_sz, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);

    struct kvm_sregs s; ioctl(vcpu, KVM_GET_SREGS, &s);
    seg32(&s.cs, 0x08, 0xb);   // exec/read
    seg32(&s.ds, 0x10, 0x3);   // read/write
    s.es = s.ds; s.ss = s.ds; s.fs = s.ds; s.gs = s.ds;
    s.cr0 |= 1;                 // PE on, paging off
    ioctl(vcpu, KVM_SET_SREGS, &s);

    size_t bm_longs = MEM / 4096 / 64 + 2;
    unsigned long *bitmap = calloc(bm_longs, sizeof(long));

    double sum_warm = 0; int warm_n = 0; int ok = 1;
    for (int rr = 0; rr < RUNS && ok; rr++) {
        struct kvm_regs regs = { .rip = CODE, .rflags = 0x2, .rdi = SCRATCH, .rcx = npages, .rsp = 0xF000 };
        ioctl(vcpu, KVM_SET_REGS, &regs);
        double t = now_ms();
        int hlt = 0;
        for (int g = 0; g < 8 && !hlt; g++) {
            if (ioctl(vcpu, KVM_RUN, 0) < 0) { ok = 0; break; }
            if (run->exit_reason == KVM_EXIT_HLT) hlt = 1;
            else if (run->exit_reason == KVM_EXIT_SHUTDOWN) { ok = 0; break; }
        }
        double el = now_ms() - t;
        if (!hlt) { ok = 0; break; }
        if (rr == 0) *cold = el;
        else { sum_warm += el; warm_n++; }
        // logging on: re-protect pages so the next run re-faults (steady state).
        if (dirty_flag) {
            struct kvm_dirty_log dl = { .slot = 0 }; dl.dirty_bitmap = bitmap;
            (void)ioctl(vm, KVM_GET_DIRTY_LOG, &dl);
        }
    }
    *warm = warm_n ? sum_warm / warm_n : *cold;

    free(bitmap); munmap(run, run_sz); close(vcpu); munmap(mem, MEM); close(vm);
    return ok;
}

int main(void) {
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) { printf("[FAIL] open(/dev/kvm) errno=%d\n", errno); return 2; }

    size_t Ns[] = { 256, 4096, 16384, 33000 };   // up to ~132 MB worth of pages
    printf("dirty-tracking EXECUTION overhead (write N pages, logging off vs on)\n");
    printf("host = AMD/nested-VMware/stock-KVM (no PML) — PESSIMISTIC FLOOR\n\n");
    printf("%-8s %-8s | %-22s | %-22s | %-12s %s\n",
           "npages", "MB", "logging OFF (ms)", "logging ON (ms)", "warm delta", "delta/page");
    printf("%-8s %-8s | %-10s %-10s | %-10s %-10s | %-12s %s\n",
           "", "", "cold", "warm", "cold", "warm", "(ms)", "(us/page)");
    for (unsigned i = 0; i < sizeof(Ns) / sizeof(Ns[0]); i++) {
        size_t N = Ns[i];
        double off_c = 0, off_w = 0, on_c = 0, on_w = 0;
        int ok1 = measure(kvm, N, 0, &off_c, &off_w);
        int ok2 = measure(kvm, N, KVM_MEM_LOG_DIRTY_PAGES, &on_c, &on_w);
        if (!ok1 || !ok2) { printf("%-8zu  FAILED (ok_off=%d ok_on=%d)\n", N, ok1, ok2); return 3; }
        double dwarm = on_w - off_w;
        printf("%-8zu %-8.1f | %-10.4f %-10.4f | %-10.4f %-10.4f | %-12.4f %.4f\n",
               N, N * 4096.0 / (1 << 20), off_c, off_w, on_c, on_w, dwarm, dwarm * 1000.0 / N);
    }
    printf("\ndelta = pure write-protect dirty-tracking cost per program run.\n");
    printf("full per-restore ≈ this (tracking, during run) + step-1 copy-back (after run).\n");
    printf("baseline to beat: continuous fork+wait ~16 ms/program (18 exec/s).\n");
    return 0;
}
