// Minimal guest KCOV agent for the PR0 snapshot end-to-end.
//
// Runs INSIDE the snapshot VM as the foreground process that owns ttyS0. It is
// the "guest agent" in syz-snapshot terms, minus ivshmem: it speaks over the
// serial console instead. Lifecycle:
//   - mount sysfs+debugfs, open /sys/kernel/debug/kcov, KCOV_INIT_TRACE+mmap,
//     KCOV_ENABLE(TRACE_PC)  -> print AGENT_READY, then block on read(stdin).
//   - the host takes savevm S0 here (agent blocked at the read).
//   - per host "RUN" line: reset cover[0], run a fixed REAL syscall program,
//     read the PC count, print  COV n=<pcs> hash=<fnv>  (coverage of that run).
//   - host restores S0 (loadvm) between runs.
//
// Goal it proves: snapshot mode can execute a real program and collect real,
// STABLE KCOV (same program from the same S0 -> same PC set) -- a production
// fuzzing property, not a syscall-parity oracle thing.
//
// Built static (gcc -static) so it runs in the bookworm guest regardless of its
// libc.  x86-64.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define KCOV_TRACE_PC 0
#define COVER_ENTRIES (64UL << 10) // unsigned long entries

static unsigned long *cover;

static void try_mounts(void)
{
    mkdir("/sys", 0755);
    // ignore EBUSY/EEXIST -- best effort, init=/bin/sh has nothing mounted.
    mount("sysfs", "/sys", "sysfs", 0, 0);
    mount("debugfs", "/sys/kernel/debug", "debugfs", 0, 0);
    mount("proc", "/proc", "proc", 0, 0);
}

// A fixed, deterministic real syscall program. Success/failure does not matter
// -- KCOV records the kernel PCs traversed either way; determinism gives a
// stable coverage signature across identical snapshot restores.
static void run_program(void)
{
    syscall(SYS_getpid);
    syscall(SYS_getuid);
    syscall(SYS_getppid);
    syscall(SYS_gettid);
    syscall(SYS_sched_yield);
    long m = syscall(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m > 0)
        syscall(SYS_munmap, m, 4096);
    long fd = syscall(SYS_openat, AT_FDCWD, "/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char b[128];
        syscall(SYS_read, fd, b, sizeof(b));
        syscall(SYS_close, fd);
    }
}

static uint64_t fnv1a(const unsigned long *pcs, unsigned long n)
{
    uint64_t h = 1469598103934665603ULL;
    for (unsigned long i = 0; i < n; i++) {
        uint64_t v = pcs[i];
        for (int b = 0; b < 8; b++) {
            h ^= (v >> (b * 8)) & 0xff;
            h *= 1099511628211ULL;
        }
    }
    return h;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    try_mounts();

    int fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (fd < 0) {
        printf("AGENT_ERR kcov_open errno=%d\n", errno);
        // keep the tty alive so the host can still drive savevm/diag.
        for (;;)
            pause();
    }
    if (ioctl(fd, KCOV_INIT_TRACE, COVER_ENTRIES)) {
        printf("AGENT_ERR kcov_init errno=%d\n", errno);
        for (;;)
            pause();
    }
    cover = mmap(NULL, COVER_ENTRIES * sizeof(unsigned long),
                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (cover == MAP_FAILED) {
        printf("AGENT_ERR kcov_mmap errno=%d\n", errno);
        for (;;)
            pause();
    }
    if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC)) {
        printf("AGENT_ERR kcov_enable errno=%d\n", errno);
        for (;;)
            pause();
    }

    printf("AGENT_READY cover_entries=%lu\n", COVER_ENTRIES);

    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "RUN", 3) == 0) {
            __atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
            run_program();
            unsigned long n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
            if (n >= COVER_ENTRIES)
                n = COVER_ENTRIES - 1;
            uint64_t h = fnv1a(&cover[1], n);
            printf("COV n=%lu hash=%016llx\n", n, (unsigned long long)h);
        } else if (strncmp(line, "QUIT", 4) == 0) {
            break;
        }
    }
    return 0;
}
