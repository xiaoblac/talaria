// PR0/PR1 dirty-set measurement helper — page-level diff of two raw guest-RAM
// dumps (e.g. QMP `pmemsave 0 <size> file`).
//
// Counts how many 4 KiB pages differ between BEFORE and AFTER snapshots taken
// around exactly one replayed program (see replayer REFUZZ_DUMP hook). That
// count = the program's guest dirty-set (minus a background floor measured
// separately). This is the accurate per-program number the synthetic
// kvm_track_overhead curve cannot give.
//
// Build:  cc -O2 -o pagediff pagediff.c
// Usage:  pagediff BEFORE.raw AFTER.raw [page_size]
//         pagediff --selftest

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

static int diff_files(const char *pa, const char *pb, size_t ps) {
    int fa = open(pa, O_RDONLY), fb = open(pb, O_RDONLY);
    if (fa < 0 || fb < 0) { fprintf(stderr, "open failed\n"); return -1; }
    struct stat sa, sb;
    fstat(fa, &sa); fstat(fb, &sb);
    size_t na = sa.st_size, nb = sb.st_size;
    size_t n = na < nb ? na : nb;
    if (na != nb) fprintf(stderr, "[warn] sizes differ: %zu vs %zu; comparing first %zu\n", na, nb, n);
    void *a = mmap(NULL, n, PROT_READ, MAP_PRIVATE, fa, 0);
    void *b = mmap(NULL, n, PROT_READ, MAP_PRIVATE, fb, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) { fprintf(stderr, "mmap failed\n"); return -1; }

    size_t pages = n / ps, diff = 0;
    const char *ca = a, *cb = b;
    for (size_t p = 0; p < pages; p++)
        if (memcmp(ca + p * ps, cb + p * ps, ps) != 0) diff++;

    double mb = diff * (double)ps / (1 << 20);
    printf("page_size=%zu  total_pages=%zu  DIRTY_PAGES=%zu  (%.2f MB)\n", ps, pages, diff, mb);
    printf("DIRTY_PAGES=%zu\n", diff); // machine-readable line
    munmap(a, n); munmap(b, n); close(fa); close(fb);
    return (int)diff;
}

static int selftest(void) {
    const size_t ps = 4096, pages = 64;
    const char *fa = "/tmp/pagediff_a.bin", *fb = "/tmp/pagediff_b.bin";
    char *buf = calloc(pages, ps);
    FILE *f = fopen(fa, "wb"); fwrite(buf, ps, pages, f); fclose(f);
    // flip one byte in pages 3, 10, 10 (dup), 63 -> 3 distinct dirty pages
    buf[3 * ps + 1] = 1; buf[10 * ps + 100] = 1; buf[63 * ps + ps - 1] = 1;
    f = fopen(fb, "wb"); fwrite(buf, ps, pages, f); fclose(f);
    free(buf);
    printf("[selftest] expect DIRTY_PAGES=3:\n");
    int d = diff_files(fa, fb, ps);
    unlink(fa); unlink(fb);
    if (d == 3) { printf("[selftest] PASS\n"); return 0; }
    printf("[selftest] FAIL (got %d)\n", d); return 1;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--selftest") == 0) return selftest();
    if (argc < 3) { fprintf(stderr, "usage: %s BEFORE.raw AFTER.raw [page_size]\n   or: %s --selftest\n", argv[0], argv[0]); return 2; }
    size_t ps = argc >= 4 ? (size_t)strtoul(argv[3], NULL, 0) : 4096;
    int d = diff_files(argv[1], argv[2], ps);
    return d < 0 ? 1 : 0;
}
