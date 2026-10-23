// [syscall-support-detection Step C] Unit test for the guest env probe's
// /proc/filesystems parser (the testable seam). The device-open part of
// ProbeEnvFeatures needs a live /dev, so it is exercised only in-VM, not here.

#include "worker/env/env_probe.hpp"
#include "refuzz/proto_wire/env_features.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

int main() {
    // /proc/filesystems shape: "nodev\t<name>\n" or "\t<name>\n"; the last line
    // has no tab to exercise the whole-line fallback.
    const char* proc =
        "nodev\tsysfs\n"
        "nodev\tproc\n"
        "\text4\n"
        "\tbtrfs\n"
        "nodev\tfuse\n"
        "ext2\n";
    ::EnvFeatures e;
    std::memset(&e, 0, sizeof(e));
    refuzz::worker::env::ParseProcFilesystems(proc, std::strlen(proc), &e);

    CHECK(env_features_has_filesystem(&e, "sysfs"));
    CHECK(env_features_has_filesystem(&e, "proc"));
    CHECK(env_features_has_filesystem(&e, "ext4"));
    CHECK(env_features_has_filesystem(&e, "btrfs"));
    CHECK(env_features_has_filesystem(&e, "fuse"));
    CHECK(env_features_has_filesystem(&e, "ext2"));    // no-tab line → whole line
    CHECK(!env_features_has_filesystem(&e, "nodev"));  // prefix dropped, not stored
    CHECK(!env_features_has_filesystem(&e, "xfs"));

    // empty / degenerate input must not crash or append.
    ::EnvFeatures empty;
    std::memset(&empty, 0, sizeof(empty));
    refuzz::worker::env::ParseProcFilesystems("", 0, &empty);
    refuzz::worker::env::ParseProcFilesystems("\n\n\n", 3, &empty);
    CHECK(empty.filesystems_len == 0);

    // ---- [C4.1] ParseKernelVersion: first " X.Y." token ----
    auto parse_ver = [](const char* s, uint32_t* mj, uint32_t* mn) {
        refuzz::worker::env::ParseKernelVersion(s, std::strlen(s), mj, mn);
    };
    uint32_t mj = 99, mn = 99;
    parse_ver("Linux version 6.8.0-88-generic (buildd@lcy02) ...", &mj, &mn);
    CHECK(mj == 6 && mn == 8);
    parse_ver("Linux version 4.17.0 ...", &mj, &mn);
    CHECK(mj == 4 && mn == 17);
    parse_ver("Linux version 6.0.0-rc1 ...", &mj, &mn);    // minor 0 is valid
    CHECK(mj == 6 && mn == 0);
    parse_ver("no version here", &mj, &mn);                // no match → 0/0
    CHECK(mj == 0 && mn == 0);
    parse_ver("Linux version 6 .8.", &mj, &mn);            // not "X.Y." → no match
    CHECK(mj == 0 && mn == 0);

    // env_features_kernel_at_least + has_lsm + set_lsm helpers.
    ::EnvFeatures kf;
    std::memset(&kf, 0, sizeof(kf));
    kf.kernel_major = 6; kf.kernel_minor = 8;
    CHECK(env_features_kernel_at_least(&kf, 4, 17));
    CHECK(env_features_kernel_at_least(&kf, 6, 8));
    CHECK(!env_features_kernel_at_least(&kf, 6, 9));
    ::EnvFeatures unkf;
    std::memset(&unkf, 0, sizeof(unkf));                   // major 0 = unknown
    CHECK(!env_features_kernel_at_least(&unkf, 1, 0));     // no evidence → false

    ::EnvFeatures lf;
    std::memset(&lf, 0, sizeof(lf));
    const char* lsm = "capability,landlock,yama,apparmor";
    env_features_set_lsm(&lf, lsm, std::strlen(lsm));
    CHECK((lf.flags & ENV_FEAT_LSM_PRESENT) != 0);
    CHECK(env_features_has_lsm(&lf, "apparmor"));
    CHECK(env_features_has_lsm(&lf, "yama"));
    CHECK(!env_features_has_lsm(&lf, "selinux"));
    ::EnvFeatures lf0;
    std::memset(&lf0, 0, sizeof(lf0));
    CHECK(!env_features_has_lsm(&lf0, "selinux"));         // empty → false

    std::fprintf(stdout, "env_probe_test ALL PASS\n");
    return 0;
}
