// [syscall-support-detection Step C] Compile + behavior check for the
// EnvFeatures wire contract (proto/wire/env_features.h): flag helpers and the
// '\n'-separated filesystems buffer round-trip (append + whole-token lookup).

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

// POD contract: must stay trivially copyable / fixed-layout for ivshmem.
// Header = 7 × uint32 (version, flags, filesystems_len, kernel_major,
// kernel_minor, lsm_len, reserved) = 28 B, then the two char buffers. If this
// changes, bump ENV_FEATURES_VERSION (done: v2) and — once EnvFeatures is
// embedded in the ShmHeader (C4.6) — the ivshmem PROTOCOL_VERSION too.
static_assert(sizeof(struct EnvFeatures) ==
                  28u + ENV_FILESYSTEMS_CAP + ENV_LSM_CAP,
              "EnvFeatures layout changed — bump ENV_FEATURES_VERSION + ivshmem PROTOCOL_VERSION");

int main() {
    struct EnvFeatures e;
    std::memset(&e, 0, sizeof(e));
    e.version = ENV_FEATURES_VERSION;

    // flags
    CHECK(!env_features_has_flag(&e, ENV_FEAT_RAW_GADGET));
    e.flags |= ENV_FEAT_RAW_GADGET | ENV_FEAT_KVM;
    CHECK(env_features_has_flag(&e, ENV_FEAT_RAW_GADGET));
    CHECK(env_features_has_flag(&e, ENV_FEAT_KVM));
    CHECK(!env_features_has_flag(&e, ENV_FEAT_TUN));
    CHECK(!env_features_has_flag(nullptr, ENV_FEAT_KVM));

    // filesystems round-trip
    CHECK(!env_features_has_filesystem(&e, "ext4"));
    CHECK(env_features_append_filesystem(&e, "ext4"));
    CHECK(env_features_append_filesystem(&e, "sysfs"));
    CHECK(env_features_append_filesystem(&e, "proc"));
    CHECK(env_features_has_filesystem(&e, "ext4"));
    CHECK(env_features_has_filesystem(&e, "sysfs"));
    CHECK(env_features_has_filesystem(&e, "proc"));
    CHECK(!env_features_has_filesystem(&e, "btrfs"));
    // whole-token: "ext" must NOT match "ext4"; "ext4" must NOT match a longer token
    CHECK(!env_features_has_filesystem(&e, "ext"));
    CHECK(env_features_append_filesystem(&e, "ext4dev"));
    CHECK(env_features_has_filesystem(&e, "ext4dev"));
    CHECK(env_features_has_filesystem(&e, "ext4"));     // still its own token
    CHECK(!env_features_has_filesystem(&e, ""));
    CHECK(!env_features_has_filesystem(nullptr, "ext4"));

    // overflow guard: filling past capacity returns 0, no corruption
    struct EnvFeatures big;
    std::memset(&big, 0, sizeof(big));
    int appended = 0;
    while (env_features_append_filesystem(&big, "xfsxfsxfs")) {
        ++appended;
        CHECK(big.filesystems_len <= ENV_FILESYSTEMS_CAP);
    }
    CHECK(appended > 0);
    CHECK(big.filesystems_len <= ENV_FILESYSTEMS_CAP);

    std::fprintf(stdout, "env_features_test ALL PASS (%d fs before overflow)\n", appended);
    return 0;
}
