#include "refuzz/program/syz/generated/target_linux_amd64_call_table.gen.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace syz = ::refuzz::program::syz;

#ifndef REFUZZ_SOURCE_DIR
#error "REFUZZ_SOURCE_DIR must be defined by CMake"
#endif

void call_table_matches_full_target()
{
    const auto& target = syz::Target::linux_amd64();

    CHECK(target.data_offset() == syz::generated::kLinuxAmd64DataOffset);
    CHECK(target.syscalls().size() == syz::generated::kLinuxAmd64CallCount);

    for (std::size_t i = 0; i < syz::generated::kLinuxAmd64CallCount; ++i) {
        const auto* meta = target.syscalls()[i].get();
        CHECK(meta != nullptr);
        if (meta->nr() != syz::generated::kLinuxAmd64CallIdToNr[i]) {
            std::fprintf(stderr,
                         "nr mismatch at call_id=%zu name=%s target=%llu table=%llu\n",
                         i,
                         meta->name().c_str(),
                         static_cast<unsigned long long>(meta->nr()),
                         static_cast<unsigned long long>(
                             syz::generated::kLinuxAmd64CallIdToNr[i]));
            std::abort();
        }
    }
}

void worker_driver_does_not_load_full_target()
{
    const std::string path =
        std::string(REFUZZ_SOURCE_DIR) +
        "/executor/channel/worker/src/driver/kernel_wire_driver.cpp";
    std::ifstream in(path);
    CHECK(in.good());
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string text = ss.str();

    CHECK(text.find("Target::linux_amd64") == std::string::npos);
    CHECK(text.find("refuzz/program/syz/target.hpp") == std::string::npos);
}

} // namespace

int main()
{
    RUN_TEST(call_table_matches_full_target);
    RUN_TEST(worker_driver_does_not_load_full_target);
    return 0;
}
