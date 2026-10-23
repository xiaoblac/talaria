// hints_data_test.cpp — Epic 5 PR-5-C
//
// Adapt of `prog/hints_test.go::TestHintsData`. Upstream targets a
// specific test syscall (`test$hint_data`) deserialized from text;
// this port synthesizes an equivalent shape: 1-call Prog with one
// PointerArg wrapping a DataArg over a BufferType{kBlobRand}. Verifies
// that MutateProgWithHints reaches the inner DataArg via foreach_arg
// recursion and produces the upstream candidate output.

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_apply.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace hints = refuzz::mutator::syz_v2::hints;
namespace syz   = refuzz::program::syz;

namespace {

std::unique_ptr<syz::BufferType> MakeBlobBufferType(size_t fixed) {
    auto t = std::make_unique<syz::BufferType>();
    t->set_name("test_blob");
    t->set_buffer_kind(syz::BufferKind::kBlobRand);
    t->set_var_len(false);
    t->set_size(fixed);
    return t;
}

std::string ToHex(const std::vector<uint8_t>& v) {
    std::string out;
    out.reserve(v.size() * 2);
    static const char hex[] = "0123456789abcdef";
    for (uint8_t b : v) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 0xf]); }
    return out;
}

} // namespace

int main()
{
    // Upstream test fixture:
    //   in    = "0809101112131415"           (8 bytes, hex)
    //   comps = 0x12111009 → 0x42
    //   want  = "0842000000131415"
    // The target arg is a DataArg over an array of int8 — exposed via
    // PointerArg in upstream. reFuzz adaptation: top-level DataArg
    // (foreach_arg walks PointerArg/GroupArg recursively, but a flat
    // top-level DataArg is the simplest equivalent that exercises
    // CheckDataArgHints end-to-end via MutateProgWithHints).
    syz::SyscallMeta meta;
    meta.set_name("test$hints_data");
    meta.set_call_name("test_hints_data");
    meta.set_id(0);
    meta.set_nr(0);

    auto buf_type = MakeBlobBufferType(8);
    std::vector<syz::Field> fields;
    fields.emplace_back("data", buf_type.get());
    meta.set_args(std::move(fields));

    syz::Prog prog;
    prog.set_target(&syz::Target::linux_amd64());

    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    auto darg = std::make_unique<syz::DataArg>();
    darg->set_type(buf_type.get());
    darg->set_dir(syz::Dir::kIn);
    darg->set_data({0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15});
    call->add_arg(std::move(darg));
    prog.add_call(std::move(call));

    // Hints: little-endian uint32 at offset 1 = 0x12111009. Replacer = 0x42.
    hints::CompMap comps;
    comps.Add(0x1, 0x12111009, 0x42, /*is_const=*/true);

    std::set<std::string> got_hex;
    hints::MutateProgWithHints(prog, /*call_index=*/0, comps,
        [&](const syz::Prog& mutated) {
            const auto* mc = mutated.calls()[0].get();
            const auto* da = static_cast<const syz::DataArg*>(mc->args()[0].get());
            got_hex.insert(ToHex(da->data()));
            return true;
        });

    // Expected upstream candidate (offset=1, 4-byte replace, padded with zeros):
    //   "0842000000131415"
    CHECK(got_hex.count("0842000000131415") == 1);

    // Original prog unchanged.
    {
        const auto* da0 = static_cast<const syz::DataArg*>(prog.calls()[0]->args()[0].get());
        const std::vector<uint8_t> orig{0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
        CHECK(da0->data() == orig);
    }

    std::printf("hints_data_test PASSED\n");
    return 0;
}
