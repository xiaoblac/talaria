// [machine-check C4.4] unit test for the transitive-resource closure
// (program/syz transitively_enabled_calls). Uses the real linux/amd64 Target.
//
// Checks the syz TransitivelyEnabledCalls semantics:
//   * a consumer with no enabled creator for a (non-optional) input resource is
//     dropped, with a "<resource> [ctors]" reason;
//   * a creator with no inputs re-enables its consumer;
//   * a no-input call always survives;
//   * the full-mask result is a fixed point and every drop carries a reason.

#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

namespace syz = ::refuzz::program::syz;

// First real, generatable call with at least one (non-optional) input resource.
const syz::SyscallMeta* find_consumer(const syz::Target& t) {
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        if (sc->is_pseudo()) continue;
        if (sc->attrs().disabled || sc->attrs().no_generate) continue;
        if (!sc->input_resources().empty()) return sc.get();
    }
    return nullptr;
}

// First call with NO input resources (self-supporting).
const syz::SyscallMeta* find_no_input(const syz::Target& t) {
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        if (sc->attrs().disabled || sc->attrs().no_generate) continue;
        if (sc->input_resources().empty()) return sc.get();
    }
    return nullptr;
}

std::vector<std::uint8_t> zero_mask(const syz::Target& t) {
    return std::vector<std::uint8_t>(t.syscalls().size(), 0);
}

std::vector<std::uint8_t> full_mask(const syz::Target& t) {
    return std::vector<std::uint8_t>(t.syscalls().size(), 1);
}

} // namespace

int main() {
    const auto& t = syz::Target::linux_amd64();

    // ---- 1. orphan consumer is dropped, with a reason ----
    const auto* k = find_consumer(t);
    CHECK(k != nullptr);
    {
        auto mask = zero_mask(t);
        mask[k->id()] = 1;   // only the consumer enabled → no creator for its input
        std::vector<syz::DisabledCall> dis;
        auto out = syz::transitively_enabled_calls(t, mask, &dis);
        CHECK(out.size() == mask.size());
        CHECK(out[k->id()] == 0);                 // dropped
        bool found = false;
        const std::string& want = k->input_resources()[0]->name();
        for (const auto& d : dis) {
            if (d.call == k) {
                found = true;
                CHECK(d.reason.rfind(want, 0) == 0);  // reason starts "<resource> ..."
            }
        }
        CHECK(found);
    }

    // ---- 2. a no-input creator re-enables its consumer ----
    {
        const syz::ResourceDesc* r = k->input_resources()[0];
        const syz::SyscallMeta*  ctor = nullptr;
        for (const auto& c : r->ctors()) {
            if (c.precise && c.call != nullptr && c.call != k &&
                c.call->input_resources().empty()) {
                ctor = c.call;
                break;
            }
        }
        if (ctor != nullptr) {
            auto mask = zero_mask(t);
            mask[k->id()]    = 1;
            mask[ctor->id()] = 1;
            auto out = syz::transitively_enabled_calls(t, mask, nullptr);
            CHECK(out[ctor->id()] == 1);   // self-supporting creator
            CHECK(out[k->id()] == 1);      // consumer now satisfied
        }
    }

    // ---- 3. a no-input call always survives, even alone ----
    {
        const auto* n = find_no_input(t);
        CHECK(n != nullptr);
        auto mask = zero_mask(t);
        mask[n->id()] = 1;
        auto out = syz::transitively_enabled_calls(t, mask, nullptr);
        CHECK(out[n->id()] == 1);
    }

    // ---- 4. full mask → fixed point + every drop carries a reason ----
    {
        auto mask = full_mask(t);
        std::vector<syz::DisabledCall> dis;
        auto s1 = syz::transitively_enabled_calls(t, mask, &dis);

        // idempotent: closing the closed set changes nothing.
        auto s2 = syz::transitively_enabled_calls(t, s1, nullptr);
        CHECK(s1 == s2);

        // every call dropped from the full mask has exactly one reason entry.
        std::size_t dropped = 0;
        for (std::size_t i = 0; i < mask.size(); ++i) {
            if (mask[i] && !s1[i]) ++dropped;
        }
        CHECK(dropped == dis.size());
    }

    std::fprintf(stdout, "transitive_enabled_calls_test ALL PASS\n");
    return 0;
}
