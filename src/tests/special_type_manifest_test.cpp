// Manifest test for the 14 linux/amd64 SpecialType bodies.
//
// Four deterministic cases:
//   1. AllRegistered      — every name has a non-null SpecialTypeFn.
//   2. NativeBodiesProduceArg — invoking each body returns a
//      non-null Arg with a sane ArgKind (Group for Struct,
//      Group/Union for Union schemas).
//   3. UsbBodyPatchesIds — generated USB descriptors get non-zero
//      idVendor/idProduct from the generated ID database.
//   4. NoAbort_FixedSeeds — drive 16 fixed seeds × all 14 bodies and
//      confirm none aborts. Sanitizes the abort-placeholder
//      regression that PR-3-B2 retired.

#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/mutator/linux/syz_v2/special_gen.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <cstdint>
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

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace syz    = ::refuzz::program::syz;
namespace mut_v2 = ::refuzz::mutator::syz_v2;

const std::vector<std::string>& special_names() {
    static const std::vector<std::string> v = {
        "timespec",
        "timeval",
        "sockaddr_alg",
        "alg_name",
        "alg_aead_name",
        "alg_hash_name",
        "alg_skcipher_name",
        "ipt_replace",
        "ip6t_replace",
        "arpt_replace",
        "ebt_replace",
        "usb_device_descriptor",
        "usb_device_descriptor_printer",
        "usb_device_descriptor_hid",
    };
    return v;
}

// Locate the first Type tagged with `name` in the schema (any Struct
// / Union of that name). Returns nullptr if absent.
const syz::Type* find_named_type(const syz::Target& target,
                                 const std::string& name) {
    const syz::Type* hit = nullptr;
    syz::foreach_type(target, [&](const syz::Type* t, syz::TypeCtx* ctx) {
        if (hit != nullptr) { ctx->stop = true; return; }
        if (t == nullptr) return;
        if (t->name() != name) return;
        if (t->kind() == syz::TypeKind::kStruct ||
            t->kind() == syz::TypeKind::kUnion) {
            hit = t;
            ctx->stop = true;
        }
    });
    return hit;
}

void test_all_registered() {
    const auto& target = syz::Target::linux_amd64();
    for (const auto& name : special_names()) {
        const auto* fn = target.find_special_type(name);
        if (fn == nullptr) {
            std::fprintf(stderr, "missing special type: %s\n", name.c_str());
            CHECK(fn != nullptr);
        }
    }
}

void test_native_bodies_produce_arg() {
    const auto& target = syz::Target::linux_amd64();
    int produced = 0;
    int skipped  = 0;
    std::vector<std::string> failed;
    for (const auto& name : special_names()) {
        const auto* fn = target.find_special_type(name);
        CHECK(fn != nullptr);
        const syz::Type* typ = find_named_type(target, name);
        if (typ == nullptr) {
            // Schema doesn't carry this type — skip; AllRegistered
            // already proved the function is registered.
            ++skipped;
            continue;
        }
        mut_v2::RandGen r(0xB2B20000ULL);
        mut_v2::GenState s(target);
        mut_v2::GenImpl g(r, s);
        std::vector<std::unique_ptr<syz::Call>> extras;
        auto arg = (*fn)(&g, typ, syz::Dir::kIn, /*old=*/nullptr, &extras);
        if (arg == nullptr) {
            failed.push_back(name + " (null arg)");
            continue;
        }
        if (arg->type() != typ) {
            failed.push_back(name + " (type mismatch)");
            continue;
        }
        const auto kind = arg->arg_kind();
        if (kind != syz::ArgKind::kGroup && kind != syz::ArgKind::kUnion) {
            failed.push_back(name + " (wrong arg_kind)");
            continue;
        }
        ++produced;
    }
    std::fprintf(stderr, "  produced=%d skipped=%d failed=%zu\n",
                 produced, skipped, failed.size());
    for (const auto& f : failed) {
        std::fprintf(stderr, "  BODY FAILED: %s\n", f.c_str());
    }
    // Per-body assertion: every name whose schema-type is present
    // must produce a sane arg. PR-3-B2 ships full native bodies for
    // all 14 names — any individual body regression must surface
    // here by name (not be hidden by an aggregate threshold).
    CHECK(failed.empty());
    // produced >= 1 catches the pathological case where every body
    // schema-skipped (would mean find_named_type broke).
    CHECK(produced >= 1);
}

// USB body patch sanity: drive usb_device_descriptor across a
// deterministic seed sweep and verify the body actually patches
// idVendor / idProduct (i.e., they're not all zero, which is what
// the schema default would yield). A regression that removed
// patch_usb_device_id and returned the default-walk descriptor
// unmodified would leave idVendor=0 across all seeds.
//
// This is the direct signal that the kUsbIds database is wired
// into the body, beyond the weaker "registered and does not abort"
// manifest checks.
void test_usb_body_patches_ids() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fn = target.find_special_type("usb_device_descriptor");
    CHECK(fn != nullptr);
    const syz::Type* typ = find_named_type(target, "usb_device_descriptor");
    if (typ == nullptr) {
        std::fprintf(stderr, "  schema lacks usb_device_descriptor; skip\n");
        return;
    }

    int patched = 0;
    int total   = 0;
    for (uint64_t k = 0; k < 30; ++k) {
        mut_v2::RandGen r(0xD4D40000ULL + k);
        mut_v2::GenState s(target);
        mut_v2::GenImpl g(r, s);
        std::vector<std::unique_ptr<syz::Call>> extras;
        auto arg = (*fn)(&g, typ, syz::Dir::kIn, /*old=*/nullptr, &extras);
        if (arg == nullptr || arg->arg_kind() != syz::ArgKind::kGroup) continue;
        ++total;
        // Walk root → inner[0] (dev) → inner[7] (idVendor ConstArg).
        auto* root = static_cast<const syz::GroupArg*>(arg.get());
        if (root->inner().empty()) continue;
        const auto* dev = root->inner()[0].get();
        if (dev == nullptr || dev->arg_kind() != syz::ArgKind::kGroup) continue;
        const auto* dev_g = static_cast<const syz::GroupArg*>(dev);
        if (dev_g->inner().size() < 9) continue;
        const auto* id_vendor = dev_g->inner()[7].get();
        const auto* id_product = dev_g->inner()[8].get();
        if (id_vendor == nullptr || id_vendor->arg_kind() != syz::ArgKind::kConst) continue;
        if (id_product == nullptr || id_product->arg_kind() != syz::ArgKind::kConst) continue;
        const auto v = static_cast<const syz::ConstArg*>(id_vendor)->val();
        const auto p = static_cast<const syz::ConstArg*>(id_product)->val();
        // patchNonMatching=true means EVERY id record yields non-zero
        // idVendor and idProduct (either real match-table values or
        // RNG-generated values for non-matching slots). A run with
        // both fields zero across 30 seeds means the patch path is
        // dead.
        if (v != 0 || p != 0) ++patched;
    }
    std::fprintf(stderr, "  patched=%d (of %d successful gens)\n",
                 patched, total);
    CHECK(total >= 10);     // schema produces a usable arg most of the time
    CHECK(patched >= total - 2);  // overwhelming majority must show patched IDs
}

void test_no_abort_fixed_seeds() {
    const auto& target = syz::Target::linux_amd64();
    for (uint64_t seed = 0xC3C30000ULL; seed < 0xC3C30000ULL + 16; ++seed) {
        for (const auto& name : special_names()) {
            const auto* fn = target.find_special_type(name);
            CHECK(fn != nullptr);
            const syz::Type* typ = find_named_type(target, name);
            if (typ == nullptr) continue;
            mut_v2::RandGen r(seed);
            mut_v2::GenState s(target);
            mut_v2::GenImpl g(r, s);
            std::vector<std::unique_ptr<syz::Call>> extras;
            auto arg = (*fn)(&g, typ, syz::Dir::kIn, /*old=*/nullptr, &extras);
            (void)arg;  // each invocation just needs to NOT abort.
        }
    }
}

} // namespace

int main() {
    RUN_TEST(test_all_registered);
    RUN_TEST(test_native_bodies_produce_arg);
    RUN_TEST(test_usb_body_patches_ids);
    RUN_TEST(test_no_abort_fixed_seeds);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
