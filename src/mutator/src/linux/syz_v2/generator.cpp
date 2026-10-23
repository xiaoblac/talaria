// Implementation of refuzz/mutator/linux/syz_v2/generator.hpp.
//
// Per-type generators dispatch on Type::kind(). Each branch is a port of
// the corresponding `(*XxxType).generate(...)` method in prog/rand.go.

#include "refuzz/mutator/linux/syz_v2/generator.hpp"

#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"
#include "refuzz/mutator/linux/syz_v2/special_gen.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/alloc.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/expr.hpp"
#include "refuzz/program/syz/sanitize.hpp"
#include "refuzz/program/syz/transform.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <unordered_set>

namespace refuzz::mutator::syz_v2 {

namespace {

constexpr uint64_t kProcDefaultValue = ~uint64_t{0};

// Mirror of prog.Type.TypeBitSize.
uint64_t type_bit_size(const syz::Type* t) {
    if (t == nullptr) return 64;
    if (t->is_bitfield()) return t->bitfield_length();
    return t->size() * 8;
}

std::unique_ptr<syz::ConstArg> make_const_arg(const syz::Type* t,
                                              syz::Dir dir, uint64_t v) {
    auto a = std::make_unique<syz::ConstArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_val(v);
    return a;
}

std::unique_ptr<syz::DataArg> make_data_arg(const syz::Type* t, syz::Dir dir,
                                            std::vector<uint8_t> data) {
    auto a = std::make_unique<syz::DataArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_data(std::move(data));
    return a;
}

std::unique_ptr<syz::DataArg> make_out_data_arg(const syz::Type* t,
                                                syz::Dir dir,
                                                uint64_t out_size) {
    auto a = std::make_unique<syz::DataArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_out_size(out_size);
    return a;
}

std::unique_ptr<syz::PointerArg> make_pointer_arg(const syz::Type* t,
                                                  syz::Dir dir,
                                                  uint64_t addr,
                                                  std::unique_ptr<syz::Arg> res) {
    auto a = std::make_unique<syz::PointerArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_address(addr);
    a->set_res(std::move(res));
    return a;
}

std::unique_ptr<syz::PointerArg> make_vma_pointer_arg(const syz::Type* t,
                                                      syz::Dir dir,
                                                      uint64_t page,
                                                      uint64_t size_pages,
                                                      uint64_t page_size) {
    auto a = std::make_unique<syz::PointerArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_address(page * page_size);
    a->set_vma_size(size_pages * page_size);
    return a;
}

std::unique_ptr<syz::ResultArg> make_result_arg(const syz::Type* t,
                                                syz::Dir dir, uint64_t val) {
    auto a = std::make_unique<syz::ResultArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_val(val);
    return a;
}

std::unique_ptr<syz::GroupArg> make_group_arg(const syz::Type* t, syz::Dir dir,
                                              std::vector<std::unique_ptr<syz::Arg>> inner) {
    auto a = std::make_unique<syz::GroupArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_inner(std::move(inner));
    return a;
}

std::unique_ptr<syz::UnionArg> make_union_arg(const syz::Type* t, syz::Dir dir,
                                              std::unique_ptr<syz::Arg> opt,
                                              int idx) {
    auto a = std::make_unique<syz::UnionArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_option(std::move(opt));
    a->set_index(idx);
    return a;
}

// Mirror of rand.go::randString (rand.go:346-371).
std::vector<uint8_t> rand_string_payload(RandGen& r, GenState& s,
                                         const syz::BufferType* bt) {
    // Enumerated string type → ALWAYS pick one of its values (no probability
    // gate — the previous 1000/1011 gate was spurious).
    if (!bt->values().empty()) {
        const auto& v =
            bt->values()[r.rand(static_cast<int>(bt->values().size()))];
        return std::vector<uint8_t>(v.begin(), v.end());
    }
    // 50% of the time reuse a string observed elsewhere in the program
    // (randFromMap: deterministic sorted-uniform pick over s.strings).
    const auto& pool = s.strings();
    if (!pool.empty() && r.bin()) {
        std::vector<const std::string*> keys;
        keys.reserve(pool.size());
        for (const std::string& str : pool) keys.push_back(&str);
        std::sort(keys.begin(), keys.end(),
                  [](const std::string* a, const std::string* b) { return *a < *b; });
        const std::string& chosen = *keys[r.rand(static_cast<int>(keys.size()))];
        return std::vector<uint8_t>(chosen.begin(), chosen.end());
    }
    // Otherwise build a punctuation-biased, geometric-length string —
    // punctuation hits string-parser edge cases far more than uniform random
    // bytes do (rand.go:355-364).
    static const uint8_t kPunct[] = {
        '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '\\',
        '/', ':', '.', ',', '-', '\'', '[', ']', '{', '}'};
    std::vector<uint8_t> buf;
    while (r.n_out_of(3, 4)) {
        if (r.n_out_of(10, 11)) {
            buf.push_back(kPunct[r.rand(static_cast<int>(sizeof(kPunct)))]);
        } else {
            buf.push_back(static_cast<uint8_t>(r.rand(256)));
        }
    }
    // Null-terminate unless the type is explicitly no_z (rand.go:367-369):
    // oneOf(100) == NoZ → ~99% terminate for normal strings, ~1% for no_z.
    if (r.one_of(100) == bt->no_z()) {
        buf.push_back(0);
    }
    return buf;
}

std::vector<uint8_t> rand_blob_payload(RandGen& r, uint64_t size) {
    std::vector<uint8_t> v(size);
    for (uint64_t i = 0; i < size; ++i) v[i] = static_cast<uint8_t>(r.rand(256));
    return v;
}

// Produce a short non-escaping random name (used for glob patterns, which are
// not part of the file tree).
std::vector<uint8_t> rand_filename_payload(RandGen& r) {
    int len = static_cast<int>(r.rand(8) + 1);
    std::string s = "./";
    for (int i = 0; i < len; ++i) {
        char c = static_cast<char>('a' + r.rand(26));
        s.push_back(c);
    }
    s.push_back('\0');
    return std::vector<uint8_t>(s.begin(), s.end());
}

// Mirror of rand.go::filenameImpl — reuse the in-program file pool so generated
// path arguments target a shared, growing directory tree (and, after a
// syz_mount_image, paths under the mountpoint) instead of always minting a
// fresh, unrelated ./xxxx that the kernel rejects at path lookup (ENOENT)
// before reaching the mounted fs. Pool entries (GenState::files) carry a
// trailing '\0' per the filename-payload convention; strip it when reusing an
// entry as a directory prefix.
std::vector<uint8_t> gen_filename_payload(RandGen& r, GenState& s) {
    auto to_bytes = [](std::string str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    };
    const auto& files = s.files();

    // 1/100: special file ("" or ".").
    if (r.one_of(100)) {
        static const char* const kSpecial[] = {"", "."};
        std::string sp = kSpecial[r.rand(2)];
        sp.push_back('\0');
        return to_bytes(std::move(sp));
    }

    // randFromMap: uniform pick over the pool, iterated in sorted order for
    // determinism (mirrors syz; pick_existing_resource sorts for the same
    // reason).
    auto rand_from_files = [&]() -> std::string {
        std::vector<const std::string*> keys;
        keys.reserve(files.size());
        for (const std::string& f : files) keys.push_back(&f);
        std::sort(keys.begin(), keys.end(),
                  [](const std::string* a, const std::string* b) { return *a < *b; });
        return *keys[r.rand(static_cast<int>(keys.size()))];
    };

    if (files.empty() || r.one_of(10)) {
        // Generate a new name, optionally nested under an existing entry so the
        // program builds a real directory tree. Names are deterministic
        // (dir/fileN), so independently generated/mutated calls converge on the
        // same paths and operate on each other's files.
        std::string dir = ".";
        if (r.bin() && !files.empty()) {
            dir = rand_from_files();
            if (!dir.empty() && dir.back() == '\0') dir.pop_back();
            // syz also escapes here via "/.." (r.oneOf(10)); reFuzz keeps
            // generated paths non-escaping, so that branch is omitted.
        }
        for (int i = 0;; ++i) {
            std::string f = dir + "/file" + std::to_string(i);
            f.push_back('\0');
            if (files.find(f) == files.end()) return to_bytes(std::move(f));
        }
    }

    // Reuse an existing path (the common case once the pool is non-empty).
    return to_bytes(rand_from_files());
}

// Mirror of rand.go::existingResource. Walks every bucket in
// GenState sorted by name, runs the primary compat check on
// desc->name(), plus a 1/50 broadening check against desc->kind()[0],
// aggregates matches, and uniformly picks one. nullptr when no
// compatible producer exists in the partial program.
syz::ResultArg* pick_existing_resource(RandGen& r, GenState& s,
                                       const syz::ResourceDesc* desc) {
    if (desc == nullptr) return nullptr;
    const auto& res_map = s.resources_map();
    if (res_map.empty()) return nullptr;

    // Collect bucket pointers, sorted by name for determinism.
    std::vector<std::pair<const std::string*,
                          const std::vector<syz::ResultArg*>*>> buckets;
    buckets.reserve(res_map.size());
    for (const auto& kv : res_map) {
        if (kv.second.empty()) continue;
        buckets.emplace_back(&kv.first, &kv.second);
    }
    std::sort(buckets.begin(), buckets.end(),
              [](const auto& a, const auto& b) { return *a.first < *b.first; });

    const auto& target = s.target();
    const std::string& dst_name = desc->name();
    const bool has_kind0 = !desc->kind().empty();
    const std::string  dst_kind0 = has_kind0 ? desc->kind()[0] : std::string{};

    std::vector<syz::ResultArg*> all;
    for (const auto& [name_ptr, vec_ptr] : buckets) {
        const std::string& src_name = *name_ptr;
        const bool primary = target.is_compatible_resource(dst_name, src_name);
        bool broaden = false;
        if (!primary && has_kind0 && r.one_of(50)) {
            broaden = target.is_compatible_resource(dst_kind0, src_name);
        }
        if (primary || broaden) {
            for (auto* a : *vec_ptr) all.push_back(a);
        }
    }
    if (all.empty()) return nullptr;
    return all[r.rand(static_cast<int>(all.size()))];
}

// Forward decls for the type dispatch.
GenResult gen_int(RandGen& r, GenState& s, const syz::IntType* t, syz::Dir d);
GenResult gen_const(const syz::ConstType* t, syz::Dir d);
GenResult gen_flags(RandGen& r, const syz::FlagsType* t, syz::Dir d);
GenResult gen_len(const syz::LenType* t, syz::Dir d);
GenResult gen_proc(RandGen& r, const syz::ProcType* t, syz::Dir d);
GenResult gen_csum(const syz::CsumType* t, syz::Dir d);
GenResult gen_vma(RandGen& r, GenState& s, const syz::VmaType* t, syz::Dir d);
GenResult gen_buffer(RandGen& r, GenState& s, const syz::BufferType* t, syz::Dir d);
GenResult gen_array(RandGen& r, GenState& s, const syz::ArrayType* t, syz::Dir d);
GenResult gen_struct(RandGen& r, GenState& s, const syz::StructType* t, syz::Dir d);
GenResult gen_union(RandGen& r, GenState& s, const syz::UnionType* t, syz::Dir d);
GenResult gen_ptr(RandGen& r, GenState& s, const syz::PtrType* t, syz::Dir d);
GenResult gen_resource(RandGen& r, GenState& s, const syz::ResourceType* t, syz::Dir d);
// create_resource / resource_centric are declared in the public
// header (mutator/include/.../generator.hpp); definitions live at
// file scope below the anonymous namespace.

// Out-direction int-like args must equal the type's default value
// (validation enforces this — see prog/validation.go::validateConstArg).
// For ConstType the default is `Val`; for everything else it's 0.

GenResult gen_int(RandGen& r, GenState& /*s*/, const syz::IntType* t, syz::Dir d) {
    if (d == syz::Dir::kOut) return {make_const_arg(t, d, 0), {}};
    const uint64_t bits = type_bit_size(t);
    uint64_t v;
    if (t->int_kind() == syz::IntType::Kind::kRange) {
        v = r.rand_range_int(t->range_begin(), t->range_end(), bits, t->int_align());
    } else {
        v = r.rand_int(bits);
    }
    return {make_const_arg(t, d, v), {}};
}

GenResult gen_const(const syz::ConstType* t, syz::Dir d) {
    return {make_const_arg(t, d, t->val()), {}};
}

GenResult gen_flags(RandGen& r, const syz::FlagsType* t, syz::Dir d) {
    if (d == syz::Dir::kOut) return {make_const_arg(t, d, 0), {}};
    const uint64_t v = r.flags(t->vals(), t->bitmask(), 0);
    return {make_const_arg(t, d, v), {}};
}

GenResult gen_len(const syz::LenType* t, syz::Dir d) {
    // Filled at finalize by assign_sizes; placeholder here. Same rule
    // applies for Out (default = 0).
    return {make_const_arg(t, d, 0), {}};
}

GenResult gen_proc(RandGen& r, const syz::ProcType* t, syz::Dir d) {
    if (d == syz::Dir::kOut) {
        // ProcType default is procDefaultValue (~0); see arg.cpp
        // is_default_arg + validation per-proc check.
        return {make_const_arg(t, d, kProcDefaultValue), {}};
    }
    uint64_t v = r.rand(static_cast<int>(t->values_per_proc()));
    return {make_const_arg(t, d, v), {}};
}

GenResult gen_csum(const syz::CsumType* t, syz::Dir d) {
    return {make_const_arg(t, d, 0), {}};
}

GenResult gen_vma(RandGen& r, GenState& s, const syz::VmaType* t, syz::Dir d) {
    // [syz-parity rand.go:888-893] No range → weighted randPageCount
    // (1..a few, occasionally up to ~20 or NumPages/4), NOT a fixed 1 page.
    // With a range → uniform in [RangeBegin, RangeEnd].
    uint64_t pages;
    if (t->range_begin() != 0 || t->range_end() != 0) {
        pages = r.rand_range(t->range_begin(), t->range_end());
    } else {
        pages = r.rand_page_count(s.va().num_pages());
    }
    if (pages == 0) pages = 1;
    if (pages > s.va().num_pages()) pages = s.va().num_pages();
    uint64_t page = s.va().alloc(r, pages);
    return {make_vma_pointer_arg(t, d, page, pages, s.target().page_size()), {}};
}

GenResult gen_buffer(RandGen& r, GenState& s, const syz::BufferType* t,
                     syz::Dir d) {
    if (d == syz::Dir::kOut) {
        uint64_t sz = (t->var_len() ? r.rand_buf_len() : t->size());
        return {make_out_data_arg(t, d, sz), {}};
    }
    std::vector<uint8_t> body;
    switch (t->buffer_kind()) {
        case syz::BufferKind::kBlobRand: {
            uint64_t sz = (t->var_len() ? r.rand_buf_len() : t->size());
            body = rand_blob_payload(r, sz);
            break;
        }
        case syz::BufferKind::kBlobRange: {
            uint64_t sz = r.rand_range(t->range_begin(), t->range_end());
            body = rand_blob_payload(r, sz);
            break;
        }
        case syz::BufferKind::kString:
            body = rand_string_payload(r, s, t);
            break;
        case syz::BufferKind::kFilename:
            body = gen_filename_payload(r, s);
            s.note_file(std::string(body.begin(), body.end()));
            break;
        case syz::BufferKind::kGlob:
            body = rand_filename_payload(r);
            break;
        case syz::BufferKind::kText: {
            // Defer ifuzz integration; emit a small random byte blob —
            // sufficient for syscalls that take BPF/insn buffers without
            // crashing the validator.
            uint64_t sz = r.rand(64) + 1;
            body = rand_blob_payload(r, sz);
            break;
        }
        case syz::BufferKind::kCompressed: {
            // Emit a tiny "compressed" header — generation here is best-
            // effort; real compressed-data mutations come in §3.5.
            body = {uint8_t{0x1f}, uint8_t{0x8b}, uint8_t{0x08},
                    uint8_t{0}, uint8_t{0}, uint8_t{0}, uint8_t{0},
                    uint8_t{0}, uint8_t{0}, uint8_t{0}};
            break;
        }
    }
    return {make_data_arg(t, d, std::move(body)), {}};
}

GenResult gen_array(RandGen& r, GenState& s, const syz::ArrayType* t, syz::Dir d) {
    uint64_t n;
    if (t->array_kind() == syz::ArrayKind::kRangeLen) {
        n = r.rand_range(t->range_begin(), t->range_end());
    } else {
        n = r.rand_array_len();
    }
    // syz rand.go:931-934 — the resource being generated may live in the array
    // elements, so create at least one while inside resource generation.
    if (s.in_generate_resource() && n == 0) {
        n = 1;
    }
    std::vector<std::unique_ptr<syz::Arg>> inner;
    std::vector<std::unique_ptr<syz::Call>> calls;
    inner.reserve(n);
    for (uint64_t i = 0; i < n; ++i) {
        auto sub = generate_arg(r, s, t->elem(), d);
        inner.push_back(std::move(sub.arg));
        for (auto& c : sub.calls) calls.push_back(std::move(c));
    }
    return {make_group_arg(t, d, std::move(inner)), std::move(calls)};
}

GenResult gen_struct(RandGen& r, GenState& s, const syz::StructType* t, syz::Dir d) {
    auto fr = generate_args(r, s, t->fields(), d);
    return {make_group_arg(t, d, std::move(fr.args)), std::move(fr.calls)};
}

GenResult gen_union(RandGen& r, GenState& s, const syz::UnionType* t, syz::Dir d) {
    if (t->fields().empty()) {
        // No arms — emit zero-value Const placeholder.
        return {make_const_arg(nullptr, d, 0), {}};
    }
    if (t->is_conditional()) {
        // [syz-parity rand.go:951-954] A conditional union's arm is chosen by
        // its sibling-field conditions, which may not be generated yet. Emit
        // the type's transient default arm now; patch_conditional_fields
        // selects a condition-matching arm once the whole call is built.
        return {t->default_arg(d), {}};
    }
    const int idx = static_cast<int>(r.rand(static_cast<int>(t->fields().size())));
    const auto& f = t->fields()[idx];
    auto sub = generate_arg(r, s, f.type(), f.dir(d));
    return {make_union_arg(t, d, std::move(sub.arg), idx), std::move(sub.calls)};
}

GenResult gen_ptr(RandGen& r, GenState& s, const syz::PtrType* t, syz::Dir d) {
    // syz rand.go:971-976 — occasionally emit a special pointer (NULL or one
    // of target.SpecialPointers). Gated on !in_generate_resource (an empty
    // special ptr while creating a resource behind it would lose the resource),
    // NOT on optional — any pointer can take a special value. Pick a random
    // index, not always NULL. (Optional-ptr recursion depth still yields NULL
    // via depth_name_prologue.) Special-pointer encoding: address = -(index),
    // see PointerArg::is_special.
    if (!s.in_generate_resource() && r.one_of(1000)) {
        const auto& sp = s.target().special_pointers();
        if (!sp.empty()) {
            const uint64_t idx = r.rand(static_cast<int>(sp.size()));
            auto a = std::make_unique<syz::PointerArg>();
            a->set_type(t);
            a->set_dir(d);
            a->set_address(static_cast<uint64_t>(-static_cast<int64_t>(idx)));
            return {std::move(a), {}};
        }
    }
    auto sub = generate_arg(r, s, t->elem(), t->elem_dir());
    const uint64_t sz = (sub.arg && sub.arg->type() && !sub.arg->type()->var_len())
                          ? sub.arg->type()->size()
                          : (sub.arg ? sub.arg->size() : 0);
    const uint64_t align = (sub.arg && sub.arg->type()) ? sub.arg->type()->align() : 0;
    const uint64_t addr = s.ma().alloc(sz == 0 ? 1 : sz, align == 0 ? 1 : align);
    return {make_pointer_arg(t, d, addr, std::move(sub.arg)), std::move(sub.calls)};
}

// Helper: build a ResultArg referring to an existing producer.
std::unique_ptr<syz::ResultArg> wrap_existing(const syz::ResourceType* t,
                                              syz::Dir d,
                                              syz::ResultArg* existing) {
    auto a = std::make_unique<syz::ResultArg>();
    a->set_type(t);
    a->set_dir(d);
    a->set_res(existing);
    a->set_val(0);
    return a;
}

// Mirror of rand.go::(*ResourceType).generate (lines 752-788).
//
// Three-branch dispatch:
//   1. existingResource via pick_existing_resource — preference
//      8/10 when can_recurse, 19/20 when already inside createResource.
//   2. resourceCentric (1/4) — corpus-walk producer chain.
//   3. createResource (4/5) — recursive ctor walk.
//   4. fallback to default value.
GenResult gen_resource(RandGen& r, GenState& s, const syz::ResourceType* t,
                       syz::Dir d) {
    if (d == syz::Dir::kOut) {
        // OUT resource: produce a fresh ResultArg without backing.
        return {make_result_arg(t, d, 0), {}};
    }
    const bool can_recurse = !s.in_generate_resource();
    const bool prefer_existing = can_recurse
        ? r.n_out_of(8, 10) : r.n_out_of(19, 20);
    if (prefer_existing) {
        if (auto* existing = pick_existing_resource(r, s, t->desc())) {
            return {wrap_existing(t, d, existing), {}};
        }
    }
    if (can_recurse) {
        if (r.one_of(4)) {
            GenResult rc = resource_centric(r, s, t, d);
            if (rc.arg != nullptr) return rc;
        }
        if (r.n_out_of(4, 5)) {
            GenResult cr = create_resource(r, s, t, d);
            if (cr.arg != nullptr) return cr;
        }
    }
    // Fall back to a special value (rand.go:823-824): a ResultArg with no
    // producer and a literal drawn UNIFORMLY from the resource's special
    // values — not always Values[0], so each sentinel (-1, AT_FDCWD, …) gets
    // explored.
    uint64_t def = 0;
    if (t->desc() != nullptr && !t->desc()->values().empty()) {
        const auto& vals = t->desc()->values();
        def = vals[r.rand(static_cast<int>(vals.size()))];
    }
    return {make_result_arg(t, d, def), {}};
}

// RAII guard for the GenState::in_generate_resource_ latch.
struct InGenResourceGuard {
    GenState* s;
    bool      prior;
    explicit InGenResourceGuard(GenState& gs)
        : s(&gs), prior(gs.in_generate_resource()) {
        s->set_in_generate_resource(true);
    }
    ~InGenResourceGuard() { s->set_in_generate_resource(prior); }
};

} // namespace

// =========================================================================
// Public resource-creation entries (declared in generator.hpp).
//
// These live at file scope (not in the anonymous namespace) so unit tests
// can call them directly. They still consume anonymous-ns helpers
// (wrap_existing, InGenResourceGuard) by name lookup within the same TU.
// =========================================================================

// Bumps when resource_centric falls back to TextDecoder.decode on a
// legacy artifact-less seed. Production v2 corpora carry artifact;
// the oracle asserts this stays at 0.
namespace { thread_local uint64_t g_rc_payload_fallback_hits = 0; }

uint64_t resource_centric_payload_fallback_hits() {
    return g_rc_payload_fallback_hits;
}
void reset_resource_centric_payload_fallback_hits() {
    g_rc_payload_fallback_hits = 0;
}

// Mirror of rand.go::resourceCentric + getCompatibleResources.
GenResult resource_centric(RandGen& r, GenState& s,
                           const syz::ResourceType* t, syz::Dir d) {
    if (t == nullptr) return {nullptr, {}};
    const auto* corpus = s.corpus_store();
    if (corpus == nullptr) return {nullptr, {}};
    const auto& target = s.target();
    const syz::ResourceDesc* desc = t->desc();
    if (desc == nullptr) return {nullptr, {}};

    std::vector<const ::refuzz::fuzzer::Seed*> seeds;
    corpus->ForEachSeed([&](const ::refuzz::fuzzer::Seed& seed) {
        seeds.push_back(&seed);
    });
    if (seeds.empty()) return {nullptr, {}};

    // Fisher-Yates permutation over seed indices.
    std::vector<size_t> idx(seeds.size());
    for (size_t i = 0; i < idx.size(); ++i) idx[i] = i;
    for (size_t i = idx.size(); i > 1; --i) {
        const size_t j = static_cast<size_t>(r.rand(static_cast<int>(i)));
        std::swap(idx[i - 1], idx[j]);
    }

    // Lazy: constructed only when the legacy fallback branch fires;
    // reused for the rest of this call.
    std::unique_ptr<syz::TextDecoder> decoder;
    auto get_decoder = [&]() -> syz::TextDecoder& {
        if (!decoder) {
            decoder = std::make_unique<syz::TextDecoder>(target);
        }
        return *decoder;
    };

    // Mirror of upstream getCompatibleResources (rand.go:1031-1046).
    // Each candidate carries its source-call index so the caller can
    // locate the cloned counterpart in O(1) without a second arg-tree
    // walk; DeepClone preserves call ordering.
    struct Candidate {
        const syz::ResultArg* arg;
        size_t                call_idx;
    };
    const std::string& want = desc->name();
    auto find_compat = [&](const syz::Prog& p) {
        std::vector<Candidate> out;
        for (size_t ci = 0; ci < p.calls().size(); ++ci) {
            const auto& c = p.calls()[ci];
            if (!c) continue;
            ::refuzz::program::syz::foreach_arg(
                c.get(),
                [&](syz::Arg* arg, ::refuzz::program::syz::ArgCtx*) {
                    if (arg == nullptr) return;
                    if (arg->arg_kind() != syz::ArgKind::kResult) return;
                    auto* ra = static_cast<syz::ResultArg*>(arg);
                    if (ra->dir() != syz::Dir::kOut) return;
                    if (ra->uses().empty()) return;
                    const syz::Type* aty = ra->type();
                    if (aty == nullptr ||
                        aty->kind() != syz::TypeKind::kResource) return;
                    const auto* rt =
                        static_cast<const syz::ResourceType*>(aty);
                    if (rt->desc() == nullptr) return;
                    if (!target.is_compatible_resource(
                            want, rt->desc()->name())) return;
                    out.push_back({ra, ci});
                });
        }
        return out;
    };

    std::unique_ptr<syz::Prog> cloned;
    syz::ResultArg* picked_clone = nullptr;
    syz::Call*      picked_call  = nullptr;  // Call* identity, used by
                                             // post-prune index lookup.
    for (size_t k : idx) {
        const auto& seed = *seeds[k];

        // Artifact-first contract: prefer seed.artifact->As<Prog>();
        // legacy fallback decodes seed.payload but increments the
        // diagnostic counter so oracle #29 can pin "no payload decode
        // on the v2 hot path".
        std::shared_ptr<const syz::Prog> src_shared;
        if (seed.artifact != nullptr) {
            src_shared = seed.artifact->As<syz::Prog>();
        }
        std::unique_ptr<syz::Prog> decoded_owner;
        const syz::Prog* prog_view = src_shared.get();
        if (prog_view == nullptr) {
            if (seed.payload.empty()) continue;
            ++g_rc_payload_fallback_hits;
            std::string_view text(
                reinterpret_cast<const char*>(seed.payload.data()),
                seed.payload.size());
            auto decoded = get_decoder().decode(text);
            if (!decoded.has_value() || !decoded.value()) continue;
            decoded_owner = std::move(decoded.value());
            prog_view = decoded_owner.get();
        }
        if (prog_view == nullptr || prog_view->calls().empty()) continue;

        auto candidates = find_compat(*prog_view);
        if (candidates.empty()) continue;

        syz::ResultMap remap;
        cloned = syz::DeepClone(*prog_view, &remap);
        const Candidate& chosen =
            candidates[r.rand(static_cast<int>(candidates.size()))];
        auto it = remap.find(chosen.arg);
        if (it == remap.end() || it->second == nullptr ||
            chosen.call_idx >= cloned->calls().size()) {
            cloned.reset();
            continue;
        }
        picked_clone = it->second;
        picked_call  = cloned->mutable_calls()[chosen.call_idx].get();
        break;
    }

    if (picked_clone == nullptr || cloned == nullptr) {
        return {nullptr, {}};
    }

    // Prune unrelated calls back-to-front (mirror rand.go:996-1017).
    // Walking from the back keeps the earlier-index elements stable
    // across each RemoveCall.
    std::unordered_set<const syz::ResultArg*> related;
    related.insert(picked_clone);

    for (size_t i = cloned->calls().size(); i > 0;) {
        --i;
        bool include = false;
        std::vector<const syz::ResultArg*> new_resources;
        ::refuzz::program::syz::foreach_arg(
            cloned->mutable_calls()[i].get(),
            [&](syz::Arg* arg, ::refuzz::program::syz::ArgCtx*) {
                if (arg == nullptr) return;
                if (arg->arg_kind() != syz::ArgKind::kResult) return;
                auto* ra = static_cast<syz::ResultArg*>(arg);
                const syz::ResultArg* res = ra->res();
                if (res != nullptr &&
                    related.find(res) == related.end()) {
                    new_resources.push_back(res);
                }
                if (related.find(ra) != related.end() ||
                    (res != nullptr &&
                     related.find(res) != related.end())) {
                    include = true;
                }
            });
        if (include) {
            for (const syz::ResultArg* res : new_resources) {
                related.insert(res);
            }
        } else {
            // RemoveCall refuses to empty the prog; safe because the
            // call producing picked_clone is always included
            // (related[picked_clone]==true), so calls.size() stays
            // >= 1 throughout.
            ::refuzz::program::syz::RemoveCall(*cloned, i);
        }
    }

    // Biased length cap (rand.go:1019-1026). C++ vs Go semantic note:
    // upstream relies on Go GC to keep the picked ResultArg alive after
    // slice trim. In reFuzz, RemoveCall destroys the unique_ptr<Call>
    // and frees its ResultArg subtree — so biased_len MUST be floored
    // at picked_call's current index + 1 or wrap_existing later
    // dereferences a freed pointer. picked_call's identity was
    // captured at clone time; locating its post-prune index is a
    // pointer-compare scan, no arg-tree walk.
    {
        const int n = static_cast<int>(cloned->calls().size());
        if (n > 2) {
            int picked_idx = -1;
            for (int ci = 0; ci < n; ++ci) {
                if (cloned->mutable_calls()[ci].get() == picked_call) {
                    picked_idx = ci;
                    break;
                }
            }
            int biased_len = 2 + r.biased_rand(n - 1, 10);
            if (picked_idx >= 0 && picked_idx + 1 > biased_len) {
                biased_len = picked_idx + 1;
            }
            if (biased_len < n) {
                for (int i = n - 1; i >= biased_len; --i) {
                    ::refuzz::program::syz::RemoveCall(
                        *cloned, static_cast<size_t>(i));
                }
            }
        }
    }

    std::vector<std::unique_ptr<syz::Call>> extracted =
        std::move(cloned->mutable_calls());
    return {wrap_existing(t, d, picked_clone), std::move(extracted)};
}

// Bumps on every post-swap ANYRES spoof (rand.go:399-423) where
// kind/desc/ctors actually got replaced.
namespace { thread_local uint64_t g_anyres_spoof_hits = 0; }

uint64_t anyres_spoof_hits()       { return g_anyres_spoof_hits; }
void     reset_anyres_spoof_hits() { g_anyres_spoof_hits = 0; }

// Mirror of rand.go::createResource (lines 392-468). Returns
// {nullptr,{}} fail-soft instead of upstream's panic when the
// harvest is empty — production reFuzz keeps the fuzz session
// running on hostile schemas.
GenResult create_resource(RandGen& r, GenState& s,
                          const syz::ResourceType* t, syz::Dir d) {
    if (t == nullptr) return {nullptr, {}};
    InGenResourceGuard latch(s);

    const auto& target = s.target();
    const syz::ResourceDesc* desc = t->desc();
    if (desc == nullptr) return {nullptr, {}};
    std::string kind = desc->name();

    // Helper: build the enabled-ctor list for a given desc.
    // Mirrors enabledCtors: ChoiceTable generatable() when CT is wired;
    // otherwise fall back to the attribute check (!disabled && !no_generate
    // && !kfuzztest). [impl-kind removed] No pseudo-policy gate — syz's
    // (disabled) attr + the enable/disable whitelist (baked into the CT)
    // are the only pseudo filters.
    const ChoiceTable* ct = s.choice_table();
    auto enabled_ctors_for = [&](const syz::ResourceDesc* d_in)
        -> std::vector<syz::ResourceCtor> {
        std::vector<syz::ResourceCtor> out;
        if (d_in == nullptr) return out;
        for (const syz::ResourceCtor& info : d_in->ctors()) {
            if (info.call == nullptr) continue;
            const auto id = info.call->id();
            if (ct != nullptr && ct->ready()) {
                if (!ct->generatable(id)) continue;
            } else {
                const auto& a = info.call->attrs();
                if (a.disabled || a.no_generate) continue;
                if (a.kfuzztest) continue;
            }
            out.push_back(info);
        }
        return out;
    };

    std::vector<syz::ResourceCtor> ctors = enabled_ctors_for(desc);

    // ANYRES spoof (rand.go:399-423). 1/1000 attempt to swap to a
    // compat kind so the dynamic resource pool doesn't degenerate
    // into an exact-name closed system.
    if (r.one_of(1000)) {
        // Walk all resources sorted by name; collect compat names
        // against desc->kind()[0].
        std::vector<std::string> compat_names;
        const std::string& kind0 = desc->kind().empty() ? kind : desc->kind()[0];
        for (const auto& rd_up : target.resource_arena().descs()) {
            if (rd_up == nullptr) continue;
            const std::string& cand = rd_up->name();
            if (target.is_compatible_resource(kind0, cand)) {
                compat_names.push_back(cand);
            }
        }
        std::sort(compat_names.begin(), compat_names.end());
        if (!compat_names.empty()) {
            const std::string& spoof = compat_names[
                r.rand(static_cast<int>(compat_names.size()))];
            const syz::ResourceDesc* spoof_desc = target.find_resource(spoof);
            std::vector<syz::ResourceCtor> spoof_ctors =
                enabled_ctors_for(spoof_desc);
            if (!spoof_ctors.empty()) {
                kind  = spoof;
                desc  = spoof_desc;
                ctors = std::move(spoof_ctors);
                ++g_anyres_spoof_hits;
            }
        }
    }

    if (ctors.empty()) return {nullptr, {}};

    // Precise/random ctor pick (rand.go:432-447).
    const syz::SyscallMeta* meta = nullptr;
    {
        std::vector<const syz::SyscallMeta*> precise;
        for (const syz::ResourceCtor& info : ctors) {
            if (info.precise) precise.push_back(info.call);
        }
        if (!precise.empty()) {
            meta = precise[r.rand(static_cast<int>(precise.size()))];
        }
        if (meta == nullptr || r.one_of(3)) {
            meta = ctors[r.rand(static_cast<int>(ctors.size()))].call;
        }
    }
    if (meta == nullptr) return {nullptr, {}};

    // Recursive materialization (rand.go:449-451).
    auto calls = generate_particular_call(r, s, meta);
    if (calls.empty()) return {nullptr, {}};

    // Harvest matching ResultArgs from a temporary GenState. This
    // mirrors `s1 := newState(target, s.ct, nil); s1.analyze(...)`.
    // We only need the resource map of s1, not its full state.
    GenState s1(target);
    if (calls.back()) s1.analyze(calls.back().get());

    std::vector<syz::ResultArg*> all;
    {
        // Sorted iteration for determinism (mirror rand.go:459-461).
        const auto& s1_res = s1.resources_map();
        std::vector<const std::string*> keys;
        keys.reserve(s1_res.size());
        for (const auto& kv : s1_res) keys.push_back(&kv.first);
        std::sort(keys.begin(), keys.end(),
                  [](const std::string* a, const std::string* b) {
                      return *a < *b;
                  });
        for (const std::string* k : keys) {
            if (target.is_compatible_resource(kind, *k)) {
                const auto& vec = s1_res.at(*k);
                for (auto* a : vec) all.push_back(a);
            }
        }
    }
    if (all.empty()) {
        // Fail-soft: upstream panics here on TestCreateResource
        // assertions. Production reFuzz prefers caller-fallback so
        // an unusual schema doesn't kill the fuzz session.
        return {nullptr, {}};
    }

    syz::ResultArg* picked = all[r.rand(static_cast<int>(all.size()))];
    return {wrap_existing(t, d, picked), std::move(calls)};
}

// Recursion-guard state: per-thread (single-threaded today, but keep
// safe for future). Mirrors prog/rand.go::pruneRecursion + the absolute
// depth bound that prevents stack overflow on iovec-of-ptr-of-iovec
// patterns.
thread_local std::unordered_map<std::string, int> g_rec_counts;
thread_local int g_depth = 0;

// Bounds are inclusive on the *active* depth — i.e. once the count
// equals the bound, the next call refuses to descend.
constexpr int kMaxDepth         = 96;
constexpr int kMaxRecPerName    = 3;   // matches upstream pruneRecursion

struct DepthGuard {
    DepthGuard()  { ++g_depth; }
    ~DepthGuard() { --g_depth; }
};

struct NameGuard {
    std::string name;
    bool        active;
    NameGuard(const std::string& n, bool a) : name(n), active(a) {
        if (active) ++g_rec_counts[name];
    }
    ~NameGuard() {
        if (active) {
            auto it = g_rec_counts.find(name);
            if (it != g_rec_counts.end() && it->second > 0) --it->second;
        }
    }
};

// Per-kind switch. Pre-conditions: caller has already taken the
// DepthGuard / NameGuard frames and confirmed t != nullptr. Mirrors
// the per-kind tail of upstream generateArgImpl after the SpecialType
// dispatch falls through (rand.go:749 → typ.generate).
namespace {
GenResult dispatch_per_kind(RandGen& r, GenState& s, const syz::Type* t,
                            syz::Dir d) {
    switch (t->kind()) {
        case syz::TypeKind::kInt:      return gen_int   (r, s, static_cast<const syz::IntType*>(t),     d);
        case syz::TypeKind::kConst:    return gen_const (   static_cast<const syz::ConstType*>(t),      d);
        case syz::TypeKind::kFlags:    return gen_flags (r, static_cast<const syz::FlagsType*>(t),      d);
        case syz::TypeKind::kLen:      return gen_len   (   static_cast<const syz::LenType*>(t),        d);
        case syz::TypeKind::kProc:     return gen_proc  (r, static_cast<const syz::ProcType*>(t),       d);
        case syz::TypeKind::kCsum:     return gen_csum  (   static_cast<const syz::CsumType*>(t),       d);
        case syz::TypeKind::kVma:      return gen_vma   (r, s, static_cast<const syz::VmaType*>(t),     d);
        case syz::TypeKind::kBuffer:   return gen_buffer(r, s, static_cast<const syz::BufferType*>(t),  d);
        case syz::TypeKind::kArray:    return gen_array (r, s, static_cast<const syz::ArrayType*>(t),   d);
        case syz::TypeKind::kStruct:   return gen_struct(r, s, static_cast<const syz::StructType*>(t),  d);
        case syz::TypeKind::kUnion:    return gen_union (r, s, static_cast<const syz::UnionType*>(t),   d);
        case syz::TypeKind::kPtr:      return gen_ptr   (r, s, static_cast<const syz::PtrType*>(t),     d);
        case syz::TypeKind::kResource: return gen_resource(r, s, static_cast<const syz::ResourceType*>(t), d);
    }
    return {make_const_arg(t, d, 0), {}};
}

// Shared depth/name-guard prologue for both generate_arg variants.
// On overflow returns true via *out_short_circuit and writes the
// placeholder into *out_result. On success returns false and the
// caller proceeds to per-kind / SpecialType dispatch under the
// installed RAII guards.
//
// Returning the placeholder via out-params (rather than throwing)
// keeps the hot path branch-light and matches the pre-PR-3-B3
// shape of generate_arg.
bool depth_name_prologue(const syz::Type* t, syz::Dir d,
                         GenResult* out_result) {
    if (g_depth >= kMaxDepth) {
        // Recursion cutoff: emit the type's canonical default arg, which is
        // kind-correct for EVERY type (union→UnionArg, struct/array→GroupArg,
        // ptr→null PointerArg, scalar→ConstArg). Mirrors syzkaller's cutoff
        // returning typ.DefaultArg(dir) (prog/rand.go:766). Emitting a ConstArg
        // for a composite type here would break the type-kind⇒arg-kind invariant
        // every static_cast<…Arg*> consumer relies on (mutate / exec_wire /
        // clone / encoding / minimize) — that mismatch was the heap-buffer-overflow.
        *out_result = {t->default_arg(d), {}};
        return true;
    }
    const std::string& tname = t->name();

    // 对齐上游 prog/rand.go:917-928 (*PtrType).generate 的 a.Optional()
    // 守卫。原 v1 gate 对任何 Ptr 都短路,fallback 体只 set_address(0)
    // 不 set_res,产生 PointerArg(res=null, address=0) → is_special()
    // 命中 → 编码为 special pointer NULL → 非 optional ptr 永远是 NULL,
    // 该 syscall coverage 走不进 (worker_dead 现场样本 incident #3 的
    // syz_genetlink_get_family_id$auto_nbd 的 name=ptr[in,string] 就是
    // 这条路径的产物)。
    // 改成只 gate optional Ptr 后,非 optional Ptr 走正常 gen_ptr 递归;
    // 若真深递归触底,靠 line 879-882 的 g_depth>=kMaxDepth 转 ConstArg
    // (val=0,Const-encoded NULL,无害 -EFAULT) 兜底。
    // 详见 docs/plans/worker-special-pointer-fix/03_pr_b_draft.md。
    const bool gate = !tname.empty() &&
        (t->kind() == syz::TypeKind::kStruct ||
         t->kind() == syz::TypeKind::kUnion ||
         (t->kind() == syz::TypeKind::kPtr &&
          static_cast<const syz::PtrType*>(t)->optional()));
    if (gate) {
        const int cur = g_rec_counts[tname];
        if (cur >= kMaxRecPerName) {
            if (t->kind() == syz::TypeKind::kStruct) {
                *out_result = {make_group_arg(t, d, {}), {}};
                return true;
            }
            if (t->kind() == syz::TypeKind::kPtr) {
                // [v2 PR-B] 此分支现在只对 optional Ptr 触发 (gate 已守住)。
                // PointerArg(res=null, address=0) 在 is_special() 下识别为
                // NULL,与上游 MakeSpecialPointerArg(a, dir, 0) 语义等价。
                auto a = std::make_unique<syz::PointerArg>();
                a->set_type(t);
                a->set_dir(d);
                a->set_address(0);
                *out_result = {std::move(a), {}};
                return true;
            }
            // kUnion (kStruct→make_group_arg, kPtr→null PointerArg handled
            // above): emit the union's default arm as a UnionArg, never a
            // ConstArg — preserves the type-kind⇒arg-kind invariant.
            *out_result = {t->default_arg(d), {}};
            return true;
        }
    }
    return false;
}

// [syz-parity rand.go:758-776] Shared prologue for generate_arg /
// generate_arg_no_special — the two early returns upstream generateArgImpl
// performs before per-kind generation:
//   * OUT scalar args (Int/Flags/Const/Proc/Vma/Resource) collapse to the
//     type's canonical default — "no need to generate something interesting
//     for output scalar arguments" (rand.go:759-767). This also makes the
//     per-kind OUT branches for vma/resource consistent (they previously
//     diverged: vma allocated a real VMA, resource used 0 not Values[0]).
//   * any Optional() type collapses to its default with probability 1/5
//     (rand.go:770-776). For resources the default is a literal drawn
//     UNIFORMLY from Desc.Values (mirrors MakeResultArg(t, dir, nil, v)),
//     not Values[0].
// Returns true (with *out filled) when it handled the arg.
bool arg_default_prologue(RandGen& r, const syz::Type* t, syz::Dir d,
                          GenResult* out) {
    using K = syz::TypeKind;
    if (d == syz::Dir::kOut) {
        switch (t->kind()) {
            case K::kInt:
            case K::kFlags:
            case K::kConst:
            case K::kProc:
            case K::kVma:
            case K::kResource:
                *out = {t->default_arg(d), {}};
                return true;
            default:
                break;
        }
    }
    if (t->optional() && r.one_of(5)) {
        if (t->kind() == K::kResource) {
            const auto* rt = static_cast<const syz::ResourceType*>(t);
            const auto* desc = rt->desc();
            if (desc != nullptr && !desc->values().empty()) {
                auto a = std::make_unique<syz::ResultArg>();
                a->set_type(t);
                a->set_dir(d);
                a->set_val(desc->values()[r.rand(
                    static_cast<int>(desc->values().size()))]);
                *out = {std::move(a), {}};
                return true;
            }
        }
        *out = {t->default_arg(d), {}};
        return true;
    }
    return false;
}
} // namespace

GenResult generate_arg(RandGen& r, GenState& s, const syz::Type* t,
                       syz::Dir d) {
    if (t == nullptr) return {make_const_arg(nullptr, d, 0), {}};

    GenResult short_circuit;
    if (depth_name_prologue(t, d, &short_circuit)) {
        return short_circuit;
    }
    GenResult def_arg;
    if (arg_default_prologue(r, t, d, &def_arg)) {
        return def_arg;
    }
    DepthGuard depth_guard;
    const std::string& tname = t->name();
    const bool gate = !tname.empty() &&
        (t->kind() == syz::TypeKind::kStruct ||
         t->kind() == syz::TypeKind::kUnion ||
         t->kind() == syz::TypeKind::kPtr);
    NameGuard name_guard(tname, gate);

    // SpecialType dispatch hook. Mirror upstream rand.go:740-747:
    // when dir != Out and the type is a Struct or Union with a
    // registered SpecialType fn, route through the fn (with old=nullptr
    // — generation, not mutation). A null result from the fn falls
    // through to the per-kind walk so bodies that opt out by name
    // (return nullptr) still get a usable arg.
    //
    // The fn's recursive entry into the generator must use
    // generate_arg_no_special (via GenImpl::generate_special_arg) to
    // avoid re-dispatching on the same outer type. SpecialType bodies
    // shipped in PR-3-B2 do this; future bodies must follow suit.
    if (d != syz::Dir::kOut &&
        (t->kind() == syz::TypeKind::kStruct ||
         t->kind() == syz::TypeKind::kUnion)) {
        const auto* fn = s.target().find_special_type(t->name());
        if (fn != nullptr) {
            GenImpl gen_impl(r, s);
            std::vector<std::unique_ptr<syz::Call>> extras;
            auto arg = (*fn)(&gen_impl, t, d, /*old=*/nullptr, &extras);
            if (arg != nullptr) {
                return {std::move(arg), std::move(extras)};
            }
        }
    }

    return dispatch_per_kind(r, s, t, d);
}

// Bypasses the SpecialType dispatch on the outer type — consumed by
// GenImpl::generate_special_arg, which is the entry point SpecialType
// bodies use to drive the per-kind default walk on their own type
// without re-triggering the dispatch hook (matches upstream's
// `generateArgImpl(..., ignoreSpecial=true)` from rand.go:720).
GenResult generate_arg_no_special(RandGen& r, GenState& s,
                                  const syz::Type* t, syz::Dir d) {
    if (t == nullptr) return {make_const_arg(nullptr, d, 0), {}};

    GenResult short_circuit;
    if (depth_name_prologue(t, d, &short_circuit)) {
        return short_circuit;
    }
    GenResult def_arg;
    if (arg_default_prologue(r, t, d, &def_arg)) {
        return def_arg;
    }
    DepthGuard depth_guard;
    const std::string& tname = t->name();
    const bool gate = !tname.empty() &&
        (t->kind() == syz::TypeKind::kStruct ||
         t->kind() == syz::TypeKind::kUnion ||
         t->kind() == syz::TypeKind::kPtr);
    NameGuard name_guard(tname, gate);

    return dispatch_per_kind(r, s, t, d);
}

GenFieldsResult generate_args(RandGen& r, GenState& s,
                              const std::vector<syz::Field>& fields,
                              syz::Dir parent_dir) {
    GenFieldsResult out;
    out.args.reserve(fields.size());
    for (const auto& f : fields) {
        auto sub = generate_arg(r, s, f.type(), f.dir(parent_dir));
        out.args.push_back(std::move(sub.arg));
        for (auto& c : sub.calls) out.calls.push_back(std::move(c));
    }
    return out;
}

std::vector<std::unique_ptr<syz::Call>>
generate_call(RandGen& r, GenState& s, int64_t prev_call_id) {
    const auto& target = s.target();
    const auto& syscalls = target.syscalls();
    if (syscalls.empty()) return {};

    const syz::SyscallMeta* meta = nullptr;
    const ChoiceTable* ct = s.choice_table();

    if (ct != nullptr && ct->ready()) {
        // Use ChoiceTable. build() already excludes disabled+no_generate
        // (incl. syz's (disabled) pseudos like syz_builtin*) and honors the
        // enable/disable whitelist, so choose() only surfaces generatable calls.
        for (int attempt = 0; attempt < 200; ++attempt) {
            const uint64_t id = ct->choose(r, prev_call_id);
            if (id >= syscalls.size()) continue;
            const auto& sc = syscalls[id];
            if (!sc) continue;
            if (sc->attrs().kfuzztest) continue;
            meta = sc.get();
            break;
        }
    }

    if (meta == nullptr) {
        // Uniform fallback (also primary path when ct is null). Apply
        // the same pseudo gate the ChoiceTable applies, so generation
        // distribution is consistent regardless of which path picked
        // the syscall.
        for (int t = 0; t < 200; ++t) {
            const auto& sc = syscalls[r.rand(static_cast<int>(syscalls.size()))];
            if (sc->attrs().disabled || sc->attrs().no_generate) continue;
            if (sc->attrs().kfuzztest) continue;
            meta = sc.get();
            break;
        }
    }
    if (meta == nullptr) {
        // Last-resort scan.
        for (const auto& sc : syscalls) {
            if (sc->attrs().disabled || sc->attrs().kfuzztest) continue;
            meta = sc.get();
            break;
        }
    }
    if (meta == nullptr) return {};
    return generate_particular_call(r, s, meta);
}

// [syz-parity prog/expr.go patchConditionalFields] After a call's args exist
// (generation) or one is mutated, every conditional union holds a transient
// default arm. Resolve them: repeatedly take a stale conditional union, pick a
// random arm whose condition is currently satisfied, and regenerate it.
// Producer calls for the regenerated arms are returned so the caller can splice
// them before the owning call. Patching one union per pass keeps nested-union
// replacement memory-safe (replacing an outer arm would free a collected inner
// pointer); the bounded loop re-walks until nothing is stale.
std::vector<std::unique_ptr<syz::Call>>
patch_conditional_fields(RandGen& r, GenState& s, syz::Call& call) {
    std::vector<std::unique_ptr<syz::Call>> extra;
    for (int guard = 0; guard < 256; ++guard) {
        syz::UnionArg*        sel_ua  = nullptr;
        const syz::UnionType* sel_ut  = nullptr;
        int                   sel_idx = -1;
        syz::for_each_stale_union(
            s.target(), &call,
            [&](syz::UnionArg* ua, const syz::UnionType* ut,
                const std::vector<int>& matching) {
                if (sel_ua != nullptr) return;  // one per pass; re-walk for the rest
                sel_ua  = ua;
                sel_ut  = ut;
                sel_idx = matching[r.rand(static_cast<int>(matching.size()))];
            });
        if (sel_ua == nullptr) break;
        const syz::Field& f = sel_ut->fields()[static_cast<size_t>(sel_idx)];
        auto sub = generate_arg(r, s, f.type(), f.dir(sel_ua->dir()));
        sel_ua->set_option(std::move(sub.arg));
        sel_ua->set_index(sel_idx);
        sel_ua->set_transient(false);
        for (auto& c : sub.calls) extra.push_back(std::move(c));
    }
    return extra;
}

std::vector<std::unique_ptr<syz::Call>>
generate_particular_call(RandGen& r, GenState& s,
                         const syz::SyscallMeta* meta) {
    auto fr = generate_args(r, s, meta->args(), syz::Dir::kIn);
    auto c = std::make_unique<syz::Call>();
    c->set_meta(meta);
    c->set_args(std::move(fr.args));
    if (meta->ret() != nullptr) {
        auto ret = std::make_unique<syz::ResultArg>();
        ret->set_type(meta->ret());
        ret->set_dir(syz::Dir::kOut);
        c->set_ret(std::move(ret));
    }

    // [syz-parity rand.go:667] Resolve conditional-union arms now that the
    // whole call's args exist (gen_union emitted transient default arms).
    auto cond_extra = patch_conditional_fields(r, s, *c);

    // LenType placeholders stay at 0 — the text codec's fixup pass on
    // re-decode will compute the actual lengths (mirrors codec contract;
    // see L4 fixed-point oracle in corpus-roundtrip).

    std::vector<std::unique_ptr<syz::Call>> out;
    for (auto& extra : fr.calls)   out.push_back(std::move(extra));
    for (auto& extra : cond_extra) out.push_back(std::move(extra));
    out.push_back(std::move(c));
    return out;
}

std::unique_ptr<syz::Prog>
generate_program(const syz::Target& target, uint64_t seed, int ncalls,
                 const ChoiceTable* ct) {
    auto p = std::make_unique<syz::Prog>();
    p->set_target(&target);
    RandGen r(seed);
    GenState s(target);
    if (ct != nullptr) s.set_choice_table(ct);
    while (static_cast<int>(p->calls().size()) < ncalls) {
        // [syz-parity rand.go:629-638] Bias the ChoiceTable selection on a
        // UNIFORMLY-RANDOM prior call in [0, insertionPoint), NOT the
        // immediately-preceding call. Generation always appends at the end,
        // so insertionPoint == current length. (Using only the last call
        // collapsed generation toward adjacent-call chains and discarded the
        // producer→consumer-across-gaps structure the static priority models.)
        int64_t bias = -1;
        const std::size_t insertion_point = p->calls().size();
        if (insertion_point > 0) {
            const auto& bc =
                p->calls()[r.rand(static_cast<int>(insertion_point))];
            if (bc && bc->meta() != nullptr && !bc->meta()->attrs().no_generate) {
                bias = static_cast<int64_t>(bc->meta()->id());
            }
        }
        auto calls = generate_call(r, s, bias);
        if (calls.empty()) break;
        for (auto& c : calls) {
            s.analyze(c.get());
            p->add_call(std::move(c));
        }
    }
    // [syz-parity generation.go:28-31] overflow trim. The LAST generate_call
    // returns [resource-creator deps..., target] (generate_particular_call) and
    // can push past ncalls. syzkaller removes at index (ncalls-1) repeatedly,
    // which drops the overflow *deps* and KEEPS the last (target) call —
    // defaulting its now-orphaned resource args — with proper ResultArg ref
    // cleanup (RemoveCall semantics). RemoveCallRange(ncalls-1, overflow) keeps
    // [0..ncalls-2] + the target call, identical to syz's loop. (The previous
    // pop_back() removed from the END → dropped the target, kept the deps, and
    // skipped ref cleanup — inverted from syz.)
    const bool overflowed = static_cast<int>(p->calls().size()) > ncalls;
    if (overflowed) {
        const std::size_t overflow =
            p->calls().size() - static_cast<std::size_t>(ncalls);
        syz::RemoveCallRange(*p, static_cast<std::size_t>(ncalls) - 1, overflow);
    }
    // §3.11 follow-up — apply target-specific invariant repair on
    // freshly generated typed Prog before returning. Mirrors
    // syzkaller `prog/generation.go:32` calling `p.sanitizeFix()` at
    // the end of `GenerateProg`. Without this hook a generated seed
    // can carry e.g. mmap-without-MAP_FIXED, PTRACE_TRACEME, dangerous
    // ioctl cmds, etc., which then flow into corpus / executor
    // without invariant repair. sanitize_fix is conservative — only
    // touches calls in its dispatch table, no-op for everything else.
    syz::sanitize_fix(*p);
    return p;
}

} // namespace refuzz::mutator::syz_v2
