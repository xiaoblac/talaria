// reFuzz syz_v2 mutator — ChoiceTable implementation (§3.6).
//
// Algorithmic 1:1 port of `prog/prio.go`:
//   * `calcResourceUsage` → `compute_static_prio` usage walk
//   * `calcStaticPriorities` → contribution sum + self-priority
//   * `calcDynamicPrio` → `compute_dynamic_prio` (corpus pair counts)
//   * `normalizePrios` → row-normalize to 10*|enabled|
//   * `BuildChoiceTable` → cumulative-sum runs[i][j]
//
// Differences from upstream:
//   * Walks v2 IR types via a local `walk_call_types` mirror of
//     `prog.foreachTypeRec` (the existing one in program/src/syz_v2/
//     target.cpp is anonymous-ns; we don't lift it just for §3.6).
//   * Dynamic prio decodes corpus seeds through TextDecoder rather
//     than holding `[]*Prog` like upstream.
//   * Disabled+no_generate handling matches upstream's
//     `prepareEnabledSyscalls` exactly.

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"

#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::mutator::syz_v2 {

namespace {

// ---------------------------------------------------------------------
// Type-tree walker (mirror of prog.foreachTypeRec, scoped to choice-
// table needs). Tracks Direction inheritance + recursion guard via
// (type*, dir, optional) seen-set.
// ---------------------------------------------------------------------

struct WalkCtx {
    syz::Dir dir;
    bool     stop;
};

struct SeenKey {
    const syz::Type* t;
    syz::Dir         dir;
    bool             optional;
    bool operator==(const SeenKey& o) const {
        return t == o.t && dir == o.dir && optional == o.optional;
    }
};
struct SeenKeyHash {
    size_t operator()(const SeenKey& k) const noexcept {
        return std::hash<const void*>{}(k.t)
               ^ (static_cast<size_t>(k.dir) * 131u)
               ^ (k.optional ? 0xC2B2AE3D27D4EB4FULL : 0u);
    }
};
using SeenSet = std::unordered_set<SeenKey, SeenKeyHash>;

template <typename Cb>
void walk_type(const syz::Type* t, syz::Dir dir, bool optional,
               SeenSet& seen, Cb& cb) {
    if (t == nullptr) return;
    optional = optional || t->optional();
    WalkCtx ctx{dir, false};
    cb(t, ctx);
    if (ctx.stop) return;

    switch (t->kind()) {
        case syz::TypeKind::kPtr: {
            const auto* pt = static_cast<const syz::PtrType*>(t);
            walk_type(pt->elem(), pt->elem_dir(), optional, seen, cb);
            break;
        }
        case syz::TypeKind::kArray: {
            const auto* at = static_cast<const syz::ArrayType*>(t);
            walk_type(at->elem(), dir, optional, seen, cb);
            break;
        }
        case syz::TypeKind::kStruct: {
            const auto* st = static_cast<const syz::StructType*>(t);
            const SeenKey key{st, dir, optional};
            if (seen.find(key) != seen.end()) break;
            seen.insert(key);
            for (const auto& f : st->fields()) {
                walk_type(f.type(), f.dir(dir), optional, seen, cb);
            }
            break;
        }
        case syz::TypeKind::kUnion: {
            const auto* ut = static_cast<const syz::UnionType*>(t);
            const SeenKey key{ut, dir, optional};
            if (seen.find(key) != seen.end()) break;
            seen.insert(key);
            for (const auto& f : ut->fields()) {
                walk_type(f.type(), f.dir(dir), optional, seen, cb);
            }
            break;
        }
        default:
            break;
    }
}

template <typename Cb>
void walk_call_types(const syz::SyscallMeta& sc, Cb cb) {
    SeenSet seen;
    for (const auto& f : sc.args()) {
        walk_type(f.type(), f.dir(syz::Dir::kIn), false, seen, cb);
    }
    if (sc.ret() != nullptr) {
        walk_type(sc.ret(), syz::Dir::kOut, false, seen, cb);
    }
}

// ---------------------------------------------------------------------
// Usage tally (mirror of prog/prio.go::weights).
// ---------------------------------------------------------------------

struct CallWeights {
    int32_t in    = 0;
    int32_t inout = 0;
};
using UsesByCall = std::unordered_map<uint64_t, CallWeights>;
using UsesByKey  = std::unordered_map<std::string, UsesByCall>;

void note_usage(UsesByKey& uses, uint64_t call_id, int32_t weight,
                syz::Dir dir, std::string key) {
    auto& bucket = uses[std::move(key)];
    auto&  w     = bucket[call_id];
    if (dir != syz::Dir::kOut && weight > w.in) {
        w.in = weight;
    }
    if (weight > w.inout) {
        w.inout = weight;
    }
}

} // namespace

// =====================================================================
// ChoiceTable::build
// =====================================================================

void ChoiceTable::build(const syz::Target& target,
                        const std::vector<std::uint8_t>& enabled_filter) {
    target_ = &target;
    const size_t n = target.syscalls().size();

    // Mirror upstream prepareEnabledSyscalls: enabled iff !disabled
    // (no_generate calls are also EXCLUDED from generatable, but they
    // can still legally appear in corpus — upstream tracks them in a
    // separate noGenerateCalls set we don't need here because the
    // matrix only matters for *picking*).
    enabled_.assign(n, 0);
    enabled_count_ = 0;
    generatable_ids_.clear();
    generatable_ids_.reserve(n);
    for (const auto& sc : target.syscalls()) {
        if (!sc) continue;
        const auto& a = sc->attrs();
        // [impl-kind removed] enabled iff !disabled && !no_generate. syz's
        // (disabled) attr (e.g. syz_builtin*) is the only pseudo gate here;
        // the enable/disable whitelist (enabled_filter) handles the rest.
        if (a.disabled || a.no_generate) continue;
        const uint64_t id = sc->id();
        if (id >= n) continue;
        // [syscall-enable-whitelist] empty filter = no whitelist (all enabled).
        if (!enabled_filter.empty() &&
            (id >= enabled_filter.size() || enabled_filter[id] == 0)) {
            continue;
        }
        enabled_[id] = 1;
        generatable_ids_.push_back(id);
        ++enabled_count_;
    }
    if (enabled_count_ == 0) {
        prios_.clear();
        runs_.clear();
        return;
    }

    prios_.assign(n, std::vector<int32_t>(n, 0));
    compute_static_prio();
    apply_self_priority();
    normalize_rows();
    build_runs();
}

void ChoiceTable::build(const syz::Target& target,
                        const ::refuzz::fuzzer::ICorpusStore& corpus_store,
                        syz::TextDecoder& decoder,
                        const std::vector<std::uint8_t>& enabled_filter) {
    build(target, enabled_filter);
    if (prios_.empty()) return;
    compute_dynamic_prio(corpus_store, decoder);
    // Re-apply normalize over combined matrix (static was already
    // normalized; dynamic was normalized on its own pass before sum).
    // Upstream sums normalized static + normalized dynamic; we mirror.
    build_runs();
}

// =====================================================================
// Static priority
// =====================================================================

void ChoiceTable::compute_static_prio() {
    UsesByKey uses;
    uses.reserve(target_->syscalls().size() * 2);

    for (const auto& sc_up : target_->syscalls()) {
        if (!sc_up) continue;
        const syz::SyscallMeta& sc = *sc_up;
        if (!enabled_call(sc.id())) continue;

        walk_call_types(sc, [&](const syz::Type* t, WalkCtx& ctx) {
            switch (t->kind()) {
                case syz::TypeKind::kResource: {
                    const auto* rt = static_cast<const syz::ResourceType*>(t);
                    const auto* desc = rt->desc();
                    if (desc == nullptr) break;
                    if (target_->is_aux_resource(desc->name())) {
                        note_usage(uses, sc.id(), 1, ctx.dir,
                                   "res" + desc->name());
                    } else {
                        std::string key = "res";
                        const auto& kinds = desc->kind();
                        for (size_t i = 0; i < kinds.size(); ++i) {
                            key += '-';
                            key += kinds[i];
                            const int32_t w = (i + 1 == kinds.size()) ? 10 : 2;
                            note_usage(uses, sc.id(), w, ctx.dir, key);
                        }
                    }
                    break;
                }
                case syz::TypeKind::kPtr: {
                    const auto* pt = static_cast<const syz::PtrType*>(t);
                    const auto* elem = pt->elem();
                    if (elem == nullptr) break;
                    if (elem->kind() == syz::TypeKind::kStruct ||
                        elem->kind() == syz::TypeKind::kUnion ||
                        elem->kind() == syz::TypeKind::kArray) {
                        std::string key = "ptrto-";
                        if (elem->kind() == syz::TypeKind::kArray) {
                            const auto* at = static_cast<const syz::ArrayType*>(elem);
                            if (at->elem() != nullptr) {
                                key += at->elem()->name();
                            }
                        } else {
                            key += elem->name();
                        }
                        note_usage(uses, sc.id(), 10, ctx.dir, std::move(key));
                    }
                    break;
                }
                case syz::TypeKind::kBuffer: {
                    const auto* bt = static_cast<const syz::BufferType*>(t);
                    switch (bt->buffer_kind()) {
                        case syz::BufferKind::kBlobRand:
                        case syz::BufferKind::kBlobRange:
                        case syz::BufferKind::kText:
                        case syz::BufferKind::kCompressed:
                            break;
                        case syz::BufferKind::kString:
                        case syz::BufferKind::kGlob:
                            if (!bt->sub_kind().empty()) {
                                note_usage(uses, sc.id(), 2, ctx.dir,
                                           "str-" + bt->sub_kind());
                            }
                            break;
                        case syz::BufferKind::kFilename:
                            note_usage(uses, sc.id(), 10, syz::Dir::kIn,
                                       "filename");
                            break;
                    }
                    break;
                }
                case syz::TypeKind::kVma:
                    note_usage(uses, sc.id(), 5, ctx.dir, "vma");
                    break;
                default:
                    break;
            }
        });
    }

    // Apply pairwise contributions:
    //   prios[c0][c1] += w0.inout * w1.in * 3 / 2 + w0.inout * w1.inout
    for (auto& [_key, calls] : uses) {
        for (const auto& [c0, w0] : calls) {
            for (const auto& [c1, w1] : calls) {
                if (c0 == c1) continue;
                if (c0 >= prios_.size() || c1 >= prios_.size()) continue;
                prios_[c0][c1] += w0.inout * w1.in * 3 / 2 + w0.inout * w1.inout;
            }
        }
    }
}

void ChoiceTable::apply_self_priority() {
    // Self-priority: max(row) * 3 / 4; if row is all zero, set to 1.
    for (uint64_t i = 0; i < prios_.size(); ++i) {
        if (!enabled_call(i)) continue;
        auto& row = prios_[i];
        int32_t mx = 0;
        for (int32_t v : row) if (v > mx) mx = v;
        if (mx == 0) {
            row[i] = 1;
        } else {
            row[i] = mx * 3 / 4;
        }
    }
}

void ChoiceTable::normalize_rows() {
    const int32_t total = 10 * static_cast<int32_t>(enabled_count_);
    for (auto& row : prios_) {
        int32_t sum = 0;
        for (int32_t v : row) sum += v;
        if (sum == 0) continue;
        for (auto& v : row) {
            v = static_cast<int32_t>(static_cast<int64_t>(v) * total / sum);
        }
    }
}

// =====================================================================
// Dynamic priority
// =====================================================================

namespace {
std::atomic<std::uint64_t> s_payload_fallback_count{0};
} // namespace

std::uint64_t ChoiceTable::payload_fallback_count() {
    return s_payload_fallback_count.load(std::memory_order_relaxed);
}

void ChoiceTable::reset_payload_fallback_count_for_test() {
    s_payload_fallback_count.store(0, std::memory_order_relaxed);
}

void ChoiceTable::compute_dynamic_prio(
    const ::refuzz::fuzzer::ICorpusStore& corpus,
    syz::TextDecoder& decoder)
{
    const size_t n = prios_.size();
    std::vector<std::vector<int32_t>> dyn(n, std::vector<int32_t>(n, 0));

    // RebuildChoiceTable can fire on the v2 hot path (lazy first
    // build from MutateTyped, or OnSeedAdmitted from corpus admit).
    // The seed walk MUST NOT decode seed.payload — that violates the
    // §3.10 D6 artifact-first contract. Primary path uses the typed
    // view via seed.artifact->As<Prog>(); legacy seeds without an
    // artifact bump the fallback counter for oracle pinning.
    auto walk_calls = [&](const std::vector<std::unique_ptr<syz::Call>>& calls) {
        for (size_t i = 0; i < calls.size(); ++i) {
            if (!calls[i] || !calls[i]->meta()) continue;
            const uint64_t id0 = calls[i]->meta()->id();
            if (!enabled_call(id0)) continue;
            for (size_t j = i + 1; j < calls.size(); ++j) {
                if (!calls[j] || !calls[j]->meta()) continue;
                const uint64_t id1 = calls[j]->meta()->id();
                if (!enabled_call(id1)) continue;
                if (id0 < n && id1 < n) {
                    ++dyn[id0][id1];
                }
            }
        }
    };

    corpus.ForEachSeed([&](const ::refuzz::fuzzer::Seed& seed) {
        // Primary: artifact-first typed view, no decode.
        if (seed.artifact != nullptr) {
            auto typed = seed.artifact->As<syz::Prog>();
            if (typed) {
                walk_calls(typed->calls());
                return;
            }
        }
        // Legacy fallback: only when artifact is null. Count and
        // decode. This branch is unreachable on a v2 corpus session;
        // oracle #29 (PR-3-D) asserts the count stays at 0.
        if (seed.payload.empty()) return;
        s_payload_fallback_count.fetch_add(1, std::memory_order_relaxed);
        std::string_view text(reinterpret_cast<const char*>(seed.payload.data()),
                              seed.payload.size());
        auto decoded = decoder.decode(text);
        if (!decoded.has_value() || !decoded.value()) return;
        walk_calls(decoded.value()->calls());
    });

    // Sqrt damping then row-normalize, mirroring upstream:
    //   prio = int32(2 * sqrt(double(count)))
    for (auto& row : dyn) {
        for (auto& v : row) {
            v = static_cast<int32_t>(2.0 * std::sqrt(static_cast<double>(v)));
        }
    }
    const int32_t total = 10 * static_cast<int32_t>(enabled_count_);
    for (auto& row : dyn) {
        int32_t sum = 0;
        for (int32_t v : row) sum += v;
        if (sum == 0) continue;
        for (auto& v : row) {
            v = static_cast<int32_t>(static_cast<int64_t>(v) * total / sum);
        }
    }

    // Combine: prios_[i][j] += dyn[i][j].
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            prios_[i][j] += dyn[i][j];
        }
    }
}

// =====================================================================
// Runs (cumulative for binary search)
// =====================================================================

void ChoiceTable::build_runs() {
    const size_t n = prios_.size();
    runs_.assign(n, {});
    for (size_t i = 0; i < n; ++i) {
        if (!enabled_call(i)) continue;
        runs_[i].assign(n, 0);
        int32_t sum = 0;
        for (size_t j = 0; j < n; ++j) {
            if (enabled_call(j)) {
                sum += prios_[i][j];
            }
            runs_[i][j] = sum;
        }
    }
}

// =====================================================================
// choose
// =====================================================================

// Target::IChoiceTable adapter. Mutator hot path uses choose(RandGen&,
// int64_t) which rolls 64 bits and forwards. Non-mutator readers
// (hints / fault injection holding a Target::IChoiceTable snapshot)
// supply a pre-rolled 64-bit random directly.
//
// 64-bit budget split: low 32 bits drive the 5% uniform fallback
// gate; high 32 bits index either the uniform pool or the runs CDF.
// Branches are mutually exclusive so the budget never runs out.
std::uint64_t ChoiceTable::choose(std::uint64_t prev_id,
                                  std::uint64_t random_64) const {
    if (generatable_ids_.empty()) return 0;
    const std::uint32_t lo = static_cast<std::uint32_t>(random_64);
    const std::uint32_t hi = static_cast<std::uint32_t>(random_64 >> 32);
    const auto pick_uniform = [&]() {
        return generatable_ids_[hi % generatable_ids_.size()];
    };
    if ((lo % 100u) < 5u) return pick_uniform();
    // [syz prio.go:321-323] bias<0 / unusable prev row → a uniformly-random
    // generatable anchor; either way a WEIGHTED CDF lookup over that anchor's
    // row (syz never does a plain-uniform pick for bias<0). The CDF draw uses
    // lo/100 so hi is free for the random anchor.
    std::uint64_t anchor = prev_id;
    if (anchor >= runs_.size() || runs_[anchor].empty() ||
        runs_[anchor].back() <= 0) {
        anchor = generatable_ids_[hi % generatable_ids_.size()];
    }
    const auto& run = runs_[anchor];
    const int32_t run_sum = run.back();
    if (run_sum <= 0) return pick_uniform();
    const int32_t x =
        static_cast<int32_t>((lo / 100u) % static_cast<std::uint32_t>(run_sum)) + 1;
    auto it = std::lower_bound(run.begin(), run.end(), x);
    if (it == run.end()) return run.size() - 1;
    return static_cast<std::uint64_t>(std::distance(run.begin(), it));
}

uint64_t ChoiceTable::choose(RandGen& r, int64_t prev_id) const {
    const std::uint64_t random_64 = r.rand64();
    const std::uint64_t prev =
        prev_id < 0 ? std::numeric_limits<std::uint64_t>::max()
                    : static_cast<std::uint64_t>(prev_id);
    return choose(prev, random_64);
}

} // namespace refuzz::mutator::syz_v2
