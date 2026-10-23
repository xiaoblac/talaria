// reFuzz syz_v2 mutator — mutateArg dispatch (§3.5 M1).
//
// Port of `prog/mutation.go::mutateArg` and the 13 per-type `mutate()`
// methods, applied to the v2 IR (`refuzz::program::syz::Prog`).
// See ops/mutate_arg.hpp for the high-level contract.
//
// In-place mutation strategy:
//   * We never call upstream's `replaceArg(arg, newArg)` (which relies
//     on Go's `*a = *new` interface-pointer trick). Instead each
//     per-type mutator either tweaks scalar members on the chosen
//     subclass (Int / Flags / Buffer / Proc / Vma / Resource), or
//     manipulates the v2 IR's exposed setters for child slots
//     (Pointer.res, Union.option, GroupArg.inner). This avoids
//     needing a "find this arg's slot in its parent" tree walk while
//     preserving the algorithm shape of upstream.

#include "refuzz/mutator/linux/syz_v2/ops/mutate_arg.hpp"

#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>
#include <vector>

namespace refuzz::mutator::syz_v2 {

namespace {

// ---------------------------------------------------------------------
// Local helpers (mirrors of generator.cpp anonymous-ns helpers — kept
// duplicated here on purpose; sharing would require lifting them into
// a public header that's not on the §3.5 critical path).
// ---------------------------------------------------------------------

constexpr uint64_t kProcDefaultValue = ~uint64_t{0};

uint64_t type_bit_size(const syz::Type* t) {
    if (t == nullptr) return 64;
    if (t->is_bitfield()) return t->bitfield_length();
    return t->size() * 8;
}

uint64_t truncate_to_bit_size(uint64_t v, uint64_t bit_size) {
    if (bit_size == 0 || bit_size >= 64) return v;
    return v & ((uint64_t{1} << bit_size) - 1);
}

// ---------------------------------------------------------------------
// Priority weights for arg selection (mirror prog/mutation.go).
// ---------------------------------------------------------------------

constexpr double kMaxPriority = 10.0;
constexpr double kMinPriority = 1.0;
constexpr double kDontMutate  = 0.0;

double range_size_prio(uint64_t size) {
    if (size == 0) return kDontMutate;
    if (size == 1) return kMinPriority;
    return std::min<double>(static_cast<double>(size) / 3.0 + 0.4 * kMaxPriority,
                            0.9 * kMaxPriority);
}

// Returns (priority, stop_recursion). If priority == kDontMutate the
// arg is not collected by mutationArgs.
std::pair<double, bool> get_mutation_prio(const syz::Type* type,
                                          const syz::Arg*  arg,
                                          bool             ignore_lengths)
{
    if (type == nullptr) return {kDontMutate, false};

    switch (type->kind()) {
        case syz::TypeKind::kInt: {
            const auto* it = static_cast<const syz::IntType*>(type);
            const double plain = std::log2(static_cast<double>(type_bit_size(type)))
                                 + 0.1 * kMaxPriority;
            if (it->int_kind() != syz::IntType::Kind::kRange) {
                return {plain, false};
            }
            uint64_t size = it->range_end() - it->range_begin() + 1;
            if (it->int_align() != 0) {
                if (it->range_begin() == 0 &&
                    static_cast<int64_t>(it->range_end()) == -1) {
                    size = (uint64_t{1} << type_bit_size(type)) / it->int_align();
                    if (size == 0) size = 1;
                } else {
                    size = (it->range_end() - it->range_begin()) / it->int_align() + 1;
                }
            }
            double prio;
            if (size <= 15)       prio = range_size_prio(size);
            else if (size <= 256) prio = kMaxPriority;
            else                  prio = plain;
            return {prio, false};
        }
        case syz::TypeKind::kFlags: {
            const auto* ft = static_cast<const syz::FlagsType*>(type);
            double prio = range_size_prio(static_cast<uint64_t>(ft->vals().size()));
            if (ft->bitmask()) prio += 0.1 * kMaxPriority;
            return {prio, false};
        }
        case syz::TypeKind::kLen:
            return {ignore_lengths ? kDontMutate : 0.1 * kMaxPriority, false};
        case syz::TypeKind::kProc:
            return {0.5 * kMaxPriority, false};
        case syz::TypeKind::kResource:
            return {0.5 * kMaxPriority, false};
        case syz::TypeKind::kVma:
            return {0.5 * kMaxPriority, false};
        case syz::TypeKind::kBuffer: {
            const auto* bt = static_cast<const syz::BufferType*>(type);
            // Mirror prog/mutation.go BufferType.getMutationPrio: dontMutate
            // for a 1-byte fixed-content blob; plainPrio otherwise.
            if (bt->buffer_kind() == syz::BufferKind::kBlobRange &&
                bt->range_begin() == 1 && bt->range_end() == 1 && type->size() == 1) {
                return {kDontMutate, false};
            }
            return {0.8 * kMaxPriority, false};
        }
        case syz::TypeKind::kPtr: {
            const auto* pa = static_cast<const syz::PointerArg*>(arg);
            // Special pointers are not mutated (matches upstream TODO).
            if (pa != nullptr && pa->is_special()) return {kDontMutate, false};
            return {0.3 * kMaxPriority, false};
        }
        case syz::TypeKind::kArray:
            // Array length itself: a small prio; descent into elements
            // happens via foreach_arg (their priorities accumulate too).
            return {0.5 * kMaxPriority, false};
        case syz::TypeKind::kStruct:
            // Without SpecialTypes hooks (deferred to a future backend
            // landing) we don't have a way to "mutate the struct as a
            // whole". Skip the struct itself; descent into fields still
            // happens via foreach_arg.
            return {kDontMutate, false};
        case syz::TypeKind::kUnion: {
            const auto* ut = static_cast<const syz::UnionType*>(type);
            if (ut->fields().size() <= 1) return {kDontMutate, false};
            return {kMaxPriority, false};
        }
        case syz::TypeKind::kConst:
        case syz::TypeKind::kCsum:
            return {kDontMutate, false};
    }
    return {kDontMutate, false};
}

// ---------------------------------------------------------------------
// chooseCall — priority-weighted call selection.
// ---------------------------------------------------------------------

int choose_call(const syz::Prog& prog, RandGen& r, bool ignore_lengths) {
    if (prog.calls().empty()) return -1;

    std::vector<double> cum;
    cum.reserve(prog.calls().size());
    double sum = 0.0;
    for (const auto& cup : prog.calls()) {
        if (!cup) {
            cum.push_back(sum);
            continue;
        }
        double total = 0.0;
        syz::foreach_arg(const_cast<syz::Call*>(cup.get()),
                         [&](syz::Arg* a, syz::ArgCtx* ctx) {
            const auto [prio, stop] = get_mutation_prio(a ? a->type() : nullptr,
                                                       a, ignore_lengths);
            total += prio;
            ctx->stop = stop;
        });
        sum += total;
        cum.push_back(sum);
    }
    if (sum == 0.0) return -1;

    const double goal = sum * r.randf();
    auto it = std::lower_bound(cum.begin(), cum.end(), goal);
    if (it == cum.end()) return static_cast<int>(cum.size()) - 1;
    return static_cast<int>(std::distance(cum.begin(), it));
}

// ---------------------------------------------------------------------
// mutationArgs — collect (arg, parent slot info, priority) tuples for
// chooseArg to pick from.
// ---------------------------------------------------------------------

struct MutationArg {
    syz::Arg*                                   arg      = nullptr;
    std::vector<std::unique_ptr<syz::Arg>>*     parent   = nullptr;
    syz::Dir                                    dir      = syz::Dir::kIn;
    double                                      priority = 0.0;
};

struct MutationArgs {
    std::vector<MutationArg> args;
    double                   prio_sum = 0.0;
    bool                     ignore_lengths = false;
};

void collect_args(syz::Call* call, MutationArgs& out) {
    syz::foreach_arg(call, [&](syz::Arg* a, syz::ArgCtx* ctx) {
        if (a == nullptr || a->type() == nullptr) return;

        const syz::Type* t = a->type();
        const auto [prio, stop] = get_mutation_prio(t, a, out.ignore_lengths);
        ctx->stop = stop;
        if (prio == kDontMutate) return;

        // Match upstream's collectArg filter:
        //   skip out-direction args except buffer/array, and skip
        //   zero-size non-varlen types.
        const bool is_buffer = t->kind() == syz::TypeKind::kBuffer;
        const bool is_array  = t->kind() == syz::TypeKind::kArray;
        if (!is_buffer && !is_array && a->dir() == syz::Dir::kOut) return;
        if (!t->var_len() && t->size() == 0) return;

        MutationArg ma;
        ma.arg      = a;
        ma.parent   = ctx->parent;
        ma.dir      = a->dir();
        out.prio_sum += prio;
        ma.priority = out.prio_sum;
        out.args.push_back(ma);
    });
}

const MutationArg* choose_arg(const MutationArgs& m, RandGen& r) {
    if (m.args.empty() || m.prio_sum <= 0.0) return nullptr;
    const double goal = m.prio_sum * r.randf();
    for (const auto& ma : m.args) {
        if (ma.priority >= goal) return &ma;
    }
    return &m.args.back();
}

// ---------------------------------------------------------------------
// IntType helpers.
// ---------------------------------------------------------------------

uint64_t mutate_int_value(RandGen& r, uint64_t old_val, uint64_t bit_size) {
    if (r.n_out_of(1, 3)) {
        return old_val + (r.rand(4) + 1);
    }
    if (r.n_out_of(1, 2)) {
        return old_val - (r.rand(4) + 1);
    }
    if (bit_size == 0) bit_size = 64;
    return old_val ^ (uint64_t{1} << r.rand(static_cast<int>(bit_size)));
}

uint64_t mutate_aligned_int_value(RandGen& r, uint64_t old_val,
                                  const syz::IntType* t, uint64_t bit_size) {
    uint64_t range_end = t->range_end();
    if (t->range_begin() == 0 && static_cast<int64_t>(range_end) == -1) {
        if (bit_size >= 64) range_end = ~uint64_t{0};
        else                range_end = (uint64_t{1} << bit_size) - 1;
    }
    const uint64_t align = t->int_align() == 0 ? 1 : t->int_align();
    uint64_t index        = (old_val - t->range_begin()) / align;
    const uint64_t misalign = (old_val - t->range_begin()) % align;
    if (r.n_out_of(1, 3)) {
        index += r.rand(4) + 1;
    } else if (r.n_out_of(1, 2)) {
        index -= r.rand(4) + 1;
    } else {
        index ^= uint64_t{1} << r.rand(static_cast<int>(bit_size == 0 ? 64 : bit_size));
    }
    const uint64_t last_index = (range_end - t->range_begin()) / align;
    if (last_index != ~uint64_t{0}) {
        index %= last_index + 1;
    }
    return t->range_begin() + index * align + misalign;
}

// ---------------------------------------------------------------------
// BufferType helpers.
// ---------------------------------------------------------------------

// [align syz] 单 blob/buffer 上限 = syz prog/mutation.go:17 maxBlobLen = 100<<10
// (100 KiB)。原 1 MiB 比 syz 大 10×,多 blob 参数累加易破 kExecBufferSize(4 MiB)→
// serialize_for_exec "too large program"。syz 无总尺寸预算,就靠这个小 per-blob 上限。
constexpr uint64_t kMaxBlobLen = 100 << 10;

void mutate_buffer_size(RandGen& r, syz::DataArg* a,
                        uint64_t min_len, uint64_t max_len) {
    const uint64_t old = a->size();
    for (int spin = 0; spin < 8; ++spin) {
        int64_t delta = static_cast<int64_t>(r.rand(33)) - 16;
        int64_t newsz = static_cast<int64_t>(a->out_size() != 0 ? a->out_size()
                                                                : a->data().size());
        newsz += delta;
        if (newsz < static_cast<int64_t>(min_len)) newsz = static_cast<int64_t>(min_len);
        if (static_cast<uint64_t>(newsz) > max_len) newsz = static_cast<int64_t>(max_len);
        const uint64_t newu = static_cast<uint64_t>(newsz);
        if (newu != old) {
            if (a->out_size() != 0) {
                a->set_out_size(newu);
            } else {
                std::vector<uint8_t> data = a->data();
                data.resize(newu, 0);
                a->set_data(std::move(data));
            }
            return;
        }
    }
}

// mutate_data_blob — faithful port of prog/mutation.go::mutateData (the
// 7-operator table). Defined at namespace scope below (external linkage,
// declared in ops/mutate_arg.hpp) so squashAny shares the same operator set.

// ---------------------------------------------------------------------
// Per-type mutators. All return true on success, false on retry.
// Each modifies arg's members in place via the v2 IR setters; no
// upstream `replaceArg` slot finding is required.
// ---------------------------------------------------------------------

bool mutate_int_arg(RandGen& r, syz::Arg* arg) {
    if (r.bin()) {
        // regenerate path: pick a fresh value with rand_int.
        auto* a = static_cast<syz::ConstArg*>(arg);
        const auto* t = static_cast<const syz::IntType*>(arg->type());
        const uint64_t bits = type_bit_size(t);
        uint64_t v = r.rand_int(bits);
        a->set_val(truncate_to_bit_size(v, bits));
        return true;
    }
    auto* a = static_cast<syz::ConstArg*>(arg);
    const auto* t = static_cast<const syz::IntType*>(arg->type());
    const uint64_t bits = type_bit_size(t);
    uint64_t v = a->val();
    if (t->int_align() == 0) {
        v = mutate_int_value(r, v, bits);
    } else {
        v = mutate_aligned_int_value(r, v, t, bits);
    }
    a->set_val(truncate_to_bit_size(v, bits));
    return true;
}

bool mutate_flags_arg(RandGen& r, syz::Arg* arg) {
    auto* a = static_cast<syz::ConstArg*>(arg);
    const auto* t = static_cast<const syz::FlagsType*>(arg->type());
    if (t->vals().empty()) return false;
    uint64_t old = a->val();
    uint64_t v = old;
    for (int spin = 0; spin < 16 && v == old; ++spin) {
        v = r.flags(t->vals(), t->bitmask(), old);
    }
    if (v == old) return false;
    a->set_val(v);
    return true;
}

bool mutate_len_arg(RandGen& r, syz::Arg* arg) {
    // [syz-parity mutation.go:376-383 (LenType.mutate→mutateSize, preserve)]
    // Perturb the length ConstArg to a value that differs from the
    // auto-computed one, so the program can ship a deliberately-INCONSISTENT
    // length — the path that exercises kernel length/bounds validation. The
    // dispatcher (mutate_one_arg) marks the owning call size-preserved so the
    // engine's assign_sizes pass won't recompute the value back.
    //
    // Note: upstream mutateSize derives candidate sizes from the parent
    // struct's fields; reFuzz instead reuses the integer-mutation machinery
    // (small ± deltas AND interesting values via mutate_int_value), which
    // covers the same inconsistent-length space without threading the parent
    // group through the dispatch. Returns false if it couldn't change the
    // value (caller retries with a different arg).
    auto* a = static_cast<syz::ConstArg*>(arg);
    const uint64_t bits = type_bit_size(arg->type());
    const uint64_t old = a->val();
    uint64_t v = old;
    for (int spin = 0; spin < 16 && v == old; ++spin) {
        v = truncate_to_bit_size(mutate_int_value(r, old, bits), bits);
    }
    if (v == old) return false;
    a->set_val(v);
    return true;
}

bool mutate_proc_arg(RandGen& r, syz::Arg* arg, syz::Dir dir) {
    auto* a = static_cast<syz::ConstArg*>(arg);
    const auto* t = static_cast<const syz::ProcType*>(arg->type());
    if (dir == syz::Dir::kOut) {
        a->set_val(kProcDefaultValue);
        return true;
    }
    // Mirror gen_proc: val is the per-proc *index* in [0, values_per_proc),
    // not values_start+index. validation per-proc check requires
    // `val < values_per_proc OR val == kProcDefaultValue`. The pid-stride
    // expansion (val + values_start * pid * something) lives in
    // ConstArg::value_with_pid_stride at exec-wire emit time.
    if (r.n_out_of(1, 50)) {
        a->set_val(kProcDefaultValue);
        return true;
    }
    const uint64_t per = t->values_per_proc() == 0 ? 1 : t->values_per_proc();
    a->set_val(r.rand(static_cast<int>(per)));
    return true;
}

bool mutate_resource_arg(RandGen& r, GenState& gs, syz::Arg* arg, syz::Dir dir) {
    auto* a = static_cast<syz::ResultArg*>(arg);
    if (dir == syz::Dir::kOut) {
        // OUT resource: just keep the existing slot; nothing to mutate.
        return false;
    }
    const auto* rt = static_cast<const syz::ResourceType*>(arg->type());
    if (rt->desc() == nullptr) return false;

    // Try kind tail walk: pick the most-specific compatible producer
    // first, then fall back. v2 generator stashes ResultArg* by exact
    // resource name in gen_state.resources_; mirror that here.
    const auto& kinds = rt->desc()->kind();
    for (auto it = kinds.rbegin(); it != kinds.rend(); ++it) {
        const auto* candidates = gs.resources_for(*it);
        if (candidates == nullptr || candidates->empty()) continue;
        if (r.bin()) continue;  // 50%: try a different kind level
        syz::ResultArg* pick = (*candidates)[r.rand(static_cast<int>(candidates->size()))];
        if (pick == a) continue;
        a->set_res(pick);
        a->set_val(0);
        a->set_op_div(0);
        a->set_op_add(0);
        return true;
    }

    // No existing producer matched. Mirror upstream
    // (*ResourceType).generate's r.nOutOf(4, 5) arm scaled to 50%
    // because the kind-tail walk above already consumed half the
    // budget for existing-pick. createResource produces a brand-new
    // producer chain; the prepended calls go into pending_extras for
    // the engine op-apply boundary to splice in front of the
    // consumer (ctx.affected_call_index).
    if (!gs.in_generate_resource() && r.bin()) {
        GenResult cr = create_resource(r, gs, rt, dir);
        if (cr.arg != nullptr) {
            auto* wrapper = static_cast<syz::ResultArg*>(cr.arg.get());
            a->set_res(wrapper->mutable_res());
            a->set_val(0);
            a->set_op_div(0);
            a->set_op_add(0);
            for (auto& c : cr.calls) gs.push_pending_extra(std::move(c));
            return true;
        }
    }

    // Fall back to default value (no producer chain available).
    a->set_res(nullptr);
    a->set_val(rt->default_value());
    a->set_op_div(0);
    a->set_op_add(0);
    return true;
}

bool mutate_vma_arg(RandGen& r, GenState& gs, syz::Arg* arg) {
    auto* a = static_cast<syz::PointerArg*>(arg);
    const auto* t = static_cast<const syz::VmaType*>(arg->type());
    const uint64_t page_size = gs.target().page_size();

    uint64_t pages = r.rand_page_count(gs.va().num_pages());
    if (t->range_begin() != 0 || t->range_end() != 0) {
        const uint64_t lo = std::max<uint64_t>(t->range_begin(), 1);
        uint64_t hi = std::max<uint64_t>(t->range_end(), lo);
        if (hi > gs.va().num_pages()) hi = gs.va().num_pages();
        if (hi < lo) hi = lo;
        pages = lo + r.rand(static_cast<int>(hi - lo + 1));
    }
    if (pages == 0) pages = 1;
    const uint64_t page = gs.va().alloc(r, pages);
    a->set_address(page * page_size);
    a->set_vma_size(pages * page_size);
    a->set_res(nullptr);
    return true;
}

bool mutate_buffer_arg(RandGen& r, GenState& gs, syz::Arg* arg, syz::Dir dir) {
    auto* a = static_cast<syz::DataArg*>(arg);
    const auto* t = static_cast<const syz::BufferType*>(arg->type());

    uint64_t min_len = 0, max_len = kMaxBlobLen;
    if (t->buffer_kind() == syz::BufferKind::kBlobRange) {
        min_len = t->range_begin();
        max_len = t->range_end() == 0 ? kMaxBlobLen : t->range_end();
    }

    if (dir == syz::Dir::kOut) {
        if (t->buffer_kind() == syz::BufferKind::kFilename && r.one_of(100)) {
            a->set_out_size(static_cast<uint64_t>(r.rand(64) + 1));
            return true;
        }
        mutate_buffer_size(r, a, min_len, max_len);
        return true;
    }

    switch (t->buffer_kind()) {
        case syz::BufferKind::kBlobRand:
        case syz::BufferKind::kBlobRange: {
            std::vector<uint8_t> data = a->data();
            data = mutate_data_blob(r, std::move(data), min_len, max_len);
            a->set_data(std::move(data));
            return true;
        }
        case syz::BufferKind::kString: {
            if (!t->values().empty()) {
                const auto& s = t->values()[r.rand(static_cast<int>(t->values().size()))];
                a->set_data(std::vector<uint8_t>(s.begin(), s.end()));
                return true;
            }
            if (t->size() != 0) {
                min_len = max_len = t->size();
            }
            std::vector<uint8_t> data = a->data();
            data = mutate_data_blob(r, std::move(data), min_len, max_len);
            a->set_data(std::move(data));
            return true;
        }
        case syz::BufferKind::kFilename:
        case syz::BufferKind::kGlob: {
            // Re-roll a filename. Best-effort: we don't have r.filename
            // ported, so pick from gs.files() if non-empty, else
            // synthesize one.
            const auto& fset = gs.files();
            std::string name;
            if (!fset.empty() && r.bin()) {
                auto it = fset.begin();
                std::advance(it, r.rand(static_cast<int>(fset.size())));
                name = *it;
            } else {
                name = "./file" + std::to_string(r.rand(8));
            }
            std::vector<uint8_t> data(name.begin(), name.end());
            a->set_data(std::move(data));
            return true;
        }
        case syz::BufferKind::kText: {
            // Minimal: keep the existing text bytes, optionally bit-flip
            // one byte. Full ifuzz/text mutation deferred per §3.4 note.
            std::vector<uint8_t> data = a->data();
            if (!data.empty()) {
                const size_t pos = r.rand(static_cast<int>(data.size()));
                data[pos] ^= static_cast<uint8_t>(uint8_t{1} << r.rand(8));
            }
            a->set_data(std::move(data));
            return true;
        }
        case syz::BufferKind::kCompressed: {
            // Compressed image mutation uses image package; deferred per
            // §3.4. Leave content intact (validate-clean).
            return false;
        }
    }
    return false;
}

bool mutate_array_arg(RandGen& r, GenState& gs, syz::Arg* arg, syz::Dir dir) {
    auto* a = static_cast<syz::GroupArg*>(arg);
    const auto* t = static_cast<const syz::ArrayType*>(arg->type());

    auto& inner = a->mutable_inner();
    if (inner.size() > 1 && r.one_of(5)) {
        // Swap two random elements.
        for (int spin = 0; r.n_out_of(2, 3); ++spin) {
            const size_t i = r.rand(static_cast<int>(inner.size()));
            const size_t j = r.rand(static_cast<int>(inner.size()));
            std::swap(inner[i], inner[j]);
            if (spin > 8) break;  // safety bound
        }
        return true;
    }
    uint64_t target_count = inner.size();
    switch (t->array_kind()) {
        case syz::ArrayKind::kRandLen:
            if (r.bin()) {
                for (target_count = inner.size(); r.bin();) ++target_count;
            } else {
                int spin = 0;
                while (target_count == inner.size() && spin++ < 8) {
                    target_count = r.rand_array_len();
                }
            }
            break;
        case syz::ArrayKind::kRangeLen:
            if (t->range_begin() == t->range_end()) return false;
            int spin = 0;
            while (target_count == inner.size() && spin++ < 8) {
                target_count = t->range_begin() +
                    r.rand(static_cast<int>(t->range_end() - t->range_begin() + 1));
            }
            break;
    }
    if (target_count == inner.size()) return false;

    if (target_count > inner.size()) {
        const uint64_t add = target_count - inner.size();
        for (uint64_t i = 0; i < add; ++i) {
            auto sub = generate_arg(r, gs, t->elem(), dir);
            if (!sub.arg) break;
            inner.push_back(std::move(sub.arg));
            // Drop any extra producer calls — v2 generate_arg currently
            // doesn't produce any, but if it ever does (when resource
            // chain creation lands in §3.5 follow-ups), they'll be
            // surfaced through ctx.gen_state and inserted by callers.
        }
    } else {
        inner.resize(target_count);
    }
    return true;
}

bool mutate_ptr_arg(RandGen& r, GenState& gs, syz::Arg* arg) {
    auto* a = static_cast<syz::PointerArg*>(arg);
    const auto* t = static_cast<const syz::PtrType*>(arg->type());
    const auto& sps = gs.target().special_pointers();

    if (r.one_of(1000) && !sps.empty()) {
        // PointerArg encodes a special pointer as the *negation* of its
        // index in target.special_pointers() (mirror of upstream
        // MakeSpecialPointerArg). The is_special() check in arg.cpp
        // recovers (-address) and tests it against kMaxSpecialPointers.
        // Storing the raw special pointer *value* (e.g. 0x9999...) here
        // would slip past is_special and trigger the "ptr has bad
        // address" branch in validation.
        const uint64_t idx = static_cast<uint64_t>(r.rand(static_cast<int>(sps.size())));
        a->set_address(static_cast<uint64_t>(-static_cast<int64_t>(idx)));
        a->set_vma_size(0);
        a->set_res(nullptr);
        return true;
    }

    auto sub = generate_arg(r, gs, t->elem(), t->elem_dir());
    if (!sub.arg) return false;

    const uint64_t sz = (sub.arg->type() && !sub.arg->type()->var_len())
                          ? sub.arg->type()->size()
                          : sub.arg->size();
    const uint64_t align = sub.arg->type() ? sub.arg->type()->align() : 0;
    const uint64_t addr = gs.ma().alloc(sz == 0 ? 1 : sz, align == 0 ? 1 : align);
    a->set_address(addr);
    a->set_vma_size(0);
    a->set_res(std::move(sub.arg));
    return true;
}

bool mutate_union_arg(RandGen& r, GenState& gs, syz::Arg* arg, syz::Dir parent_dir) {
    // A kUnion-typed slot is always a UnionArg: the generator emits
    // kind-matching args even at the recursion cutoff (depth_name_prologue →
    // Type::default_arg, which builds a UnionArg for unions), mirroring
    // syzkaller (rand.go:766 → UnionType.DefaultArg). The cast is safe by
    // construction — same as the other static_cast<UnionArg*> sites and as
    // syz's UnionType.mutate (unguarded arg.(*UnionArg)).
    auto* a = static_cast<syz::UnionArg*>(arg);
    const auto* t = static_cast<const syz::UnionType*>(arg->type());
    if (t->fields().size() < 2) return false;
    if (t->is_conditional()) {
        // Conditional union arms are gated by sibling values; mutating
        // the index without checking conditions can violate validate
        // (Call.checkConditions). §3.4 emitted only the default arm;
        // §3.5 keeps that contract and skips conditional unions until
        // §3.1 / §3.5-followup ports `setDefaultConditions`.
        return false;
    }

    // Pick a different index: 0..N-2, then bump if >= old.
    const int old_idx = a->index();
    int new_idx = static_cast<int>(r.rand(static_cast<int>(t->fields().size()) - 1));
    if (new_idx >= old_idx) ++new_idx;
    if (new_idx < 0 || new_idx >= static_cast<int>(t->fields().size())) return false;

    const auto& field = t->fields()[new_idx];
    auto sub = generate_arg(r, gs, field.type(), field.dir(parent_dir));
    if (!sub.arg) return false;

    a->set_index(new_idx);
    a->set_option(std::move(sub.arg));
    return true;
}

// ---------------------------------------------------------------------
// Top-level dispatch.
// ---------------------------------------------------------------------

bool mutate_one_arg(syz::Call*           call,
                    const MutationArg&   ma,
                    SyzV2MutationContext& mctx,
                    RandGen&              r)
{
    syz::Arg* arg = ma.arg;
    if (arg == nullptr || arg->type() == nullptr) return false;
    GenState* gs = mctx.gen_state;
    if (gs == nullptr) return false;

    bool ok = false;
    bool preserve_sizes = false;  // true only for a successful LenType mutation
    switch (arg->type()->kind()) {
        case syz::TypeKind::kInt:      ok = mutate_int_arg(r, arg); break;
        case syz::TypeKind::kFlags:    ok = mutate_flags_arg(r, arg); break;
        case syz::TypeKind::kLen:      ok = mutate_len_arg(r, arg); preserve_sizes = ok; break;
        case syz::TypeKind::kProc:     ok = mutate_proc_arg(r, arg, ma.dir); break;
        case syz::TypeKind::kResource: ok = mutate_resource_arg(r, *gs, arg, ma.dir); break;
        case syz::TypeKind::kVma:      ok = mutate_vma_arg(r, *gs, arg); break;
        case syz::TypeKind::kBuffer:   ok = mutate_buffer_arg(r, *gs, arg, ma.dir); break;
        case syz::TypeKind::kArray:    ok = mutate_array_arg(r, *gs, arg, ma.dir); break;
        case syz::TypeKind::kPtr:      ok = mutate_ptr_arg(r, *gs, arg); break;
        case syz::TypeKind::kUnion:    ok = mutate_union_arg(r, *gs, arg, ma.dir); break;
        case syz::TypeKind::kStruct:
        case syz::TypeKind::kConst:
        case syz::TypeKind::kCsum:
            // Either non-mutatable per upstream, or requires the
            // SpecialTypes hook (Struct) — skip and let mutationArgs
            // pick a different arg next round.
            return false;
    }

    // [syz-parity mutation.go:304-306] A successful LenType mutation sets
    // preserve → this call's sizes must NOT be recomputed (else the deliberate
    // length is clobbered). Any other successful mutation needs a recompute, so
    // clear a prior preserve mark on this call (the last mutation wins, as in
    // upstream where updateSizes resets true each mutateArg invocation).
    if (call != nullptr && ok) {
        if (preserve_sizes) {
            mctx.size_preserved_calls.insert(call);
        } else {
            mctx.size_preserved_calls.erase(call);
        }
    }
    return ok;
}

} // namespace

// ---------------------------------------------------------------------
// mutate_data_blob — 1:1 port of prog/mutation.go::mutateData +
// mutateDataFuncs[7] + loadInt/storeInt/swapInt (rand.go:944-987).
// External linkage (declared in ops/mutate_arg.hpp); squashAny reuses it.
// ---------------------------------------------------------------------
namespace {
uint64_t mdb_load_int_le(const uint8_t* p, int width) {
    uint64_t v = 0;
    for (int i = 0; i < width; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}
void mdb_store_int_le(uint8_t* p, uint64_t v, int width) {
    for (int i = 0; i < width; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
uint64_t mdb_swap_int(uint64_t v, int width) {
    switch (width) {
        case 2:  return __builtin_bswap16(static_cast<uint16_t>(v));
        case 4:  return __builtin_bswap32(static_cast<uint32_t>(v));
        case 8:  return __builtin_bswap64(v);
        default: return v;  // width 1: no-op
    }
}
}  // namespace

std::vector<uint8_t> mutate_data_blob(RandGen& r, std::vector<uint8_t> data,
                                      uint64_t min_len, uint64_t max_len) {
    constexpr int kMaxDelta = 35;
    // Upstream loop: keep applying ops (retry on a no-op), 1/3 chance to stop
    // after each *successful* op → geometric, mean ~3 mutations.
    bool stop = false;
    while (!stop) {
        bool applied = false;
        switch (r.rand(7)) {
            case 0: {  // flip a bit
                if (!data.empty()) {
                    const size_t byt = r.rand(static_cast<int>(data.size()));
                    data[byt] ^= static_cast<uint8_t>(1u << r.rand(8));
                    applied = true;
                }
                break;
            }
            case 1: {  // insert random bytes (maybe truncate to preserve length)
                if (!data.empty() && static_cast<uint64_t>(data.size()) < max_len) {
                    const uint64_t room = max_len - data.size();
                    const uint64_t n = std::min<uint64_t>(r.rand(16) + 1, room);
                    const size_t pos = r.rand(static_cast<int>(data.size()));
                    data.insert(data.begin() + static_cast<long>(pos),
                                static_cast<size_t>(n), 0);
                    for (uint64_t i = 0; i < n; ++i)
                        data[pos + i] = static_cast<uint8_t>(r.rand(256));
                    if (static_cast<uint64_t>(data.size()) > max_len || r.bin())
                        data.resize(data.size() - static_cast<size_t>(n));
                    applied = true;
                }
                break;
            }
            case 2: {  // remove bytes (maybe re-pad to preserve length)
                if (!data.empty()) {
                    const uint64_t n =
                        std::min<uint64_t>(r.rand(16) + 1, data.size());
                    size_t pos = 0;
                    if (n < data.size())
                        pos = r.rand(static_cast<int>(data.size() - n));
                    data.erase(data.begin() + static_cast<long>(pos),
                               data.begin() + static_cast<long>(pos + n));
                    if (static_cast<uint64_t>(data.size()) < min_len || r.bin())
                        data.insert(data.end(), static_cast<size_t>(n), 0);
                    applied = true;
                }
                break;
            }
            case 3: {  // append a (biased-toward-few) bunch of bytes
                if (static_cast<uint64_t>(data.size()) < max_len) {
                    const uint64_t room = max_len - data.size();
                    const uint64_t n = std::min<uint64_t>(
                        256 - static_cast<uint64_t>(r.biased_rand(256, 10)), room);
                    for (uint64_t i = 0; i < n; ++i)
                        data.push_back(static_cast<uint8_t>(r.rand(256)));
                    applied = true;
                }
                break;
            }
            case 4: {  // replace an int8/16/32/64 with a random value
                const int width = 1 << r.rand(4);
                if (static_cast<int>(data.size()) >= width) {
                    const size_t i =
                        r.rand(static_cast<int>(data.size()) - width + 1);
                    mdb_store_int_le(data.data() + i, r.rand64(), width);
                    applied = true;
                }
                break;
            }
            case 5: {  // add/subtract a small delta from an int
                const int width = 1 << r.rand(4);
                if (static_cast<int>(data.size()) >= width) {
                    const size_t i =
                        r.rand(static_cast<int>(data.size()) - width + 1);
                    uint64_t v = mdb_load_int_le(data.data() + i, width);
                    int64_t delta =
                        static_cast<int64_t>(r.rand(2 * kMaxDelta + 1)) - kMaxDelta;
                    if (delta == 0) delta = 1;
                    if (r.one_of(10)) {  // big-endian delta
                        v = mdb_swap_int(v, width);
                        v = static_cast<uint64_t>(v + static_cast<uint64_t>(delta));
                        v = mdb_swap_int(v, width);
                    } else {
                        v = static_cast<uint64_t>(v + static_cast<uint64_t>(delta));
                    }
                    mdb_store_int_le(data.data() + i, v, width);
                    applied = true;
                }
                break;
            }
            default: {  // case 6: set an int to an interesting value
                const int width = 1 << r.rand(4);
                if (static_cast<int>(data.size()) >= width) {
                    const size_t i =
                        r.rand(static_cast<int>(data.size()) - width + 1);
                    uint64_t value = r.rand_int64();
                    if (r.one_of(10)) value = mdb_swap_int(value, 8);
                    mdb_store_int_le(data.data() + i, value, width);
                    applied = true;
                }
                break;
            }
        }
        stop = applied && r.one_of(3);
    }
    return data;
}

// =====================================================================
// Public entry
// =====================================================================

bool mutate_arg_impl(syz::Prog& prog, SyzV2MutationContext& mctx, RandGen& r) {
    if (prog.calls().empty()) return false;
    if (mctx.target == nullptr || mctx.gen_state == nullptr) return false;

    const int idx = choose_call(prog, r, /*ignore_lengths=*/false);
    if (idx < 0 || idx >= static_cast<int>(prog.calls().size())) return false;

    // Tell create_resource (when triggered down the stack) where to
    // splice prepended producer calls — in front of this consumer.
    mctx.affected_call_index = idx;

    syz::Call* call = prog.mutable_calls()[idx].get();
    if (call == nullptr) return false;

    // [v2 Epic 7 PR-12 B2 — Step 3] 上游 prog/mutation.go::mutateArg:
    //     c := p.Calls[idx]
    //     s := analyze(ctx.ct, ctx.corpus, p, c)
    // boundary = consumer 自己;mutate_resource_arg 从 s.resources 选
    // producer 时只看 calls[0..idx),不会撞上后面 call 的 ret。
    mctx.gen_state->analyze_for_mutation_boundary(prog, call);

    // One-shot mutate (upstream takes a `MutateArgCount`-driven loop;
    // for §3.5 M1 a single mutation per Mutate is sufficient — the
    // FuzzerLoop calls Mutate again to compose more).
    MutationArgs collected;
    collected.ignore_lengths = false;
    collect_args(call, collected);
    if (collected.args.empty()) return false;

    const MutationArg* picked = choose_arg(collected, r);
    if (picked == nullptr) return false;

    const bool ok = mutate_one_arg(call, *picked, mctx, r);
    if (ok) {
        // [syz-parity mutation.go:256] The mutated field may feed a conditional
        // union's condition, or the mutation regenerated a subtree carrying
        // transient conditional unions. Re-resolve them; producer calls for the
        // regenerated arms go through pending_extras so the engine splices them
        // before this call (mirrors mutate_resource_arg's producer routing).
        auto cond_extra = patch_conditional_fields(r, *mctx.gen_state, *call);
        for (auto& c : cond_extra) {
            mctx.gen_state->push_pending_extra(std::move(c));
        }
    }
    return ok;
}

// Per-arg mutation entry (Target::IGen::mutate_arg adapter). Unlike
// mutate_arg_impl this does NOT require a Call/Prog context — just
// the arg and a GenState. Producer calls created by a ResourceType
// mutation (via create_resource fallback) get pushed into
// gs.pending_extras_; the caller drains at the right splice
// boundary.
bool mutate_single_arg(RandGen& r, GenState& gs, syz::Arg* arg) {
    if (arg == nullptr || arg->type() == nullptr) return false;
    const syz::Dir dir = arg->dir();
    switch (arg->type()->kind()) {
        case syz::TypeKind::kInt:      return mutate_int_arg(r, arg);
        case syz::TypeKind::kFlags:    return mutate_flags_arg(r, arg);
        case syz::TypeKind::kLen:      return mutate_len_arg(r, arg);
        case syz::TypeKind::kProc:     return mutate_proc_arg(r, arg, dir);
        case syz::TypeKind::kResource: return mutate_resource_arg(r, gs, arg, dir);
        case syz::TypeKind::kVma:      return mutate_vma_arg(r, gs, arg);
        case syz::TypeKind::kBuffer:   return mutate_buffer_arg(r, gs, arg, dir);
        case syz::TypeKind::kArray:    return mutate_array_arg(r, gs, arg, dir);
        case syz::TypeKind::kPtr:      return mutate_ptr_arg(r, gs, arg);
        case syz::TypeKind::kUnion:    return mutate_union_arg(r, gs, arg, dir);
        case syz::TypeKind::kStruct:
        case syz::TypeKind::kConst:
        case syz::TypeKind::kCsum:
            return false;
    }
    return false;
}

} // namespace refuzz::mutator::syz_v2
