// Implementation of refuzz/mutator/linux/syz_v2/gen_state.hpp.

#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"

#include "refuzz/program/syz/analysis.hpp"

#include <algorithm>

namespace refuzz::mutator::syz_v2 {

namespace {

uint64_t min_u(uint64_t a, uint64_t b) { return a < b ? a : b; }

} // namespace

void VmaAlloc::note_alloc(uint64_t page, uint64_t size) {
    for (uint64_t i = page; i < page + size; ++i) {
        if (seen_.insert(i).second) used_.push_back(i);
    }
}

uint64_t VmaAlloc::alloc(RandGen& r, uint64_t size) {
    if (size == 0 || size > num_pages_) size = 1;
    uint64_t page = 0;
    if (used_.empty() || r.one_of(5)) {
        page = r.rand(4);
        if (!r.one_of(100)) page = num_pages_ - page - size;
    } else {
        page = used_[r.rand(static_cast<int>(used_.size()))];
        if (size > 1 && r.bin()) {
            const uint64_t shift = min_u(r.rand(static_cast<int>(size)), page);
            page -= shift;
        }
        if (page + size > num_pages_) page = num_pages_ - size;
    }
    if (page >= num_pages_ || size > num_pages_ || page + size > num_pages_) {
        // Fall back to a safe slot rather than panic — in pure generation
        // paths we'd rather emit something validate can review than abort.
        page = 0;
    }
    note_alloc(page, size);
    return page;
}

GenState::GenState(const syz::Target& target)
    : target_(target),
      ma_(target.num_pages() * target.page_size()),
      va_(target.num_pages()) {}

const std::vector<syz::ResultArg*>* GenState::resources_for(
        const std::string& kind) const {
    auto it = resources_.find(kind);
    return it == resources_.end() ? nullptr : &it->second;
}

void GenState::add_resource(const std::string& kind, syz::ResultArg* arg) {
    resources_[kind].push_back(arg);
}

void GenState::analyze(syz::Call* c) {
    analyze_impl(c, /*track_resources=*/true);
}

// [v2 Epic 7 PR-12 B2 — Step 3] Mirror of upstream prog/analysis.go::analyze.
//
// 走全 prog,在 boundary call 处把 track_resources 从 true 切到 false。
// 等价上游:
//   for _, c1 := range p.Calls {
//       if c1 == c { resources = false }
//       s.analyzeImpl(c1, resources)
//   }
//
// 注:reset 前先收 pending_extras_/ct_/pseudo_policy_/corpus_/in_gen_res_,
// reset 后恢复 —— 这些是注入式依赖,不属于"分析结果",不该被清。
// 当前实现选择不把它们写进 reset 路径里(更清楚:reset 只清分析产物)。
void GenState::analyze_for_mutation_boundary(const syz::Prog& prog,
                                             const syz::Call* boundary) {
    // 清掉所有"分析产物"。ct_/pseudo_policy_/corpus_/in_gen_res_/target_/
    // pending_extras_ 都不属于分析产物,不动。
    resources_.clear();
    files_.clear();
    strings_.clear();
    ma_.clear_all();
    va_.clear();

    bool track_resources = true;
    for (const auto& cup : prog.calls()) {
        syz::Call* c1 = cup.get();
        if (c1 == nullptr) continue;
        if (c1 == boundary) {
            track_resources = false;
        }
        analyze_impl(c1, track_resources);
    }
}

void GenState::analyze_impl(syz::Call* c, bool track_resources) {
    syz::foreach_arg(c, [&](syz::Arg* arg, syz::ArgCtx*) {
        if (arg->arg_kind() == syz::ArgKind::kPointer) {
            auto* pa = static_cast<syz::PointerArg*>(arg);
            if (pa->is_special()) {
                // nothing
            } else if (pa->vma_size() != 0) {
                va_.note_alloc(pa->address() / target_.page_size(),
                               pa->vma_size() / target_.page_size());
            } else if (pa->res() != nullptr) {
                ma_.note_alloc(pa->address(), pa->res()->size());
            }
        }
        const syz::Type* t = arg->type();
        if (t == nullptr) return;
        if (t->kind() == syz::TypeKind::kResource) {
            auto* ra = static_cast<syz::ResultArg*>(arg);
            if (track_resources && ra->dir() != syz::Dir::kOut) {
                // upstream tracks for any non-DirIn — mirrors that.
            }
            if (track_resources && ra->dir() != syz::Dir::kIn) {
                const auto* rt = static_cast<const syz::ResourceType*>(t);
                if (rt->desc() != nullptr) {
                    add_resource(rt->desc()->name(), ra);
                }
            }
        } else if (t->kind() == syz::TypeKind::kBuffer) {
            auto* da = static_cast<syz::DataArg*>(arg);
            const auto* bt = static_cast<const syz::BufferType*>(t);
            if (da->dir() != syz::Dir::kOut && !da->data().empty()) {
                std::string val(reinterpret_cast<const char*>(da->data().data()),
                                da->data().size());
                while (val.size() >= 2 && val[val.size() - 1] == '\0' &&
                       val[val.size() - 2] == '\0') {
                    val.pop_back();
                }
                if (bt->buffer_kind() == syz::BufferKind::kString) {
                    note_string(val);
                } else if (bt->buffer_kind() == syz::BufferKind::kFilename) {
                    while (!val.empty() && val.back() == '\0') val.pop_back();
                    note_file(val);
                }
            }
        }
    });
}

} // namespace refuzz::mutator::syz_v2
