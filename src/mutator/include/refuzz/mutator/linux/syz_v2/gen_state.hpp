// reFuzz syz_v2 mutator — GenState.
//
// Per-program generation/mutation state; mirror of prog/analysis.go::state.
// Tracks running collections of resources, files, strings discovered in
// the partial program, plus address allocators (MemAlloc, VmaAlloc).
//
// Lifetime is one Target::generate call. The state is fed by analyze()
// after each new Call lands, so subsequent generation can reference
// already-realized resources.

#pragma once

#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/alloc.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::fuzzer { class ICorpusStore; }

namespace refuzz::mutator::syz_v2 {

namespace syz = ::refuzz::program::syz;

class ChoiceTable;

// Mirror of prog/alloc.go::vmaAlloc.
class VmaAlloc {
public:
    explicit VmaAlloc(uint64_t total_pages) : num_pages_(total_pages) {}

    void note_alloc(uint64_t page, uint64_t size);
    uint64_t alloc(RandGen& r, uint64_t size);
    uint64_t num_pages() const { return num_pages_; }
    // [v2 PR-12 B2 — Step 3] reset bitmap;analyze_for_mutation_boundary 在
    // 重新走全 prog 之前需要清掉旧分析。num_pages_ 来自 target,不动。
    void clear() { used_.clear(); seen_.clear(); }

private:
    uint64_t                          num_pages_;
    std::vector<uint64_t>             used_;
    std::unordered_set<uint64_t>      seen_;
};

class GenState {
public:
    GenState(const syz::Target& target);

    const syz::Target& target() const { return target_; }
    syz::MemAlloc&     ma()           { return ma_; }
    VmaAlloc&          va()           { return va_; }

    // Lookup container for ResultArgs that have been emitted by earlier
    // calls. Keyed by ResourceDesc.name; values are ResultArg* observed
    // with non-In direction. Mirrors upstream `s.resources`.
    const std::vector<syz::ResultArg*>* resources_for(const std::string& kind) const;
    void add_resource(const std::string& kind, syz::ResultArg* arg);

    // Full resource map for compat walks. Iteration order is
    // unordered_map's; callers that need determinism must sort.
    const std::unordered_map<std::string, std::vector<syz::ResultArg*>>&
    resources_map() const { return resources_; }

    // String/filename memory used by buffer generators (mirrors files /
    // strings maps).
    void note_file(const std::string& name) { files_.insert(name); }
    void note_string(const std::string& s)  { strings_.insert(s); }
    const std::unordered_set<std::string>& files()   const { return files_; }
    const std::unordered_set<std::string>& strings() const { return strings_; }

    // Run analyze on a Call newly added to the partial program. Side-effects:
    // updates ma/va alloc bitmap; appends ResultArgs to resources_; notes
    // BufferType strings/filenames.
    void analyze(syz::Call* c);

    // [v2 Epic 7 PR-12 B2 — Step 3] Per-mutation-op state rebuild。
    //
    // Mirror of upstream `prog/analysis.go::analyze(ct, corpus, p, c)`:
    //   "analyzes the program p up to but not including call c"
    //
    // 语义:
    //   - ma_/va_/files_/strings_: 全 prog 收(allocator 防撞,corpus 快照)
    //   - resources_: 只收 calls[0..boundary) 的 producers
    //   - 注入依赖 (ct_/pseudo_policy_/corpus_/in_gen_res_) 不动
    //   - pending_extras_ 不动(op apply 边界各自管理)
    //
    // boundary == nullptr → "boundary 在 prog 末尾", resources 收全 prog
    // (匹配上游 insertCall 选 idx == len(p.Calls) 时 `c = nil` 的语义)。
    //
    // Step 2.5 evidence:reFuzz 之前在 SyzV2MutatorEngine::Mutate*ViaPolicy
    // 顶部预 analyze 整个 prog → resources_ 含所有 call 的 producers →
    // insert_call/mutate_arg 在 mid-position 选 producer 时撞上未来 call
    // 的 ret → encoder [kResult] unknown res reference (27/28 失败 = 96.4%
    // TOPO_REVERSED)。修法是把"state 长期持有"换成"per-op 临时构造"
    // 同时保留 GenState 容器(choice_table / pseudo_policy / corpus_store
    // 注入式依赖)。每个 mutation op 入口自行调用此函数,boundary 由 op
    // 自己决定:
    //   * insert_call: boundary = prog.calls[insert_pos] (插入位置当前那个
    //     call;若插末尾则 nullptr)
    //   * mutate_arg : boundary = 被 mutate 的 call(consumer 自己)
    //   * squash_any : boundary = squashed-ptr 所在 call
    //   * splice/remove_call: 不读 resources_,不必调用
    void analyze_for_mutation_boundary(const syz::Prog& prog,
                                       const syz::Call* boundary);

    // Optional ChoiceTable for biased syscall picking (§3.6 M1). Null
    // when generation should fall back to uniform — keeps backward
    // compat with §3.4 callers (e.g. tools that don't build a corpus).
    const ChoiceTable* choice_table() const { return ct_; }
    void set_choice_table(const ChoiceTable* ct) { ct_ = ct; }

    // createResource re-entrancy latch (mirror rand.go:393-395 —
    // r.inGenerateResource). While set, nested ResourceType requests
    // downgrade to existing-pick + default to bound recursion.
    bool in_generate_resource() const { return in_gen_res_; }
    void set_in_generate_resource(bool v) { in_gen_res_ = v; }

    // Borrowed corpus store, consumed by resource_centric. Null when
    // the session has no corpus (tools / unit tests).
    const ::refuzz::fuzzer::ICorpusStore* corpus_store() const { return corpus_; }
    void set_corpus_store(const ::refuzz::fuzzer::ICorpusStore* c) { corpus_ = c; }

    // Mutation-extras buffer. createResource invoked from
    // mutate_resource_arg pushes producer calls here; the op-apply
    // boundary drains and splices them in front of
    // ctx.affected_call_index.
    std::vector<std::unique_ptr<syz::Call>> take_pending_extras() {
        std::vector<std::unique_ptr<syz::Call>> out;
        out.swap(pending_extras_);
        return out;
    }
    void push_pending_extra(std::unique_ptr<syz::Call> c) {
        pending_extras_.push_back(std::move(c));
    }
    bool has_pending_extras() const { return !pending_extras_.empty(); }

private:
    void analyze_impl(syz::Call* c, bool track_resources);

    const syz::Target&                                      target_;
    const ChoiceTable*                                      ct_ = nullptr;
    bool                                                    in_gen_res_ = false;
    const ::refuzz::fuzzer::ICorpusStore*                   corpus_ = nullptr;
    std::vector<std::unique_ptr<syz::Call>>                 pending_extras_;
    syz::MemAlloc                                           ma_;
    VmaAlloc                                                va_;
    std::unordered_map<std::string,
                       std::vector<syz::ResultArg*>>        resources_;
    std::unordered_set<std::string>                         files_;
    std::unordered_set<std::string>                         strings_;
};

} // namespace refuzz::mutator::syz_v2
