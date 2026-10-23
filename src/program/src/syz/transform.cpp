#include "refuzz/program/syz/transform.hpp"

#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::program::syz {
namespace {

void collect_result_args(Call* call, std::unordered_set<ResultArg*>& out)
{
    if (call == nullptr) return;
    foreach_arg(call, [&](Arg* arg, ArgCtx*) {
        if (arg != nullptr && arg->arg_kind() == ArgKind::kResult) {
            out.insert(static_cast<ResultArg*>(arg));
        }
    });
}

void clear_dangling_refs(std::vector<std::unique_ptr<Call>>& calls,
                         const std::unordered_set<ResultArg*>& removed)
{
    for (auto& call : calls) {
        if (!call) continue;
        foreach_arg(call.get(), [&](Arg* arg, ArgCtx*) {
            if (arg == nullptr || arg->arg_kind() != ArgKind::kResult) {
                return;
            }

            auto* result = static_cast<ResultArg*>(arg);
            if (result->res() == nullptr ||
                removed.count(result->mutable_res()) == 0) {
                return;
            }

            uint64_t default_value = 0;
            if (const auto* resource = as_resource(arg->type())) {
                default_value = resource->default_value();
            }
            result->set_res(nullptr);
            result->set_op_div(0);
            result->set_op_add(0);
            result->set_val(default_value);
        });
    }
}

bool add_call(std::vector<bool>& keep,
              std::vector<std::size_t>& pending,
              std::size_t index)
{
    if (index >= keep.size() || keep[index]) {
        return false;
    }
    keep[index] = true;
    pending.push_back(index);
    return true;
}

} // namespace

bool RemoveCallRange(Prog& prog, std::size_t start, std::size_t count)
{
    auto& calls = prog.mutable_calls();
    if (count == 0 || start >= calls.size()) {
        return false;
    }

    const std::size_t removable = std::min(count, calls.size() - start);
    if (removable == 0 || removable >= calls.size()) {
        return false;
    }

    std::vector<std::unique_ptr<Call>> removed_holder;
    removed_holder.reserve(removable);
    std::unordered_set<ResultArg*> removed;

    for (std::size_t index = 0; index < removable; ++index) {
        auto victim = std::move(calls[start]);
        calls.erase(calls.begin() + static_cast<std::ptrdiff_t>(start));
        collect_result_args(victim.get(), removed);
        removed_holder.push_back(std::move(victim));
    }

    if (!removed.empty()) {
        clear_dangling_refs(calls, removed);
    }
    return true;
}

bool RemoveCall(Prog& prog, std::size_t index)
{
    return RemoveCallRange(prog, index, 1);
}

namespace {

// Extract the filename string from a non-Out DataArg whose BufferType
// kind is kFilename. Mirrors syzkaller `prog/minimization.go:217-223`:
// `bytes.TrimRight(a.Data(), "\x00")` then string-cast. Returns empty
// string when the arg isn't a filename-buffer or its data is missing.
std::string filename_string_of(const Arg* arg)
{
    if (arg == nullptr || arg->dir() == Dir::kOut) return {};
    const auto* data = as_data_arg(arg);
    if (data == nullptr) return {};
    const auto* buffer = as_buffer(arg->type());
    if (buffer == nullptr || buffer->buffer_kind() != BufferKind::kFilename) {
        return {};
    }
    const auto& bytes = data->data();
    std::size_t end = bytes.size();
    while (end > 0 && bytes[end - 1] == 0) --end;
    return std::string(reinterpret_cast<const char*>(bytes.data()), end);
}

} // namespace

RelatedCallAnalysis AnalyzeRelatedCalls(Prog& prog, std::size_t anchor_index)
{
    RelatedCallAnalysis analysis;
    analysis.keep.assign(prog.calls().size(), false);
    if (prog.calls().empty() || anchor_index >= prog.calls().size()) {
        return analysis;
    }

    std::unordered_map<const ResultArg*, std::size_t> owner;
    std::vector<std::vector<ResultArg*>> result_args_by_call(prog.calls().size());

    // §3.11 follow-up — filename string sharing edge.
    // Mirrors syzkaller `prog/minimization.go::uses` BufferFilename
    // branch: a call that uses filename "/foo" (in any in-direction
    // DataArg of BufferType{kFilename}) is kept together with every
    // other call that mentions the same filename. This catches
    // mkdir(/foo) + mount(/foo, ...) + unlink(/foo) families that
    // share dependency through a path rather than through a
    // resource fd.
    std::vector<std::vector<std::string>> filenames_by_call(prog.calls().size());

    for (std::size_t call_index = 0; call_index < prog.mutable_calls().size();
         ++call_index) {
        Call* call = prog.mutable_calls()[call_index].get();
        if (call == nullptr) continue;
        foreach_arg(call, [&](Arg* arg, ArgCtx*) {
            if (arg == nullptr) return;
            if (arg->arg_kind() == ArgKind::kResult) {
                auto* result = static_cast<ResultArg*>(arg);
                owner.emplace(result, call_index);
                result_args_by_call[call_index].push_back(result);
                ++analysis.result_args;
                return;
            }
            std::string fname = filename_string_of(arg);
            if (!fname.empty()) {
                filenames_by_call[call_index].push_back(std::move(fname));
                ++analysis.filename_atoms;
            }
        });
    }
    analysis.owner_entries = owner.size();

    // Reverse index: filename string -> set of calls that mention it.
    std::unordered_map<std::string, std::vector<std::size_t>> filename_to_calls;
    for (std::size_t call_index = 0; call_index < filenames_by_call.size();
         ++call_index) {
        for (const auto& fname : filenames_by_call[call_index]) {
            filename_to_calls[fname].push_back(call_index);
        }
    }

    std::vector<std::size_t> pending;
    add_call(analysis.keep, pending, anchor_index);
    while (!pending.empty()) {
        const std::size_t call_index = pending.back();
        pending.pop_back();

        for (ResultArg* result : result_args_by_call[call_index]) {
            if (const ResultArg* producer = result->res();
                producer != nullptr) {
                ++analysis.producer_edge_checks;
                const auto it = owner.find(producer);
                if (it != owner.end()) {
                    if (add_call(analysis.keep, pending, it->second)) {
                        ++analysis.producer_edge_adds;
                    }
                }
            }

            for (ResultArg* consumer : result->uses()) {
                ++analysis.consumer_edge_checks;
                const auto it = owner.find(consumer);
                if (it != owner.end()) {
                    if (add_call(analysis.keep, pending, it->second)) {
                        ++analysis.consumer_edge_adds;
                    }
                }
            }
        }

        for (const auto& fname : filenames_by_call[call_index]) {
            const auto it = filename_to_calls.find(fname);
            if (it == filename_to_calls.end()) continue;
            for (std::size_t peer_index : it->second) {
                ++analysis.filename_edge_checks;
                if (add_call(analysis.keep, pending, peer_index)) {
                    ++analysis.filename_edge_adds;
                }
            }
        }
    }

    return analysis;
}

std::vector<bool> RelatedCalls(Prog& prog, std::size_t anchor_index)
{
    return AnalyzeRelatedCalls(prog, anchor_index).keep;
}

} // namespace refuzz::program::syz
