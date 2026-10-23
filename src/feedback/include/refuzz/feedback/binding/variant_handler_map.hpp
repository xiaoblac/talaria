// Copyright 2026 reFuzz project author -------youngkk.
//
// VariantHandlerMap — the LIVE variant->handler binding (per_call-attributed).
//
// The variant->kernel-handler relation is, by the kernel's design, a RUNTIME relation: the
// cmd->handler dispatch lives in code, not in names (static name-match binds only ~2% of
// variants; 41% are $auto). The reliable binding is per_call: when a variant executes,
// KernelCallObservation.per_call[i].coverage_hashes is exactly the code that call ran, and
// per_call[i].syscall_id is the variant's identity (SyscallMeta::id). This component
// accumulates, across executions, variant_id -> {handler functions it covered}, building the
// real binding for every variant the campaign exercises (30% in a 2h corpus, growing).
//
// It is the entry side of the structural-horizon region: region(variant) = forward closure
// from these handler functions x specificity (1/reach_count). See
// docs/plans/variant-handler-binding-report.md and door-frontier-seed-value-p1.md.
//
// Observation-only here: it builds + flushes the map; it drives nothing.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::fuzzer {

struct KernelExecutionObservation;

class VariantHandlerMap {
public:
    // Optional RAII dump path: Flush()/the dtor write here (mirrors SeedLineageYieldStore).
    // Empty = in-memory only (tests use the explicit Flush(path) overload).
    explicit VariantHandlerMap(std::string dump_path = {}) : dump_path_(std::move(dump_path)) {}
    ~VariantHandlerMap() { if (!dump_path_.empty()) Flush(dump_path_); }

    VariantHandlerMap(const VariantHandlerMap&) = delete;
    VariantHandlerMap& operator=(const VariantHandlerMap&) = delete;

    // Static function universe (function_block_map.tsv: "<hex_start>\t<blocks>\t<name>"),
    // used to map a per-call KCOV PC to its containing kernel function. Inert if unreadable.
    bool LoadFunctionMap(const std::string& tsv_path);
    bool ready() const { return !func_starts_.empty(); }

    // SyscallMeta::id -> variant name (from Target), for a human-readable flush. Optional;
    // without it the flush emits numeric ids.
    void SetVariantNames(std::vector<std::string> id_to_name) { id_to_name_ = std::move(id_to_name); }

    // Accumulate this execution's per-call binding: for each EXECUTED call with coverage,
    // variant = per_call[i].syscall_id, handlers += functions of per_call[i].coverage_hashes.
    // Cheap: O(covered PCs). Needs raw_pc=true (else FuncOf is meaningless).
    void OnExec(const KernelExecutionObservation& obs);

    // Dump variant -> top handler functions (by hit-count) + exec/cover stats. Rewrites `path`.
    bool Flush(const std::string& path) const;
    // Flush to the RAII dump_path_ (periodic mid-run dump); no-op if unset.
    bool Flush() const { return dump_path_.empty() ? false : Flush(dump_path_); }

    std::size_t variant_count() const { return per_variant_.size(); }

private:
    int FuncOf(std::uint64_t pc) const;  // binary search; -1 below range

    std::string                dump_path_;     // RAII flush target ("" = in-memory)
    std::vector<std::uint64_t> func_starts_;   // sorted ascending
    std::vector<std::int32_t>  func_blocks_;    // parallel
    std::vector<std::string>   func_names_;     // parallel (for flush)
    std::vector<std::string>   id_to_name_;     // SyscallMeta::id -> name (optional)

    // variant syscall_id -> (func_idx -> #execs that covered it); + per-variant exec count.
    std::unordered_map<std::uint32_t, std::unordered_map<int, std::uint32_t>> per_variant_;
    std::unordered_map<std::uint32_t, std::uint32_t> exec_count_;
};

}  // namespace refuzz::fuzzer
