#pragma once

#include "refuzz/crash/infra/diagnostic_artifact.hpp"

#include <mutex>
#include <string>
#include <unordered_set>

namespace refuzz::crash {

enum class SaveStatus {
    kSaved,
    kDuplicate,
    kIOError,
};

class DiagnosticStore {
public:
    explicit DiagnosticStore(std::string root_dir);

    SaveStatus SaveArtifact(const DiagnosticArtifact& artifact);
    bool IsDuplicate(CrashKind kind, uint64_t hash) const;
    size_t Count() const;
    static std::string Hex16(uint64_t value);

private:
    void LoadExistingArtifacts();

    std::string root_dir_;
    mutable std::mutex mu_;
    std::unordered_set<std::string> seen_keys_;
};

} // namespace refuzz::crash
