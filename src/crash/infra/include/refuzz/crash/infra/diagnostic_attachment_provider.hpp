#pragma once

#include "refuzz/crash/infra/diagnostic_artifact.hpp"
#include "refuzz/proto_domain/combined_crash_event.hpp"

namespace refuzz::crash {

class IDiagnosticAttachmentProvider {
public:
    virtual ~IDiagnosticAttachmentProvider() = default;

    virtual void EnrichCrashProgram(const refuzz::proto::FrozenProgramEntry&,
                                    DiagnosticArtifact*)
    {}

    virtual void EnrichFaultEvent(const refuzz::proto::FaultEvent&,
                                  DiagnosticArtifact*)
    {}
};

} // namespace refuzz::crash
