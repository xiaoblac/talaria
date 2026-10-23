#pragma once

namespace refuzz::worker {

class IWorkerRegistrar {
public:
    virtual ~IWorkerRegistrar() = default;
    // Publishes daemon ownership in a not-ready state and starts liveness
    // reporting. Execution-domain READY is published separately after setup.
    virtual int Register() { return 0; }
};

} // namespace refuzz::worker
