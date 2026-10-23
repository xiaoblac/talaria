#include "refuzz/core/service.hpp"
#include "refuzz/core/service_registry.hpp"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

class MockService : public refuzz::core::IService {
public:
    explicit MockService(std::string name)
        : name_(std::move(name))
    {
    }

    std::string_view Name() const override { return name_; }

    refuzz::core::ServiceResult Init() override
    {
        inited_ = true;
        return init_fail_ ? std::unexpected(refuzz::core::ComponentError::Init(name_, "init fail"))
                          : refuzz::core::ServiceResult{};
    }

    refuzz::core::ServiceResult Start() override
    {
        if (!inited_) {
            return std::unexpected(refuzz::core::ComponentError::Init(name_, "not inited"));
        }
        started_ = true;
        running_ = true;
        return start_fail_ ? std::unexpected(refuzz::core::ComponentError::Init(name_, "start fail"))
                           : refuzz::core::ServiceResult{};
    }

    refuzz::core::ServiceResult Stop() override
    {
        running_ = false;
        stopped_count_++;
        return {};
    }

    bool IsRunning() const override { return running_; }

    bool inited_        = false;
    bool started_       = false;
    int  stopped_count_ = 0;
    bool init_fail_     = false;
    bool start_fail_    = false;
    bool running_       = false;

private:
    std::string name_;
};

} // namespace

int main()
{
    using refuzz::core::ServiceRegistry;

    // 1. Register + Find
    {
        ServiceRegistry reg;
        auto            a = std::make_unique<MockService>("a");
        if (!reg.Register(std::move(a))) {
            return 1;
        }
        if (reg.Find("a") == nullptr || reg.Find("missing") != nullptr || reg.Size() != 1) {
            return 2;
        }
    }

    // 2. Topological order with deps
    {
        ServiceRegistry reg;
        auto            c = std::make_unique<MockService>("c");
        auto            b = std::make_unique<MockService>("b");
        auto            a = std::make_unique<MockService>("a");
        reg.Register(std::move(c), {"b"});
        reg.Register(std::move(b), {"a"});
        reg.Register(std::move(a));
        auto order = reg.TopologicalOrder();
        if (!order.has_value()) {
            return 3;
        }
        auto index_of = [&](std::string_view name) {
            auto it = std::find(order->begin(), order->end(), name);
            return std::distance(order->begin(), it);
        };
        if (!(index_of("a") < index_of("b") && index_of("b") < index_of("c"))) {
            return 4;
        }
    }

    // 3. Cycle detection
    {
        ServiceRegistry reg;
        auto            a = std::make_unique<MockService>("a");
        auto            b = std::make_unique<MockService>("b");
        reg.Register(std::move(a), {"b"});
        reg.Register(std::move(b), {"a"});
        if (reg.TopologicalOrder().has_value()) {
            return 5;
        }
    }

    // 4. InitAll does not roll back earlier inits on failure
    {
        ServiceRegistry reg;
        auto            ok  = std::make_unique<MockService>("ok");
        auto            bad = std::make_unique<MockService>("bad");
        bad->init_fail_ = true;
        reg.Register(std::move(ok));
        reg.Register(std::move(bad), {"ok"});
        if (reg.InitAll()) {
            return 6;
        }
        auto* ok_svc = static_cast<MockService*>(reg.Find("ok"));
        if (ok_svc == nullptr || !ok_svc->inited_) {
            return 7;
        }
    }

    // 5. StartAll failure rolls back with Stop on started
    {
        ServiceRegistry reg;
        auto            a = std::make_unique<MockService>("a");
        auto            b = std::make_unique<MockService>("b");
        auto*           bp = static_cast<MockService*>(b.get());
        bp->start_fail_ = true;
        reg.Register(std::move(a));
        reg.Register(std::move(b), {"a"});
        if (!reg.InitAll() || reg.StartAll()) {
            return 8;
        }
        auto* a_svc = static_cast<MockService*>(reg.Find("a"));
        if (a_svc == nullptr || a_svc->stopped_count_ < 1 || a_svc->IsRunning()) {
            return 9;
        }
    }

    // 6. StopAll idempotent
    {
        ServiceRegistry reg;
        auto            s = std::make_unique<MockService>("s");
        reg.Register(std::move(s));
        if (!reg.InitAll() || !reg.StartAll() || !reg.StopAll() || !reg.StopAll()) {
            return 10;
        }
    }

    // 7. Dependency chain A -> B -> C
    {
        ServiceRegistry reg;
        reg.Register(std::make_unique<MockService>("c"), {"b"});
        reg.Register(std::make_unique<MockService>("b"), {"a"});
        reg.Register(std::make_unique<MockService>("a"));
        auto order = reg.TopologicalOrder();
        if (!order.has_value() || order->size() != 3) {
            return 11;
        }
        if ((*order)[0] != "a" || (*order)[1] != "b" || (*order)[2] != "c") {
            return 12;
        }
    }

    // 8. Real topology (plan)
    {
        ServiceRegistry reg;
        auto            ch       = std::make_unique<MockService>("channel_0");
        auto            exec     = std::make_unique<MockService>("executor");
        auto            health   = std::make_unique<MockService>("health_monitor");
        auto            tele     = std::make_unique<MockService>("telemetry");
        auto            exporter = std::make_unique<MockService>("state_exporter");

        reg.Register(std::move(tele), {"health_monitor"});
        reg.Register(std::move(exporter), {"telemetry"});
        reg.Register(std::move(ch));
        reg.Register(std::move(exec), {"channel_0"});
        reg.Register(std::move(health), {"executor"});

        auto order = reg.TopologicalOrder();
        if (!order.has_value()) {
            return 13;
        }
        auto index_of = [&](std::string_view name) {
            auto it = std::find(order->begin(), order->end(), name);
            return std::distance(order->begin(), it);
        };
        if (!(index_of("channel_0") < index_of("executor")
              && index_of("executor") < index_of("health_monitor")
              && index_of("health_monitor") < index_of("telemetry")
              && index_of("telemetry") < index_of("state_exporter"))) {
            return 14;
        }
    }

    return 0;
}
