#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/core/watch_bus.hpp"

#include <string>
#include <vector>

int main()
{
    {
        refuzz::core::WatchBus<std::string> bus;
        bus.Publish("first");
        auto sub = bus.Subscribe();

        std::string value;
        if (!sub.TryConsume(value) || value != "first") {
            return 1;
        }
        if (sub.TryConsume(value)) {
            return 1;
        }

        auto late_sub = bus.Subscribe();
        bus.Publish("second");
        if (!sub.TryConsume(value) || value != "second") {
            return 1;
        }
        if (!late_sub.TryConsume(value) || value != "second") {
            return 1;
        }
    }

    {
        refuzz::core::BroadcastBus<int> bus(2);
        auto sub = bus.Subscribe();
        bus.Publish(1);
        bus.Publish(2);
        bus.Publish(3);

        std::vector<int> values;
        const auto stats = sub.Drain(values);
        if (stats.dropped != 1 || stats.delivered != 2) {
            return 1;
        }
        if (values.size() != 2 || values[0] != 2 || values[1] != 3) {
            return 1;
        }
    }

    return 0;
}
