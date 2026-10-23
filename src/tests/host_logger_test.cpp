#include "refuzz/logging/host_logger.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace {

std::atomic<bool> g_count_allocations{false};
std::atomic<size_t> g_allocations{0};

void CountAllocation()
{
    if (g_count_allocations.load(std::memory_order_relaxed)) {
        g_allocations.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace

void* operator new(std::size_t size)
{
    CountAllocation();
    if (void* ptr = std::malloc(size)) {
        return ptr;
    }
    throw std::bad_alloc();
}

void* operator new[](std::size_t size)
{
    CountAllocation();
    if (void* ptr = std::malloc(size)) {
        return ptr;
    }
    throw std::bad_alloc();
}

void operator delete(void* ptr) noexcept
{
    std::free(ptr);
}

void operator delete[](void* ptr) noexcept
{
    std::free(ptr);
}

void operator delete(void* ptr, std::size_t) noexcept
{
    std::free(ptr);
}

void operator delete[](void* ptr, std::size_t) noexcept
{
    std::free(ptr);
}

#define CHECK(cond)                                                                           \
    do {                                                                                      \
        if (!(cond)) {                                                                        \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__);            \
            return 1;                                                                         \
        }                                                                                     \
    } while (0)

static std::string TestPath()
{
    return "/tmp/refuzz_host_logger_test_" + std::to_string(static_cast<long long>(getpid())) +
           ".txt";
}

static int TestDisabledDoesNotWriteSink()
{
    namespace fs = std::filesystem;
    const std::string path = TestPath();
    fs::remove(path);

    auto& logger = refuzz::logging::HostLogger::Instance();
    logger.Shutdown();
    refuzz::logging::HostLoggerConfig config;
    config.enabled = false;
    config.stream_to_stdout = false;
    config.path = path;
    config.hot_path_sample_rate = 1;
    logger.Initialize(std::move(config));

    logger.Log("C", "E");
    logger.Shutdown();

    CHECK(!fs::exists(path));
    return 0;
}

static int TestDisabledEmptyLogAllocatesNothing()
{
    auto& logger = refuzz::logging::HostLogger::Instance();
    logger.Shutdown();
    refuzz::logging::HostLoggerConfig config;
    config.enabled = false;
    config.stream_to_stdout = false;
    config.hot_path_sample_rate = 1;
    logger.Initialize(std::move(config));

    g_allocations.store(0, std::memory_order_relaxed);
    g_count_allocations.store(true, std::memory_order_relaxed);
    logger.Log("C", "E");
    g_count_allocations.store(false, std::memory_order_relaxed);

    logger.Shutdown();
    CHECK(g_allocations.load(std::memory_order_relaxed) == 0);
    return 0;
}

static int TestDisabledVectorLogAllocatesNothing()
{
    std::vector<refuzz::logging::HostLogField> fields;
    fields.reserve(1);
    fields.push_back(refuzz::logging::HostLogField{"k", "v"});

    auto& logger = refuzz::logging::HostLogger::Instance();
    logger.Shutdown();
    refuzz::logging::HostLoggerConfig config;
    config.enabled = false;
    config.stream_to_stdout = false;
    config.hot_path_sample_rate = 1;
    logger.Initialize(std::move(config));

    g_allocations.store(0, std::memory_order_relaxed);
    g_count_allocations.store(true, std::memory_order_relaxed);
    logger.Log("C", "E", fields);
    g_count_allocations.store(false, std::memory_order_relaxed);

    logger.Shutdown();
    CHECK(g_allocations.load(std::memory_order_relaxed) == 0);
    return 0;
}

static int TestTaskTraceSamplingIsIndependent()
{
    namespace fs = std::filesystem;
    const std::string path = TestPath();
    fs::remove(path);

    auto& logger = refuzz::logging::HostLogger::Instance();
    logger.Shutdown();
    refuzz::logging::HostLoggerConfig config;
    config.enabled = true;
    config.stream_to_stdout = false;
    config.path = path;
    config.hot_path_sample_rate = 0;
    config.task_trace_sample_rate = 3;
    logger.Initialize(std::move(config));

    CHECK(!logger.ShouldLogHotPath(3));
    CHECK(!logger.ShouldSampleTaskTrace(1));
    CHECK(logger.ShouldSampleTaskTrace(3));
    CHECK(logger.ShouldSampleTaskTrace(6));

    logger.Shutdown();
    fs::remove(path);
    return 0;
}

int main()
{
    if (int rc = TestDisabledDoesNotWriteSink()) return rc;
    if (int rc = TestDisabledEmptyLogAllocatesNothing()) return rc;
    if (int rc = TestDisabledVectorLogAllocatesNothing()) return rc;
    if (int rc = TestTaskTraceSamplingIsIndependent()) return rc;
    return 0;
}
