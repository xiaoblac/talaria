// runtime_pool.cpp — RuntimePool 实现
//
// Create 校验 RuntimePoolConfig（§5）；
// CreateInstance 校验 RuntimeInstanceConfig + WorkerConfig，
// 调用 substrate_ops_.create_instance 获取函数表，构造 RuntimeInstance。
//
// 设计来源：docs/channel-redesign/components/runtime.md §2.1 §5

#include "refuzz/channel/runtime/runtime_pool.hpp"
#include "refuzz/channel/runtime/runtime_instance.hpp"

#include <sys/stat.h>
#include <unistd.h>

namespace refuzz::channel::runtime {

namespace {

// ── 校验辅助 ─────────────────────────────────────────────────

static bool FileReadable(const std::string& path) {
    return !path.empty() && ::access(path.c_str(), R_OK) == 0;
}

static bool EnsureDir(const std::string& path) {
    if (path.empty()) return false;
    struct stat st{};
    if (::stat(path.c_str(), &st) == 0) {
        // 已存在：必须是目录
        return S_ISDIR(st.st_mode);
    }
    // 不存在：尝试创建（单层）
    return ::mkdir(path.c_str(), 0755) == 0;
}

// §5.1 RuntimeInstanceConfig 必填 + 文件可读性校验
static Result<void> ValidateInstanceConfig(const RuntimeInstanceConfig& cfg)
{
    // 必填字段
    if (cfg.kernel.empty())
        return Error{ErrorKind::kConfig, "RuntimeInstanceConfig.kernel is required"};
    if (cfg.disk_image.empty())
        return Error{ErrorKind::kConfig, "RuntimeInstanceConfig.disk_image is required"};
    if (cfg.ssh_key.empty())
        return Error{ErrorKind::kConfig, "RuntimeInstanceConfig.ssh_key is required"};
    if (cfg.workdir.empty())
        return Error{ErrorKind::kConfig, "RuntimeInstanceConfig.workdir is required"};

    // 文件可读性
    if (!FileReadable(cfg.kernel))
        return Error{ErrorKind::kConfig, "kernel not readable: " + cfg.kernel};
    if (!FileReadable(cfg.disk_image))
        return Error{ErrorKind::kConfig, "disk_image not readable: " + cfg.disk_image};
    if (!FileReadable(cfg.ssh_key))
        return Error{ErrorKind::kConfig, "ssh_key not readable: " + cfg.ssh_key};

    // workdir：不存在则创建
    if (!EnsureDir(cfg.workdir))
        return Error{ErrorKind::kConfig, "workdir not writable/creatable: " + cfg.workdir};

    // §5.2 枚举约束
    if (cfg.ivshmem_mode != "plain" && cfg.ivshmem_mode != "doorbell")
        return Error{ErrorKind::kConfig,
                     "ivshmem_mode must be 'plain' or 'doorbell', got: " + cfg.ivshmem_mode};

    if (cfg.ivshmem_mode == "plain") {
        if (cfg.ivshmem_path.empty())
            return Error{ErrorKind::kConfig, "ivshmem_path required for plain mode"};
        if (cfg.ivshmem_bytes == 0)
            return Error{ErrorKind::kConfig, "ivshmem_bytes > 0 required for plain mode"};
    } else { // doorbell
        if (cfg.ivshmem_socket.empty())
            return Error{ErrorKind::kConfig, "ivshmem_socket required for doorbell mode"};
        if (cfg.ivshmem_vectors < 1)
            return Error{ErrorKind::kConfig, "ivshmem_vectors >= 1 required for doorbell mode"};
    }

    if (cfg.qmp_port_policy == QmpPortPolicy::kFixed && cfg.qmp_fixed_port <= 0)
        return Error{ErrorKind::kConfig, "qmp_fixed_port > 0 required when policy=kFixed"};

    return Result<void>::Ok();
}

// §5.1 WorkerConfig 必填 + 文件可读性校验
static Result<void> ValidateWorkerConfig(const worker::WorkerConfig& cfg)
{
    if (cfg.worker_binary_host_path.empty())
        return Error{ErrorKind::kConfig,
                     "WorkerConfig.worker_binary_host_path is required"};
    if (!FileReadable(cfg.worker_binary_host_path))
        return Error{ErrorKind::kConfig,
                     "worker_binary_host_path not readable: " +
                     cfg.worker_binary_host_path};
    if (cfg.n_workers == 0)
        return Error{ErrorKind::kConfig, "WorkerConfig.n_workers must be > 0"};
    return Result<void>::Ok();
}

} // namespace

// ── 私有构造 ─────────────────────────────────────────────────

RuntimePool::RuntimePool(RuntimePoolConfig cfg, SubstratePoolOps ops)
    : config_(std::move(cfg)), substrate_ops_(std::move(ops))
{}

RuntimePool::~RuntimePool() = default;

// ── Create ────────────────────────────────────────────────────

Result<std::unique_ptr<RuntimePool>> RuntimePool::Create(
    RuntimePoolConfig cfg,
    SubstratePoolOps  substrate_ops)
{
    // §5.2 substrate_kind 约束
    if (cfg.substrate_kind != "vm")
        return Error{ErrorKind::kConfig,
                     "substrate_kind must be 'vm', got: " + cfg.substrate_kind};

    if (cfg.pool_size == 0)
        return Error{ErrorKind::kConfig, "pool_size must be > 0"};

    // substrate_ops 有效性（count 回调必须存在）
    if (!substrate_ops.count || !substrate_ops.create_instance || !substrate_ops.close)
        return Error{ErrorKind::kConfig, "substrate_ops callbacks must not be null"};

    return Result<std::unique_ptr<RuntimePool>>::Ok(
        std::unique_ptr<RuntimePool>(
            new RuntimePool(std::move(cfg), std::move(substrate_ops))));
}

// ── CreateInstance ────────────────────────────────────────────

Result<std::unique_ptr<RuntimeInstance>> RuntimePool::CreateInstance(
    const RuntimeInstanceConfig& instance_cfg,
    const worker::WorkerConfig&  worker_cfg)
{
    if (closed_)
        return Error{ErrorKind::kConfig, "RuntimePool already closed"};

    // §5 校验
    auto vcfg = ValidateInstanceConfig(instance_cfg);
    if (!vcfg.ok()) return Error{vcfg.error().kind, vcfg.error().message};

    auto vwcfg = ValidateWorkerConfig(worker_cfg);
    if (!vwcfg.ok()) return Error{vwcfg.error().kind, vwcfg.error().message};


    // doorbell 模式要求 ivshmem_vectors 严格等于 n_workers，
    // 保证 worker_id ↔ vector/eventfd 1:1 映射，避免多余 vector 导致路由歧义
    if (instance_cfg.ivshmem_mode == "doorbell" &&
        instance_cfg.ivshmem_vectors != static_cast<int>(worker_cfg.n_workers)) {
        return Error{
            ErrorKind::kConfig,
            "doorbell mode requires ivshmem_vectors == n_workers (vectors=" +
                std::to_string(instance_cfg.ivshmem_vectors) +
                ", n_workers=" + std::to_string(worker_cfg.n_workers) + ")"
        };
    }

    // 底座实例函数表
    auto ops_r = substrate_ops_.create_instance(instance_cfg);
    if (!ops_r.ok())
        return Error{ops_r.error().kind, ops_r.error().message};

    // 将 RuntimeInstanceConfig 中的部署超时注入 WorkerConfig
    worker::WorkerConfig effective_cfg = worker_cfg;
    effective_cfg.deploy_timeout       = instance_cfg.deploy_timeout;
    effective_cfg.start_worker_timeout = instance_cfg.start_worker_timeout;
    effective_cfg.stop_worker_timeout  = instance_cfg.stop_worker_timeout;

    return Result<std::unique_ptr<RuntimeInstance>>::Ok(
        std::make_unique<RuntimeInstance>(
            std::move(ops_r).value(), std::move(effective_cfg)));
}

// ── Count / Close ─────────────────────────────────────────────

uint32_t RuntimePool::Count() const {
    return config_.pool_size;
}

Result<void> RuntimePool::Close() {
    if (closed_) return Result<void>::Ok();
    closed_ = true;
    return substrate_ops_.close();
}

} // namespace refuzz::channel::runtime
