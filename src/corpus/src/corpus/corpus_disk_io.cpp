#include "refuzz/corpus/corpus_disk_io.hpp"

#include "refuzz/logging/host_logger.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/seed_metadata.hpp"        // [v2 batch 3 G6] SeedAdmissionStateMetadata
#include "refuzz/program/seed_metadata_serde.hpp"  // [v2 batch 3 PR-W3]
#include "refuzz/program/syz/target.hpp"
#include "util/json.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <optional>  // [v2 batch 3 G6 fix #5] LoadFromFiles force_source param
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

namespace refuzz::fuzzer {

namespace {
std::string Hex16(uint64_t value)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << value;
    return oss.str();
}

bool ReadWholeFile(const std::filesystem::path& path, std::vector<uint8_t>& out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        return false;
    }
    in.seekg(0, std::ios::beg);
    out.assign(static_cast<size_t>(size), 0);
    if (!out.empty()) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
        if (!in) {
            return false;
        }
    }
    return true;
}

bool WriteMetadataSidecar(const Seed& seed, const std::filesystem::path& path)
{
    // [v2 batch 3 PR-W3] lazy 幂等注册 builtin metadata serde(同 json_key
    // replace-in-place;无 std::call_once,test ResetForTest 后再次触发可重新装载)。
    RegisterBuiltinSeedMetadataSerdes();

    nlohmann::json root;
    // ── core sidecar 字段(corpus 自管,不进 registry) ─────────────────────
    root["schema_version"]   = 1;
    root["seed_id"]          = seed.seed_id;
    root["priority"]         = seed.priority;
    root["interesting_hits"] = seed.interesting_hits;

    if (seed.metadata.Get<SeedSourceMetadata>() == nullptr) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_write_invalid")
            << "path=" << path.string()
            << " reason=missing_seed_source\n";
        return false;
    }
    if (seed.metadata.Get<SeedAdmissionStateMetadata>() == nullptr) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_write_invalid")
            << "path=" << path.string()
            << " reason=missing_seed_admission_state\n";
        return false;
    }

    // ── durable metadata 通过 registry 写(corpus_disk_io 不直接 include 类型) ──
    SeedMetadataSerdeRegistry::Instance().WriteAll(seed.metadata, root);
    if (!root.contains("seed_source") || !root["seed_source"].is_object() ||
        !root.contains("seed_admission_state") ||
        !root["seed_admission_state"].is_object()) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_write_invalid")
            << "path=" << path.string()
            << " reason=missing_required_runtime_metadata\n";
        return false;
    }

    const auto tmp = path.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            return false;
        }
        out << root.dump(2) << "\n";
        out.flush();
        if (!out.good()) {
            return false;
        }
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::error_code ignore_ec;
        std::filesystem::remove(tmp, ignore_ec);
        return false;
    }
    return true;
}

enum class MetadataSidecarStatus {
    kOk,
    kMissingLegacy,
    kInvalid,
};

MetadataSidecarStatus ReadMetadataSidecar(Seed& seed, const std::filesystem::path& path)
{
    // [v2 batch 3 PR-W3] lazy 幂等注册 builtin metadata serde。
    RegisterBuiltinSeedMetadataSerdes();

    nlohmann::json root;
    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_stat_failed")
            << "path=" << path.string()
            << " error=" << ec.message() << "\n";
        return MetadataSidecarStatus::kInvalid;
    }
    if (!exists) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_migration")
            << "old-format seed missing metadata sidecar: " << path.string() << "\n";
        seed.metadata.Set(SeedSourceMetadata{SeedSource::kBootCorpus, /*attempt=*/0});
        seed.metadata.Set(SeedAdmissionStateMetadata{});
        return MetadataSidecarStatus::kMissingLegacy;
    }

    std::ifstream in(path);
    if (!in) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_open_failed")
            << "path=" << path.string() << "\n";
        return MetadataSidecarStatus::kInvalid;
    }
    try {
        in >> root;
    } catch (const std::exception& ex) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_parse_failed")
            << "path=" << path.string()
            << " error=" << ex.what() << "\n";
        return MetadataSidecarStatus::kInvalid;
    } catch (...) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_parse_failed")
            << "path=" << path.string()
            << " error=unknown\n";
        return MetadataSidecarStatus::kInvalid;
    }
    if (!root.is_object()) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_schema_invalid")
            << "path=" << path.string()
            << " reason=root_not_object\n";
        return MetadataSidecarStatus::kInvalid;
    }

    // ── core sidecar 字段(corpus 自管,只在 root 是 object 时读) ──
    if (root.contains("priority") && root["priority"].is_number_integer()) {
        seed.priority = root["priority"].get<int32_t>();
    }
    if (root.contains("interesting_hits") && root["interesting_hits"].is_number_unsigned()) {
        seed.interesting_hits = root["interesting_hits"].get<uint32_t>();
    }

    // ── durable metadata 通过 registry 读 ──
    SeedMetadataSerdeRegistry::Instance().ReadAll(root, seed.metadata);
    return MetadataSidecarStatus::kOk;
}

bool ValidateLoadedMetadata(const Seed& seed,
                            MetadataSidecarStatus status,
                            const std::filesystem::path& metadata_path,
                            const std::filesystem::path& payload_file)
{
    if (status == MetadataSidecarStatus::kInvalid) {
        return false;
    }

    if (seed.metadata.Get<SeedSourceMetadata>() == nullptr) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_schema_invalid")
            << "path=" << metadata_path.string()
            << " payload=" << payload_file.string()
            << " reason=missing_or_invalid_seed_source\n";
        return false;
    }
    if (seed.metadata.Get<SeedAdmissionStateMetadata>() == nullptr) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "metadata_schema_invalid")
            << "path=" << metadata_path.string()
            << " payload=" << payload_file.string()
            << " reason=missing_or_invalid_seed_admission_state\n";
        return false;
    }
    return true;
}

std::vector<std::filesystem::path> CollectPayloadFiles(const std::string& root_dir,
                                                       const char* filename)
{
    namespace fs = std::filesystem;
    std::vector<fs::path> files;

    std::error_code ec;
    if (!fs::exists(root_dir, ec) || ec) {
        return files;
    }

    for (fs::directory_iterator it(root_dir, ec), end; !ec && it != end; it.increment(ec)) {
        if (!it->is_directory()) {
            continue;
        }
        const fs::path payload = it->path() / filename;
        std::error_code exists_ec;
        if (fs::exists(payload, exists_ec) && !exists_ec) {
            files.push_back(payload);
        }
    }
    if (ec) {
        files.clear();
        return files;
    }

    std::sort(files.begin(), files.end());
    return files;
}


// [v2 batch 3 G6 fix #5] `force_source` 参数:non-null 时,**覆盖** ReadMetadataSidecar
// 后的 SeedSourceMetadata.source。`std::nullopt` 走原 path(LoadAll 用)。
// [candidate-model] 从单个 payload 文件物化一个 Seed,**不**插入任何
// store / scheduler / pending。返回 nullopt = 文件不可读或被 load_policy 丢弃。
// corpus-store 加载路径(LoadFromFiles)和 candidate 加载路径(LoadAllAsSeeds)
// 共用它,使 materialize + metadata-sidecar 读取只有一处。
std::optional<Seed> BuildSeedFromFile(
    const std::filesystem::path&                     payload_file,
    SeedIdAllocator&                                 id_alloc,
    const ::refuzz::program::ArtifactMaterializerFn& materializer,
    CorpusLoadPolicy                                 load_policy,
    std::optional<SeedSource>                        force_source)
{
    std::vector<uint8_t> payload;
    if (!ReadWholeFile(payload_file, payload)) {
        return std::nullopt;
    }

    std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;
    if (materializer) {
        artifact = materializer(payload);
    }

    // PR1 fail-closed：StrictTyped 下没有 artifact 直接整 seed drop。
    // 同时覆盖 (a) materializer == null 和 (b) materializer 返回 null 两种。
    if (load_policy == CorpusLoadPolicy::StrictTyped && artifact == nullptr) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "drop_undecodable")
            << payload_file.string()
            << " (policy=StrictTyped, materializer="
            << (materializer ? "returned_null" : "absent") << ")\n";
        return std::nullopt;
    }

    Seed seed;
    seed.seed_id = id_alloc.Allocate();
    seed.payload = std::move(payload);
    seed.artifact = std::move(artifact);
    seed.priority = 1;
    const auto metadata_path = payload_file.parent_path() / "metadata.json";
    const auto metadata_status = ReadMetadataSidecar(seed, metadata_path);
    if (!ValidateLoadedMetadata(seed, metadata_status, metadata_path, payload_file)) {
        refuzz::logging::HostLineBuilder("CorpusDiskIO", "drop_bad_metadata")
            << payload_file.string() << "\n";
        return std::nullopt;
    }
    // [v2 batch 3 G6 fix #5] force_source override:LoadCrashRepros 传
    // kReplayHistory,确保 crash repro seed 不被 corpus_verify_producer
    // 当 kBootCorpus 处理。
    if (force_source.has_value()) {
        SeedSourceMetadata src;
        if (const auto* old = seed.metadata.Get<SeedSourceMetadata>()) {
            src = *old;  // 保 attempt 等其它字段
        }
        src.source = *force_source;
        seed.metadata.Set(std::move(src));
    }
    return seed;
}

// 扫描文件 → 建 Seed → 入 corpus store + 注册 scheduler。inactive seed 物理
// 保留但不进 scheduler pool(NextSeedId 永不返)。
// [candidate-model] boot corpus **不再**走这条(改走 LoadAllAsSeeds →
// PendingSeedMap,经 verify→minimize→admit 才入 corpus);本路径留给 crash
// repro(force_source=kReplayHistory)等"信任直入 corpus"的 seed 源。
size_t LoadFromFiles(ICorpusStore&                                   store,
                     ISchedulerEngine&                               scheduler,
                     SeedIdAllocator&                                id_alloc,
                     const std::vector<std::filesystem::path>&       files,
                     const ::refuzz::program::ArtifactMaterializerFn& materializer,
                     CorpusLoadPolicy                                 load_policy,
                     std::optional<SeedSource>                        force_source = std::nullopt)
{
    size_t loaded = 0;
    for (const auto& payload_file : files) {
        auto seed_opt = BuildSeedFromFile(payload_file, id_alloc, materializer,
                                          load_policy, force_source);
        if (!seed_opt.has_value()) {
            continue;
        }
        const uint64_t id = seed_opt->seed_id;
        bool is_inactive = false;
        if (const auto* admit = seed_opt->metadata.Get<SeedAdmissionStateMetadata>()) {
            is_inactive = (admit->state == SeedAdmissionState::kInactive);
        }
        if (!store.AddSeed(std::move(*seed_opt))) {
            continue;
        }
        if (is_inactive) {
            refuzz::logging::HostLineBuilder("CorpusDiskIO", "skip_inactive_on_load")
                << "seed_id=" << id
                << " state=kInactive (retained on disk, not scheduled)\n";
            // 不调 scheduler.OnSeedAdded;loaded 仍计数(physical load 成功)。
        } else {
            scheduler.OnSeedAdded(id);
        }
        loaded++;
    }
    return loaded;
}
} // namespace

bool CorpusDiskIO::SaveSeed(const Seed& seed, const std::string& corpus_dir)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::path(corpus_dir) / Hex16(seed.seed_id);
    const fs::path final_path = dir / "payload.bin";
    const fs::path tmp_path = dir / "payload.bin.tmp";
    const fs::path metadata_path = dir / "metadata.json";

    std::error_code ec;
    if (fs::exists(final_path, ec) && !ec) {
        return fs::exists(metadata_path, ec) && !ec
            ? true
            : WriteMetadataSidecar(seed, metadata_path);
    }
    if (ec) {
        return false;
    }

    fs::create_directories(dir, ec);
    if (ec) {
        return false;
    }

    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }

        // §3.10 step 4 — prefer the artifact's materializer when v2
        // authority is present (canonical text is computed via the
        // typed view's lazy provider — TextEncoder runs once, cache
        // sticks). Falls back to the legacy seed.payload bytes for
        // v1 profiles where seed.artifact stays null.
        const std::vector<uint8_t>* bytes_to_write = &seed.payload;
        std::shared_ptr<const std::vector<uint8_t>> materialized_holder;
        if (seed.artifact != nullptr && seed.artifact->valid()) {
            auto bytes_or = ::refuzz::program::MaterializeCanonicalText(*seed.artifact);
            if (bytes_or.has_value() && *bytes_or != nullptr) {
                materialized_holder = *bytes_or;
                bytes_to_write      = materialized_holder.get();
            }
        }

        if (bytes_to_write != nullptr && !bytes_to_write->empty()) {
            out.write(reinterpret_cast<const char*>(bytes_to_write->data()),
                      static_cast<std::streamsize>(bytes_to_write->size()));
        }
        out.flush();
        if (!out.good()) {
            return false;
        }
    }

    fs::rename(tmp_path, final_path, ec);
    if (!ec) {
        return WriteMetadataSidecar(seed, metadata_path);
    }

    std::error_code exists_ec;
    if (fs::exists(final_path, exists_ec) && !exists_ec) {
        std::error_code ignore_ec;
        fs::remove(tmp_path, ignore_ec);
        return fs::exists(metadata_path, exists_ec) && !exists_ec
            ? true
            : WriteMetadataSidecar(seed, metadata_path);
    }

    std::error_code ignore_ec;
    fs::remove(tmp_path, ignore_ec);
    return false;
}

// [persist-at-shutdown / P4] Flush the WHOLE in-memory corpus to disk in one
// pass. Called once at FuzzerLoop shutdown instead of writing per-admit on the
// hot path — so disk ends up holding exactly the FINAL (post-minimization)
// corpus (seeds dropped by MaybeMinimizeCorpus were never written, so no
// per-drop disk delete is needed). SaveSeed is idempotent; returns the number
// of seeds that failed to save (caller bumps corpus_save_error).
size_t CorpusDiskIO::SaveAll(const ICorpusStore& store, const std::string& corpus_dir)
{
    if (corpus_dir.empty()) {
        return 0;
    }
    size_t failed = 0;
    store.ForEachSeed([&corpus_dir, &failed](const Seed& seed) {
        if (!SaveSeed(seed, corpus_dir)) {
            ++failed;
        }
    });
    return failed;
}

// [v2 batch 3 G6] 强制重写 metadata sidecar(不动 payload)。
// SaveSeed 在 payload+metadata 都存在时早返 true,会**漏写** G6 inactive 状态;
// 本函数走 WriteMetadataSidecar atomic .tmp + rename,无论 sidecar 是否存在
// 都重写。`dir` 不存在 → return false(不创建 — caller 应是 mutate 已存在的
// seed,目录必然存在;不存在意味 seed 没被 SaveSeed 持久化过,此次 metadata
// 覆盖也无意义)。
bool CorpusDiskIO::SaveSeedMetadata(const Seed& seed, const std::string& corpus_dir)
{
    namespace fs = std::filesystem;
    const fs::path dir           = fs::path(corpus_dir) / Hex16(seed.seed_id);
    const fs::path metadata_path = dir / "metadata.json";

    std::error_code ec;
    if (!fs::exists(dir, ec) || ec) {
        return false;
    }
    return WriteMetadataSidecar(seed, metadata_path);
}

// [v2 PR1 — Corpus Prep Smoothing] 公开 LoadAll/LoadCrashRepros 透传 load_policy。
size_t CorpusDiskIO::LoadAll(ICorpusStore&                              store,
                             ISchedulerEngine&                          scheduler,
                             const std::string&                         corpus_dir,
                             SeedIdAllocator&                           id_alloc,
                             ::refuzz::program::ArtifactMaterializerFn  materializer,
                             CorpusLoadPolicy                           load_policy)
{
    const auto files = CollectPayloadFiles(corpus_dir, "payload.bin");
    return LoadFromFiles(store, scheduler, id_alloc, files, materializer, load_policy);
}

size_t CorpusDiskIO::LoadCrashRepros(ICorpusStore&                              store,
                                     ISchedulerEngine&                          scheduler,
                                     const std::string&                         diagnostics_dir,
                                     SeedIdAllocator&                           id_alloc,
                                     ::refuzz::program::ArtifactMaterializerFn  materializer,
                                     CorpusLoadPolicy                           load_policy)
{
    namespace fs = std::filesystem;
    std::vector<fs::path> files;
    for (const char* bucket : {"kernel_crash", "worker_dead", "vm_dead"}) {
        auto bucket_files = CollectPayloadFiles((fs::path(diagnostics_dir) / bucket).string(), "prog0.bin");
        files.insert(files.end(), bucket_files.begin(), bucket_files.end());
    }
    std::sort(files.begin(), files.end());
    // [v2 batch 3 G6 fix #5] force_source = kReplayHistory:这些是 crash repro,
    // 不是 boot corpus seed;corpus_verify_producer bootstrap 只挑 kBootCorpus。
    return LoadFromFiles(store, scheduler, id_alloc, files, materializer, load_policy,
                         /*force_source=*/SeedSource::kReplayHistory);
}

// [candidate-model] 扫描 <corpus_dir>/*/payload.bin 物化成 candidate Seed 列表,
// 不插入 store/scheduler。调用方(control 层)Put 进 PendingSeedMap。force_source
// 留 nullopt —— legacy boot corpus 缺 metadata sidecar 时由 disk-loader 的
// metadata_migration 分支显式标成 kBootCorpus/kActive。
std::vector<Seed> CorpusDiskIO::LoadAllAsSeeds(
    const std::string&                         corpus_dir,
    SeedIdAllocator&                           id_alloc,
    ::refuzz::program::ArtifactMaterializerFn  materializer,
    CorpusLoadPolicy                           load_policy)
{
    const auto files = CollectPayloadFiles(corpus_dir, "payload.bin");
    std::vector<Seed> out;
    out.reserve(files.size());
    for (const auto& payload_file : files) {
        auto seed_opt = BuildSeedFromFile(payload_file, id_alloc, materializer,
                                          load_policy, /*force_source=*/std::nullopt);
        if (seed_opt.has_value()) {
            out.push_back(std::move(*seed_opt));
        }
    }
    return out;
}

// [v2 PR1 — Corpus Prep Smoothing] CountArtifactSeeds 实现。
// 替换 orch bootstrap 处的 ICorpusStore::Size() == 0 判定，
// 数 store 中 seed.artifact != nullptr 的个数。
size_t CountArtifactSeeds(const ICorpusStore& store)
{
    size_t count = 0;
    store.ForEachSeed([&count](const Seed& s) {
        if (s.artifact != nullptr) {
            ++count;
        }
    });
    return count;
}

} // namespace refuzz::fuzzer
