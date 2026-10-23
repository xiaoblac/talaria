// §3.11-F — IEvidenceBlobStore：大 evidence blob 的外置存储抽象。
//
// 背景：3.6 浏览器 minidump（~10-50MB）/ 3.4 数据库 server log /
// 3.7 PyTorch tensor diff output 都是 MB 级数据，inline 在 incident
// record 里会让 DiagnosticStore 内存 / 索引文件膨胀。
//
// 设计：
//   - blob 内容内容寻址（content-addressed）：blob_id 由内容哈希决定，
//     重复 Put 同一份内容 idempotent（返回同 id）。
//   - 后端解耦：LocalFsEvidenceBlobStore 写到 <root_dir>/<id_prefix>/<id_rest>。
//     未来可以加 S3 / NFS / sidecar service 后端，只换实现，不动 incident
//     生命周期管理。
//   - incident.fragments 里的 LargeBlobInfo 引用 blob_id，不存内容。
//   - refcount：DiagnosticStore 在 dedup 合并 incident 时通过 store
//     的 retain/release 决定 blob 是否能被回收。Step F 仅落 store
//     primitive，refcount 接入留在 §3.11 后续工作（pipeline 改写时一并）。
//
// 哈希：用 dual-FNV-1a 64-bit（low / high 两个独立 seed）合成 128-bit
// 指纹格式化成 32 hex chars。fuzz 会话内不会撞（单会话 evidence 数远小
// 于 2^64）；不是密码学安全。Step F 后续若需要 SHA-256 cryptographic
// 安全，加一个 ICryptoHash 后端注入即可，blob_id 字符串格式不变。

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace refuzz::crash::incident {

struct EvidenceBlobStat {
    std::string  blob_id;
    std::uint64_t size_bytes = 0;
    std::string  mime_type;
};

class IEvidenceBlobStore {
public:
    virtual ~IEvidenceBlobStore() = default;

    // Put：内容寻址写入。重复内容 idempotent（不重写）。返回 blob_id（
    // 32 hex chars）；非空 mime_type 写到 sidecar。
    virtual std::string
    Put(const std::vector<std::uint8_t>& content,
        const std::string& mime_type = {}) = 0;

    // Get：按 blob_id 读出。不存在返回 nullopt。
    virtual std::optional<std::vector<std::uint8_t>>
    Get(const std::string& blob_id) const = 0;

    // Stat：尺寸 / mime 元信息。
    virtual std::optional<EvidenceBlobStat>
    Stat(const std::string& blob_id) const = 0;

    // Delete：物理删除（Step F 仅提供原语；refcount 决策在 pipeline 接入时）。
    virtual bool Delete(const std::string& blob_id) = 0;

    // Exists：仅检查存在性，不读内容。
    virtual bool Exists(const std::string& blob_id) const = 0;
};

// LocalFsEvidenceBlobStore：默认本地目录后端。
//
// 目录布局：
//   <root_dir>/blobs/<id[0..2]>/<id[2..]>            blob 内容
//   <root_dir>/blobs/<id[0..2]>/<id[2..]>.mime       mime 元信息（如非空）
class LocalFsEvidenceBlobStore : public IEvidenceBlobStore {
public:
    explicit LocalFsEvidenceBlobStore(std::string root_dir);

    std::string
    Put(const std::vector<std::uint8_t>& content,
        const std::string& mime_type = {}) override;

    std::optional<std::vector<std::uint8_t>>
    Get(const std::string& blob_id) const override;

    std::optional<EvidenceBlobStat>
    Stat(const std::string& blob_id) const override;

    bool Delete(const std::string& blob_id) override;

    bool Exists(const std::string& blob_id) const override;

private:
    std::string root_dir_;     // 实际 blob 目录 = root_dir_ + "/blobs"
};

// 给定 content，计算其 blob_id（dual-FNV-1a-64 → 32 hex）。
// 暴露成 free function 让 caller 可以预先算 id 而不写盘（diagnostic_store
// 在 incident 内引用时用得到）。
std::string ComputeBlobId(const std::vector<std::uint8_t>& content);

} // namespace refuzz::crash::incident
