// §3.11-F — LocalFsEvidenceBlobStore 实现。

#include "refuzz/crash/incident/evidence_blob_store.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>

namespace refuzz::crash::incident {

namespace {

// Dual-FNV-1a 64-bit → 128-bit 指纹。两个独立 seed 让单 64-bit 撞概率
// 进一步压低（fuzz 会话内远低于 1）。不是密码学安全；用于内容寻址
// 而非签名。
constexpr std::uint64_t kFnvOffsetA = 0xcbf29ce484222325ULL;
constexpr std::uint64_t kFnvOffsetB = 0x84222325cbf29ce4ULL;
constexpr std::uint64_t kFnvPrime   = 0x100000001b3ULL;

void Fnv1aFold(std::uint64_t& h, const std::uint8_t* data, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        h ^= data[i];
        h *= kFnvPrime;
    }
}

std::string ToHex32(std::uint64_t a, std::uint64_t b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(32, '0');
    for (int i = 15; i >= 0; --i) {
        out[i]      = kHex[a & 0xf];
        out[i + 16] = kHex[b & 0xf];
        a >>= 4;
        b >>= 4;
    }
    return out;
}

std::filesystem::path BlobsRoot(const std::string& root_dir) {
    return std::filesystem::path(root_dir) / "blobs";
}

std::filesystem::path BlobPath(const std::string& root_dir,
                                const std::string& blob_id) {
    if (blob_id.size() < 2) return BlobsRoot(root_dir) / "_";
    return BlobsRoot(root_dir) / blob_id.substr(0, 2) / blob_id.substr(2);
}

bool ReadWholeFile(const std::filesystem::path& path, std::vector<std::uint8_t>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    in.seekg(0, std::ios::end);
    const std::streamoff sz = in.tellg();
    if (sz < 0) return false;
    in.seekg(0, std::ios::beg);
    out.assign(static_cast<std::size_t>(sz), 0);
    if (sz > 0) {
        in.read(reinterpret_cast<char*>(out.data()),
                static_cast<std::streamsize>(sz));
        if (!in) return false;
    }
    return true;
}

} // namespace

std::string ComputeBlobId(const std::vector<std::uint8_t>& content) {
    std::uint64_t a = kFnvOffsetA;
    std::uint64_t b = kFnvOffsetB;
    Fnv1aFold(a, content.data(), content.size());
    // 给 b 喂相同数据但反向顺序；进一步去相关。
    for (auto it = content.rbegin(); it != content.rend(); ++it) {
        b ^= *it;
        b *= kFnvPrime;
    }
    return ToHex32(a, b);
}

// ----- LocalFsEvidenceBlobStore -----

LocalFsEvidenceBlobStore::LocalFsEvidenceBlobStore(std::string root_dir)
    : root_dir_(std::move(root_dir))
{
    std::error_code ec;
    std::filesystem::create_directories(BlobsRoot(root_dir_), ec);
    // 启动期错误吞掉；后续 Put/Get 自己再报 false。
    (void)ec;
}

std::string LocalFsEvidenceBlobStore::Put(const std::vector<std::uint8_t>& content,
                                          const std::string& mime_type)
{
    const std::string id   = ComputeBlobId(content);
    const auto        path = BlobPath(root_dir_, id);

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);

    if (!std::filesystem::exists(path, ec)) {
        const auto tmp = path.string() + ".tmp";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) return id;  // 写失败也返回 id；下次 Put 重试。
            if (!content.empty()) {
                out.write(reinterpret_cast<const char*>(content.data()),
                          static_cast<std::streamsize>(content.size()));
            }
            out.flush();
        }
        std::filesystem::rename(tmp, path, ec);
    }

    if (!mime_type.empty()) {
        const auto mpath = path.string() + ".mime";
        if (!std::filesystem::exists(mpath, ec)) {
            std::ofstream m(mpath, std::ios::binary | std::ios::trunc);
            if (m) m.write(mime_type.data(), static_cast<std::streamsize>(mime_type.size()));
        }
    }
    return id;
}

std::optional<std::vector<std::uint8_t>>
LocalFsEvidenceBlobStore::Get(const std::string& blob_id) const
{
    std::vector<std::uint8_t> out;
    if (!ReadWholeFile(BlobPath(root_dir_, blob_id), out)) {
        return std::nullopt;
    }
    return out;
}

std::optional<EvidenceBlobStat>
LocalFsEvidenceBlobStore::Stat(const std::string& blob_id) const
{
    const auto path = BlobPath(root_dir_, blob_id);
    std::error_code ec;
    auto sz = std::filesystem::file_size(path, ec);
    if (ec) return std::nullopt;

    EvidenceBlobStat s;
    s.blob_id    = blob_id;
    s.size_bytes = static_cast<std::uint64_t>(sz);
    // 读 mime sidecar（可选）。
    const auto mpath = path.string() + ".mime";
    std::ifstream m(mpath, std::ios::binary);
    if (m) {
        std::stringstream ss;
        ss << m.rdbuf();
        s.mime_type = ss.str();
    }
    return s;
}

bool LocalFsEvidenceBlobStore::Delete(const std::string& blob_id)
{
    const auto path = BlobPath(root_dir_, blob_id);
    std::error_code ec;
    bool removed = std::filesystem::remove(path, ec);
    // mime sidecar 一并删（best-effort）。
    std::filesystem::remove(path.string() + ".mime", ec);
    return removed;
}

bool LocalFsEvidenceBlobStore::Exists(const std::string& blob_id) const
{
    std::error_code ec;
    return std::filesystem::exists(BlobPath(root_dir_, blob_id), ec) && !ec;
}

} // namespace refuzz::crash::incident
