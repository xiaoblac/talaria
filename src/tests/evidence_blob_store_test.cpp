// §3.11-F — IEvidenceBlobStore (LocalFsEvidenceBlobStore) unit test.
//
// 覆盖：ComputeBlobId 一致性 + Put 幂等 + Get/Stat 还原 + Delete 清理 +
// 不同 mime_type 不影响 blob_id（mime 是 sidecar 元数据，不参与 id）。

#include "refuzz/crash/incident/evidence_blob_store.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>
#include <vector>

namespace {

#define CHECK(expr)                                                          \
    do {                                                                    \
        if (!(expr)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,     \
                         #expr);                                             \
            std::abort();                                                    \
        }                                                                    \
    } while (0)

#define RUN_TEST(fn)                                                         \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                              \
        fn();                                                                \
        std::fprintf(stderr, "OK   %s\n", #fn);                              \
    } while (0)

namespace ic = refuzz::crash::incident;

class TmpDir {
public:
    TmpDir() {
        char tmpl[] = "/tmp/refuzz_blob_store_XXXXXX";
        if (char* dir = mkdtemp(tmpl)) path_ = dir;
    }
    ~TmpDir() {
        if (!path_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
    }
    const std::string& path() const { return path_; }
private:
    std::string path_;
};

std::vector<std::uint8_t> MakeBytes(std::initializer_list<std::uint8_t> bs) {
    return {bs.begin(), bs.end()};
}

void TestComputeBlobIdDeterministic() {
    auto a = MakeBytes({0xde, 0xad, 0xbe, 0xef});
    auto b = MakeBytes({0xde, 0xad, 0xbe, 0xef});
    CHECK(ic::ComputeBlobId(a) == ic::ComputeBlobId(b));
    CHECK(ic::ComputeBlobId(a).size() == 32);  // 32 hex chars

    auto c = MakeBytes({0xde, 0xad, 0xbe, 0xef, 0x00});
    CHECK(ic::ComputeBlobId(a) != ic::ComputeBlobId(c));
}

void TestPutGetRoundTrip() {
    TmpDir tmp;
    CHECK(!tmp.path().empty());
    ic::LocalFsEvidenceBlobStore store(tmp.path());

    auto content = MakeBytes({1, 2, 3, 4, 5});
    auto id = store.Put(content, "application/octet-stream");
    CHECK(!id.empty());
    CHECK(store.Exists(id));

    auto got = store.Get(id);
    CHECK(got.has_value());
    CHECK(*got == content);

    auto stat = store.Stat(id);
    CHECK(stat.has_value());
    CHECK(stat->size_bytes == content.size());
    CHECK(stat->mime_type == "application/octet-stream");
}

void TestPutIdempotent() {
    TmpDir tmp;
    ic::LocalFsEvidenceBlobStore store(tmp.path());

    auto content = MakeBytes({0xaa, 0xbb, 0xcc});
    auto id1 = store.Put(content);
    auto id2 = store.Put(content);
    auto id3 = store.Put(content, "text/plain");
    CHECK(id1 == id2);
    CHECK(id1 == id3);  // mime 不影响 id
    CHECK(store.Exists(id1));
}

void TestDelete() {
    TmpDir tmp;
    ic::LocalFsEvidenceBlobStore store(tmp.path());

    auto content = MakeBytes({0x11, 0x22, 0x33});
    auto id = store.Put(content, "text/x-test");
    CHECK(store.Exists(id));

    CHECK(store.Delete(id));
    CHECK(!store.Exists(id));
    CHECK(!store.Get(id).has_value());
    CHECK(!store.Stat(id).has_value());

    // 二次 Delete 安全（返回 false 但不崩）
    CHECK(!store.Delete(id));
}

void TestLargeBlob() {
    TmpDir tmp;
    ic::LocalFsEvidenceBlobStore store(tmp.path());

    // 模拟 1MB minidump
    std::vector<std::uint8_t> big(1u << 20);
    std::mt19937_64 rng(42);
    for (auto& b : big) b = static_cast<std::uint8_t>(rng());

    auto id = store.Put(big, "application/x-minidump");
    CHECK(!id.empty());
    auto got = store.Get(id);
    CHECK(got.has_value());
    CHECK(got->size() == big.size());
    CHECK(*got == big);
}

void TestDifferentContentDifferentId() {
    TmpDir tmp;
    ic::LocalFsEvidenceBlobStore store(tmp.path());

    auto a = MakeBytes({1});
    auto b = MakeBytes({2});
    auto c = MakeBytes({1, 2});

    auto ida = store.Put(a);
    auto idb = store.Put(b);
    auto idc = store.Put(c);

    CHECK(ida != idb);
    CHECK(ida != idc);
    CHECK(idb != idc);

    // 三份都应在
    CHECK(store.Exists(ida));
    CHECK(store.Exists(idb));
    CHECK(store.Exists(idc));
}

void TestEmptyContent() {
    TmpDir tmp;
    ic::LocalFsEvidenceBlobStore store(tmp.path());

    std::vector<std::uint8_t> empty;
    auto id = store.Put(empty);
    CHECK(!id.empty());
    auto got = store.Get(id);
    CHECK(got.has_value());
    CHECK(got->empty());
}

} // namespace

int main() {
    RUN_TEST(TestComputeBlobIdDeterministic);
    RUN_TEST(TestPutGetRoundTrip);
    RUN_TEST(TestPutIdempotent);
    RUN_TEST(TestDelete);
    RUN_TEST(TestLargeBlob);
    RUN_TEST(TestDifferentContentDifferentId);
    RUN_TEST(TestEmptyContent);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
