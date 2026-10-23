#include "refuzz/control/request_stream_reader.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace rs = refuzz::request_stream;

namespace {

// prog_text is raw bytes; comparing it as a std::string keeps the fixture
// assertions readable as the syzlang source they actually are.
std::string AsBytes(const std::vector<uint8_t>& v) {
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #condition,  \
                         __LINE__);                                             \
            return false;                                                       \
        }                                                                       \
    } while (false)

void PutU32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(value >> (8 * i)));
}

void PutU64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(value >> (8 * i)));
}

void PutI64(std::vector<uint8_t>& out, int64_t value) {
    uint64_t raw = 0;
    std::memcpy(&raw, &value, sizeof(raw));
    PutU64(out, raw);
}

void PutI32(std::vector<uint8_t>& out, int32_t value) {
    uint32_t raw = 0;
    std::memcpy(&raw, &value, sizeof(raw));
    PutU32(out, raw);
}

void PutBytes(std::vector<uint8_t>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void PutHeader(std::vector<uint8_t>& out) {
    PutBytes(out, rs::kMagic);
    PutU32(out, rs::kVersion);
    PutU32(out, rs::kHeaderSize);
    PutU32(out, 0); // flags
    PutU32(out, 0); // reserved
    PutU64(out, 0); // reserved
}

void PutRecord(std::vector<uint8_t>& out, const rs::RequestRecord& record) {
    std::vector<uint8_t> body;
    body.push_back(rs::kRecordKindProgram);
    body.insert(body.end(), 3, 0);
    PutU64(body, record.sequence);
    PutU64(body, record.request_type);
    PutU64(body, record.exec_env_flags);
    PutU64(body, record.exec_flags);
    PutI64(body, record.sandbox_arg);
    PutU64(body, record.request_flags);
    PutU32(body, static_cast<uint32_t>(record.all_signal.size()));
    PutU32(body, static_cast<uint32_t>(record.prog_text.size()));
    for (int32_t signal : record.all_signal) PutI32(body, signal);
    body.insert(body.end(), record.prog_text.begin(), record.prog_text.end());
    PutU32(out, static_cast<uint32_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
}

void PutFooter(std::vector<uint8_t>& out, uint64_t count, uint64_t last_sequence) {
    PutU32(out, rs::kFooterMarker);
    PutBytes(out, rs::kFooterMagic);
    PutU32(out, rs::kVersion);
    PutU32(out, rs::kFooterSize);
    PutU64(out, count);
    PutU64(out, last_sequence);
}

std::vector<uint8_t> ValidBytes() {
    rs::RequestRecord first;
    first.sequence = 0;
    first.exec_env_flags = 0x11;
    first.exec_flags = 0x22;
    first.sandbox_arg = -7;
    first.request_flags = 0x3;
    first.all_signal = {-1, 7};
    first.prog_text = {0xde, 0xad, 0xbe, 0xef};

    rs::RequestRecord second;
    second.sequence = 1;
    second.exec_env_flags = 0x100;
    second.exec_flags = 0x200;
    second.sandbox_arg = 42;
    second.prog_text = {0, 1, 2};

    std::vector<uint8_t> bytes;
    PutHeader(bytes);
    PutRecord(bytes, first);
    PutRecord(bytes, second);
    PutFooter(bytes, 2, 1);
    return bytes;
}

bool TestValidStream() {
    const auto bytes = ValidBytes();
    auto parsed = rs::Read(bytes);
    CHECK(parsed.has_value());
    CHECK(parsed->records.size() == 2);
    CHECK(parsed->records[0].sequence == 0);
    CHECK(parsed->records[0].sandbox_arg == -7);
    CHECK(parsed->records[0].all_signal == std::vector<int32_t>({-1, 7}));
    CHECK(parsed->records[0].prog_text == std::vector<uint8_t>({0xde, 0xad, 0xbe, 0xef}));
    CHECK(parsed->records[1].sequence == 1);
    CHECK(parsed->records[1].prog_text == std::vector<uint8_t>({0, 1, 2}));
    return true;
}

bool TestRejectsMalformedStreams() {
    const auto valid = ValidBytes();

    auto empty = rs::Read(std::span<const uint8_t>{});
    CHECK(!empty.has_value());

    auto truncated_header = rs::Read(std::span<const uint8_t>(valid.data(), 10));
    CHECK(!truncated_header.has_value());

    auto bad_magic = valid;
    bad_magic[0] ^= 1;
    CHECK(!rs::Read(bad_magic).has_value());

    // Pick a version the format will never reach rather than "the next one".
    // This assertion used to write 2, which the v1->v2 bump turned into a VALID
    // version -- the negative test then silently asserted the opposite of what it
    // was written for. Any future bump must not resurrect that failure mode.
    auto bad_version = valid;
    bad_version[8] = 0xFF;
    CHECK(!rs::Read(bad_version).has_value());

    auto missing_footer = valid;
    missing_footer.resize(missing_footer.size() - rs::kFooterSize);
    CHECK(!rs::Read(missing_footer).has_value());

    auto sequence_gap = valid;
    // Header (32), first frame prefix (4), first body sequence at offset 40.
    sequence_gap[40] = 3;
    CHECK(!rs::Read(sequence_gap).has_value());

    auto oversized = valid;
    for (int i = 0; i < 4; ++i) {
        oversized[32 + i] = static_cast<uint8_t>((rs::kMaxRecordSize + 1) >> (8 * i));
    }
    CHECK(!rs::Read(oversized).has_value());

    auto bad_footer_count = valid;
    const size_t footer_count_offset = bad_footer_count.size() - rs::kFooterSize + 20;
    bad_footer_count[footer_count_offset] = 3;
    CHECK(!rs::Read(bad_footer_count).has_value());

    auto trailing = valid;
    trailing.push_back(0);
    CHECK(!rs::Read(trailing).has_value());
    return true;
}

bool TestCrossLanguageFixture() {
#ifdef REFUZZ_REQUEST_STREAM_FIXTURE
    auto parsed = rs::ReadFile(REFUZZ_REQUEST_STREAM_FIXTURE);
    CHECK(parsed.has_value());
    CHECK(parsed->records.size() == 2);
    CHECK(parsed->records[0].sequence == 0);
    CHECK(parsed->records[0].exec_env_flags == 0x11);
    CHECK(parsed->records[0].exec_flags == 0x22);
    CHECK(parsed->records[0].sandbox_arg == -7);
    CHECK(parsed->records[0].request_flags == 3);
    CHECK(parsed->records[0].all_signal == std::vector<int32_t>({-1, 7}));
    // v2 carries canonical syzlang TEXT, not exec bytes, so the fixture's programs
    // must stay byte-identical to what pkg/requeststream's fixtureRecords() writes
    // -- that identity is the whole point of a cross-language fixture. Keep these
    // two literals in sync with request_stream_test.go.
    CHECK(AsBytes(parsed->records[0].prog_text) == "getpid()\n");
    CHECK(parsed->records[1].sequence == 1);
    CHECK(parsed->records[1].exec_env_flags == 0x100);
    CHECK(parsed->records[1].exec_flags == 0x200);
    CHECK(parsed->records[1].sandbox_arg == 42);
    CHECK(parsed->records[1].all_signal.empty());
    CHECK(AsBytes(parsed->records[1].prog_text) ==
          "r0 = openat$dir(0xffffffffffffff9c, &(0x7f0000000000)='./file0\\x00', 0x0, 0x0)\n"
          "close(r0)\n");
#else
    std::fprintf(stderr, "fixture path was not configured\n");
    return false;
#endif
    return true;
}

} // namespace

int main() {
    if (!TestValidStream() || !TestRejectsMalformedStreams() || !TestCrossLanguageFixture()) {
        return 1;
    }
    std::puts("request_stream_reader_test: all checks PASS");
    return 0;
}
