#include "refuzz/control/request_stream_reader.hpp"

#include <cstddef>
#include <cstring>
#include <fstream>
#include <type_traits>
#include <utility>

namespace refuzz::request_stream {
namespace {

template <typename T>
bool ReadUnsigned(std::span<const uint8_t> bytes, size_t& pos, T& out) {
    static_assert(std::is_unsigned_v<T>);
    if (pos > bytes.size() || bytes.size() - pos < sizeof(T)) return false;
    out = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        out |= static_cast<T>(bytes[pos + i]) << (i * 8);
    }
    pos += sizeof(T);
    return true;
}

bool ReadSigned64(std::span<const uint8_t> bytes, size_t& pos, int64_t& out) {
    uint64_t raw = 0;
    if (!ReadUnsigned(bytes, pos, raw)) return false;
    std::memcpy(&out, &raw, sizeof(out));
    return true;
}

bool ReadSigned32(std::span<const uint8_t> bytes, size_t& pos, int32_t& out) {
    uint32_t raw = 0;
    if (!ReadUnsigned(bytes, pos, raw)) return false;
    std::memcpy(&out, &raw, sizeof(out));
    return true;
}

ParseResult Fail(std::string message) {
    return std::unexpected(std::move(message));
}

} // namespace

ParseResult Read(std::span<const uint8_t> bytes) {
    if (bytes.empty()) return Fail("request stream is empty");
    if (bytes.size() < kHeaderSize) return Fail("request stream header is truncated");
    if (std::memcmp(bytes.data(), kMagic.data(), kMagic.size()) != 0) {
        return Fail("request stream has bad magic");
    }

    size_t pos = kMagic.size();
    uint32_t version = 0;
    uint32_t header_size = 0;
    uint32_t flags = 0;
    uint32_t reserved = 0;
    uint64_t reserved2 = 0;
    if (!ReadUnsigned(bytes, pos, version) || !ReadUnsigned(bytes, pos, header_size) ||
        !ReadUnsigned(bytes, pos, flags) || !ReadUnsigned(bytes, pos, reserved) ||
        !ReadUnsigned(bytes, pos, reserved2)) {
        return Fail("request stream header is truncated");
    }
    if (version != kVersion) return Fail("request stream has unsupported version");
    if (header_size != kHeaderSize) return Fail("request stream has bad header size");
    if (flags != 0 || reserved != 0 || reserved2 != 0) {
        return Fail("request stream header has nonzero reserved fields");
    }

    RequestStream stream;
    uint64_t expected_sequence = 0;
    while (true) {
        if (pos > bytes.size() || bytes.size() - pos < sizeof(uint32_t)) {
            return Fail("request stream is missing its footer");
        }

        uint32_t frame_size = 0;
        if (!ReadUnsigned(bytes, pos, frame_size)) {
            return Fail("request stream frame prefix is truncated");
        }
        if (frame_size == kFooterMarker) {
            constexpr size_t kFooterBodySize = kFooterSize - sizeof(uint32_t);
            if (bytes.size() - pos < kFooterBodySize) {
                return Fail("request stream footer is truncated");
            }
            if (std::memcmp(bytes.data() + pos, kFooterMagic.data(),
                            kFooterMagic.size()) != 0) {
                return Fail("request stream has bad footer magic");
            }
            pos += kFooterMagic.size();
            uint32_t footer_version = 0;
            uint32_t footer_size = 0;
            uint64_t record_count = 0;
            uint64_t last_sequence = 0;
            if (!ReadUnsigned(bytes, pos, footer_version) ||
                !ReadUnsigned(bytes, pos, footer_size) ||
                !ReadUnsigned(bytes, pos, record_count) ||
                !ReadUnsigned(bytes, pos, last_sequence)) {
                return Fail("request stream footer is truncated");
            }
            if (footer_version != kVersion) {
                return Fail("request stream footer has unsupported version");
            }
            if (footer_size != kFooterSize) {
                return Fail("request stream has bad footer size");
            }
            if (stream.records.empty()) return Fail("request stream has no records");
            if (record_count != stream.records.size()) {
                return Fail("request stream footer record count mismatch");
            }
            if (last_sequence != expected_sequence - 1) {
                return Fail("request stream footer sequence mismatch");
            }
            if (pos != bytes.size()) return Fail("bytes follow request stream footer");
            return stream;
        }

        if (frame_size == 0 || frame_size > kMaxRecordSize) {
            return Fail("request stream has invalid record length");
        }
        if (frame_size < kRecordFixedSize || bytes.size() - pos < frame_size) {
            return Fail("request stream record is truncated");
        }

        const size_t body_end = pos + frame_size;
        uint8_t kind = bytes[pos++];
        if (bytes[pos] != 0 || bytes[pos + 1] != 0 || bytes[pos + 2] != 0) {
            return Fail("request stream record has nonzero reserved fields");
        }
        pos += 3;

        RequestRecord record;
        uint64_t prog_text_size = 0;
        uint32_t all_signal_count = 0;
        if (!ReadUnsigned(bytes, pos, record.sequence) ||
            !ReadUnsigned(bytes, pos, record.request_type) ||
            !ReadUnsigned(bytes, pos, record.exec_env_flags) ||
            !ReadUnsigned(bytes, pos, record.exec_flags) ||
            !ReadSigned64(bytes, pos, record.sandbox_arg) ||
            !ReadUnsigned(bytes, pos, record.request_flags) ||
            !ReadUnsigned(bytes, pos, all_signal_count)) {
            return Fail("request stream record header is truncated");
        }
        uint32_t prog_text_size32 = 0;
        if (!ReadUnsigned(bytes, pos, prog_text_size32)) {
            return Fail("request stream record header is truncated");
        }
        prog_text_size = prog_text_size32;

        if (kind != kRecordKindProgram) return Fail("request stream has unknown record kind");
        if (record.request_type != kRequestTypeProgram) {
            return Fail("request stream contains a non-program request");
        }
        if (record.sequence != expected_sequence) {
            return Fail("request stream sequence is not continuous");
        }
        if (all_signal_count > kMaxAllSignalCount || prog_text_size > kMaxProgTextSize) {
            return Fail("request stream record field is too large");
        }
        const uint64_t variable_size =
            static_cast<uint64_t>(all_signal_count) * sizeof(int32_t) + prog_text_size;
        if (variable_size != frame_size - kRecordFixedSize) {
            return Fail("request stream record length does not match its fields");
        }
        if (pos > body_end || body_end - pos < variable_size) {
            return Fail("request stream record body is truncated");
        }

        record.all_signal.reserve(all_signal_count);
        for (uint32_t i = 0; i < all_signal_count; ++i) {
            int32_t signal = 0;
            if (!ReadSigned32(bytes, pos, signal)) {
                return Fail("request stream all-signal vector is truncated");
            }
            record.all_signal.push_back(signal);
        }
        record.prog_text.assign(bytes.begin() + static_cast<std::ptrdiff_t>(pos),
                              bytes.begin() + static_cast<std::ptrdiff_t>(pos + prog_text_size));
        pos += static_cast<size_t>(prog_text_size);
        if (pos != body_end) return Fail("request stream record has trailing bytes");

        stream.records.push_back(std::move(record));
        ++expected_sequence;
    }
}

ParseResult ReadFile(std::string_view path) {
    std::ifstream input(std::string(path), std::ios::binary | std::ios::ate);
    if (!input) return Fail("cannot open request stream");
    const std::streampos end = input.tellg();
    if (end < 0) return Fail("cannot determine request stream size");
    constexpr uint64_t kMaxStreamSize = 1ULL << 30;
    if (static_cast<uint64_t>(end) > kMaxStreamSize) {
        return Fail("request stream is too large");
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(end));
    input.seekg(0);
    if (!bytes.empty() &&
        !input.read(reinterpret_cast<char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()))) {
        return Fail("cannot read request stream");
    }
    return Read(bytes);
}

} // namespace refuzz::request_stream
