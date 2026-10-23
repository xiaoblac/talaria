// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/bucket/xiuos_crash_bucket.hpp"

#include "refuzz/program/xiuos/xiuos_result.hpp"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace refuzz::fuzzer {

namespace {

namespace cc       = refuzz::core::channel_contract;
namespace progx    = refuzz::program::xiuos;

// FNV-1a 64-bit (mirrors corpus/.../content_hash_dedup_filter.cpp — same
// constants, same algorithm — so bucket dedup uses the same key space as
// the corpus filter, in case future logic wants to cross-check).
std::uint64_t Fnv1a64(const std::uint8_t* data, std::size_t len) noexcept {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    for (std::size_t i = 0; i < len; ++i) {
        h ^= static_cast<std::uint64_t>(data[i]);
        h *= 0x100000001b3ULL;
    }
    return h;
}

std::string Hex16(std::uint64_t v) {
    char buf[17] = {0};
    std::snprintf(buf, sizeof(buf), "%016" PRIx64, v);
    return std::string(buf);
}

std::uint64_t NowMicros() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// Try to interpret `output` as a XiUOS RESULT payload and confirm it
// represents a Trap. Returns std::nullopt if it doesn't.
struct DecodedTrap {
    std::uint32_t trap_pc;
    std::uint32_t mcause;
    std::uint8_t  status;
};

bool TryDecodeXiuosTrap(const std::vector<std::uint8_t>& output,
                       DecodedTrap& out) {
    if (output.size() < XIUOS_RESULT_HEADER_SIZE) return false;
    progx::XiuosDecodedResult decoded;
    try {
        decoded = progx::XiuosDecodeResult(
            std::span<const std::uint8_t>(output.data(), output.size()));
    } catch (const std::exception&) {
        return false;
    }
    if (decoded.status != progx::XiuosResultStatus::Trap) return false;
    out.trap_pc = decoded.trap_or_pc;
    out.mcause  = static_cast<std::uint32_t>(decoded.aux);
    out.status  = static_cast<std::uint8_t>(decoded.status);
    return true;
}

}  // namespace

XiuosCrashBucket::XiuosCrashBucket(std::filesystem::path dir)
    : dir_(std::move(dir)) {
    std::error_code ec;
    std::filesystem::create_directories(dir_, ec);
    // Ignore ec — Record() will surface the error when it tries to write.
}

std::string XiuosCrashBucket::MakeBucketKey(std::uint32_t trap_pc,
                                            std::uint32_t mcause) {
    char buf[64] = {0};
    std::snprintf(buf, sizeof(buf),
                  "xiuos-trap-pc_0x%08x-mcause_0x%08x", trap_pc, mcause);
    return std::string(buf);
}

std::size_t XiuosCrashBucket::LoadFromDisk() {
    std::lock_guard<std::mutex> lk(mu_);
    buckets_.clear();
    std::size_t total = 0;
    std::error_code ec;
    if (!std::filesystem::exists(dir_, ec) || ec) return 0;
    for (const auto& bucket_entry :
            std::filesystem::directory_iterator(dir_, ec)) {
        if (ec) break;
        if (!bucket_entry.is_directory(ec) || ec) continue;
        const std::string bucket_key = bucket_entry.path().filename().string();
        std::unordered_set<std::uint64_t> set;
        for (const auto& file_entry :
                std::filesystem::directory_iterator(bucket_entry.path(), ec)) {
            if (ec) break;
            if (!file_entry.is_regular_file(ec) || ec) continue;
            if (file_entry.path().extension() != ".bin") continue;
            const auto stem = file_entry.path().stem().string();
            // Expect exactly 16 lowercase hex chars; tolerate non-conforming
            // filenames by skipping them (don't crash on stray junk).
            if (stem.size() != 16) continue;
            try {
                const std::uint64_t h =
                    static_cast<std::uint64_t>(std::stoull(stem, nullptr, 16));
                set.insert(h);
            } catch (...) {
                // skip malformed
            }
        }
        if (!set.empty()) {
            total += set.size();
            buckets_.emplace(bucket_key, std::move(set));
        }
    }
    return total;
}

bool XiuosCrashBucket::WriteRecord(
        const std::string& bucket_key,
        std::uint64_t payload_hash,
        std::uint32_t trap_pc,
        std::uint32_t mcause,
        std::uint8_t  status,
        const std::vector<std::uint8_t>& program_payload) {
    const auto bucket_dir = dir_ / bucket_key;
    std::error_code ec;
    std::filesystem::create_directories(bucket_dir, ec);
    if (ec) return false;

    const auto hex = Hex16(payload_hash);
    const auto bin_path = bucket_dir / (hex + ".bin");
    const auto json_path = bucket_dir / (hex + ".json");

    // Atomic .tmp + rename for both files.
    const auto bin_tmp = bin_path.string() + ".tmp";
    {
        std::ofstream out(bin_tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        if (!program_payload.empty()) {
            out.write(reinterpret_cast<const char*>(program_payload.data()),
                      static_cast<std::streamsize>(program_payload.size()));
        }
        if (!out.good()) {
            std::error_code ignore;
            std::filesystem::remove(bin_tmp, ignore);
            return false;
        }
    }
    std::filesystem::rename(bin_tmp, bin_path, ec);
    if (ec) {
        std::error_code ignore;
        std::filesystem::remove(bin_tmp, ignore);
        return false;
    }

    const auto json_tmp = json_path.string() + ".tmp";
    {
        std::ofstream out(json_tmp, std::ios::trunc);
        if (!out) {
            std::error_code ignore;
            std::filesystem::remove(bin_path, ignore);
            return false;
        }
        // Minimal JSON; no library dep, no escaping needed (all values
        // numeric or hex).
        out << "{\n"
            << "  \"schema_version\": 1,\n"
            << "  \"bucket_key\": \"" << bucket_key << "\",\n"
            << "  \"payload_hash\": \"" << hex << "\",\n"
            << "  \"trap_pc\": " << trap_pc << ",\n"
            << "  \"mcause\": " << mcause << ",\n"
            << "  \"status\": " << static_cast<unsigned>(status) << ",\n"
            << "  \"payload_size\": " << program_payload.size() << ",\n"
            << "  \"recorded_ts_us\": " << NowMicros() << "\n"
            << "}\n";
        if (!out.good()) {
            std::error_code ignore;
            std::filesystem::remove(json_tmp, ignore);
            std::filesystem::remove(bin_path, ignore);
            return false;
        }
    }
    std::filesystem::rename(json_tmp, json_path, ec);
    if (ec) {
        std::error_code ignore;
        std::filesystem::remove(json_tmp, ignore);
        std::filesystem::remove(bin_path, ignore);
        return false;
    }
    return true;
}

XiuosCrashBucket::RecordOutcome XiuosCrashBucket::Record(
        const cc::AbnormalCompletion& ab) {
    RecordOutcome out;

    // Gate 1: only kWorkerSignaled is plausibly a worker trap. Other
    // abnormal kinds (Timeout / ExecError / Cancelled / ChildAborted /
    // WorkerCrashed) might still want bucketing in the future, but #18 is
    // scoped to XiUOS traps.
    if (ab.kind != cc::AbnormalKind::kWorkerSignaled) {
        return out;
    }

    // Gate 2: re-decode output as a XiUOS RESULT payload and confirm Trap
    // status. This protects the bucket from non-XiUOS abnormal events (eg.
    // a future kernel-mode backend that also emits kWorkerSignaled).
    DecodedTrap dt{};
    if (!TryDecodeXiuosTrap(ab.output, dt)) {
        return out;
    }

    // Cross-check the XiUOS DP convention: error_code should equal trap_pc
    // and crash_signal should equal mcause. Mismatch is a wire bug; prefer
    // decoded values (canonical) but don't fail the record.
    // (No-op — kept implicit; future telemetry could count mismatches.)

    const auto bucket_key = MakeBucketKey(dt.trap_pc, dt.mcause);
    out.bucket_key = bucket_key;

    const std::uint64_t payload_hash = Fnv1a64(
        ab.ctx.program_payload.data(), ab.ctx.program_payload.size());
    out.payload_hash = payload_hash;

    std::lock_guard<std::mutex> lk(mu_);
    auto [it, inserted] = buckets_.try_emplace(bucket_key);
    auto& set = it->second;
    out.bucket_is_new = inserted;
    if (set.count(payload_hash) != 0) {
        // Same trap, same payload — already recorded.
        return out;
    }

    // Empty program_payload is theoretically possible for a worker that
    // traps before consuming the wire payload; we still want to bucket
    // *that*, but a 0-byte .bin file is honest and dedup keyspace is still
    // valid (FNV-1a 64-bit of an empty buffer == 0xcbf29ce484222325).
    if (!WriteRecord(bucket_key, payload_hash,
                     dt.trap_pc, dt.mcause, dt.status,
                     ab.ctx.program_payload)) {
        // Write failed; don't pollute the in-memory dedup set so the next
        // attempt (or a sibling thread) can retry.
        if (inserted && set.empty()) {
            buckets_.erase(it);
            out.bucket_is_new = false;
        }
        return out;
    }

    set.insert(payload_hash);
    out.persisted = true;
    return out;
}

std::size_t XiuosCrashBucket::BucketCount() const {
    std::lock_guard<std::mutex> lk(mu_);
    return buckets_.size();
}

std::size_t XiuosCrashBucket::TotalRecordedSeeds() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t total = 0;
    for (const auto& [_, set] : buckets_) total += set.size();
    return total;
}

}  // namespace refuzz::fuzzer
