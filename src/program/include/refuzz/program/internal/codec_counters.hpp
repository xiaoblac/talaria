// Codec call counters — instrumentation for §3.10 typed-pipeline oracles.
//
// Increments are inserted at the public boundary of each codec entry point
// (TextDecoder::decode / TextEncoder::encode / serialize_for_exec /
// decode_exec_wire / encode_wire_program). Cost is one relaxed atomic add
// per call (< 1 ns/op), so counters live in production binaries — no
// separate test-only build flavor.
//
// Reads are test-only and go through `ReadForTest()` / `ResetForTest()`.
// Counters are `thread_local` because §3.10 oracles drive single-threaded
// hot-path loops; readers and writers stay on the same thread.

#pragma once

#include <atomic>
#include <cstdint>

namespace refuzz::program::codec_counters {

namespace internal {

// Definitions live in src/artifact.cpp so the symbols are emitted exactly
// once per linked binary (one TU; thread_local storage duration is
// per-thread regardless).
extern thread_local std::atomic<std::uint64_t> g_decode_text;
extern thread_local std::atomic<std::uint64_t> g_encode_text;
extern thread_local std::atomic<std::uint64_t> g_decode_wire;
extern thread_local std::atomic<std::uint64_t> g_encode_wire;

} // namespace internal

inline void OnDecodeText() noexcept {
    internal::g_decode_text.fetch_add(1, std::memory_order_relaxed);
}
inline void OnEncodeText() noexcept {
    internal::g_encode_text.fetch_add(1, std::memory_order_relaxed);
}
inline void OnDecodeWire() noexcept {
    internal::g_decode_wire.fetch_add(1, std::memory_order_relaxed);
}
inline void OnEncodeWire() noexcept {
    internal::g_encode_wire.fetch_add(1, std::memory_order_relaxed);
}

struct Counts {
    std::uint64_t decode_text_calls = 0;
    std::uint64_t encode_text_calls = 0;
    std::uint64_t decode_wire_calls = 0;
    std::uint64_t encode_wire_calls = 0;
};

inline Counts ReadForTest() noexcept {
    return Counts{
        internal::g_decode_text.load(std::memory_order_relaxed),
        internal::g_encode_text.load(std::memory_order_relaxed),
        internal::g_decode_wire.load(std::memory_order_relaxed),
        internal::g_encode_wire.load(std::memory_order_relaxed),
    };
}

inline void ResetForTest() noexcept {
    internal::g_decode_text.store(0, std::memory_order_relaxed);
    internal::g_encode_text.store(0, std::memory_order_relaxed);
    internal::g_decode_wire.store(0, std::memory_order_relaxed);
    internal::g_encode_wire.store(0, std::memory_order_relaxed);
}

} // namespace refuzz::program::codec_counters
