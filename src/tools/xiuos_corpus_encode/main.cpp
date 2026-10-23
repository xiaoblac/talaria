// Copyright 2026 reFuzz project author -------youngkk.
//
// xiuos_corpus_encode — Stage 3 去山头 corpus 桥。
//
// XiUOS 的 descriptor 语料 (`run/xiuos/corpus/generated/`,可重生缓存) 是 JSON,而
// orchestrator 的正规 corpus 加载 (`CorpusDiskIO::LoadAll`, XiUOS profile 用
// LenientBytes + 空 decoder) 把磁盘文件 bytes 直接当 wire payload。两者不匹配:
// JSON 文本喂给 worker 会被当 wire varint 解出垃圾。
//
// 本工具做一次性预编码:DiscoverXiuosProgramSeedFiles → LoadXiuosProgramSeed →
// XiuosProgramSeed::Encode() → 写成 CorpusDiskIO 认的 canonical 布局:
//
//     <out_dir>/<payload_hash16>/payload.bin     (raw XiUOS wire bytes)
//
// 子目录名用 wire payload 的 FNV-1a 64-bit hash(16 hex)做去重——相同 program
// 不重复落盘。XiuosFuzzSession::Bootstrap 当年是在内存里做同一步 (Load→Encode→
// submit);去山头后改成磁盘预编码,让 orchestrator 的标准 corpus 管线接管。
//
// 用法:
//   xiuos_corpus_encode --in <generated_corpus_dir> --out <wire_corpus_dir>
//
// 然后把 <wire_corpus_dir> 填进 xiuos config 的 persistence.corpus.dir。

#include "refuzz/program/xiuos/xiuos_program_seed.hpp"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace progx = refuzz::program::xiuos;

namespace {

std::uint64_t FnvHash64(const std::vector<std::uint8_t>& buf) {
    std::uint64_t h = 0xcbf29ce484222325ull;
    for (auto b : buf) {
        h ^= b;
        h *= 0x100000001b3ull;
    }
    return h;
}

std::string HexHash(std::uint64_t h) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx",
                  static_cast<unsigned long long>(h));
    return std::string(buf);
}

void PrintUsage(const char* prog) {
    std::fprintf(stderr,
        "usage: %s --in <generated_corpus_dir> --out <wire_corpus_dir>\n"
        "\n"
        "Pre-encode the XiUOS JSON descriptor corpus into canonical wire-byte\n"
        "seeds (<out>/<hash16>/payload.bin) consumable by CorpusDiskIO::LoadAll.\n",
        prog);
}

}  // namespace

int main(int argc, char** argv) {
    std::filesystem::path in_dir;
    std::filesystem::path out_dir;
    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", argv[i]);
                return nullptr;
            }
            return argv[++i];
        };
        if (a == "--in") {
            const char* v = next(); if (!v) return 1;
            in_dir = v;
        } else if (a == "--out") {
            const char* v = next(); if (!v) return 1;
            out_dir = v;
        } else if (a == "--help" || a == "-h") {
            PrintUsage(argv[0]);
            return 0;
        } else {
            std::fprintf(stderr, "unknown arg: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }
    }
    if (in_dir.empty() || out_dir.empty()) {
        PrintUsage(argv[0]);
        return 1;
    }
    if (!std::filesystem::is_directory(in_dir)) {
        std::fprintf(stderr, "in dir does not exist: %s\n", in_dir.string().c_str());
        return 1;
    }

    std::error_code ec;
    std::filesystem::create_directories(out_dir, ec);

    const auto seed_files = progx::DiscoverXiuosProgramSeedFiles(in_dir);
    std::size_t total = 0, encoded = 0, deduped = 0, failed = 0;
    for (const auto& path : seed_files) {
        ++total;
        auto seed_r = progx::LoadXiuosProgramSeed(path);
        if (!seed_r.ok()) {
            ++failed;
            std::fprintf(stderr, "LOAD_FAIL %s: %s\n",
                         path.string().c_str(), seed_r.error().message.c_str());
            continue;
        }
        const auto payload = seed_r.value().Encode();
        if (payload.empty()) {
            ++failed;
            std::fprintf(stderr, "ENCODE_EMPTY %s\n", path.string().c_str());
            continue;
        }
        const auto stem = HexHash(FnvHash64(payload));
        const auto dir = out_dir / stem;
        const auto bin = dir / "payload.bin";
        std::error_code ec2;
        if (std::filesystem::exists(bin, ec2) && !ec2) {
            ++deduped;
            continue;
        }
        std::filesystem::create_directories(dir, ec2);
        std::ofstream out(bin, std::ios::binary | std::ios::trunc);
        if (!out) {
            ++failed;
            std::fprintf(stderr, "WRITE_FAIL %s\n", bin.string().c_str());
            continue;
        }
        out.write(reinterpret_cast<const char*>(payload.data()),
                  static_cast<std::streamsize>(payload.size()));
        ++encoded;
    }

    std::printf("xiuos_corpus_encode: in=%s out=%s\n",
                in_dir.string().c_str(), out_dir.string().c_str());
    std::printf("  seed_files=%zu encoded=%zu deduped=%zu failed=%zu\n",
                total, encoded, deduped, failed);
    return (encoded > 0 || deduped > 0) ? 0 : 1;
}
