// refuzz-syz-v2-corpus-dump
//
// 走 reFuzz corpus 目录(<root>/<seed_id>/payload.bin),用 fuzzer 同源
// `syz::TextDecoder` 解 canonical text payload,输出与 tools/decode_prog.py
// 兼容的摘要(call_count / top_syscalls / 每 call 文本)。
//
// 与 Python 版的差别:
//   - 不重建 syscall 表,直接复用 Target::linux_amd64()(永远 schema 同源);
//   - 解码失败时打印 payload 长度 + 前 16/64 字节 hex + decoder 报错的 line/col,
//     方便定位"是 v1 wire / 二进制 artifact / 非 canonical 文本 / 损坏";
//   - 不支持 binary wire 格式(syz_exec_v2 / flat_v1) — corpus 写盘走
//     CorpusDiskIO::SaveSeed 路径正常应该是 canonical text;binary 路径只在
//     fallback / 异常时出现,正好通过 decode 失败 + hex header 暴露问题。
//
// 用法:
//   refuzz-syz-v2-corpus-dump <corpus_root> [output_log]
//
// output_log 默认 = <corpus_root>/decoded_corpus.log,与 decode_repros_cpp.sh
// 的产物完全可替换。

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

namespace syz = ::refuzz::program::syz;

namespace {

bool ReadWholeFile(const std::string& path, std::string& out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return static_cast<bool>(in) || in.eof();
}

bool IsDir(const std::string& path)
{
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool IsFile(const std::string& path)
{
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::vector<std::string> ListDirSorted(const std::string& path)
{
    std::vector<std::string> entries;
    DIR* d = ::opendir(path.c_str());
    if (d == nullptr) {
        return entries;
    }
    while (auto* ent = ::readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        entries.push_back(std::move(n));
    }
    ::closedir(d);
    std::sort(entries.begin(), entries.end());
    return entries;
}

std::string HexHead(const std::string& bytes, std::size_t max_bytes)
{
    const std::size_t n = std::min(bytes.size(), max_bytes);
    std::string out;
    out.reserve(n * 3);
    char buf[4];
    for (std::size_t i = 0; i < n; ++i) {
        std::snprintf(buf, sizeof(buf), "%02x ",
                      static_cast<unsigned>(static_cast<unsigned char>(bytes[i])));
        out += buf;
    }
    if (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out;
}

std::string IsoTimestamp()
{
    // 简单 wall clock,避免引入额外依赖;格式贴近 decode_prog.py 的产物。
    std::time_t now = std::time(nullptr);
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", std::localtime(&now)) == 0) {
        return "1970-01-01T00:00:00+0000";
    }
    return std::string(buf);
}

struct SyscallCount {
    std::string name;
    std::size_t count = 0;
};

std::vector<SyscallCount> TopSyscalls(const syz::Prog& prog, std::size_t limit = 8)
{
    std::map<std::string, std::size_t> tally;
    for (const auto& call : prog.calls()) {
        if (call == nullptr || call->meta() == nullptr) continue;
        tally[call->meta()->name()]++;
    }
    std::vector<SyscallCount> out;
    out.reserve(tally.size());
    for (auto& [name, count] : tally) {
        out.push_back({name, count});
    }
    std::sort(out.begin(), out.end(),
              [](const SyscallCount& a, const SyscallCount& b) {
                  if (a.count != b.count) return a.count > b.count;
                  return a.name < b.name;
              });
    if (out.size() > limit) {
        out.resize(limit);
    }
    return out;
}

void DumpDecoded(std::ostream& out,
                 const syz::Prog& prog,
                 syz::TextEncoder& encoder)
{
    // call_count + top_syscalls 行格式与 decode_prog.py render_text 对齐。
    out << "call_count: " << prog.calls().size() << "\n";
    auto top = TopSyscalls(prog);
    if (!top.empty()) {
        out << "top_syscalls: ";
        for (std::size_t i = 0; i < top.size(); ++i) {
            if (i > 0) out << ", ";
            out << top[i].name << "x" << top[i].count;
        }
        out << "\n";
    }
    out << "calls:\n";
    // 把整个 prog 重 encode 一次以拿"标准 canonical 文本",
    // 然后按行切,加 "  N: " 前缀。这样输出每行都是 fuzzer 自己写出来的文本。
    const std::string canon = encoder.encode(prog);
    std::vector<std::string> lines;
    {
        std::string cur;
        for (char c : canon) {
            if (c == '\n') { lines.push_back(std::move(cur)); cur.clear(); }
            else { cur.push_back(c); }
        }
        if (!cur.empty()) lines.push_back(std::move(cur));
    }
    for (std::size_t i = 0; i < lines.size(); ++i) {
        out << "  " << i << ": " << lines[i] << "\n";
    }
}

void DumpFailed(std::ostream& out,
                const std::string& payload,
                const syz::DecodeError& err)
{
    out << "decode failed (TextDecoder): line " << err.line
        << " col " << err.column << ": " << err.message << "\n";
    out << "payload_len: " << payload.size() << "\n";
    out << "payload_hex_head_16: " << HexHead(payload, 16) << "\n";
    if (payload.size() > 16) {
        out << "payload_hex_head_64: " << HexHead(payload, 64) << "\n";
    }
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2 || argc > 3) {
        std::fprintf(stderr,
                     "usage: %s <corpus_root> [output_log]\n"
                     "  corpus_root  目录 e.g. run/state/corpus,内含 <seed_id>/payload.bin\n"
                     "  output_log   输出文件,默认 <corpus_root>/decoded_corpus.log\n",
                     argv[0]);
        return 2;
    }
    const std::string root = argv[1];
    const std::string out_path = (argc == 3)
        ? std::string(argv[2])
        : (root + "/decoded_corpus.log");

    if (!IsDir(root)) {
        std::fprintf(stderr,
                     "[refuzz-syz-v2-corpus-dump] corpus root not a directory: %s\n",
                     root.c_str());
        return 1;
    }

    // 列子目录(每个 = 一个 seed)。
    std::vector<std::string> seeds;
    for (const auto& name : ListDirSorted(root)) {
        const std::string sub = root + "/" + name;
        if (IsDir(sub)) {
            seeds.push_back(name);
        }
    }
    if (seeds.empty()) {
        std::fprintf(stderr,
                     "[refuzz-syz-v2-corpus-dump] no seed directories under %s\n",
                     root.c_str());
        return 1;
    }

    // 同源 decoder/encoder:一份 Target 全程复用,O(1) 启动开销。
    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder decoder(target, syz::DecodeMode::kNonStrict);
    syz::TextEncoder encoder(target);

    std::ofstream out(out_path);
    if (!out) {
        std::fprintf(stderr,
                     "[refuzz-syz-v2-corpus-dump] cannot open output: %s\n",
                     out_path.c_str());
        return 1;
    }

    out << "decode_corpus_cpp report (refuzz-syz-v2-corpus-dump)\n"
        << "generated_at: " << IsoTimestamp() << "\n"
        << "corpus_dir: " << root << "\n"
        << "count: " << seeds.size() << "\n\n";

    std::size_t ok = 0, fail = 0;
    for (const auto& seed_name : seeds) {
        const std::string sub          = root + "/" + seed_name;
        const std::string payload_path = sub + "/payload.bin";

        out << "================================================================================\n";
        out << "corpus_id: " << seed_name << "\n";
        out << "path: " << sub << "\n\n";
        out << "[syscalls]\n";

        if (!IsFile(payload_path)) {
            out << "missing payload.bin\n\n";
            ++fail;
            continue;
        }
        out << "program: " << payload_path << "\n";

        std::string payload;
        if (!ReadWholeFile(payload_path, payload)) {
            out << "read failed: " << payload_path << "\n\n";
            ++fail;
            continue;
        }

        auto result = decoder.decode(payload);
        if (!result) {
            DumpFailed(out, payload, result.error());
            out << "\n";
            ++fail;
            continue;
        }
        DumpDecoded(out, **result, encoder);
        out << "\n";
        ++ok;
    }

    out.flush();

    std::printf("[refuzz-syz-v2-corpus-dump] processed=%zu ok=%zu fail=%zu wrote=%s\n",
                seeds.size(), ok, fail, out_path.c_str());
    return 0;
}
