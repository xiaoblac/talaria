#pragma once

// Addr2lineSymbolizer — 长驻 addr2line 子进程符号化
// 维护一个 addr2line -afi -e <vmlinux> 子进程，通过 stdin/stdout 管道通信。
// 支持 inline 展开（-i），一个 PC 可能展开为多帧。
// 内置 PC→Frame 缓存避免重复符号化。

#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::crash {

struct Addr2lineConfig {
    std::string vmlinux_path;                                    // vmlinux ELF 路径
    std::string addr2line_binary = "addr2line";                  // addr2line 可执行文件路径
    std::chrono::milliseconds read_timeout{5000};                // pipe read 超时
    size_t cache_capacity = 16384;                               // PC→Frame 缓存容量
};

class Addr2lineSymbolizer {
public:
    explicit Addr2lineSymbolizer(Addr2lineConfig config);
    ~Addr2lineSymbolizer();

    // 不可拷贝/移动（持有子进程 fd）
    Addr2lineSymbolizer(const Addr2lineSymbolizer&) = delete;
    Addr2lineSymbolizer& operator=(const Addr2lineSymbolizer&) = delete;

    // 批量符号化 ParsedCrashReport 中所有帧的 file/line
    // 修改 report.frames[] 的 file 和 line 字段
    void SymbolizeReport(ParsedCrashReport& report);

    // 单个 PC 符号化，返回 inline 展开的帧列表
    std::vector<StackFrame> Symbolize(uint64_t pc);

    // 子进程是否存活
    bool IsAlive() const;

private:
    // 启动 addr2line 子进程
    bool SpawnProcess();

    // 向子进程发送 PC 地址并读取结果
    // 返回 (function, file:line) 对列表
    std::vector<std::pair<std::string, std::string>> QueryAddr2line(uint64_t pc);

    // poll() + read() 带超时
    std::string ReadLine();

    Addr2lineConfig config_;
    pid_t child_pid_ = -1;
    int stdin_fd_ = -1;       // 写入子进程 stdin
    int stdout_fd_ = -1;      // 读取子进程 stdout
    mutable std::mutex mu_;

    // PC → 符号化结果缓存
    std::unordered_map<uint64_t, std::vector<StackFrame>> cache_;
};

} // namespace refuzz::crash
