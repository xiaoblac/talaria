#pragma once

// KernelReportParser — 结构化解析 kernel crash 报告。
// Title/AltTitles/Frame/Type/Corrupted follow syzkaller's Linux reporter;
// frames are retained separately as diagnostic symbolization input.

#include "refuzz/channel/health/health_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace refuzz::crash {

// 单个栈帧
struct StackFrame {
    std::string function;    // 函数名（如 "do_sys_open"）
    uint64_t offset = 0;     // 函数内偏移（func+0xOFF 中的 OFF）
    uint64_t size = 0;       // 函数大小（func+0xOFF/0xSIZE 中的 SIZE）
    std::string module;      // 内核模块名（如 "[ext4]"），vmlinux 为空
    uint64_t pc = 0;         // 程序计数器地址（RIP/NIP 行提取）
    std::string file;        // 源文件路径（addr2line 填充）
    uint32_t line = 0;       // 源文件行号（addr2line 填充）
};

// 结构化 crash 报告
struct ParsedCrashReport {
    std::string title;            // syzkaller-compatible canonical title
    std::string raw_title;        // 原始标题（未修改）
    refuzz::channel::CrashType type = refuzz::channel::CrashType::kUnknown;
    // Exact syzkaller report type (for example HANG or REFCOUNT_WARNING).
    // `type` remains the legacy channel-facing coarse classification.
    std::string report_type;
    std::vector<std::string> alt_titles;
    std::vector<StackFrame> frames;
    std::string guilty_function;  // syzkaller Report.Frame, extracted from title
    bool corrupted = false;       // backtrace 是否可能被截断或损坏
    std::string corrupted_reason;
};

// 轻量判定：console_output 是否含**真正的** kernel crash —— 存在匹配 crash-title 模式
// 且不在 benign 抑制表(kBenignReportRegex,镜像 syzkaller suppressions)里的行。
// 给 fault→recovery 门用：benign-only 的 console(如 "WARNING: The mand mount option
// has been deprecated")→ false → 不 reboot。镜像 syz：detect → 若 suppressed 则 caller
// 丢弃。suppression 这份"数据"属于本组件(linux-kernel report parser),不外泄给通用 sensor。
bool ConsoleContainsRealCrash(const std::string& console_output);

class KernelReportParser {
public:
    // 从 console output 解析 crash 报告
    // 返回 nullopt 表示未检测到 crash 模式
    std::optional<ParsedCrashReport> Parse(const std::string& console_output) const;

    // 标准化 crash title：移除地址、PID、CPU 号等不稳定信息
    static std::string NormalizeTitle(const std::string& raw_title);

private:
    // 解析 backtrace 行: " func+0xOFF/0xSIZE [module]"
    static std::optional<StackFrame> ParseBacktraceLine(const std::string& line);

    // 检测 crash 类型
    static refuzz::channel::CrashType DetectCrashType(const std::string& title);
};

} // namespace refuzz::crash
