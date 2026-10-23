#include "refuzz/crash/components/symbolizer/addr2line_symbolizer.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include "refuzz/logging/host_logger.hpp"
#include <sstream>

#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace refuzz::crash {

Addr2lineSymbolizer::Addr2lineSymbolizer(Addr2lineConfig config)
    : config_(std::move(config))
{
    SpawnProcess();
}

Addr2lineSymbolizer::~Addr2lineSymbolizer()
{
    // 关闭管道 fd
    if (stdin_fd_ >= 0) {
        close(stdin_fd_);
        stdin_fd_ = -1;
    }
    if (stdout_fd_ >= 0) {
        close(stdout_fd_);
        stdout_fd_ = -1;
    }

    // 等待子进程退出
    if (child_pid_ > 0) {
        kill(child_pid_, SIGTERM);
        int status = 0;
        waitpid(child_pid_, &status, 0);
        child_pid_ = -1;
    }
}

void Addr2lineSymbolizer::SymbolizeReport(ParsedCrashReport& report)
{
    for (auto& frame : report.frames) {
        if (frame.pc == 0) {
            continue;
        }

        auto resolved = Symbolize(frame.pc);
        if (!resolved.empty()) {
            // 用第一个符号化结果填充 file/line（inline 展开时取最内层）
            frame.file = resolved.front().file;
            frame.line = resolved.front().line;
            // 如果 function 为空，也用符号化结果补充
            if (frame.function.empty() && !resolved.front().function.empty()) {
                frame.function = resolved.front().function;
            }
        }
    }
}

std::vector<StackFrame> Addr2lineSymbolizer::Symbolize(uint64_t pc)
{
    std::lock_guard<std::mutex> lock(mu_);

    // 查缓存
    auto it = cache_.find(pc);
    if (it != cache_.end()) {
        return it->second;
    }

    // 子进程不存活则尝试重启
    if (!IsAlive()) {
        if (!SpawnProcess()) {
            return {};
        }
    }

    auto results = QueryAddr2line(pc);
    std::vector<StackFrame> frames;
    frames.reserve(results.size());

    for (const auto& [func, loc] : results) {
        StackFrame frame;
        frame.pc = pc;

        // 解析 function 名（去掉参数和修饰）
        frame.function = func;
        if (frame.function == "??" || frame.function == "??:0") {
            frame.function.clear();
        }

        // 解析 file:line
        const auto colon = loc.rfind(':');
        if (colon != std::string::npos) {
            frame.file = loc.substr(0, colon);
            const auto line_str = loc.substr(colon + 1);
            // 移除可能的 "(discriminator N)" 后缀
            try {
                frame.line = static_cast<uint32_t>(std::stoul(line_str));
            } catch (...) {
                frame.line = 0;
            }
        }

        // 过滤无效结果
        if (frame.file == "??" || frame.file == "??:0") {
            frame.file.clear();
            frame.line = 0;
        }

        frames.push_back(std::move(frame));
    }

    // 写入缓存（限容量）
    if (cache_.size() < config_.cache_capacity) {
        cache_[pc] = frames;
    }

    return frames;
}

bool Addr2lineSymbolizer::IsAlive() const
{
    if (child_pid_ <= 0) {
        return false;
    }
    // 非阻塞检查子进程状态
    int status = 0;
    pid_t ret = waitpid(child_pid_, &status, WNOHANG);
    return ret == 0;  // 0 表示子进程仍在运行
}

bool Addr2lineSymbolizer::SpawnProcess()
{
    // 创建两对管道：parent→child stdin, child→parent stdout
    int to_child[2] = {-1, -1};    // to_child[0]=child reads, to_child[1]=parent writes
    int from_child[2] = {-1, -1};  // from_child[0]=parent reads, from_child[1]=child writes

    if (pipe(to_child) < 0 || pipe(from_child) < 0) {
        refuzz::logging::HostLineBuilder("Addr2line", "pipe_failed") << strerror(errno) << "\n";
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        refuzz::logging::HostLineBuilder("Addr2line", "fork_failed") << strerror(errno) << "\n";
        close(to_child[0]);
        close(to_child[1]);
        close(from_child[0]);
        close(from_child[1]);
        return false;
    }

    if (pid == 0) {
        // 子进程：重定向 stdin/stdout，exec addr2line
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]);
        close(to_child[1]);
        close(from_child[0]);
        close(from_child[1]);

        // addr2line -afi -e <vmlinux>
        execlp(config_.addr2line_binary.c_str(),
               config_.addr2line_binary.c_str(),
               "-afi",
               "-e", config_.vmlinux_path.c_str(),
               nullptr);
        // exec 失败
        _exit(127);
    }

    // 父进程：关闭子进程端的 fd
    close(to_child[0]);
    close(from_child[1]);

    child_pid_ = pid;
    stdin_fd_ = to_child[1];
    stdout_fd_ = from_child[0];

    return true;
}

std::vector<std::pair<std::string, std::string>> Addr2lineSymbolizer::QueryAddr2line(uint64_t pc)
{
    std::vector<std::pair<std::string, std::string>> results;

    if (stdin_fd_ < 0 || stdout_fd_ < 0) {
        return results;
    }

    // 发送 PC 地址到 addr2line（十六进制格式 + 换行）
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "0x%lx\n", static_cast<unsigned long>(pc));
    if (len <= 0) {
        return results;
    }

    ssize_t written = write(stdin_fd_, buf, static_cast<size_t>(len));
    if (written != len) {
        return results;
    }

    // 读取响应：addr2line -afi 输出格式：
    // 0x<addr>         ← 地址回显（-a 标志）
    // function_name    ← 函数名
    // file:line        ← 文件:行号
    // （inline 展开时重复 function/file:line 对，直到下一个地址回显或空行）

    // 先读地址回显行
    std::string addr_echo = ReadLine();
    if (addr_echo.empty()) {
        return results;
    }

    // 读取 function/file:line 对
    // addr2line -i 可能输出多对（inline 展开），最后一对是最外层
    // 判断结束：下一行是空行或者以 "0x" 开头（不会发生，因为我们每次只查一个地址）
    while (true) {
        std::string func_line = ReadLine();
        if (func_line.empty()) {
            break;
        }

        std::string loc_line = ReadLine();
        if (loc_line.empty()) {
            break;
        }

        results.emplace_back(std::move(func_line), std::move(loc_line));

        // addr2line -i：inline 展开的帧之间没有分隔
        // 需要 peek 下一行是否还是 function（而不是 "0x" 地址回显）
        // 但由于我们每次只查一个地址，结束条件是读不到更多输出
        // 使用短超时 poll 来检测
        struct pollfd pfd{};
        pfd.fd = stdout_fd_;
        pfd.events = POLLIN;
        int ready = poll(&pfd, 1, 50);  // 50ms 短超时
        if (ready <= 0) {
            break;  // 没有更多数据
        }
    }

    return results;
}

std::string Addr2lineSymbolizer::ReadLine()
{
    std::string result;
    char ch = 0;

    // poll 超时保护
    struct pollfd pfd{};
    pfd.fd = stdout_fd_;
    pfd.events = POLLIN;

    const int timeout_ms = static_cast<int>(config_.read_timeout.count());

    while (true) {
        int ready = poll(&pfd, 1, timeout_ms);
        if (ready <= 0) {
            // 超时或错误
            break;
        }

        ssize_t n = read(stdout_fd_, &ch, 1);
        if (n <= 0) {
            break;
        }

        if (ch == '\n') {
            break;
        }
        result.push_back(ch);
    }

    return result;
}

} // namespace refuzz::crash
