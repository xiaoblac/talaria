// Copyright 2026 reFuzz project author -------youngkk.


#include "util/process.hpp"
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <iostream>
#include "refuzz/logging/host_logger.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <random>
#include <fstream>
#include <sstream>

namespace refuzz {
namespace vm {
namespace util {

// ========== Process 实现 ==========

Process::Process(const std::string& program,
                 const std::vector<std::string>& args,
                 const Options& options)
    : options_(options) {
    SetupPipes();

    pid_ = fork();
    if (pid_ < 0) {
        throw std::runtime_error("fork failed: " + std::string(strerror(errno)));
    }

    if (pid_ == 0) {
        // 子进程
        SetupChild();

        // 准备参数
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(program.c_str()));
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        // 执行
        execvp(program.c_str(), argv.data());

        // 如果到这里说明 exec 失败
        refuzz::logging::HostLineBuilder("Process", "exec_failed") << strerror(errno) << std::endl;
        _exit(127);
    }

    // 父进程
    close(stdin_pipe_[0]);
    close(stdout_pipe_[1]);
    if (options_.redirect_stderr) {
        close(stderr_pipe_[0]);
        close(stderr_pipe_[1]);
    }

    // 启动输出读取线程
    if (options_.output_callback) {
        StartOutputReader();
    }
}

Process::~Process() {
    if (IsRunning()) {
        Kill(true);
        Wait(std::chrono::seconds(5));
    }

    JoinOutputReader();

    if (stdin_pipe_[1] >= 0) close(stdin_pipe_[1]);
    if (stdout_pipe_[0] >= 0) close(stdout_pipe_[0]);
}

void Process::SetupPipes() {
    if (pipe(stdin_pipe_) < 0) {
        throw std::runtime_error("pipe failed: " + std::string(strerror(errno)));
    }
    if (pipe(stdout_pipe_) < 0) {
        close(stdin_pipe_[0]);
        close(stdin_pipe_[1]);
        throw std::runtime_error("pipe failed: " + std::string(strerror(errno)));
    }
    if (options_.redirect_stderr) {
        if (pipe(stderr_pipe_) < 0) {
            close(stdin_pipe_[0]);
            close(stdin_pipe_[1]);
            close(stdout_pipe_[0]);
            close(stdout_pipe_[1]);
            throw std::runtime_error("pipe failed: " + std::string(strerror(errno)));
        }
    }
}

void Process::SetupChild() {
    // 重定向标准输入/输出
    dup2(stdin_pipe_[0], STDIN_FILENO);
    dup2(stdout_pipe_[1], STDOUT_FILENO);
    if (options_.redirect_stderr) {
        dup2(stdout_pipe_[1], STDERR_FILENO);
    }

    // 关闭不需要的文件描述符
    close(stdin_pipe_[0]);
    close(stdin_pipe_[1]);
    close(stdout_pipe_[0]);
    close(stdout_pipe_[1]);
    if (options_.redirect_stderr) {
        close(stderr_pipe_[0]);
        close(stderr_pipe_[1]);
    }

    // 设置工作目录
    if (!options_.workdir.empty()) {
        if (chdir(options_.workdir.c_str()) < 0) {
            refuzz::logging::HostLineBuilder("Process", "chdir_failed") << strerror(errno) << std::endl;
            _exit(126);
        }
    }

    // 设置环境变量
    for (const auto& env : options_.env) {
        putenv(const_cast<char*>(env.c_str()));
    }
}

void Process::StartOutputReader() {
    output_thread_ = std::thread([this]() {
        char buffer[4096];
        while (true) {
            ssize_t n = read(stdout_pipe_[0], buffer, sizeof(buffer));
            if (n <= 0) break;
            if (options_.output_callback) {
                options_.output_callback(buffer, n);
            }
        }
    });
}

void Process::JoinOutputReader() {
    if (output_thread_.joinable()) {
        output_thread_.join();
    }
}

bool Process::IsRunning() const {
    if (pid_ < 0) return false;

    int status;
    pid_t result = waitpid(pid_, &status, WNOHANG);
    return result == 0;
}

int Process::Wait(std::chrono::seconds timeout) {
    if (pid_ < 0) return -1;

    int status;
    if (timeout.count() == 0) {
        // 无限等待
        if (waitpid(pid_, &status, 0) < 0) {
            return -1;
        }
    } else {
        // 超时等待
        auto start = std::chrono::steady_clock::now();
        while (true) {
            pid_t result = waitpid(pid_, &status, WNOHANG);
            if (result > 0) {
                break;
            } else if (result < 0) {
                return -1;
            }

            auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed >= timeout) {
                return -1;  // 超时
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return -1;
}

void Process::Kill(bool force) {
    if (pid_ < 0) return;

    int sig = force ? SIGKILL : SIGTERM;
    kill(pid_, sig);
}

ssize_t Process::ReadOutput(void* buffer, size_t size) {
    return read(stdout_pipe_[0], buffer, size);
}

ssize_t Process::WriteInput(const void* data, size_t size) {
    if (input_closed_) return -1;
    return write(stdin_pipe_[1], data, size);
}

void Process::CloseInput() {
    if (!input_closed_ && stdin_pipe_[1] >= 0) {
        close(stdin_pipe_[1]);
        stdin_pipe_[1] = -1;
        input_closed_ = true;
    }
}

std::pair<std::string, int> Process::RunCommand(
    const std::string& program,
    const std::vector<std::string>& args,
    std::chrono::seconds timeout
) {
    auto result = RunCommandDetailed(program, args, timeout);
    return {std::move(result.output), result.exit_code};
}

Process::CommandResult Process::RunCommandDetailed(
    const std::string& program,
    const std::vector<std::string>& args,
    std::chrono::seconds timeout
) {
    CommandResult result;

    Options opts;
    opts.output_callback = [&result](const char* data, size_t size) {
        result.output.append(data, size);
    };

    Process proc(program, args, opts);
    proc.CloseInput();

    result.exit_code = proc.Wait(timeout);
    result.timed_out = (result.exit_code == -1 && proc.IsRunning());
    if (result.timed_out) {
        proc.Kill(true);
        (void)proc.Wait(std::chrono::seconds{5});
    }
    proc.JoinOutputReader();
    return result;
}

// ========== PortUtil 实现 ==========

int PortUtil::FindUnusedPort(int start, int end) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(start, end);

    for (int i = 0; i < 100; ++i) {
        int port = dis(gen);
        if (!IsPortInUse(port)) {
            return port;
        }
    }

    return 0;
}

bool PortUtil::IsPortInUse(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        // socket() 失败不代表端口被占用，而是系统错误
        // 在这种情况下，假设端口可用，让 QEMU 自己尝试绑定
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);

    int result = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    return result < 0;
}

// ========== FileUtil 实现 ==========

bool FileUtil::Exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

bool FileUtil::MkdirAll(const std::string& path) {
    size_t pos = 0;
    std::string dir;

    if (path[0] == '/') {
        pos = 1;
        dir = "/";
    }

    while (pos < path.size()) {
        pos = path.find('/', pos);
        if (pos == std::string::npos) {
            pos = path.size();
        }

        dir = path.substr(0, pos);
        if (!dir.empty() && !Exists(dir)) {
            if (mkdir(dir.c_str(), 0755) < 0 && errno != EEXIST) {
                return false;
            }
        }
        ++pos;
    }

    return true;
}

bool FileUtil::RemoveAll(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) < 0) {
        return false;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR* dir = opendir(path.c_str());
        if (!dir) return false;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            std::string full_path = path + "/" + entry->d_name;
            RemoveAll(full_path);
        }

        closedir(dir);
        return rmdir(path.c_str()) == 0;
    } else {
        return unlink(path.c_str()) == 0;
    }
}

bool FileUtil::CopyFile(const std::string& src, const std::string& dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return false;

    std::ofstream out(dst, std::ios::binary);
    if (!out) return false;

    out << in.rdbuf();
    return out.good();
}

std::string FileUtil::ReadFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) return "";

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool FileUtil::WriteFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) return false;

    file << content;
    return file.good();
}

std::string FileUtil::TempDir() {
    const char* tmpdir = getenv("TMPDIR");
    if (tmpdir) return tmpdir;

    tmpdir = getenv("TEMP");
    if (tmpdir) return tmpdir;

    return "/tmp";
}

std::string FileUtil::MakeTempDir(const std::string& prefix) {
    std::string pattern = TempDir() + "/" + prefix + "XXXXXX";
    std::vector<char> buf(pattern.begin(), pattern.end());
    buf.push_back('\0');

    char* result = mkdtemp(buf.data());
    if (!result) {
        return "";
    }

    return result;
}

} // namespace util
} // namespace vm
} // namespace refuzz
