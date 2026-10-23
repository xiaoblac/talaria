// Copyright 2026 reFuzz project author -------youngkk.


#include "util/ssh.hpp"
#include "util/process.hpp"
#include <thread>
#include <chrono>
#include <sstream>
#include <iostream>

namespace refuzz {
namespace vm {
namespace util {

SSH::SSH(const SSHOptions& options)
    : options_(options)
    , debug_(options.debug) {}

bool SSH::WaitForConnection(std::chrono::seconds timeout) {
    auto start = std::chrono::steady_clock::now();
    int attempt = 0;

    if (debug_) {
        std::cout << "[SSH] Waiting for connection to " << options_.user << "@"
                  << options_.host << ":" << options_.port
                  << " (timeout: " << timeout.count() << "s)" << std::endl;
    }

    while (true) {
        attempt++;

        if (debug_) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start
            );
            std::cout << "[SSH] Connection attempt #" << attempt
                      << " (elapsed: " << elapsed.count() << "s)" << std::endl;
        }

        // 尝试简单的 SSH 连接测试
        auto args = BuildSSHArgs({"true"});
        auto [output, exit_code] = Process::RunCommand("ssh", args, std::chrono::seconds(30));

        if (exit_code == 0) {
            if (debug_) {
                std::cout << "[SSH] Connection successful!" << std::endl;
            }
            return true;
        }

        if (!output.empty()) {
            std::string output_str(output.begin(), output.end());
            std::cout << "[SSH] Connection failed (exit_code=" << exit_code << "):" << std::endl;
            std::cout << output_str << std::endl;
        }

        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed >= timeout) {
            if (debug_) {
                std::cout << "[SSH] Connection timeout after " << attempt
                          << " attempts" << std::endl;
            }
            return false;
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

RunResult SSH::Run(
    const std::string& command,
    std::chrono::seconds timeout
) {
    auto args = BuildSSHArgs({command});
    auto command_result = Process::RunCommandDetailed("ssh", args, timeout);

    RunResult result;
    result.output.assign(command_result.output.begin(), command_result.output.end());
    result.exit_code = command_result.exit_code;
    result.timeout = command_result.timed_out;
    return result;
}

void SSH::RunAsync(
    const std::string& command,
    OutputCallback output_callback,
    std::function<void(int)> completion_callback
) {
    const SSHOptions options = options_;
    std::thread([command, output_callback = std::move(output_callback),
                 completion_callback = std::move(completion_callback), options]() mutable {
        SSH ssh(options);
        auto result = ssh.Run(command, std::chrono::seconds(600));
        if (output_callback) {
            output_callback(result.output);
        }
        if (completion_callback) {
            completion_callback(result.exit_code);
        }
    }).detach();
}

bool SSH::CopyTo(const std::string& local_path, const std::string& remote_path) {
    auto args = BuildSCPArgs();
    args.push_back(local_path);
    args.push_back(ConnectionString() + ":" + remote_path);

    auto [output, exit_code] = Process::RunCommand("scp", args, std::chrono::seconds(300));
    return exit_code == 0;
}

bool SSH::CopyFrom(const std::string& remote_path, const std::string& local_path) {
    auto args = BuildSCPArgs();
    args.push_back(ConnectionString() + ":" + remote_path);
    args.push_back(local_path);

    auto [output, exit_code] = Process::RunCommand("scp", args, std::chrono::seconds(300));
    return exit_code == 0;
}

std::vector<std::string> SSH::BuildSSHArgs(const std::vector<std::string>& extra) const {
    std::vector<std::string> args{
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "RequestTTY=no",
        "-o", "ConnectTimeout=30",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=3",
        "-T",
        "-n",
        "-p", std::to_string(options_.port),
    };

    if (!options_.key_path.empty()) {
        args.push_back("-i");
        args.push_back(options_.key_path);
    }

    if (debug_) {
        args.push_back("-v");
    }

    args.push_back(options_.user + "@" + options_.host);

    // 添加额外参数
    for (const auto& arg : extra) {
        args.push_back(arg);
    }

    return args;
}

std::vector<std::string> SSH::BuildSCPArgs() const {
    std::vector<std::string> args{
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-P", std::to_string(options_.port),
    };

    if (!options_.key_path.empty()) {
        args.push_back("-i");
        args.push_back(options_.key_path);
    }

    if (debug_) {
        args.push_back("-v");
    }

    return args;
}

std::string SSH::ConnectionString() const {
    return options_.user + "@" + options_.host;
}

// ========== SSHKeyGen 实现 ==========

bool SSHKeyGen::Generate(
    const std::string& output_path,
    const std::string& key_type,
    int bits
) {
    std::vector<std::string> args{
        "-t", key_type,
        "-b", std::to_string(bits),
        "-N", "",  // 无密码
        "-C", "",  // 无注释
        "-f", output_path,
    };

    auto [output, exit_code] = Process::RunCommand("ssh-keygen", args, std::chrono::seconds(30));
    return exit_code == 0;
}

bool SSHKeyGen::Validate(const std::string& key_path) {
    // 检查私钥
    if (!FileUtil::Exists(key_path)) {
        return false;
    }

    // 检查公钥
    if (!FileUtil::Exists(key_path + ".pub")) {
        return false;
    }

    // 验证私钥格式
    std::vector<std::string> args{"-l", "-f", key_path};
    auto [output, exit_code] = Process::RunCommand("ssh-keygen", args, std::chrono::seconds(5));

    return exit_code == 0;
}

} // namespace util
} // namespace vm
} // namespace refuzz
