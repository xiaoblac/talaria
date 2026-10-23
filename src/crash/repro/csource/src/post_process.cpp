// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.

#include "refuzz/crash/repro/csource/internal/post_process.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

namespace {

std::string apply_regex(std::string src, const std::regex& re,
                        const std::string& replacement) {
    return std::regex_replace(src, re, replacement);
}

std::string replace_all(std::string src,
                        const std::string& from, const std::string& to) {
    if (from.empty()) return src;
    std::size_t pos = 0;
    while ((pos = src.find(from, pos)) != std::string::npos) {
        src.replace(pos, from.size(), to);
        pos += to.size();
    }
    return src;
}

} // namespace

std::string post_process(std::string src, const Options& opts,
                         const ICSourceTargetInfo& target_info) {
    if (!opts.HandleSegv) {
        // \t*NONFAILING\((.*)\);\n  →  \1;\n
        src = apply_regex(src, std::regex("\t*NONFAILING\\((.*)\\);\n"),
                          "$1;\n");
    }
    src = replace_all(std::move(src), "NORETURN",      "");
    src = replace_all(std::move(src), "doexit(",       "exit(");
    src = replace_all(std::move(src), "doexit_thread(", "exit(");

    src = apply_regex(std::move(src),
        std::regex("PRINTF\\(.*?\\)"), "");
    src = apply_regex(std::move(src),
        std::regex("\t*debug\\((.*\n)*?.*\\);\n"), "");
    src = apply_regex(std::move(src),
        std::regex("\t*debug_dump_data\\((.*\n)*?.*\\);\n"), "");
    src = apply_regex(std::move(src),
        std::regex("\t*exitf\\((.*\n)*?.*\\);\n"), "\texit(1);\n");
    src = apply_regex(std::move(src),
        std::regex("\t*fail(msg)?\\((.*\n)*?.*\\);\n"), "\texit(1);\n");

    // Remove executor include guards: `#define <UPPER_H>_H ...\n`.
    src = apply_regex(std::move(src),
        std::regex("#define\\s+[A-Z0-9_]*_H\\s*\n"), "");

    src = hoist_includes(std::move(src), target_info);
    src = remove_empty_lines(std::move(src));
    return src;
}

std::string hoist_includes(std::string src,
                           const ICSourceTargetInfo& target_info) {
    // Mirror pkg/csource/csource.go::hoistIncludes (697-732) splice
    // semantics: capture the offset of the first "#include" literal
    // PRE-strip, then strip every "#include <...>\n" line, then
    // re-insert the sorted block at that offset.
    //
    // Why the splice position matters: common.h has `#define
    // _GNU_SOURCE` ahead of the first `#include <...>` (lines 14-15
    // vs 19+). Inserting the hoisted system-include block at the
    // file head pushes `#define _GNU_SOURCE` AFTER `<sched.h>`, at
    // which point glibc's sched.h has already been processed without
    // _GNU_SOURCE active and never exposes `unshare` /
    // `CLONE_NEW*`. Splicing at the original first-include offset
    // keeps `#define _GNU_SOURCE` in front of every system include,
    // exactly as upstream does.
    const std::string include_marker = "#include";
    const auto first = src.find(include_marker);
    if (first == std::string::npos) return src;

    // Collect every "#include <...>\n" line (quoted-form includes,
    // if any reach this stage, are not hoisted — same as upstream).
    std::regex include_re("#include <[^>]*>\n");
    std::set<std::string> includes;
    {
        auto begin = std::sregex_iterator(src.begin(), src.end(), include_re);
        auto end   = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            includes.insert(it->str());
        }
    }
    src = std::regex_replace(src, include_re, "");

    std::vector<std::string> top, mid, bot;
    const std::string_view os = target_info.goos();
    for (const auto& inc : includes) {
        if (inc.find("<linux/") != std::string::npos) {
            bot.push_back(inc);
        } else if (inc.find("<netinet/if_ether.h>") != std::string::npos) {
            bot.push_back(inc);
        } else if (os == "freebsd" && inc.find("<sys/types.h>") != std::string::npos) {
            top.push_back(inc);
        } else {
            mid.push_back(inc);
        }
    }
    std::sort(top.begin(), top.end());
    std::sort(mid.begin(), mid.end());
    std::sort(bot.begin(), bot.end());

    // `first` (PRE-strip offset) is still valid inside the POST-strip
    // src because no "#include <...>" line lives in [0, first) — by
    // definition `first` is the position of the leading "#include"
    // literal, so bytes before it are untouched by the strip.
    std::string assembled;
    assembled.reserve(src.size() + 256);
    assembled.append(src, 0, first);
    for (const auto& s : top) assembled += s;
    if (!top.empty()) assembled += "\n";
    for (const auto& s : mid) assembled += s;
    if (!mid.empty()) assembled += "\n";
    for (const auto& s : bot) assembled += s;
    if (!bot.empty()) assembled += "\n";
    assembled.append(src, first);
    return assembled;
}

std::string remove_empty_lines(std::string src) {
    for (;;) {
        std::string changed = src;
        changed = replace_all(std::move(changed), "\n\n\n",  "\n\n");
        changed = replace_all(std::move(changed), "\n\n\t", "\n\t");
        changed = replace_all(std::move(changed), "\n\n ",  "\n ");
        if (changed.size() == src.size()) {
            return changed;
        }
        src = std::move(changed);
    }
}

} // namespace refuzz::crash::repro::csource::internal
