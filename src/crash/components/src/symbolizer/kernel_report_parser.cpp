#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace refuzz::crash {
namespace {

extern "C" char* RefuzzDemangleSymbol(const char* symbol);

constexpr std::string_view kLinuxRipFrame =
    R"((?:IP|NIP|pc |PC is at):? (?:(?:[0-9]+:)?(?:{{PC}} +){0,2}{{FUNC}}|(?:[0-9]+:)?0x[0-9a-f]+|(?:[0-9]+:)?{{PC}} +\[< *\(null\)>\] +\(null\)|[0-9]+: +\(null\)))";
constexpr std::string_view kLinuxCallTrace =
    R"((?:Call (?:T|t)race:)|(?:Backtrace:))";
constexpr std::string_view kWarningRipFrame =
    R"((?:(?:@@LINUX_RIP_FRAME@@)|--- interrupt: [0-9]+ at {{FUNC}}))";

void ReplaceAll(std::string& value, std::string_view from, std::string_view to)
{
    std::size_t pos = 0;
    while ((pos = value.find(from, pos)) != std::string::npos) {
        value.replace(pos, from.size(), to);
        pos += to.size();
    }
}

std::string ExpandPattern(std::string source)
{
    ReplaceAll(source, "@@WARNING_RIP_FRAME@@", kWarningRipFrame);
    ReplaceAll(source, "@@LINUX_RIP_FRAME@@", kLinuxRipFrame);
    ReplaceAll(source, "@@LINUX_CALL_TRACE@@", kLinuxCallTrace);
    ReplaceAll(source, "{{ADDR}}", R"(0x[0-9a-f]+)");
    ReplaceAll(source, "{{PC}}", R"(\[<?(?:0x)?[0-9a-f]+>?\])");
    ReplaceAll(source, "{{FUNC}}", R"(([a-zA-Z0-9_]+)(?:\.|\+))");
    ReplaceAll(source, "{{SRC}}", R"(([a-zA-Z0-9-_/.]+\.[a-z]+:[0-9]+))");
    ReplaceAll(source, "{{TASK}}", R"([\s\S]{0,100}?)");
    return source;
}

struct PatternSpec {
    std::string source;
    std::shared_ptr<const std::regex> expression;

    explicit operator bool() const { return expression != nullptr; }
};

PatternSpec MakePattern(std::string source, bool icase)
{
    source = ExpandPattern(std::move(source));
    auto flags = std::regex_constants::ECMAScript |
                 std::regex_constants::optimize;
    if (icase) {
        flags |= std::regex_constants::icase;
    }
    try {
        return PatternSpec{
            source,
            std::make_shared<const std::regex>(source, flags),
        };
    } catch (const std::regex_error& error) {
        throw std::runtime_error("invalid generated Linux report regexp '" +
                                 source + "': " + error.what());
    }
}

PatternSpec NoPattern()
{
    return {};
}

struct StackPartSpec {
    bool stack_trace = false;
    PatternSpec pattern;
};

StackPartSpec RegexPart(PatternSpec pattern)
{
    return StackPartSpec{false, std::move(pattern)};
}

StackPartSpec StackTracePart()
{
    return StackPartSpec{true, {}};
}

struct StackSpec {
    std::vector<StackPartSpec> parts;
    std::vector<StackPartSpec> parts2;
    std::vector<std::string> skip;
    std::string extractor;
};

using StackSpecPtr = std::shared_ptr<const StackSpec>;

StackSpecPtr MakeStack(std::vector<StackPartSpec> parts,
                       std::vector<StackPartSpec> parts2,
                       std::vector<std::string> skip,
                       std::string extractor)
{
    return std::make_shared<const StackSpec>(StackSpec{
        std::move(parts), std::move(parts2), std::move(skip),
        std::move(extractor),
    });
}

StackSpecPtr NoStack()
{
    return nullptr;
}

struct FormatSpec {
    PatternSpec title;
    PatternSpec report;
    std::string format;
    std::vector<std::string> alt;
    StackSpecPtr stack;
    bool no_stack_trace = false;
    bool corrupted = false;
};

FormatSpec MakeFormat(PatternSpec title, PatternSpec report,
                      std::string format, std::vector<std::string> alt,
                      StackSpecPtr stack, bool no_stack_trace,
                      bool corrupted)
{
    return FormatSpec{
        std::move(title), std::move(report), std::move(format),
        std::move(alt), std::move(stack), no_stack_trace, corrupted,
    };
}

struct OopsSpec {
    std::string header;
    std::vector<FormatSpec> formats;
    std::vector<PatternSpec> suppressions;
};

OopsSpec MakeOops(std::string header, std::vector<FormatSpec> formats,
                  std::vector<PatternSpec> suppressions)
{
    return OopsSpec{
        std::move(header), std::move(formats), std::move(suppressions),
    };
}

struct StackParamsSpec {
    std::vector<PatternSpec> stack_starts;
    std::vector<PatternSpec> frames;
    std::vector<std::string> skip;
    std::vector<PatternSpec> corrupted_lines;
    std::vector<std::string> strip_prefixes;
};

StackParamsSpec MakeStackParams(std::vector<PatternSpec> stack_starts,
                                std::vector<PatternSpec> frames,
                                std::vector<std::string> skip,
                                std::vector<PatternSpec> corrupted_lines,
                                std::vector<std::string> strip_prefixes)
{
    return StackParamsSpec{
        std::move(stack_starts), std::move(frames), std::move(skip),
        std::move(corrupted_lines), std::move(strip_prefixes),
    };
}

struct TitleTypeRule {
    std::vector<std::string> prefixes;
    std::string report_type;
};

TitleTypeRule MakeTitleTypeRule(std::vector<std::string> prefixes,
                                std::string report_type)
{
    return TitleTypeRule{std::move(prefixes), std::move(report_type)};
}

#include "linux_report_formats.gen.inc"

const std::vector<OopsSpec>& LinuxOopses()
{
    static const std::vector<OopsSpec> specs = BuildGeneratedOopsSpecs();
    return specs;
}

const StackParamsSpec& LinuxStackParams()
{
    static const StackParamsSpec params = BuildGeneratedStackParamsSpec();
    return params;
}

const std::vector<PatternSpec>& LinuxStallAnchorFrames()
{
    static const std::vector<PatternSpec> patterns =
        BuildGeneratedStallAnchorPatterns();
    return patterns;
}

const std::vector<TitleTypeRule>& LinuxTitleTypeRules()
{
    static const std::vector<TitleTypeRule> rules =
        BuildGeneratedTitleTypeRules();
    return rules;
}

bool PatternMatches(const PatternSpec& pattern, const std::string& text)
{
    return pattern && std::regex_search(text, *pattern.expression);
}

bool MatchesAny(const std::string& text,
                const std::vector<PatternSpec>& patterns)
{
    return std::any_of(patterns.begin(), patterns.end(),
                       [&text](const PatternSpec& pattern) {
                           return PatternMatches(pattern, text);
                       });
}

struct RegexMatch {
    std::size_t position = 0;
    std::size_t length = 0;
    std::vector<std::optional<std::string>> groups;
};

std::optional<RegexMatch> FindMatch(const PatternSpec& pattern,
                                    const std::string& text)
{
    if (!pattern) {
        return std::nullopt;
    }
    std::smatch match;
    if (!std::regex_search(text, match, *pattern.expression)) {
        return std::nullopt;
    }
    RegexMatch result;
    result.position = static_cast<std::size_t>(match.position(0));
    result.length = static_cast<std::size_t>(match.length(0));
    result.groups.reserve(match.size() > 0 ? match.size() - 1 : 0);
    for (std::size_t i = 1; i < match.size(); ++i) {
        if (match[i].matched) {
            result.groups.emplace_back(match[i].str());
        } else {
            result.groups.emplace_back(std::nullopt);
        }
    }
    return result;
}

bool MatchOops(const std::string& line, const OopsSpec& oops)
{
    return line.find(oops.header) != std::string::npos &&
           !MatchesAny(line, oops.suppressions);
}

struct LineRange {
    std::size_t start = 0;
    std::size_t end = 0;
};

std::vector<LineRange> LineRanges(const std::string& text)
{
    std::vector<LineRange> ranges;
    for (std::size_t pos = 0; pos < text.size();) {
        const std::size_t newline = text.find('\n', pos);
        const std::size_t end = newline == std::string::npos
            ? text.size()
            : newline;
        ranges.push_back(LineRange{pos, end});
        if (newline == std::string::npos) {
            break;
        }
        pos = newline + 1;
    }
    return ranges;
}

std::vector<std::string> SplitLines(const std::string& text)
{
    std::vector<std::string> lines;
    std::size_t pos = 0;
    for (;;) {
        const std::size_t newline = text.find('\n', pos);
        if (newline == std::string::npos) {
            lines.push_back(text.substr(pos));
            break;
        }
        lines.push_back(text.substr(pos, newline - pos));
        pos = newline + 1;
    }
    return lines;
}

bool IsTruncatedByReplay(const std::string& output, std::size_t pos)
{
    if (pos >= output.size() || output[pos] != '\n') {
        return false;
    }
    const std::size_t next = output.find('\n', pos + 1);
    const std::string_view line(
        output.data() + pos + 1,
        (next == std::string::npos ? output.size() : next) - pos - 1);
    return line.find("** replaying previous printk message **") !=
           std::string_view::npos;
}

const std::regex& ConsoleOutputRegex()
{
    static const std::regex expression(
        R"(^(?:\*\* [0-9]+ printk messages dropped \*\* )?(?:.* login: )?(?:<[0-9]+>)?\[ *[0-9]+\.[0-9]+\](\[ *(?:C|T)[0-9]+\])? )",
        std::regex_constants::ECMAScript | std::regex_constants::optimize);
    return expression;
}

std::string ExtractContext(const std::string& line)
{
    std::smatch match;
    if (!std::regex_search(line, match, ConsoleOutputRegex())) {
        return {};
    }
    if (!match[1].matched) {
        return "console";
    }
    return match[1].str();
}

bool IsCpuContext(const std::string& context)
{
    static const std::regex expression(
        R"(\[ *C[0-9]+\])",
        std::regex_constants::ECMAScript | std::regex_constants::optimize);
    return std::regex_search(context, expression);
}

bool IsTaskContext(const std::string& context)
{
    static const std::regex expression(
        R"(\[ *T[0-9]+\])",
        std::regex_constants::ECMAScript | std::regex_constants::optimize);
    return std::regex_search(context, expression);
}

struct StrippedLine {
    std::string text;
    bool questionable = false;
};

StrippedLine StripLinePrefix(const std::string& line,
                             const std::string& context,
                             bool use_questionable)
{
    if (context.empty()) {
        return StrippedLine{line, false};
    }
    const std::size_t prefix_end = line.find("] ");
    std::string stripped = prefix_end == std::string::npos
        ? line
        : line.substr(prefix_end + 2);
    if (stripped.find("<EOI>") == std::string::npos) {
        static const std::regex questionable(
            R"((?:\[<[0-9a-f]+>\])? \? )",
            std::regex_constants::ECMAScript | std::regex_constants::optimize);
        std::smatch match;
        if (std::regex_search(stripped, match, questionable)) {
            const std::size_t pos = static_cast<std::size_t>(match.position(0));
            const std::size_t marker = stripped.find(" ? ", pos);
            if (marker != std::string::npos) {
                stripped = stripped.substr(marker + 2);
            }
            return StrippedLine{std::move(stripped), !use_questionable};
        }
        constexpr std::string_view unreliable = " (unreliable)";
        if (stripped.size() >= unreliable.size() &&
            stripped.compare(stripped.size() - unreliable.size(),
                             unreliable.size(), unreliable) == 0) {
            stripped.resize(stripped.size() - unreliable.size());
            return StrippedLine{std::move(stripped), !use_questionable};
        }
    }
    return StrippedLine{std::move(stripped), false};
}

struct FirstOops {
    const OopsSpec* oops = nullptr;
    std::size_t start_pos = 0;
    std::string context;
};

std::optional<FirstOops> FindFirstOops(const std::string& output)
{
    for (const LineRange& range : LineRanges(output)) {
        const std::string line = output.substr(range.start,
                                               range.end - range.start);
        for (const OopsSpec& oops : LinuxOopses()) {
            if (!MatchOops(line, oops) ||
                IsTruncatedByReplay(output, range.end)) {
                continue;
            }
            return FirstOops{&oops, range.start, ExtractContext(line)};
        }
    }
    return std::nullopt;
}

const std::vector<PatternSpec>& ReportStartIgnores()
{
    static const std::vector<PatternSpec> patterns = {
        MakePattern("invalid opcode: 0000", false),
        MakePattern("Kernel panic - not syncing", false),
        MakePattern("unregister_netdevice: waiting for", false),
        MakePattern("PANIC: double fault", false),
        MakePattern("Internal error:", false),
    };
    return patterns;
}

constexpr std::string_view kInfoMessagesWithStack[] = {
    "vmalloc: allocation failure:",
    "FAULT_INJECTION: forcing a failure",
    "FAULT_FLAG_ALLOW_RETRY missing",
};

std::size_t ReportMinLines(const std::string& oops_line)
{
    return oops_line.find("BUG: KMSAN:") != std::string::npos ? 16 : 22;
}

struct FoundReport {
    std::size_t end_pos = 0;
    std::size_t report_end = 0;
    std::string report;
    std::vector<std::string> prefix;
};

FoundReport FindReport(const std::string& output, std::size_t start_pos,
                       const std::string& context,
                       bool use_questionable)
{
    FoundReport result;
    const std::size_t max_prefix = IsTaskContext(context) ? 50 : 5;
    std::size_t second_report_pos = 0;
    std::size_t text_lines = 0;
    bool skip_text = false;
    bool cpu_traceback = false;
    std::string oops_line;

    for (const LineRange& range : LineRanges(output)) {
        const std::string line = output.substr(range.start,
                                               range.end - range.start);
        const std::string context1 = ExtractContext(line);
        StrippedLine stripped =
            StripLinePrefix(line, context1, use_questionable);
        if (range.start < start_pos) {
            if (context1 == context && !stripped.text.empty() &&
                !stripped.questionable) {
                result.prefix.push_back(std::move(stripped.text));
                if (result.prefix.size() > max_prefix) {
                    result.prefix.erase(result.prefix.begin());
                }
            }
            continue;
        }
        const bool is_oops_line = range.start == start_pos;
        if (is_oops_line) {
            oops_line = line;
        }

        for (const OopsSpec& oops : LinuxOopses()) {
            if (!MatchOops(line, oops)) {
                continue;
            }
            if (IsTruncatedByReplay(output, range.end)) {
                continue;
            }
            result.end_pos = range.end;
            if (!is_oops_line && second_report_pos == 0 &&
                !MatchesAny(line, ReportStartIgnores())) {
                second_report_pos = range.start;
            }
        }
        if (!is_oops_line && second_report_pos == 0) {
            for (std::string_view message : kInfoMessagesWithStack) {
                if (line.find(message) != std::string::npos) {
                    second_report_pos = range.start;
                    break;
                }
            }
        }
        if (!is_oops_line &&
            (stripped.questionable ||
             (context1 != context &&
              (!cpu_traceback || !IsCpuContext(context1))))) {
            continue;
        }

        ++text_lines;
        bool skip_line = skip_text;
        if (line.find("Disabling lock debugging due to kernel taint") !=
            std::string::npos) {
            skip_line = true;
        } else if (line.find("Sending NMI from CPU") != std::string::npos) {
            cpu_traceback = true;
        } else if ((line.find("Kernel panic - not syncing") !=
                        std::string::npos ||
                    line.find("WARNING: possible circular locking dependency detected") !=
                        std::string::npos) &&
                   text_lines > ReportMinLines(oops_line)) {
            skip_text = true;
            skip_line = true;
        }
        if (!is_oops_line && skip_line) {
            continue;
        }
        result.report.append(stripped.text);
        result.report.push_back('\n');
        if (second_report_pos == 0 ||
            (!context.empty() && context != "console")) {
            result.report_end = result.report.size();
        }
    }
    return result;
}

std::vector<std::string> StripFrames(
    const std::vector<std::string>& frames,
    const StackParamsSpec& params)
{
    std::vector<std::string> result;
    result.reserve(frames.size());
    for (const std::string& original : frames) {
        std::string frame = original;
        for (const std::string& prefix : params.strip_prefixes) {
            if (original.rfind(prefix, 0) == 0) {
                std::string stripped = original.substr(prefix.size());
                if (stripped.size() < frame.size()) {
                    frame = std::move(stripped);
                }
            }
        }
        result.push_back(std::move(frame));
    }
    return result;
}

struct SelectedFrame {
    std::string canonical;
    int index = -1;
};

bool ContainsAny(std::string_view text,
                 const std::vector<std::string_view>& needles)
{
    return std::any_of(needles.begin(), needles.end(),
                       [text](std::string_view needle) {
                           return text.find(needle) != std::string_view::npos;
                       });
}

SelectedFrame LinuxHangTaskFrameExtractor(
    const std::vector<std::string>& frames)
{
    for (std::size_t i = 0; i < frames.size(); ++i) {
        const std::string& frame = frames[i];
        if (frame.find("rtnl_lock") != std::string::npos) {
            return SelectedFrame{frame, static_cast<int>(i)};
        }
        if (frame.find("synchronize_rcu") != std::string::npos ||
            frame.find("synchronize_srcu") != std::string::npos ||
            frame.find("synchronize_net") != std::string::npos ||
            frame.find("synchronize_sched") != std::string::npos) {
            return SelectedFrame{"synchronize_rcu", static_cast<int>(i)};
        }
    }
    static const std::vector<std::string_view> skip = {
        "sched", "_lock", "_slowlock", "down", "rwsem", "completion",
        "kthread", "wait", "synchronize", "context_switch", "__switch_to",
        "cancel_delayed_work", "rcu_barrier",
    };
    for (std::size_t i = 0; i < frames.size(); ++i) {
        if (!ContainsAny(frames[i], skip)) {
            return SelectedFrame{frames[i], static_cast<int>(i)};
        }
    }
    return {};
}

SelectedFrame LinuxStallFrameExtractor(
    const std::vector<std::string>& frames)
{
    if (frames.empty()) {
        return {};
    }
    std::string previous = frames.front();
    int previous_index = 0;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        if (MatchesAny(frames[i], LinuxStallAnchorFrames())) {
            if (frames[i].find("smp_call_function") != std::string::npos) {
                previous = "smp_call_function";
                previous_index = static_cast<int>(i);
            }
            return SelectedFrame{previous, previous_index};
        }
        previous = frames[i];
        previous_index = static_cast<int>(i);
    }
    return {};
}

SelectedFrame SelectFrame(const std::vector<std::string>& frames,
                          const std::string& extractor)
{
    if (frames.empty()) {
        return {};
    }
    if (extractor == "linuxHangTaskFrameExtractor") {
        return LinuxHangTaskFrameExtractor(frames);
    }
    if (extractor == "linuxStallFrameExtractor") {
        return LinuxStallFrameExtractor(frames);
    }
    return SelectedFrame{frames.front(), 0};
}

struct ExtractedFrame {
    std::string canonical;
    std::string raw;
};

bool IsSkippedFrame(const std::string& frame,
                    const std::vector<PatternSpec>& skip)
{
    return MatchesAny(frame, skip);
}

std::string DemangleFrame(const std::string& frame)
{
    char* demangled = RefuzzDemangleSymbol(frame.c_str());
    if (demangled == nullptr) {
        return frame;
    }
    std::string result(demangled);
    std::free(demangled);
    return result;
}

void AppendStackFrames(std::vector<std::string>& frames,
                       const RegexMatch& match,
                       const std::vector<PatternSpec>& skip)
{
    for (const auto& group : match.groups) {
        if (!group.has_value()) {
            continue;
        }
        std::string frame = DemangleFrame(*group);
        if (!IsSkippedFrame(frame, skip)) {
            frames.push_back(std::move(frame));
        }
    }
}

struct StackExtraction {
    std::vector<ExtractedFrame> frames;
    bool ok = true;
};

StackExtraction ExtractStackFrameImpl(
    const StackParamsSpec& params, const StackSpec& stack,
    const std::string& output, const std::vector<StackPartSpec>& parts,
    const std::vector<PatternSpec>& skip)
{
    const std::vector<std::string> lines = SplitLines(output);
    std::size_t line_index = 0;
    std::vector<std::string> raw_frames;
    StackExtraction result;
    std::size_t num_stack_traces = 0;

    for (std::size_t part_index = 0;; ++part_index) {
        if (part_index == parts.size() ||
            (parts[part_index].stack_trace && num_stack_traces > 0)) {
            const std::vector<std::string> stripped =
                StripFrames(raw_frames, params);
            const SelectedFrame selected =
                SelectFrame(stripped, stack.extractor);
            if (selected.canonical.empty() || selected.index < 0 ||
                static_cast<std::size_t>(selected.index) >= raw_frames.size()) {
                result.frames.push_back(ExtractedFrame{"corrupted", "corrupted"});
                result.ok = false;
            } else {
                result.frames.push_back(ExtractedFrame{
                    selected.canonical,
                    raw_frames[static_cast<std::size_t>(selected.index)],
                });
            }
            raw_frames.clear();
        }
        if (part_index == parts.size()) {
            break;
        }

        const StackPartSpec& part = parts[part_index];
        if (part.stack_trace) {
            ++num_stack_traces;
            while (line_index < lines.size()) {
                const std::string& line = lines[line_index++];
                if (MatchesAny(line, params.corrupted_lines)) {
                    result.ok = false;
                    break;
                }
                if (MatchesAny(line, params.stack_starts)) {
                    break;
                }
                if (part_index + 1 < parts.size() &&
                    !parts[part_index + 1].stack_trace) {
                    const auto next =
                        FindMatch(parts[part_index + 1].pattern, line);
                    if (next.has_value()) {
                        AppendStackFrames(raw_frames, *next, skip);
                        ++part_index;
                        break;
                    }
                }
                for (const PatternSpec& frame_pattern : params.frames) {
                    const auto frame = FindMatch(frame_pattern, line);
                    if (frame.has_value()) {
                        AppendStackFrames(raw_frames, *frame, skip);
                        break;
                    }
                }
            }
        } else {
            while (line_index < lines.size()) {
                const std::string& line = lines[line_index++];
                if (MatchesAny(line, params.corrupted_lines)) {
                    result.ok = false;
                    break;
                }
                const auto match = FindMatch(part.pattern, line);
                if (match.has_value()) {
                    AppendStackFrames(raw_frames, *match, skip);
                    break;
                }
            }
        }
    }
    return result;
}

StackExtraction ExtractStackFrame(const StackParamsSpec& params,
                                  const StackSpec& stack,
                                  const std::string& output)
{
    std::vector<PatternSpec> skip;
    skip.reserve(params.skip.size() + stack.skip.size());
    for (const std::string& pattern : params.skip) {
        skip.push_back(MakePattern(pattern, false));
    }
    for (const std::string& pattern : stack.skip) {
        skip.push_back(MakePattern(pattern, false));
    }
    StackExtraction result = ExtractStackFrameImpl(
        params, stack, output, stack.parts, skip);
    if (result.ok || stack.parts2.empty()) {
        return result;
    }
    return ExtractStackFrameImpl(params, stack, output, stack.parts2, skip);
}

std::string FormatTitle(const std::string& format,
                        const std::vector<std::string>& args)
{
    static const std::regex placeholder(
        R"(%\[([0-9]+)\][vs])",
        std::regex_constants::ECMAScript | std::regex_constants::optimize);
    std::string result;
    std::size_t pos = 0;
    for (std::sregex_iterator it(format.begin(), format.end(), placeholder), end;
         it != end; ++it) {
        const std::smatch& match = *it;
        const std::size_t match_pos =
            static_cast<std::size_t>(match.position(0));
        result.append(format, pos, match_pos - pos);
        const std::size_t index =
            static_cast<std::size_t>(std::stoul(match[1].str()));
        if (index > 0 && index <= args.size()) {
            result.append(args[index - 1]);
        }
        pos = match_pos + static_cast<std::size_t>(match.length(0));
    }
    result.append(format, pos, std::string::npos);
    return result;
}

void AppendUnique(std::vector<std::string>& values, std::string value)
{
    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(std::move(value));
    }
}

std::vector<std::vector<std::string>> PartiallyStrippedArgs(
    const std::vector<std::string>& prefix,
    const std::vector<ExtractedFrame>& frames,
    const StackParamsSpec& params)
{
    std::vector<std::vector<std::string>> result;
    for (std::size_t i = 0; i <= params.strip_prefixes.size(); ++i) {
        const std::string prefix_to_strip =
            i == 0 ? std::string() : params.strip_prefixes[i - 1];
        bool add = i == 0;
        std::vector<std::string> args = prefix;
        for (const ExtractedFrame& frame : frames) {
            std::string trimmed = frame.raw;
            if (!prefix_to_strip.empty() &&
                frame.raw.rfind(prefix_to_strip, 0) == 0) {
                trimmed = frame.raw.substr(prefix_to_strip.size());
                add = true;
            }
            args.push_back(std::move(trimmed));
        }
        if (add) {
            result.push_back(std::move(args));
        }
    }
    return result;
}

struct Description {
    std::string title;
    std::string corrupted_reason;
    std::vector<std::string> alt_titles;
    const FormatSpec* format = nullptr;
    std::vector<ExtractedFrame> selected_frames;
};

Description ExtractDescription(const std::string& output,
                               const OopsSpec& oops)
{
    Description result;
    std::size_t start_pos = output.size();
    bool matched_title = false;
    const StackParamsSpec& params = LinuxStackParams();

    for (const FormatSpec& format : oops.formats) {
        auto match = FindMatch(format.title, output);
        if (!match.has_value() || match->position > start_pos) {
            continue;
        }
        if (match->position == start_pos && !result.title.empty()) {
            continue;
        }
        if (match->position < start_pos) {
            result.title.clear();
            result.format = nullptr;
            result.selected_frames.clear();
            start_pos = match->position;
        }
        matched_title = true;
        if (format.report) {
            match = FindMatch(format.report, output);
            if (!match.has_value()) {
                continue;
            }
        }

        std::vector<std::string> prefix;
        prefix.reserve(match->groups.size());
        for (const auto& group : match->groups) {
            prefix.push_back(group.value_or(std::string()));
        }

        StackExtraction extraction;
        result.corrupted_reason.clear();
        if (format.stack) {
            extraction = ExtractStackFrame(
                params, *format.stack, output.substr(match->position));
            if (!extraction.ok) {
                result.corrupted_reason = "extracted no frames";
            }
        }
        std::vector<std::string> args = prefix;
        for (const ExtractedFrame& frame : extraction.frames) {
            args.push_back(frame.canonical);
        }
        result.title = FormatTitle(format.format, args);
        for (const std::string& alt : format.alt) {
            AppendUnique(result.alt_titles, FormatTitle(alt, args));
        }
        for (const auto& partial :
             PartiallyStrippedArgs(prefix, extraction.frames, params)) {
            const std::string alt_title = FormatTitle(format.format, partial);
            if (alt_title != result.title) {
                AppendUnique(result.alt_titles, alt_title);
            }
            for (const std::string& alt : format.alt) {
                AppendUnique(result.alt_titles, FormatTitle(alt, partial));
            }
        }
        result.format = &format;
        result.selected_frames = std::move(extraction.frames);
    }

    if (result.title.empty()) {
        if (matched_title) {
            result.corrupted_reason = "matched title but not report regexp";
        }
        const std::size_t pos = output.find(oops.header);
        if (pos == std::string::npos) {
            return result;
        }
        const std::size_t end = output.find('\n', pos);
        result.title = output.substr(
            pos, (end == std::string::npos ? output.size() : end) - pos);
    }
    if (result.corrupted_reason.empty() && result.format != nullptr &&
        result.format->corrupted) {
        result.corrupted_reason = "report format is marked as corrupted";
    }
    return result;
}

std::pair<bool, std::string> IsCorrupted(const std::string& title,
                                         const std::string& report,
                                         const FormatSpec* format)
{
    static const std::regex corrupted_title(
        R"(\[ *[0-9]+\.[0-9]+\])",
        std::regex_constants::ECMAScript | std::regex_constants::optimize);
    if (std::regex_search(title, corrupted_title)) {
        return {true, "title matches corrupted regexp"};
    }
    if (format == nullptr || !format->title) {
        return {false, {}};
    }
    if (format->no_stack_trace) {
        return {false, {}};
    }

    const StackParamsSpec& params = LinuxStackParams();
    bool has_stack_trace = false;
    for (std::size_t pattern_index = 0;
         pattern_index < params.stack_starts.size(); ++pattern_index) {
        const auto match = FindMatch(params.stack_starts[pattern_index], report);
        if (!match.has_value()) {
            continue;
        }
        std::vector<std::string> frames =
            SplitLines(report.substr(match->position));
        if (frames.size() < 4) {
            return {true, "call trace is missed"};
        }
        bool corrupted = true;
        for (std::size_t i = 1; i < frames.size() && i <= 15; ++i) {
            if (MatchesAny(frames[i], params.stack_starts)) {
                break;
            }
            if (frames[i].find("(stack is not available)") !=
                    std::string::npos ||
                MatchesAny(frames[i], params.frames)) {
                has_stack_trace = true;
                corrupted = false;
                break;
            }
        }
        const bool riscv_special =
            pattern_index + 1 == params.stack_starts.size();
        if (!riscv_special && corrupted) {
            return {true, "no frames in a stack trace"};
        }
    }
    if (!has_stack_trace) {
        return {true, "no stack trace in report"};
    }
    return {false, {}};
}

std::string ReplaceRepeated(const std::string& input,
                            const std::regex& expression,
                            const std::string& replacement)
{
    std::string value = input;
    for (;;) {
        std::string replaced =
            std::regex_replace(value, expression, replacement);
        if (replaced == value) {
            return value;
        }
        value = std::move(replaced);
    }
}

std::string SanitizeTitle(const std::string& title)
{
    constexpr std::size_t kMaxTitleLength = 120;
    std::string result;
    result.reserve(std::min(title.size(), kMaxTitleLength));
    char previous = ' ';
    for (std::size_t i = 0; i < title.size() && i < kMaxTitleLength; ++i) {
        unsigned char byte = static_cast<unsigned char>(title[i]);
        char ch = static_cast<char>(byte);
        if (ch == '\t') {
            ch = ' ';
        } else if (byte < 0x20 || byte >= 0x7f) {
            continue;
        }
        if (ch == ' ' && previous == ' ') {
            continue;
        }
        result.push_back(ch);
        previous = ch;
    }
    const std::size_t first = result.find_first_not_of(' ');
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = result.find_last_not_of(' ');
    return result.substr(first, last - first + 1);
}

std::string NormalizeDynamicTitle(std::string title)
{
    static const std::vector<std::pair<std::regex, std::string>> replacements = {
        {std::regex(R"(syz-executor\.?[0-9]+((/|:)[0-9]+)?)"), "syz-executor"},
        {std::regex(R"(syzkaller[0-9]+((/|:)[0-9]+)?)"), "syzkaller"},
        {std::regex(R"(([^a-zA-Z0-9])(?:0x)?[0-9a-f]{6,})"), "$1ADDR"},
        {std::regex(R"(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))"), "IP"},
        {std::regex(R"((\.\w+)(:[0-9]+)+)"), "$1:LINE"},
        {std::regex(R"(([a-zA-Z][a-zA-Z0-9_.]+)\+0x[0-9a-z]+/0x[0-9a-z]+)"), "$1"},
        {std::regex(R"(CPU#[0-9]+)"), "CPU"},
        {std::regex(R"((\W)(\d+)(\W|$))"), "$1NUM$3"},
        {std::regex(R"((\d+){7,})"), "NUM"},
    };
    for (const auto& [expression, replacement] : replacements) {
        title = ReplaceRepeated(title, expression, replacement);
    }
    return SanitizeTitle(title);
}

bool HasPrefix(const std::string& value, std::string_view prefix)
{
    return value.size() >= prefix.size() &&
           value.compare(0, prefix.size(), prefix) == 0;
}

std::string ReportTypeFromTitle(const std::string& title)
{
    for (const TitleTypeRule& rule : LinuxTitleTypeRules()) {
        for (const std::string& prefix : rule.prefixes) {
            if (HasPrefix(title, prefix)) {
                return rule.report_type;
            }
        }
    }
    return "UNKNOWN";
}

std::string FrameFromTitle(const std::string& title)
{
    static const std::regex expression(
        R"(.* in ((?:<[a-zA-Z0-9_: ]+>)?[a-zA-Z0-9_:]+))",
        std::regex_constants::ECMAScript | std::regex_constants::optimize);
    std::smatch match;
    if (!std::regex_search(title, match, expression)) {
        return {};
    }
    return match[1].str();
}

std::string RawOopsTitle(const std::string& output,
                         const FirstOops& first)
{
    const std::size_t end = output.find('\n', first.start_pos);
    const std::string line = output.substr(
        first.start_pos,
        (end == std::string::npos ? output.size() : end) - first.start_pos);
    return StripLinePrefix(line, ExtractContext(line), false).text;
}

} // namespace

bool ConsoleContainsRealCrash(const std::string& console_output)
{
    if (console_output.empty()) {
        return false;
    }
    for (const LineRange& range : LineRanges(console_output)) {
        const std::string line = console_output.substr(
            range.start, range.end - range.start);
        for (const OopsSpec& oops : LinuxOopses()) {
            if (MatchOops(line, oops)) {
                return true;
            }
        }
    }
    return false;
}

std::optional<ParsedCrashReport> KernelReportParser::Parse(
    const std::string& console_output) const
{
    if (console_output.empty()) {
        return std::nullopt;
    }
    const auto first = FindFirstOops(console_output);
    if (!first.has_value()) {
        return std::nullopt;
    }

    FoundReport found = FindReport(console_output, first->start_pos,
                                   first->context, false);
    std::string analysis_report = found.report;
    const std::size_t description_end =
        std::min(found.report_end, analysis_report.size());
    Description description = ExtractDescription(
        analysis_report.substr(0, description_end), *first->oops);
    if (description.title.empty()) {
        const std::size_t fallback_end =
            std::max(found.end_pos, first->start_pos);
        found.prefix.clear();
        analysis_report = console_output.substr(
            first->start_pos, fallback_end - first->start_pos);
        description = ExtractDescription(
            analysis_report, *first->oops);
    }

    ParsedCrashReport report;
    report.raw_title = RawOopsTitle(console_output, *first);
    report.corrupted_reason = description.corrupted_reason;
    report.corrupted = !report.corrupted_reason.empty();
    if (!report.corrupted) {
        const auto [corrupted, reason] =
            IsCorrupted(description.title, analysis_report,
                        description.format);
        report.corrupted = corrupted;
        report.corrupted_reason = reason;
    }
    report.title = NormalizeDynamicTitle(description.title);
    for (const std::string& alt : description.alt_titles) {
        report.alt_titles.push_back(NormalizeDynamicTitle(alt));
    }
    if (console_output.find("serialport: VM disconnected.") !=
        std::string::npos) {
        report.corrupted = true;
    }
    report.report_type = ReportTypeFromTitle(report.title);
    report.type = DetectCrashType(report.title);
    report.guilty_function = FrameFromTitle(report.title);

    std::string diagnostic_report;
    for (const std::string& line : found.prefix) {
        diagnostic_report.append(line);
        diagnostic_report.push_back('\n');
    }
    diagnostic_report.append(analysis_report);
    for (const std::string& line : SplitLines(diagnostic_report)) {
        auto frame = ParseBacktraceLine(line);
        if (frame.has_value()) {
            report.frames.push_back(std::move(*frame));
        }
    }
    return report;
}

std::string KernelReportParser::NormalizeTitle(const std::string& raw_title)
{
    return NormalizeDynamicTitle(raw_title);
}

std::optional<StackFrame> KernelReportParser::ParseBacktraceLine(
    const std::string& line)
{
    static const std::regex expression(
        R"((?:\[<((?:0x)?[0-9a-fA-F]+)>\])?[ \t]+\(?(?:[0-9]+:)?([a-zA-Z0-9_.]+)\+0x([0-9a-fA-F]+)/0x([0-9a-fA-F]+)(?: ?\[([a-zA-Z0-9_.]+)(?: .*)?\])?\)?)",
        std::regex_constants::ECMAScript | std::regex_constants::optimize);
    std::smatch match;
    if (!std::regex_search(line, match, expression)) {
        return std::nullopt;
    }
    StackFrame frame;
    frame.function = match[2].str();
    try {
        frame.offset = std::stoull(match[3].str(), nullptr, 16);
        frame.size = std::stoull(match[4].str(), nullptr, 16);
        if (match[1].matched) {
            std::string address = match[1].str();
            if (address.rfind("0x", 0) == 0) {
                address.erase(0, 2);
            }
            frame.pc = std::stoull(address, nullptr, 16);
        }
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (match[5].matched) {
        frame.module = match[5].str();
    }
    return frame;
}

refuzz::channel::CrashType KernelReportParser::DetectCrashType(
    const std::string& title)
{
    if (title.find("KASAN") != std::string::npos ||
        title.find("KFENCE") != std::string::npos ||
        title.find("KMSAN") != std::string::npos) {
        return refuzz::channel::CrashType::kKasan;
    }
    if (title.find("UBSAN") != std::string::npos) {
        return refuzz::channel::CrashType::kUbsan;
    }
    if (title.find("kernel panic") != std::string::npos ||
        HasPrefix(title, "panic:")) {
        return refuzz::channel::CrashType::kPanic;
    }
    if (title.find("BUG:") != std::string::npos ||
        title.find("kernel BUG") != std::string::npos) {
        return refuzz::channel::CrashType::kBug;
    }
    if (title.find("Oops:") != std::string::npos) {
        return refuzz::channel::CrashType::kOops;
    }
    return refuzz::channel::CrashType::kUnknown;
}

} // namespace refuzz::crash
