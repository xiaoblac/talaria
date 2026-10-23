#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace {

struct ExpectedReport {
    bool present = false;
    std::string title;
    std::vector<std::string> alt_titles;
    std::string type = "UNKNOWN";
    std::string frame;
    bool frame_specified = false;
    bool corrupted = false;
    std::string output;
};

std::string ReadFile(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

ExpectedReport ParseExpected(const std::string& file)
{
    ExpectedReport expected;
    if (file.empty() || file.front() == '\n') {
        expected.output = !file.empty() && file.front() == '\n'
            ? file.substr(1)
            : file;
        return expected;
    }
    const std::size_t separator = file.find("\n\n");
    const std::string metadata = file.substr(0, separator);
    expected.output = separator == std::string::npos
        ? std::string()
        : file.substr(separator + 2);

    std::size_t pos = 0;
    while (pos <= metadata.size()) {
        const std::size_t newline = metadata.find('\n', pos);
        const std::string line = metadata.substr(
            pos, (newline == std::string::npos ? metadata.size() : newline) - pos);
        const std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            const std::string key = line.substr(0, colon);
            const std::string value = colon + 1 < line.size() && line[colon + 1] == ' '
                ? line.substr(colon + 2)
                : line.substr(colon + 1);
            if (key == "TITLE") {
                expected.title = value;
            } else if (key == "ALT") {
                expected.alt_titles.push_back(value);
            } else if (key == "TYPE") {
                expected.type = value;
            } else if (key == "FRAME") {
                expected.frame = value;
                expected.frame_specified = true;
            } else if (key == "CORRUPTED") {
                expected.corrupted = value == "Y";
            }
        }
        if (newline == std::string::npos) {
            break;
        }
        pos = newline + 1;
    }
    expected.present = !expected.title.empty();
    return expected;
}

std::string Join(const std::vector<std::string>& values)
{
    std::string result;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) {
            result.append(" | ");
        }
        result.append(values[i]);
    }
    return result;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "usage: linux_report_parser_corpus_test CORPUS_DIR\n";
        return 2;
    }
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(argv[1])) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end(), [](const auto& lhs, const auto& rhs) {
        return std::stoul(lhs.filename().string()) <
               std::stoul(rhs.filename().string());
    });

    refuzz::crash::KernelReportParser parser;
    std::map<std::string, std::size_t> mismatches;
    for (const auto& path : files) {
        const ExpectedReport expected = ParseExpected(ReadFile(path));
        const bool contains =
            refuzz::crash::ConsoleContainsRealCrash(expected.output);
        const auto actual = parser.Parse(expected.output);

        auto mismatch = [&](const std::string& field,
                            const std::string& want,
                            const std::string& got) {
            const std::size_t count = ++mismatches[field];
            if (count <= 20) {
                std::cerr << path.filename().string() << " " << field
                          << "\n  want: " << want << "\n  got:  " << got << "\n";
            }
        };

        if (contains != expected.present) {
            mismatch("ContainsCrash", expected.present ? "true" : "false",
                     contains ? "true" : "false");
        }
        if (actual.has_value() != expected.present) {
            mismatch("ParsePresence", expected.present ? "present" : "absent",
                     actual.has_value() ? "present" : "absent");
            continue;
        }
        if (!actual.has_value()) {
            continue;
        }
        if (actual->title != expected.title) {
            mismatch("Title", expected.title, actual->title);
        }
        std::vector<std::string> actual_alt_titles = actual->alt_titles;
        std::vector<std::string> expected_alt_titles = expected.alt_titles;
        std::sort(actual_alt_titles.begin(), actual_alt_titles.end());
        std::sort(expected_alt_titles.begin(), expected_alt_titles.end());
        if (actual_alt_titles != expected_alt_titles) {
            mismatch("AltTitles", Join(expected_alt_titles),
                     Join(actual_alt_titles));
        }
        if (actual->report_type != expected.type) {
            mismatch("Type", expected.type, actual->report_type);
        }
        if (expected.frame_specified &&
            actual->guilty_function != expected.frame) {
            mismatch("Frame", expected.frame, actual->guilty_function);
        }
        if (actual->corrupted != expected.corrupted) {
            mismatch("Corrupted", expected.corrupted ? "true" : "false",
                     actual->corrupted ? "true" : "false");
        }
    }

    std::cout << "linux report corpus: " << files.size() << " files\n";
    for (const auto& [field, count] : mismatches) {
        std::cout << "  " << field << ": " << count << "\n";
    }
    return mismatches.empty() ? 0 : 1;
}
