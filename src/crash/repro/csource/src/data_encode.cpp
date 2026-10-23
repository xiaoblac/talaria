// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.

#include "refuzz/crash/repro/csource/internal/data_encode.hpp"

namespace refuzz::crash::repro::csource::internal {

namespace {

bool is_printable(std::uint8_t v) {
    // Mirror of prog/encoding.go::isPrintable: ASCII printable or
    // common whitespace (\t \n \r etc.). Match the criteria upstream
    // uses inside encodeData's switch.
    return v >= 0x20 && v < 0x7f;
}

bool is_readable_data(std::span<const std::uint8_t> data) {
    if (data.empty()) return false;
    int printable = 0;
    for (auto v : data) {
        if (is_printable(v) || v == '\t' || v == '\n' || v == '\r') {
            ++printable;
        }
    }
    // Upstream isReadableData: > 80% printable.
    return printable * 5 > static_cast<int>(data.size()) * 4;
}

constexpr char kHex[] = "0123456789abcdef";

void emit_hex(std::string& out, std::uint8_t v) {
    out.push_back('\\');
    out.push_back('x');
    out.push_back(kHex[(v >> 4) & 0xf]);
    out.push_back(kHex[v & 0xf]);
}

void emit_octal(std::string& out, std::uint8_t v) {
    out.push_back('\\');
    out.push_back(static_cast<char>('0' + ((v >> 6) & 0x7)));
    out.push_back(static_cast<char>('0' + ((v >> 3) & 0x7)));
    out.push_back(static_cast<char>('0' + (v & 0x7)));
}

} // namespace

std::string to_c_string(std::span<const std::uint8_t> data, bool readable) {
    if (!readable && is_readable_data(data)) {
        readable = true;
    }
    std::string out;
    out.reserve(data.size() * 4);
    for (auto v : data) {
        if (!readable) {
            emit_hex(out, v);
            continue;
        }
        switch (v) {
            case '\a': out += "\\a";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\v': out += "\\v";  break;
            case '\'': out += "\\'";  break;
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            default:
                if (is_printable(v)) {
                    out.push_back(static_cast<char>(v));
                } else {
                    // cstr=true semantics: octal escape (matches upstream
                    // toCString → encodeData(cstr=true) path).
                    emit_octal(out, v);
                }
                break;
        }
    }
    return out;
}

} // namespace refuzz::crash::repro::csource::internal
