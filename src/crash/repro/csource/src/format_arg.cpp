// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/csource.go::generateComment +
// prog/prog.go::FormatArg + prog/types.go various String() methods.

#include "refuzz/crash/repro/csource/internal/format_arg.hpp"

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <format>
#include <string>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

namespace syz = ::refuzz::program::syz;

namespace {

constexpr std::string_view kIndent = "  ";  // two spaces

std::string repeat_indent(int depth) {
    std::string out;
    out.reserve(depth * kIndent.size());
    for (int i = 0; i < depth; ++i) out.append(kIndent);
    return out;
}

std::string_view dir_string(syz::Dir d) {
    switch (d) {
        case syz::Dir::kIn:    return "in";
        case syz::Dir::kOut:   return "out";
        case syz::Dir::kInOut: return "inout";
    }
    return "in";
}

std::string lines_to_c_style_comment(const std::vector<std::string>& lines) {
    // Mirror upstream linesToCStyleComment (csource.go:247-256): each
    // line becomes "//<indent><line>" and joined with "\n".
    std::string out;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (i != 0) out.push_back('\n');
        out += "//  ";
        out += lines[i];
    }
    return out;
}

void format_data_buffer_inline(std::string& out,
                               const syz::DataArg& da) {
    // Upstream: "{% x} (length 0x<n>)" where %x is space-separated hex
    // bytes (Go format verb %x with " " separator).
    const auto& bytes = da.data();
    out += "{";
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) out.push_back(' ');
        out += std::format("{:x}", bytes[i]);
    }
    out += std::format("}} (length 0x{:x})", bytes.size());
}

} // namespace

std::string type_string(const syz::Type& t) {
    switch (t.kind()) {
        case syz::TypeKind::kPtr: {
            const auto& pt = static_cast<const syz::PtrType&>(t);
            const auto* elem = pt.elem();
            const std::string elem_str =
                elem != nullptr ? type_string(*elem) : "void";
            return std::format("ptr[{}, {}]", dir_string(pt.elem_dir()),
                               elem_str);
        }
        case syz::TypeKind::kArray: {
            const auto& at = static_cast<const syz::ArrayType&>(t);
            const auto* elem = at.elem();
            const std::string elem_str =
                elem != nullptr ? type_string(*elem) : "void";
            return std::format("array[{}]", elem_str);
        }
        case syz::TypeKind::kConst: {
            const auto& ct = static_cast<const syz::ConstType&>(t);
            if (ct.is_pad()) {
                return std::format("pad[{}]", t.size());
            }
            return std::format("const[{}, {}]", ct.val(), ct.name());
        }
        case syz::TypeKind::kCsum: return "csum";
        case syz::TypeKind::kVma:  return "vma";
        case syz::TypeKind::kBuffer: return "buffer";
        // All others: just the name.
        case syz::TypeKind::kInt:
        case syz::TypeKind::kFlags:
        case syz::TypeKind::kLen:
        case syz::TypeKind::kProc:
        case syz::TypeKind::kStruct:
        case syz::TypeKind::kUnion:
        case syz::TypeKind::kResource:
            return t.name();
    }
    return t.name();
}

std::vector<std::string> format_arg(const syz::Arg& arg, const std::string& name) {
    std::vector<std::string> out;
    auto visit = [&](auto& self, const syz::Arg& a, const std::string& nm,
                     int depth) -> void {
        std::string line = repeat_indent(depth);
        if (!nm.empty()) {
            line += std::format("{}: ", nm);
        }
        const syz::Type* t = a.type();
        const std::string ts = (t != nullptr) ? type_string(*t) : "<null>";
        switch (a.arg_kind()) {
            case syz::ArgKind::kGroup: {
                const auto& g = static_cast<const syz::GroupArg&>(a);
                line += std::format("{} {{", ts);
                out.push_back(line);
                const auto* st = (t != nullptr && t->kind() == syz::TypeKind::kStruct)
                                  ? static_cast<const syz::StructType*>(t)
                                  : nullptr;
                for (std::size_t i = 0; i < g.inner().size(); ++i) {
                    std::string child_name;
                    if (st != nullptr && i < st->fields().size()) {
                        child_name = st->fields()[i].name();
                    }
                    if (g.inner()[i] != nullptr) {
                        self(self, *g.inner()[i], child_name, depth + 1);
                    }
                }
                out.push_back(repeat_indent(depth) + "}");
                break;
            }
            case syz::ArgKind::kConst: {
                const auto& c = static_cast<const syz::ConstArg&>(a);
                const std::string nm_or = (t != nullptr ? t->name() : std::string("<null>"));
                line += std::format("{} = 0x{:x} ({} bytes)", nm_or,
                                    c.val(), c.size());
                out.push_back(line);
                break;
            }
            case syz::ArgKind::kData: {
                const auto& d = static_cast<const syz::DataArg&>(a);
                line += std::format("{}: ", ts);
                if (a.dir() == syz::Dir::kOut) {
                    line += "(DirOut)";
                } else if (t != nullptr && t->kind() == syz::TypeKind::kBuffer &&
                           static_cast<const syz::BufferType*>(t)->is_compressed()) {
                    line += std::format("(compressed buffer with length 0x{:x})",
                                        d.data().size());
                } else {
                    format_data_buffer_inline(line, d);
                }
                out.push_back(line);
                break;
            }
            case syz::ArgKind::kPointer: {
                const auto& p = static_cast<const syz::PointerArg&>(a);
                if (p.res() != nullptr) {
                    line += std::format("{} {{", ts);
                    out.push_back(line);
                    self(self, *p.res(), "", depth + 1);
                    out.push_back(repeat_indent(depth) + "}");
                } else {
                    if (p.vma_size() == 0) {
                        line += "nil";
                    } else {
                        line += std::format("VMA[0x{:x}]", p.vma_size());
                    }
                    out.push_back(line);
                }
                break;
            }
            case syz::ArgKind::kUnion: {
                const auto& u = static_cast<const syz::UnionArg&>(a);
                const std::string nm_or = (t != nullptr ? t->name() : std::string("<null>"));
                line += std::format("union {} {{", nm_or);
                out.push_back(line);
                if (u.option() != nullptr && t != nullptr &&
                    t->kind() == syz::TypeKind::kUnion) {
                    const auto& ut = static_cast<const syz::UnionType&>(*t);
                    std::string opt_name;
                    if (u.index() >= 0 &&
                        static_cast<std::size_t>(u.index()) < ut.fields().size()) {
                        opt_name = ut.fields()[u.index()].name();
                    }
                    self(self, *u.option(), opt_name, depth + 1);
                }
                out.push_back(repeat_indent(depth) + "}");
                break;
            }
            case syz::ArgKind::kResult: {
                line += std::format("{} (resource)", ts);
                out.push_back(line);
                break;
            }
        }
    };
    visit(visit, arg, name, 0);
    return out;
}

std::string make_typed_call_comment(const syz::Call& call) {
    if (call.meta() == nullptr) return {};
    const auto* meta = call.meta();
    std::vector<std::string> lines;
    lines.push_back(std::format("{} arguments: [", meta->name()));
    for (std::size_t i = 0; i < call.args().size(); ++i) {
        const auto& arg = call.args()[i];
        if (arg == nullptr) continue;
        std::string field_name;
        if (i < meta->args().size()) {
            field_name = meta->args()[i].name();
        }
        auto sub = format_arg(*arg, field_name);
        for (auto& s : sub) {
            lines.push_back(kIndent.data() + std::move(s));
        }
    }
    lines.push_back("]");
    if (meta->ret() != nullptr) {
        lines.push_back(std::string("returns ") + meta->ret()->name());
    }
    return lines_to_c_style_comment(lines);
}

std::vector<std::string> make_typed_call_comments(const syz::Prog& prog) {
    std::vector<std::string> out;
    out.reserve(prog.calls().size());
    for (const auto& c : prog.calls()) {
        if (c == nullptr) {
            out.push_back("");
            continue;
        }
        out.push_back(make_typed_call_comment(*c));
    }
    return out;
}

} // namespace refuzz::crash::repro::csource::internal
