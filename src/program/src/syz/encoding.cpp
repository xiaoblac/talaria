// Implementation of refuzz/program/syz/encoding.hpp.
//
// Closely mirrors syzkaller prog/encoding.go. Comments cite the upstream
// function name when behavior is non-obvious.

#include "refuzz/program/syz/encoding.hpp"

#include "refuzz/program/internal/codec_counters.hpp"
#include "refuzz/program/syz/alloc.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/sanitize.hpp"
#include "refuzz/program/syz/size.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace refuzz::program::syz {

namespace {

// Mirror of prog.encodingAddrBase.
constexpr uint64_t kEncodingAddrBase = 0x7f0000000000ULL;

bool is_printable(uint8_t v) {
    return v >= 0x20 && v < 0x7f;
}

bool is_ident_char(char c) {
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '_' || c == '$';
}

bool is_readable_data(const std::vector<uint8_t>& data) {
    if (data.empty()) return false;
    for (uint8_t v : data) {
        if (is_printable(v)) continue;
        switch (v) {
            case 0: case '\a': case '\b': case '\f':
            case '\n': case '\r': case '\t': case '\v':
                continue;
        }
        return false;
    }
    return true;
}

bool is_readable_buffer_kind(BufferKind k) {
    return k == BufferKind::kString ||
           k == BufferKind::kFilename ||
           k == BufferKind::kGlob;
}

bool is_any_ptr(const Target& target, const Type* t) {
    (void)target;
    const auto* pt = as_ptr(t);
    if (pt == nullptr) return false;
    const auto* at = as_array(pt->elem());
    if (at == nullptr) return false;
    const auto* ut = as_union(at->elem());
    return ut != nullptr && ut->name() == "ANYUNION";
}

const PtrType* get_any_ptr_type(const Target& target, uint64_t size) {
    for (const auto& up : target.arena().types()) {
        const auto* ut = as_union(up.get());
        if (ut == nullptr || ut->name() != "ANYPTRS") continue;
        const auto& fields = ut->fields();
        if (size == target.ptr_size() && !fields.empty()) {
            return as_ptr(fields[0].type());
        }
        if (size == 8 && fields.size() > 1) {
            return as_ptr(fields[1].type());
        }
        return nullptr;
    }
    return nullptr;
}

uint8_t to_hex_char(uint8_t v) {
    if (v < 10) return static_cast<uint8_t>('0' + v);
    return static_cast<uint8_t>('a' + v - 10);
}

bool from_hex_char(uint8_t v, uint8_t* out) {
    if (v >= '0' && v <= '9') { *out = static_cast<uint8_t>(v - '0'); return true; }
    if (v >= 'a' && v <= 'f') { *out = static_cast<uint8_t>(v - 'a' + 10); return true; }
    if (v >= 'A' && v <= 'F') { *out = static_cast<uint8_t>(v - 'A' + 10); return true; }
    return false;
}

bool hex_to_byte(uint8_t lo, uint8_t hi, uint8_t* out) {
    uint8_t h, l;
    if (!from_hex_char(hi, &h)) return false;
    if (!from_hex_char(lo, &l)) return false;
    *out = static_cast<uint8_t>((h << 4) | l);
    return true;
}

int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool base64_decode(std::string_view in, std::vector<uint8_t>* out) {
    out->clear();
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=') break;
        int v = base64_value(c);
        if (v < 0) return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out->push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
        }
    }
    return true;
}

std::string base64_encode(const std::vector<uint8_t>& in) {
    static constexpr char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= in.size()) {
        uint32_t v = (static_cast<uint32_t>(in[i]) << 16) |
                     (static_cast<uint32_t>(in[i + 1]) << 8) |
                     static_cast<uint32_t>(in[i + 2]);
        out.push_back(kTable[(v >> 18) & 0x3f]);
        out.push_back(kTable[(v >> 12) & 0x3f]);
        out.push_back(kTable[(v >> 6) & 0x3f]);
        out.push_back(kTable[v & 0x3f]);
        i += 3;
    }
    if (i < in.size()) {
        uint32_t v = static_cast<uint32_t>(in[i]) << 16;
        bool two = i + 1 < in.size();
        if (two) v |= static_cast<uint32_t>(in[i + 1]) << 8;
        out.push_back(kTable[(v >> 18) & 0x3f]);
        out.push_back(kTable[(v >> 12) & 0x3f]);
        out.push_back(two ? kTable[(v >> 6) & 0x3f] : '=');
        out.push_back('=');
    }
    return out;
}

// `encodeData` from upstream: emit data bytes into `out`.
// `cstr` toggles octal escapes for non-printable bytes (keeps the
// resulting string valid C); the .syz format uses `cstr=false`, i.e.
// hex escapes.
void encode_data(std::string& out, const std::vector<uint8_t>& data,
                 bool readable, bool cstr) {
    for (uint8_t v : data) {
        if (!readable) {
            const uint8_t lo = v & 0xf;
            const uint8_t hi = (v >> 4) & 0xf;
            out.push_back('\\');
            out.push_back('x');
            out.push_back(static_cast<char>(to_hex_char(hi)));
            out.push_back(static_cast<char>(to_hex_char(lo)));
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
                } else if (cstr) {
                    out.push_back('\\');
                    out.push_back(static_cast<char>('0' + ((v >> 6) & 0x7)));
                    out.push_back(static_cast<char>('0' + ((v >> 3) & 0x7)));
                    out.push_back(static_cast<char>('0' + (v & 0x7)));
                } else {
                    const uint8_t lo = v & 0xf;
                    const uint8_t hi = (v >> 4) & 0xf;
                    out.push_back('\\');
                    out.push_back('x');
                    out.push_back(static_cast<char>(to_hex_char(hi)));
                    out.push_back(static_cast<char>(to_hex_char(lo)));
                }
                break;
        }
    }
}

// `serializeData` from upstream.
void serialize_data(std::string& out, const std::vector<uint8_t>& data, bool readable) {
    if (!readable && !is_readable_data(data)) {
        out.push_back('"');
        for (uint8_t v : data) {
            const uint8_t lo = v & 0xf;
            const uint8_t hi = (v >> 4) & 0xf;
            out.push_back(static_cast<char>(to_hex_char(hi)));
            out.push_back(static_cast<char>(to_hex_char(lo)));
        }
        out.push_back('"');
        return;
    }
    out.push_back('\'');
    encode_data(out, data, /*readable=*/true, /*cstr=*/false);
    out.push_back('\'');
}

// ============================================================
// Lexer — line-oriented scanner over a multi-line .syz string.
// Closely mirrors prog.parser's Scan/Char/Parse/Ident/SkipWs.
// ============================================================

class Lexer {
public:
    explicit Lexer(std::string_view text) : data_(text) {}

    bool        scan();                     // load next line into s_
    bool        eof() const { return i_ >= s_.size(); }
    char        ch() const  { return eof() ? '\0' : s_[i_]; }
    int         line() const { return l_; }
    int         column() const { return i_; }
    const std::string& current_line() const { return s_; }

    // Consume current char and verify it equals `c`.
    bool parse(char c);
    // Consume current char without verification.
    char consume();
    // Skip ASCII space + tab.
    void skip_ws();
    // Parse [a-zA-Z0-9_$]+. Empty result => failure recorded.
    std::string ident();
    // Lookahead: does the current position start with `prefix`?
    bool has_next(std::string_view prefix) const;

    // Error reporting.
    void failf(std::string msg);
    bool failed() const { return !err_.empty(); }
    const std::string& error_msg() const { return err_; }
    int  error_line() const { return err_line_; }
    int  error_col() const  { return err_col_; }

private:
    std::string_view data_;       // remaining unscanned bytes
    std::string      s_;          // current line
    std::size_t      i_ = 0;
    int              l_ = 0;

    std::string err_;
    int         err_line_ = 0;
    int         err_col_  = 0;
};

bool Lexer::scan() {
    if (!err_.empty() || data_.empty()) return false;
    auto nl = data_.find('\n');
    if (nl == std::string_view::npos) {
        s_.assign(data_.begin(), data_.end());
        data_ = {};
    } else {
        s_.assign(data_.begin(), data_.begin() + nl);
        data_.remove_prefix(nl + 1);
    }
    i_ = 0;
    l_++;
    return true;
}

bool Lexer::parse(char c) {
    if (!err_.empty()) return false;
    if (eof()) {
        failf(std::string("want '") + c + "', got EOF");
        return false;
    }
    if (s_[i_] != c) {
        std::string m = "want '";
        m.push_back(c);
        m += "', got '";
        m.push_back(s_[i_]);
        m += "'";
        failf(std::move(m));
        return false;
    }
    i_++;
    skip_ws();
    return true;
}

char Lexer::consume() {
    if (!err_.empty() || eof()) {
        if (err_.empty()) failf("unexpected eof");
        return 0;
    }
    return s_[i_++];
}

void Lexer::skip_ws() {
    while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t')) i_++;
}

std::string Lexer::ident() {
    const std::size_t start = i_;
    while (i_ < s_.size() && is_ident_char(s_[i_])) i_++;
    if (i_ == start) {
        failf("failed to parse identifier");
        return {};
    }
    std::string out(s_.begin() + start, s_.begin() + i_);
    skip_ws();
    return out;
}

bool Lexer::has_next(std::string_view prefix) const {
    if (s_.size() < i_ + prefix.size()) return false;
    return std::memcmp(s_.data() + i_, prefix.data(), prefix.size()) == 0;
}

void Lexer::failf(std::string msg) {
    if (!err_.empty()) return;
    err_      = std::move(msg);
    err_line_ = l_;
    err_col_  = static_cast<int>(i_);
}

// ============================================================
// TextDecoder::Impl
// ============================================================

class DecodeException {
public:
    explicit DecodeException(std::string msg) : msg_(std::move(msg)) {}
    const std::string& msg() const { return msg_; }
private:
    std::string msg_;
};

bool default_dir_pad_only(const Type* t) {
    auto* ct = as_const(t);
    return ct != nullptr && ct->is_pad();
}

// Build a default arg (mirror of prog.Type.DefaultArg). Used when a
// field is missing or to fill out-args.
std::unique_ptr<Arg> make_default_arg(const Type* t, Dir dir);

// Helper to deep-copy default args lazily; a minimal implementation
// suffices for the structures we need to fall back to.
std::unique_ptr<Arg> make_zero_const_arg(const Type* t, Dir dir) {
    auto a = std::make_unique<ConstArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_val(0);
    return a;
}

std::unique_ptr<Arg> make_default_arg(const Type* t, Dir dir) {
    if (t == nullptr) return nullptr;
    switch (t->kind()) {
        case TypeKind::kInt:
        case TypeKind::kFlags:
        case TypeKind::kLen:
        case TypeKind::kCsum:
            return make_zero_const_arg(t, dir);
        case TypeKind::kConst: {
            auto a = std::make_unique<ConstArg>();
            a->set_type(t);
            a->set_dir(dir);
            a->set_val(static_cast<const ConstType*>(t)->val());
            return a;
        }
        case TypeKind::kProc: {
            // Mirror procDefaultValue (0xffffffffffffffff).
            auto a = std::make_unique<ConstArg>();
            a->set_type(t);
            a->set_dir(dir);
            a->set_val(~uint64_t{0});
            return a;
        }
        case TypeKind::kResource: {
            auto a = std::make_unique<ResultArg>();
            a->set_type(t);
            a->set_dir(dir);
            const auto* rt = static_cast<const ResourceType*>(t);
            uint64_t v = 0;
            if (rt->desc() != nullptr && !rt->desc()->values().empty()) {
                v = rt->desc()->values()[0];
            }
            a->set_val(v);
            return a;
        }
        case TypeKind::kVma: {
            auto a = std::make_unique<PointerArg>();
            a->set_type(t);
            a->set_dir(dir);
            a->set_address(0);
            return a;
        }
        case TypeKind::kPtr: {
            const auto* pt = static_cast<const PtrType*>(t);
            auto a = std::make_unique<PointerArg>();
            a->set_type(t);
            a->set_dir(Dir::kIn);                              // pointers are always 'in'
            a->set_address(0);
            if (t->optional()) {
                // Special-pointer style nil; encoded as address 0 with no res.
                return a;
            }
            a->set_res(make_default_arg(pt->elem(), pt->elem_dir()));
            return a;
        }
        case TypeKind::kBuffer: {
            auto a = std::make_unique<DataArg>();
            a->set_type(t);
            a->set_dir(dir);
            const auto* bt = static_cast<const BufferType*>(t);
            if (dir == Dir::kOut) {
                uint64_t sz = t->var_len() ? 0 : t->size();
                a->set_out_size(sz);
            } else if (bt->values().size() == 1) {
                std::vector<uint8_t> d(bt->values().front().begin(),
                                       bt->values().front().end());
                a->set_data(std::move(d));
            } else if (!t->var_len()) {
                a->set_data(std::vector<uint8_t>(t->size(), 0));
            }
            return a;
        }
        case TypeKind::kArray: {
            auto a = std::make_unique<GroupArg>();
            a->set_type(t);
            a->set_dir(dir);
            const auto* at = static_cast<const ArrayType*>(t);
            if (at->array_kind() == ArrayKind::kRangeLen &&
                at->range_begin() == at->range_end()) {
                for (uint64_t i = 0; i < at->range_begin(); ++i) {
                    a->add_inner(make_default_arg(at->elem(), dir));
                }
            }
            return a;
        }
        case TypeKind::kStruct: {
            auto a = std::make_unique<GroupArg>();
            a->set_type(t);
            a->set_dir(dir);
            const auto* st = static_cast<const StructType*>(t);
            for (const Field& f : st->fields()) {
                a->add_inner(make_default_arg(f.type(), f.dir(dir)));
            }
            return a;
        }
        case TypeKind::kUnion: {
            auto a = std::make_unique<UnionArg>();
            a->set_type(t);
            a->set_dir(dir);
            const auto* ut = static_cast<const UnionType*>(t);
            int idx = 0;
            if (ut->is_conditional() && !ut->fields().empty() &&
                ut->fields().back().condition() == nullptr) {
                idx = static_cast<int>(ut->fields().size()) - 1;
            }
            a->set_index(idx);
            if (idx < static_cast<int>(ut->fields().size())) {
                const Field& f = ut->fields()[idx];
                a->set_option(make_default_arg(f.type(), f.dir(dir)));
            }
            return a;
        }
    }
    return nullptr;
}

class DecoderImpl {
public:
    DecoderImpl(const Target& target, DecodeMode mode)
        : target_(target), strict_(mode == DecodeMode::kStrict) {}

    std::unique_ptr<Prog> parse(std::string_view text);
    bool                  failed() const { return lex_ && lex_->failed(); }
    DecodeError           error() const;

private:
    std::unique_ptr<Call> parseCall();
    std::unique_ptr<Arg>  parseArg(const Type* t, Dir dir);
    std::unique_ptr<Arg>  parseArgImpl(const Type* t, Dir dir);
    std::unique_ptr<Arg>  parseArgInt(const Type* t, Dir dir);
    std::unique_ptr<Arg>  parseArgRes(const Type* t, Dir dir);
    std::unique_ptr<Arg>  parseArgAddr(const Type* t, Dir dir);
    std::unique_ptr<Arg>  parseArgString(const Type* t, Dir dir);
    std::unique_ptr<Arg>  parseArgStruct(const Type* t, Dir dir);
    std::unique_ptr<Arg>  parseArgArray(const Type* t, Dir dir);
    std::unique_ptr<Arg>  parseArgUnion(const Type* t, Dir dir);
    std::unique_ptr<Arg>  parseAuto(const Type* t, Dir dir);
    CallProps             parseCallProps();
    bool                  parseAddr(uint64_t* addr_out, uint64_t* vma_size_out);
    bool                  deserializeData(std::vector<uint8_t>* out, bool* b64_out);
    void                  eatExcessive(bool stop_at_comma, std::string what);
    bool                  parseUint(std::string_view s, uint64_t* out);

    void strictFailf(std::string msg) {
        if (strict_) lex_->failf(std::move(msg));
    }

    void fixupAutos(Prog* p);
    void sanitize(Prog* p);

    const Target&            target_;
    bool                     strict_;
    std::unique_ptr<Lexer>   lex_;
    std::string              comment_;
    std::unordered_map<std::string, ResultArg*> vars_;
    std::unordered_set<const Arg*>              autos_;
};

DecodeError DecoderImpl::error() const {
    DecodeError e{};
    if (lex_ != nullptr && lex_->failed()) {
        e.line    = lex_->error_line();
        e.column  = lex_->error_col();
        e.message = lex_->error_msg();
    } else {
        e.message = "unknown decode error";
    }
    return e;
}

bool DecoderImpl::parseUint(std::string_view s, uint64_t* out) {
    if (s.empty()) return false;
    int base = 10;
    std::size_t off = 0;
    bool negate = false;
    if (s[0] == '-') {
        negate = true;
        off    = 1;
    }
    if (s.size() >= off + 2 && s[off] == '0' && (s[off + 1] == 'x' || s[off + 1] == 'X')) {
        base = 16;
        off += 2;
    } else if (s.size() >= off + 1 && s[off] == '0' && s.size() > off + 1) {
        // Go's strconv.ParseUint with base 0 treats leading 0 as octal,
        // but encoding.go uses 0x... and decimals; treat plain decimal
        // for our subset.
        base = 10;
    }
    uint64_t v = 0;
    auto res = std::from_chars(s.data() + off, s.data() + s.size(), v, base);
    if (res.ec != std::errc{} || res.ptr != s.data() + s.size()) return false;
    if (negate) v = static_cast<uint64_t>(-static_cast<int64_t>(v));
    *out = v;
    return true;
}

void DecoderImpl::eatExcessive(bool stop_at_comma, std::string what) {
    strictFailf(std::move(what));
    int paren = 0, brack = 0, brace = 0;
    while (!lex_->eof() && !lex_->failed()) {
        const char c = lex_->ch();
        switch (c) {
            case '(':  paren++; break;
            case ')':
                if (paren == 0) return;
                paren--;
                break;
            case '[':  brack++; break;
            case ']':
                if (brack == 0) return;
                brack--;
                break;
            case '{':  brace++; break;
            case '}':
                if (brace == 0) return;
                brace--;
                break;
            case ',':
                if (stop_at_comma && paren == 0 && brack == 0 && brace == 0) return;
                break;
            case '\'':
            case '"': {
                lex_->parse(c);
                while (!lex_->eof() && lex_->ch() != c) lex_->parse(lex_->ch());
                if (lex_->eof()) return;
                break;
            }
            default: break;
        }
        lex_->parse(c);
    }
}

bool DecoderImpl::parseAddr(uint64_t* addr_out, uint64_t* vma_size_out) {
    if (!lex_->parse('(')) return false;
    std::string s = lex_->ident();
    if (s.empty()) return false;
    uint64_t addr = 0;
    if (!parseUint(s, &addr)) {
        lex_->failf("bad addr " + s);
        return false;
    }
    addr -= kEncodingAddrBase;
    uint64_t vma_size = 0;
    if (lex_->ch() == '/') {
        lex_->parse('/');
        std::string sz = lex_->ident();
        if (sz.empty()) return false;
        uint64_t size = 0;
        if (!parseUint(sz, &size)) {
            lex_->failf("bad addr size " + sz);
            return false;
        }
        const uint64_t page = target_.page_size();
        addr     = addr & ~(page - 1);
        vma_size = (size + page - 1) & ~(page - 1);
        if (vma_size == 0) vma_size = page;
        const uint64_t maxMem = target_.num_pages() * page;
        if (vma_size > maxMem) vma_size = maxMem;
        if (addr > maxMem - vma_size) addr = maxMem - vma_size;
    }
    if (!lex_->parse(')')) return false;
    *addr_out     = addr;
    *vma_size_out = vma_size;
    return true;
}

bool DecoderImpl::deserializeData(std::vector<uint8_t>* out, bool* b64_out) {
    *b64_out = false;
    if (lex_->ch() == '"') {
        lex_->parse('"');
        if (lex_->ch() == '$') {
            lex_->consume();
            std::string raw;
            while (!lex_->eof() && lex_->ch() != '"') raw.push_back(lex_->consume());
            if (!lex_->parse('"')) return false;
            *b64_out = true;
            if (!base64_decode(raw, out)) {
                lex_->failf("bad base64 data");
                return false;
            }
            return true;
        }
        std::string val;
        if (lex_->ch() != '"') val = lex_->ident();
        if (!lex_->parse('"')) return false;
        if (val.size() % 2 != 0) {
            lex_->failf("hex data has odd length");
            return false;
        }
        out->reserve(val.size() / 2);
        for (std::size_t k = 0; k + 1 < val.size(); k += 2) {
            uint8_t b = 0;
            if (!hex_to_byte(static_cast<uint8_t>(val[k + 1]),
                             static_cast<uint8_t>(val[k]), &b)) {
                lex_->failf("bad hex digit");
                return false;
            }
            out->push_back(b);
        }
        return true;
    }
    if (lex_->consume() != '\'') {
        lex_->failf("data arg does not start with \" or '");
        return false;
    }
    while (lex_->ch() != '\'' && lex_->ch() != 0) {
        const uint8_t v = static_cast<uint8_t>(lex_->consume());
        if (v != '\\') {
            out->push_back(v);
            continue;
        }
        const uint8_t e = static_cast<uint8_t>(lex_->consume());
        switch (e) {
            case 'x': {
                const uint8_t hi = static_cast<uint8_t>(lex_->consume());
                const uint8_t lo = static_cast<uint8_t>(lex_->consume());
                uint8_t b = 0;
                if (!hex_to_byte(lo, hi, &b)) {
                    lex_->failf("bad hex escape");
                    return false;
                }
                out->push_back(b);
                break;
            }
            case 'a': out->push_back('\a'); break;
            case 'b': out->push_back('\b'); break;
            case 'f': out->push_back('\f'); break;
            case 'n': out->push_back('\n'); break;
            case 'r': out->push_back('\r'); break;
            case 't': out->push_back('\t'); break;
            case 'v': out->push_back('\v'); break;
            case '\'': out->push_back('\''); break;
            case '"':  out->push_back('"');  break;
            case '\\': out->push_back('\\'); break;
            default:
                lex_->failf(std::string("bad escape sequence \\") + static_cast<char>(e));
                return false;
        }
    }
    if (!lex_->parse('\'')) return false;
    return true;
}

std::unique_ptr<Arg> DecoderImpl::parseArgInt(const Type* t, Dir dir) {
    std::string s = lex_->ident();
    if (s.empty()) return nullptr;
    uint64_t v = 0;
    if (!parseUint(s, &v)) {
        lex_->failf("bad int " + s);
        return nullptr;
    }
    if (t == nullptr) return nullptr;
    switch (t->kind()) {
        case TypeKind::kConst:
        case TypeKind::kInt:
        case TypeKind::kFlags:
        case TypeKind::kProc:
        case TypeKind::kCsum:
        case TypeKind::kLen: {
            auto a = std::make_unique<ConstArg>();
            a->set_type(t);
            a->set_dir(dir);
            a->set_val(v);
            return a;
        }
        case TypeKind::kResource: {
            auto a = std::make_unique<ResultArg>();
            a->set_type(t);
            a->set_dir(dir);
            a->set_val(v);
            return a;
        }
        case TypeKind::kPtr:
        case TypeKind::kVma: {
            auto a = std::make_unique<PointerArg>();
            a->set_type(t);
            // Mirror MakeSpecialPointerArg: PtrType always forces DirIn,
            // VmaType keeps the caller's dir.
            a->set_dir(t->kind() == TypeKind::kPtr ? Dir::kIn : dir);
            // Special pointer: address = -index.
            const std::size_t maxSpecial = 16;
            const uint64_t idx = (~v + 1) % maxSpecial;
            a->set_address(static_cast<uint64_t>(-static_cast<int64_t>(idx)));
            return a;
        }
        default:
            eatExcessive(true, "wrong int arg for type kind");
            return make_default_arg(t, dir);
    }
}

std::unique_ptr<Arg> DecoderImpl::parseArgRes(const Type* t, Dir dir) {
    std::string id = lex_->ident();
    if (id.empty()) return nullptr;
    uint64_t div = 0, add = 0;
    if (lex_->ch() == '/') {
        lex_->parse('/');
        std::string s = lex_->ident();
        if (!parseUint(s, &div)) {
            lex_->failf("bad result div op");
            return nullptr;
        }
    }
    if (lex_->ch() == '+') {
        lex_->parse('+');
        std::string s = lex_->ident();
        if (!parseUint(s, &add)) {
            lex_->failf("bad result add op");
            return nullptr;
        }
    }
    auto it = vars_.find(id);
    if (it == vars_.end()) {
        strictFailf("undefined variable " + id);
        return make_default_arg(t, dir);
    }
    auto a = std::make_unique<ResultArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_res(it->second);
    a->set_op_div(div);
    a->set_op_add(add);
    return a;
}

std::unique_ptr<Arg> DecoderImpl::parseArgAddr(const Type* t, Dir dir) {
    const Type* elem    = nullptr;
    Dir         elemDir = Dir::kInOut;
    bool        isVma   = false;
    if (auto* pt = as_ptr(t)) {
        elem    = pt->elem();
        elemDir = pt->elem_dir();
    } else if (auto* vm = as_vma(t)) {
        (void)vm;
        isVma = true;
    } else {
        eatExcessive(true, "wrong addr arg");
        return make_default_arg(t, dir);
    }
    if (!lex_->parse('&')) return nullptr;
    bool     autoAddr = false;
    uint64_t addr     = 0;
    uint64_t vmaSize  = 0;
    if (lex_->ch() == 'A' && lex_->has_next("AUTO")) {
        lex_->parse('A');
        lex_->parse('U');
        lex_->parse('T');
        lex_->parse('O');
        if (elem == nullptr) {
            lex_->failf("vma type can't be AUTO");
            return nullptr;
        }
        autoAddr = true;
    } else {
        if (!parseAddr(&addr, &vmaSize)) return nullptr;
    }
    std::unique_ptr<Arg> inner;
    if (lex_->ch() == '=') {
        lex_->parse('=');
        if (lex_->has_next("ANY=")) {
            // ANY: skip the prefix, fall back to elem-typed parse.
            lex_->parse('A');
            lex_->parse('N');
            lex_->parse('Y');
            lex_->parse('=');
            if (auto* pt = as_ptr(t); pt != nullptr && pt->squashable_elem()) {
                const PtrType* any = get_any_ptr_type(target_, pt->size());
                if (any != nullptr) {
                    t       = any;
                    elem    = any->elem();
                    elemDir = any->elem_dir();
                }
            }
        }
        inner = parseArg(elem, elemDir);
        if (!inner && lex_->failed()) return nullptr;
    }
    if (isVma) {
        const uint64_t page = target_.page_size();
        if (addr % page != 0) {
            strictFailf("unaligned vma addr");
            addr &= ~(page - 1);
        }
        auto a = std::make_unique<PointerArg>();
        a->set_type(t);
        a->set_dir(dir);
        a->set_address(addr);
        a->set_vma_size(vmaSize);
        return a;
    }
    if (!inner) inner = make_default_arg(elem, elemDir);
    auto a = std::make_unique<PointerArg>();
    a->set_type(t);
    a->set_dir(Dir::kIn);
    a->set_address(addr);
    a->set_res(std::move(inner));
    if (autoAddr) {
        autos_.insert(a.get());
    }
    return a;
}

std::unique_ptr<Arg> DecoderImpl::parseArgString(const Type* t, Dir dir) {
    auto* bt = as_buffer(t);
    if (!bt) {
        eatExcessive(true, "wrong string arg");
        return make_default_arg(t, dir);
    }
    std::vector<uint8_t> data;
    bool b64 = false;
    if (!deserializeData(&data, &b64)) return nullptr;
    uint64_t size = ~uint64_t{0};
    if (lex_->ch() == '/' && !b64) {
        lex_->parse('/');
        std::string s = lex_->ident();
        if (!parseUint(s, &size)) {
            lex_->failf("bad buffer size " + s);
            return nullptr;
        }
        const uint64_t maxMem = target_.num_pages() * target_.page_size();
        if (size > maxMem) {
            strictFailf("oversized string arg");
            size = maxMem;
        }
    }
    if (!t->var_len()) {
        size = t->size();
    } else if (size == ~uint64_t{0}) {
        size = static_cast<uint64_t>(data.size());
    }
    if (dir == Dir::kOut) {
        auto a = std::make_unique<DataArg>();
        a->set_type(t);
        a->set_dir(dir);
        a->set_out_size(size);
        return a;
    }
    if (data.size() < size) data.resize(size, 0);
    if (data.size() > size) data.resize(size);
    auto a = std::make_unique<DataArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_data(std::move(data));
    return a;
}

std::unique_ptr<Arg> DecoderImpl::parseArgStruct(const Type* t, Dir dir) {
    if (!lex_->parse('{')) return nullptr;
    const auto* st = as_struct(t);
    if (!st) {
        eatExcessive(false, "wrong struct arg");
        lex_->parse('}');
        return make_default_arg(t, dir);
    }
    std::vector<std::unique_ptr<Arg>> inner;
    for (std::size_t i = 0; lex_->ch() != '}' && !lex_->failed(); ++i) {
        if (i >= st->fields().size()) {
            eatExcessive(false, "excessive struct fields");
            break;
        }
        const Field& f = st->fields()[i];
        if (default_dir_pad_only(f.type())) {
            inner.push_back(make_zero_const_arg(f.type(), f.dir(dir)));
            // Pad fields don't consume tokens; do not call parseArg.
        } else {
            auto a = parseArg(f.type(), f.dir(dir));
            if (!a) return nullptr;
            inner.push_back(std::move(a));
            if (lex_->ch() != '}') {
                if (!lex_->parse(',')) return nullptr;
            }
        }
    }
    if (!lex_->parse('}')) return nullptr;
    while (inner.size() < st->fields().size()) {
        const Field& f = st->fields()[inner.size()];
        if (!default_dir_pad_only(f.type())) {
            strictFailf("missing struct fields");
        }
        inner.push_back(make_default_arg(f.type(), f.dir(dir)));
    }
    auto a = std::make_unique<GroupArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_inner(std::move(inner));
    return a;
}

std::unique_ptr<Arg> DecoderImpl::parseArgArray(const Type* t, Dir dir) {
    if (!lex_->parse('[')) return nullptr;
    const auto* at = as_array(t);
    if (!at) {
        eatExcessive(false, "wrong array arg");
        lex_->parse(']');
        return make_default_arg(t, dir);
    }
    std::vector<std::unique_ptr<Arg>> inner;
    while (lex_->ch() != ']' && !lex_->failed()) {
        auto a = parseArg(at->elem(), dir);
        if (!a) return nullptr;
        inner.push_back(std::move(a));
        if (lex_->ch() != ']') {
            if (!lex_->parse(',')) return nullptr;
        }
    }
    if (!lex_->parse(']')) return nullptr;
    if (at->array_kind() == ArrayKind::kRangeLen &&
        at->range_begin() == at->range_end()) {
        while (inner.size() < at->range_begin()) {
            inner.push_back(make_default_arg(at->elem(), dir));
        }
        if (inner.size() > at->range_begin()) inner.resize(at->range_begin());
    }
    auto a = std::make_unique<GroupArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_inner(std::move(inner));
    return a;
}

std::unique_ptr<Arg> DecoderImpl::parseArgUnion(const Type* t, Dir dir) {
    const auto* ut = as_union(t);
    if (!ut) {
        eatExcessive(true, "wrong union arg");
        return make_default_arg(t, dir);
    }
    if (!lex_->parse('@')) return nullptr;
    std::string name = lex_->ident();
    if (name.empty()) return nullptr;
    int idx = -1;
    const Type* optType = nullptr;
    Dir optDir = dir;
    for (std::size_t i = 0; i < ut->fields().size(); ++i) {
        if (ut->fields()[i].name() == name) {
            idx     = static_cast<int>(i);
            optType = ut->fields()[i].type();
            optDir  = ut->fields()[i].dir(dir);
            break;
        }
    }
    if (idx < 0) {
        eatExcessive(true, "unknown union arm " + name);
        return make_default_arg(t, dir);
    }
    std::unique_ptr<Arg> opt;
    if (lex_->ch() == '=') {
        lex_->parse('=');
        opt = parseArg(optType, optDir);
        if (!opt) return nullptr;
    } else {
        opt = make_default_arg(optType, optDir);
    }
    auto a = std::make_unique<UnionArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_index(idx);
    a->set_option(std::move(opt));
    return a;
}

std::unique_ptr<Arg> DecoderImpl::parseAuto(const Type* t, Dir dir) {
    if (t == nullptr) return nullptr;
    switch (t->kind()) {
        case TypeKind::kConst:
        case TypeKind::kLen:
        case TypeKind::kCsum: {
            auto a = make_zero_const_arg(t, dir);
            autos_.insert(a.get());
            return a;
        }
        case TypeKind::kStruct: {
            auto a = std::make_unique<GroupArg>();
            a->set_type(t);
            a->set_dir(dir);
            const auto* st = static_cast<const StructType*>(t);
            for (const Field& f : st->fields()) {
                a->add_inner(parseAuto(f.type(), f.dir(dir)));
            }
            return a;
        }
        default:
            lex_->failf("wrong type for AUTO");
            return nullptr;
    }
}

std::unique_ptr<Arg> DecoderImpl::parseArgImpl(const Type* t, Dir dir) {
    if (t == nullptr && lex_->ch() != 'n') {
        eatExcessive(true, "non-nil arg for nil type");
        return nullptr;
    }
    const char c = lex_->ch();
    switch (c) {
        case '0':
        case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        case '-':
            return parseArgInt(t, dir);
        case 'r':
            return parseArgRes(t, dir);
        case '&':
            return parseArgAddr(t, dir);
        case '"':
        case '\'':
            return parseArgString(t, dir);
        case '{':
            return parseArgStruct(t, dir);
        case '[':
            return parseArgArray(t, dir);
        case '@':
            return parseArgUnion(t, dir);
        case 'n':
            lex_->parse('n');
            lex_->parse('i');
            lex_->parse('l');
            return nullptr;
        case 'A':
            if (lex_->has_next("AUTO")) {
                lex_->parse('A');
                lex_->parse('U');
                lex_->parse('T');
                lex_->parse('O');
                return parseAuto(t, dir);
            }
            [[fallthrough]];
        default:
            lex_->failf(std::string("failed to parse argument at '") + c + "'");
            return nullptr;
    }
}

std::unique_ptr<Arg> DecoderImpl::parseArg(const Type* t, Dir dir) {
    std::string r;
    if (lex_->ch() == '<') {
        lex_->parse('<');
        r = lex_->ident();
        if (!lex_->parse('=')) return nullptr;
        if (!lex_->parse('>')) return nullptr;
    }
    auto a = parseArgImpl(t, dir);
    if (lex_->failed()) return nullptr;
    if (!a) {
        if (t != nullptr) {
            a = make_default_arg(t, dir);
        } else if (!r.empty()) {
            lex_->failf("named nil argument");
            return nullptr;
        }
    }
    if (!r.empty()) {
        if (auto* res = dynamic_cast<ResultArg*>(a.get())) {
            vars_[r] = res;
        } else {
            strictFailf("variable doesn't refer to a resource: " + r);
        }
    }
    return a;
}

std::unique_ptr<Call> DecoderImpl::parseCall() {
    std::string r;
    std::string name = lex_->ident();
    if (lex_->ch() == '=') {
        r = name;
        lex_->parse('=');
        name = lex_->ident();
    }
    const SyscallMeta* meta = target_.find_syscall(name);
    if (meta == nullptr) {
        lex_->failf("unknown syscall " + name);
        return nullptr;
    }
    auto call = std::make_unique<Call>();
    call->set_meta(meta);
    if (!comment_.empty()) {
        call->set_comment(std::move(comment_));
        comment_.clear();
    }
    if (!lex_->parse('(')) return nullptr;
    std::vector<std::unique_ptr<Arg>> args;
    for (std::size_t i = 0; lex_->ch() != ')' && !lex_->failed(); ++i) {
        if (i >= meta->args().size()) {
            eatExcessive(false, "excessive syscall arguments");
            break;
        }
        const Field& f = meta->args()[i];
        if (default_dir_pad_only(f.type())) {
            lex_->failf("padding in syscall args");
            return nullptr;
        }
        auto a = parseArg(f.type(), Dir::kIn);
        if (!a) {
            if (lex_->failed()) return nullptr;
            a = make_default_arg(f.type(), Dir::kIn);
        }
        args.push_back(std::move(a));
        if (lex_->ch() != ')') {
            if (!lex_->parse(',')) return nullptr;
        }
    }
    if (!lex_->parse(')')) return nullptr;

    if (!lex_->eof() && lex_->ch() == '(') {
        call->set_props(parseCallProps());
    }

    while (args.size() < meta->args().size()) {
        const Field& f = meta->args()[args.size()];
        strictFailf("missing syscall args");
        args.push_back(make_default_arg(f.type(), Dir::kIn));
    }
    call->set_args(std::move(args));

    // Allocate ret slot if syscall returns a resource.
    if (meta->ret() != nullptr) {
        auto ret = std::make_unique<ResultArg>();
        ret->set_type(meta->ret());
        ret->set_dir(Dir::kOut);
        if (!r.empty()) vars_[r] = ret.get();
        call->set_ret(std::move(ret));
    }
    return call;
}

CallProps DecoderImpl::parseCallProps() {
    CallProps props{};
    if (!lex_->parse('(')) return props;
    while (!lex_->eof() && lex_->ch() != ')' && !lex_->failed()) {
        std::string key = lex_->ident();
        if (key == "async") {
            props.async = true;
        } else if (key == "fail_nth" || key == "rerun") {
            if (!lex_->parse(':')) return props;
            std::string s = lex_->ident();
            uint64_t v = 0;
            if (!parseUint(s, &v)) {
                strictFailf("invalid call property value: " + s);
                v = 0;
            }
            if (key == "fail_nth") props.fail_nth = static_cast<int>(v);
            if (key == "rerun")    props.rerun    = static_cast<int>(v);
        } else {
            eatExcessive(true, "unknown call property: " + key);
        }
        if (lex_->ch() != ')') {
            if (!lex_->parse(',')) return props;
        }
    }
    lex_->parse(')');
    return props;
}

std::unique_ptr<Prog> DecoderImpl::parse(std::string_view text) {
    lex_ = std::make_unique<Lexer>(text);
    comment_.clear();
    vars_.clear();
    autos_.clear();
    auto prog = std::make_unique<Prog>();
    prog->set_target(&target_);
    while (lex_->scan() && !lex_->failed()) {
        if (lex_->eof()) {
            if (!comment_.empty()) {
                prog->add_comment(std::move(comment_));
                comment_.clear();
            }
            continue;
        }
        if (lex_->ch() == '#') {
            if (!comment_.empty()) prog->add_comment(std::move(comment_));
            comment_ = lex_->current_line().substr(lex_->column() + 1);
            // Trim leading spaces.
            std::size_t k = 0;
            while (k < comment_.size() && comment_[k] == ' ') k++;
            comment_.erase(0, k);
            continue;
        }
        auto call = parseCall();
        if (!call) return nullptr;
        prog->add_call(std::move(call));
        comment_.clear();
    }
    if (!comment_.empty()) prog->add_comment(std::move(comment_));
    if (lex_->failed()) return nullptr;
    fixupAutos(prog.get());
    sanitize(prog.get());
    return prog;
}

// Mirror prog/encoding.go fixupAutos: assign sizes for AUTO LenType args,
// set ConstArg.val to ConstType.val for AUTO consts, and allocate addresses
// for AUTO pointers via memAlloc. Run only after the full prog has parsed.
void DecoderImpl::fixupAutos(Prog* p) {
    if (autos_.empty() || p == nullptr) return;
    MemAlloc ma(target_.num_pages() * target_.page_size());

    // Phase 1 mirrors analyze(): note all current pointer addresses,
    // including AUTO pointers that still sit at address 0. This is why
    // syzkaller's first &AUTO allocation usually starts at 0x40.
    for (const auto& cup : p->calls()) {
        foreach_arg(const_cast<Call*>(cup.get()), [&](Arg* a, ArgCtx*) {
            if (auto* pa = dynamic_cast<PointerArg*>(a)) {
                if (pa->vma_size() != 0)         return;
                if (pa->res() == nullptr)        return;
                if (pa->is_special())            return;
                ma.note_alloc(pa->address(), pa->res()->size());
            }
        });
    }

    // Phase 2: assignSizesArray over each call's args, only filling LenType
    // entries that are auto-marked (assign_sizes_array removes them from
    // the autos set after assigning).
    for (auto& cup : p->mutable_calls()) {
        if (cup->meta() == nullptr) continue;
        assign_sizes_array(target_, cup->mutable_args(), cup->meta()->args(), &autos_);
    }

    // Phase 3: fix remaining Const autos (val ← ConstType.val) and Pointer
    // autos (address ← ma.alloc(res.size, res.type.align)).
    for (const auto& cup : p->calls()) {
        foreach_arg(const_cast<Call*>(cup.get()), [&](Arg* a, ArgCtx*) {
            if (autos_.count(a) == 0) return;
            autos_.erase(a);
            if (auto* ct = as_const(a->type())) {
                static_cast<ConstArg*>(a)->set_val(ct->val());
                return;
            }
            if (as_ptr(a->type())) {
                auto* pa = static_cast<PointerArg*>(a);
                uint64_t sz = pa->res() ? pa->res()->size() : 0;
                uint64_t alg = (pa->res() && pa->res()->type())
                    ? pa->res()->type()->align() : 0;
                pa->set_address(ma.alloc(sz, alg));
            }
        });
    }
}

// Minimal mirror of Target.sanitize -> UnixNeutralizer.Neutralize for
// text-roundtrip parity. This intentionally starts with the largest observed
// L3 diff class; add Linux-specific cases as the corpus diff shrinks.
void DecoderImpl::sanitize(Prog* p) {
    if (p == nullptr) return;
    constexpr uint64_t kLinuxMapFixed = 0x10;
    for (auto& cup : p->mutable_calls()) {
        Call* c = cup.get();
        if (c == nullptr || c->meta() == nullptr) continue;
        if (c->meta()->call_name() == "mmap" &&
            c->meta()->name() != "mmap$bifrost" &&
            c->mutable_args().size() > 3) {
            if (auto* flags = dynamic_cast<ConstArg*>(c->mutable_args()[3].get())) {
                flags->set_val(flags->val() | kLinuxMapFixed);
            }
        } else if (c->meta()->call_name() == "ptrace" &&
                   c->mutable_args().size() > 0) {
            if (auto* req = dynamic_cast<ConstArg*>(c->mutable_args()[0].get())) {
                if (static_cast<uint32_t>(req->val()) == 0) {
                    req->set_val(~uint64_t{0});
                }
            }
        }
    }
}

// `is_default_arg` lives in arg.cpp (declared in arg.hpp) — same dispatch
// is shared with validation.cpp. Callers that also need to preserve
// named-result decls should additionally guard on `carriesNamedRef`.

// ============================================================
// TextEncoder::Impl
// ============================================================

class EncoderImpl {
public:
    explicit EncoderImpl(const Target& target) : target_(target) {}

    std::string encode(const Prog& prog);

private:
    void writeCall(const Call& c);
    void writeArg(const Arg& a);
    void writeConst(const ConstArg& a);
    void writePointer(const PointerArg& a);
    void writeData(const DataArg& a);
    void writeGroup(const GroupArg& a);
    void writeUnion(const UnionArg& a);
    void writeResult(const ResultArg& a);
    int  allocVarId(const ResultArg* a);
    void scanUses(const Arg& a);
    // True if the subtree rooted at `a` contains a ResultArg that is itself
    // referenced (a producer that hasn't yet emitted its `<rN=>` decl).
    // Such subtrees must NOT be collapsed to type-default, even if structurally
    // identical to default.
    bool carriesNamedRef(const Arg* a) const;
    // Wrapper around is_default_arg that returns false whenever the subtree
    // carries a named-result decl that hasn't been emitted yet.
    bool collapsibleDefault(const Arg* a) const;

    const Target&                                  target_;
    std::string                                    out_;
    std::unordered_map<const ResultArg*, int>      vars_;
    std::unordered_set<const ResultArg*>           used_rets_;
    int                                            varSeq_ = 0;
};

int EncoderImpl::allocVarId(const ResultArg* a) {
    int id = varSeq_++;
    vars_[a] = id;
    return id;
}

bool EncoderImpl::carriesNamedRef(const Arg* a) const {
    if (a == nullptr) return false;
    switch (a->arg_kind()) {
        case ArgKind::kResult: {
            const auto* ra = static_cast<const ResultArg*>(a);
            return used_rets_.count(ra) != 0 && vars_.count(ra) == 0;
        }
        case ArgKind::kPointer: {
            const auto& p = static_cast<const PointerArg&>(*a);
            return carriesNamedRef(p.res());
        }
        case ArgKind::kGroup: {
            const auto& g = static_cast<const GroupArg&>(*a);
            for (const auto& up : g.inner()) {
                if (carriesNamedRef(up.get())) return true;
            }
            return false;
        }
        case ArgKind::kUnion: {
            const auto& u = static_cast<const UnionArg&>(*a);
            return carriesNamedRef(u.option());
        }
        case ArgKind::kConst:
        case ArgKind::kData:
            return false;
    }
    return false;
}

bool EncoderImpl::collapsibleDefault(const Arg* a) const {
    if (carriesNamedRef(a)) return false;
    return is_default_arg(a);
}

void EncoderImpl::scanUses(const Arg& a) {
    switch (a.arg_kind()) {
        case ArgKind::kResult: {
            const auto* res = static_cast<const ResultArg&>(a).res();
            if (res != nullptr) used_rets_.insert(res);
            break;
        }
        case ArgKind::kPointer: {
            const auto& p = static_cast<const PointerArg&>(a);
            if (p.res() != nullptr) scanUses(*p.res());
            break;
        }
        case ArgKind::kGroup: {
            const auto& g = static_cast<const GroupArg&>(a);
            for (const auto& up : g.inner()) if (up) scanUses(*up);
            break;
        }
        case ArgKind::kUnion: {
            const auto& u = static_cast<const UnionArg&>(a);
            if (u.option() != nullptr) scanUses(*u.option());
            break;
        }
        case ArgKind::kConst:
        case ArgKind::kData:
            break;
    }
}

std::string EncoderImpl::encode(const Prog& prog) {
    out_.clear();
    vars_.clear();
    used_rets_.clear();
    varSeq_ = 0;
    for (const auto& cup : prog.calls()) {
        for (const auto& aup : cup->args()) if (aup) scanUses(*aup);
    }
    for (const auto& up : prog.calls()) {
        writeCall(*up);
    }
    return out_;
}

void EncoderImpl::writeCall(const Call& c) {
    // Mirror serializer.call: assign `r%d = ` only when the ret is used
    // by some downstream ResultArg. Otherwise omit the prefix.
    if (c.ret() != nullptr && used_rets_.count(c.ret()) != 0) {
        int id = allocVarId(c.ret());
        char buf[24];
        std::snprintf(buf, sizeof(buf), "r%d = ", id);
        out_ += buf;
    }
    out_ += c.meta()->name();
    out_ += "(";
    bool first = true;
    for (const auto& up : c.args()) {
        if (default_dir_pad_only(up->type())) continue;
        if (!first) out_ += ", ";
        first = false;
        writeArg(*up);
    }
    out_ += ")";
    const CallProps& props = c.props();
    bool wrote_prop = false;
    auto begin_prop = [&] {
        if (!wrote_prop) {
            out_ += " (";
            wrote_prop = true;
        } else {
            out_ += ", ";
        }
    };
    if (props.fail_nth != 0) {
        begin_prop();
        char buf[40];
        std::snprintf(buf, sizeof(buf), "fail_nth: %d", props.fail_nth);
        out_ += buf;
    }
    if (props.async) {
        begin_prop();
        out_ += "async";
    }
    if (props.rerun != 0) {
        begin_prop();
        char buf[32];
        std::snprintf(buf, sizeof(buf), "rerun: %d", props.rerun);
        out_ += buf;
    }
    if (wrote_prop) out_ += ")";
    out_ += "\n";
}

void EncoderImpl::writeArg(const Arg& a) {
    switch (a.arg_kind()) {
        case ArgKind::kConst:   writeConst  (static_cast<const ConstArg&>(a));   break;
        case ArgKind::kPointer: writePointer(static_cast<const PointerArg&>(a)); break;
        case ArgKind::kData:    writeData   (static_cast<const DataArg&>(a));    break;
        case ArgKind::kGroup:   writeGroup  (static_cast<const GroupArg&>(a));   break;
        case ArgKind::kUnion:   writeUnion  (static_cast<const UnionArg&>(a));   break;
        case ArgKind::kResult:  writeResult (static_cast<const ResultArg&>(a));  break;
    }
}

void EncoderImpl::writeConst(const ConstArg& a) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(a.val()));
    out_ += buf;
}

void EncoderImpl::writePointer(const PointerArg& a) {
    if (a.is_special()) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(a.address()));
        out_ += buf;
        return;
    }
    char addr_buf[64];
    if (a.vma_size() != 0) {
        std::snprintf(addr_buf, sizeof(addr_buf), "&(0x%llx/0x%llx)",
                      static_cast<unsigned long long>(kEncodingAddrBase + a.address()),
                      static_cast<unsigned long long>(a.vma_size()));
    } else {
        std::snprintf(addr_buf, sizeof(addr_buf), "&(0x%llx)",
                      static_cast<unsigned long long>(kEncodingAddrBase + a.address()));
    }
    out_ += addr_buf;
    if (a.res() == nullptr) {
        if (a.type() != nullptr && a.type()->kind() == TypeKind::kVma) {
            out_ += "=nil";
        }
        return;
    }
    const bool any = is_any_ptr(target_, a.type());
    // Mirror upstream: omit `=<inner>` when the inner is the type default,
    // except for ANY pointers and subtrees that carry an unsatisfied named-result
    // decl.
    if (!any && collapsibleDefault(a.res())) return;
    out_ += "=";
    if (any) out_ += "ANY=";
    writeArg(*a.res());
}

void EncoderImpl::writeData(const DataArg& a) {
    auto* bt = as_buffer(a.type());
    if (a.dir() == Dir::kOut) {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "\"\"/%llu",
                      static_cast<unsigned long long>(a.size()));
        out_ += buf;
        return;
    }
    if (bt && bt->is_compressed()) {
        out_ += "\"$";
        out_ += base64_encode(a.data());
        out_ += "\"";
        return;
    }
    auto data = a.data();
    const std::size_t original_size = data.size();
    while (data.size() >= 2 &&
           data[data.size() - 1] == 0 &&
           data[data.size() - 2] == 0) {
        data.pop_back();
    }
    if (a.type() != nullptr && a.type()->var_len() &&
        data.size() + 8 >= original_size) {
        data.resize(original_size);
    }
    bool readable = bt && is_readable_buffer_kind(bt->buffer_kind());
    serialize_data(out_, data, readable);
    if (a.type() != nullptr && a.type()->var_len() &&
        original_size != data.size()) {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "/%llu",
                      static_cast<unsigned long long>(original_size));
        out_ += buf;
    }
}

void EncoderImpl::writeGroup(const GroupArg& a) {
    char open  = '{';
    char close = '}';
    if (a.type() && a.type()->kind() == TypeKind::kArray) {
        open  = '[';
        close = ']';
    }
    out_.push_back(open);

    // Mirror prog/encoding.go GroupArg.serialize: when the inner-size is
    // structurally fixed (struct, or array with fixed range), trim trailing
    // default elements.
    int last = static_cast<int>(a.inner().size()) - 1;
    bool fixed = false;
    if (a.type() != nullptr) {
        if (a.type()->kind() == TypeKind::kStruct) {
            fixed = true;
        } else if (auto* at = as_array(a.type())) {
            fixed = at->array_kind() == ArrayKind::kRangeLen &&
                    at->range_begin() == at->range_end();
        }
    }
    if (fixed) {
        while (last >= 0) {
            const auto& up = a.inner()[last];
            if (up && !collapsibleDefault(up.get())) break;
            last--;
        }
    }

    bool first = true;
    for (int i = 0; i <= last; ++i) {
        const auto& up = a.inner()[i];
        if (up && default_dir_pad_only(up->type())) continue;
        if (!first) out_ += ", ";
        first = false;
        if (up) writeArg(*up);
    }
    out_.push_back(close);
}

void EncoderImpl::writeUnion(const UnionArg& a) {
    auto* ut = as_union(a.type());
    out_ += "@";
    if (ut && a.index() >= 0 && a.index() < static_cast<int>(ut->fields().size())) {
        out_ += ut->fields()[a.index()].name();
    }
    // Mirror upstream: omit `=<inner>` when the option is the type default,
    // unless the subtree carries a named-result decl.
    if (a.option() == nullptr) return;
    if (collapsibleDefault(a.option())) return;
    out_ += "=";
    writeArg(*a.option());
}

void EncoderImpl::writeResult(const ResultArg& a) {
    // Mirror upstream serializer: when this ResultArg is itself referenced
    // by some downstream ResultArg, emit a `<rN=>` decl prefix at this
    // inline position. Ret args are handled in writeCall(); here we only
    // handle args that appear inside other args (e.g. inside struct fields).
    if (used_rets_.count(&a) != 0 && vars_.count(&a) == 0) {
        int id = allocVarId(&a);
        char buf[24];
        std::snprintf(buf, sizeof(buf), "<r%d=>", id);
        out_ += buf;
    }
    if (a.res() == nullptr) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(a.val()));
        out_ += buf;
        return;
    }
    auto it = vars_.find(a.res());
    if (it == vars_.end()) {
        // Unresolved reference; emit literal default to keep round-trip valid.
        out_ += "0x0";
        return;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "r%d", it->second);
    out_ += buf;
    if (a.op_div() != 0) {
        std::snprintf(buf, sizeof(buf), "/%llu",
                      static_cast<unsigned long long>(a.op_div()));
        out_ += buf;
    }
    if (a.op_add() != 0) {
        std::snprintf(buf, sizeof(buf), "+%llu",
                      static_cast<unsigned long long>(a.op_add()));
        out_ += buf;
    }
}

} // namespace

// ============================================================
// Public API
// ============================================================

class TextDecoder::Impl {
public:
    DecoderImpl decoder;
    Impl(const Target& t, DecodeMode m) : decoder(t, m) {}
};

TextDecoder::TextDecoder(const Target& target, DecodeMode mode)
    : impl_(std::make_unique<Impl>(target, mode)) {}
TextDecoder::~TextDecoder() = default;

std::expected<std::unique_ptr<Prog>, DecodeError> TextDecoder::decode(std::string_view text) {
    refuzz::program::codec_counters::OnDecodeText();
    auto prog = impl_->decoder.parse(text);
    if (!prog) return std::unexpected(impl_->decoder.error());
    // §3.11 follow-up — apply target-specific invariant repairs after
    // parse. Mirrors syzkaller `prog/encoding.go::Deserialize` calling
    // `prog.sanitize(!strict)` before returning. Without this, decoded
    // programs that hit one of the per-syscall sanitize cases (ptrace
    // PTRACE_TRACEME, mremap MREMAP_MAYMOVE, ...) carry the
    // pre-sanitize values forward into minimize, breaking byte parity
    // with the syzkaller golden output.
    sanitize_fix(*prog);
    return prog;
}

class TextEncoder::Impl {
public:
    EncoderImpl encoder;
    explicit Impl(const Target& t) : encoder(t) {}
};

TextEncoder::TextEncoder(const Target& target) : impl_(std::make_unique<Impl>(target)) {}
TextEncoder::~TextEncoder() = default;

std::string TextEncoder::encode(const Prog& prog) {
    refuzz::program::codec_counters::OnEncodeText();
    return impl_->encoder.encode(prog);
}

} // namespace refuzz::program::syz
