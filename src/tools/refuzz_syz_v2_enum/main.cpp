// refuzz-syz-v2-enum: full field-level enumeration of the v2 IR.
//
// Output format MUST be byte-identical to syzgen enum-dump (Go side).
// Used as the L1 oracle: diff /tmp/cpp.txt /tmp/go.txt → expected empty.

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace syz = ::refuzz::program::syz;

namespace {

const char* kind_name(syz::TypeKind k) {
    switch (k) {
        case syz::TypeKind::kInt:      return "Int";
        case syz::TypeKind::kConst:    return "Const";
        case syz::TypeKind::kFlags:    return "Flags";
        case syz::TypeKind::kProc:     return "Proc";
        case syz::TypeKind::kLen:      return "Len";
        case syz::TypeKind::kCsum:     return "Csum";
        case syz::TypeKind::kResource: return "Resource";
        case syz::TypeKind::kBuffer:   return "Buffer";
        case syz::TypeKind::kPtr:      return "Ptr";
        case syz::TypeKind::kArray:    return "Array";
        case syz::TypeKind::kStruct:   return "Struct";
        case syz::TypeKind::kUnion:    return "Union";
        case syz::TypeKind::kVma:      return "Vma";
    }
    return "?";
}

uint64_t size_of(const syz::Type* t) {
    return t->var_len() ? 0 : t->size();
}

void print_uint_list(const std::vector<uint64_t>& vs) {
    for (std::size_t i = 0; i < vs.size(); ++i) {
        if (i != 0) std::putchar(',');
        std::printf("%llu", static_cast<unsigned long long>(vs[i]));
    }
}

void print_string_list_sep(const std::vector<std::string>& vs, char sep) {
    for (std::size_t i = 0; i < vs.size(); ++i) {
        if (i != 0) std::putchar(sep);
        std::fwrite(vs[i].data(), 1, vs[i].size(), stdout);
    }
}

void dump_int_common(const syz::IntTypeCommon* c) {
    std::printf("  format=%d\n",      static_cast<int>(c->format()));
    std::printf("  bf_off=%llu\n",    static_cast<unsigned long long>(c->bitfield_off()));
    std::printf("  bf_len=%llu\n",    static_cast<unsigned long long>(c->bitfield_len()));
    std::printf("  bf_unit=%llu\n",   static_cast<unsigned long long>(c->bitfield_unit()));
    std::printf("  bf_unit_off=%llu\n", static_cast<unsigned long long>(c->bitfield_unit_off()));
}

std::string expr_digest(const syz::Expression* e) {
    if (e == nullptr) return "?";
    if (e->expr_kind() == syz::Expression::Kind::kValue) {
        const auto* v = static_cast<const syz::ValueExpr*>(e);
        std::string out = "Value(";
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v->value()));
        out += buf;
        out += ',';
        for (std::size_t i = 0; i < v->path().size(); ++i) {
            if (i != 0) out += '.';
            out += v->path()[i];
        }
        out += ')';
        return out;
    }
    const auto* b = static_cast<const syz::BinaryExpression*>(e);
    std::string out = "Binary(";
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%d", static_cast<int>(b->op()));
    out += buf;
    out += ',';
    out += expr_digest(b->left());
    out += ',';
    out += expr_digest(b->right());
    out += ')';
    return out;
}

class Enumerator {
public:
    explicit Enumerator(const syz::Target& t) : target_(t) {
        const auto& types = target_.arena().types();
        type_id_.reserve(types.size());
        for (std::size_t i = 0; i < types.size(); ++i) {
            type_id_[types[i].get()] = static_cast<int>(i);
        }
        const auto& resources = target_.resource_arena().descs();
        res_id_.reserve(resources.size());
        for (std::size_t i = 0; i < resources.size(); ++i) {
            res_id_[resources[i].get()] = static_cast<int>(i);
        }
    }

    void run() {
        std::printf("==target==\n");
        std::printf("os=%s\n",          target_.os().c_str());
        std::printf("arch=%s\n",        target_.arch().c_str());
        std::printf("revision=%s\n",    target_.revision().c_str());
        std::printf("ptr_size=%llu\n",  static_cast<unsigned long long>(target_.ptr_size()));
        std::printf("page_size=%llu\n", static_cast<unsigned long long>(target_.page_size()));
        std::printf("num_pages=%llu\n", static_cast<unsigned long long>(target_.num_pages()));
        std::printf("data_offset=%llu\n", static_cast<unsigned long long>(target_.data_offset()));
        std::printf("big_endian=%d\n",  target_.big_endian() ? 1 : 0);
        std::printf("type_count=%zu\n",     target_.arena().types().size());
        std::printf("syscall_count=%zu\n",  target_.syscalls().size());
        std::printf("resource_count=%zu\n", target_.resource_arena().descs().size());

        std::printf("==consts==\n");
        std::printf("count=%zu\n", target_.consts().size());
        for (std::size_t i = 0; i < target_.consts().size(); ++i) {
            const auto& c = target_.consts()[i];
            std::printf("const %zu: name=%s value=%llu\n", i, c.name.c_str(),
                        static_cast<unsigned long long>(c.value));
        }

        std::printf("==flags==\n");
        std::printf("count=%zu\n", target_.flag_descs().size());
        for (std::size_t i = 0; i < target_.flag_descs().size(); ++i) {
            const auto& f = target_.flag_descs()[i];
            std::printf("flag %zu: name=%s values=", i, f.name.c_str());
            print_string_list_sep(f.values, '\x1f');
            std::putchar('\n');
        }

        std::printf("==special_pointers==\n");
        std::printf("count=%zu\n", target_.special_pointers().size());
        for (std::size_t i = 0; i < target_.special_pointers().size(); ++i) {
            std::printf("special_ptr %zu: %llu\n", i,
                        static_cast<unsigned long long>(target_.special_pointers()[i]));
        }

        std::printf("==special_file_lengths==\n");
        std::printf("count=%zu\n", target_.special_file_lengths().size());
        for (std::size_t i = 0; i < target_.special_file_lengths().size(); ++i) {
            std::printf("special_file_len %zu: %lld\n", i,
                        static_cast<long long>(target_.special_file_lengths()[i]));
        }

        std::printf("==aux_resources==\n");
        std::printf("count=%zu\n", target_.aux_resources().size());
        for (std::size_t i = 0; i < target_.aux_resources().size(); ++i) {
            std::printf("aux %zu: %s\n", i, target_.aux_resources()[i].c_str());
        }

        std::printf("==resources==\n");
        const auto& resources = target_.resource_arena().descs();
        for (std::size_t i = 0; i < resources.size(); ++i) {
            dumpResource(static_cast<int>(i), resources[i].get());
        }

        std::printf("==types==\n");
        const auto& types = target_.arena().types();
        for (std::size_t i = 0; i < types.size(); ++i) {
            dumpType(static_cast<int>(i), types[i].get());
        }

        std::printf("==syscalls==\n");
        const auto& syscalls = target_.syscalls();
        for (std::size_t i = 0; i < syscalls.size(); ++i) {
            dumpSyscall(static_cast<int>(i), syscalls[i].get());
        }
    }

private:
    void dumpResource(int i, const syz::ResourceDesc* r) {
        std::printf("resource %d:\n", i);
        std::printf("  name=%s\n", r->name().c_str());
        std::printf("  kind=");
        print_string_list_sep(r->kind(), ',');
        std::putchar('\n');
        std::printf("  values=");
        print_uint_list(r->values());
        std::putchar('\n');
    }

    void dumpField(int idx, const syz::Field& f) {
        std::printf("    field %d:\n", idx);
        std::printf("      name=%s\n", f.name().c_str());
        std::printf("      type=%d\n", typeRefId(f.type()));
        std::printf("      has_dir=%d\n", f.has_direction() ? 1 : 0);
        std::printf("      dir=%d\n", static_cast<int>(f.direction()));
        if (f.condition() == nullptr) {
            std::printf("      cond=none\n");
        } else {
            std::string s = expr_digest(f.condition());
            std::printf("      cond=%s\n", s.c_str());
        }
    }

    int typeRefId(const syz::Type* t) {
        if (t == nullptr) return -1;
        auto it = type_id_.find(t);
        return it == type_id_.end() ? -2 : it->second;
    }

    int resRefId(const syz::ResourceDesc* r) {
        if (r == nullptr) return -1;
        auto it = res_id_.find(r);
        return it == res_id_.end() ? -2 : it->second;
    }

    void dumpType(int i, const syz::Type* t) {
        std::printf("type %d:\n", i);
        std::printf("  kind=%s\n", kind_name(t->kind()));
        std::printf("  name=%s\n", t->name().c_str());
        std::printf("  size=%llu\n",     static_cast<unsigned long long>(size_of(t)));
        std::printf("  align=%llu\n",    static_cast<unsigned long long>(t->align()));
        std::printf("  optional=%d\n",   t->optional() ? 1 : 0);
        std::printf("  varlen=%d\n",     t->var_len() ? 1 : 0);

        switch (t->kind()) {
            case syz::TypeKind::kInt: {
                auto* v = static_cast<const syz::IntType*>(t);
                dump_int_common(v);
                std::printf("  int_kind=%d\n",      static_cast<int>(v->int_kind()));
                std::printf("  range_begin=%llu\n", static_cast<unsigned long long>(v->range_begin()));
                std::printf("  range_end=%llu\n",   static_cast<unsigned long long>(v->range_end()));
                std::printf("  int_align=%llu\n",   static_cast<unsigned long long>(v->int_align()));
                break;
            }
            case syz::TypeKind::kConst: {
                auto* v = static_cast<const syz::ConstType*>(t);
                dump_int_common(v);
                std::printf("  val=%llu\n",    static_cast<unsigned long long>(v->val()));
                std::printf("  is_pad=%d\n",   v->is_pad() ? 1 : 0);
                break;
            }
            case syz::TypeKind::kFlags: {
                auto* v = static_cast<const syz::FlagsType*>(t);
                dump_int_common(v);
                std::printf("  vals=");
                print_uint_list(v->vals());
                std::putchar('\n');
                std::printf("  bitmask=%d\n", v->bitmask() ? 1 : 0);
                break;
            }
            case syz::TypeKind::kLen: {
                auto* v = static_cast<const syz::LenType*>(t);
                dump_int_common(v);
                std::printf("  bit_size=%llu\n", static_cast<unsigned long long>(v->bit_size()));
                std::printf("  offset=%d\n",    v->offset() ? 1 : 0);
                std::printf("  path=");
                print_string_list_sep(v->path(), ',');
                std::putchar('\n');
                break;
            }
            case syz::TypeKind::kProc: {
                auto* v = static_cast<const syz::ProcType*>(t);
                dump_int_common(v);
                std::printf("  values_start=%llu\n",
                            static_cast<unsigned long long>(v->values_start()));
                std::printf("  values_per_proc=%llu\n",
                            static_cast<unsigned long long>(v->values_per_proc()));
                break;
            }
            case syz::TypeKind::kCsum: {
                auto* v = static_cast<const syz::CsumType*>(t);
                dump_int_common(v);
                std::printf("  csum_kind=%d\n", static_cast<int>(v->csum_kind()));
                std::printf("  buf=%s\n",       v->buf().c_str());
                std::printf("  protocol=%llu\n",
                            static_cast<unsigned long long>(v->protocol()));
                break;
            }
            case syz::TypeKind::kResource: {
                auto* v = static_cast<const syz::ResourceType*>(t);
                std::printf("  format=%d\n", static_cast<int>(v->format()));
                std::printf("  desc=%d\n",   resRefId(v->desc()));
                break;
            }
            case syz::TypeKind::kBuffer: {
                auto* v = static_cast<const syz::BufferType*>(t);
                std::printf("  buffer_kind=%d\n", static_cast<int>(v->buffer_kind()));
                std::printf("  range_begin=%llu\n", static_cast<unsigned long long>(v->range_begin()));
                std::printf("  range_end=%llu\n",   static_cast<unsigned long long>(v->range_end()));
                std::printf("  text_kind=%d\n",  static_cast<int>(v->text_kind()));
                std::printf("  sub_kind=%s\n",   v->sub_kind().c_str());
                std::printf("  values=");
                print_string_list_sep(v->values(), '\x1f');
                std::putchar('\n');
                std::printf("  no_z=%d\n", v->no_z() ? 1 : 0);
                break;
            }
            case syz::TypeKind::kPtr: {
                auto* v = static_cast<const syz::PtrType*>(t);
                std::printf("  elem=%d\n",      typeRefId(v->elem()));
                std::printf("  elem_dir=%d\n",  static_cast<int>(v->elem_dir()));
                std::printf("  squashable_elem=%d\n",
                            v->squashable_elem() ? 1 : 0);
                break;
            }
            case syz::TypeKind::kArray: {
                auto* v = static_cast<const syz::ArrayType*>(t);
                std::printf("  elem=%d\n",       typeRefId(v->elem()));
                std::printf("  array_kind=%d\n", static_cast<int>(v->array_kind()));
                std::printf("  range_begin=%llu\n", static_cast<unsigned long long>(v->range_begin()));
                std::printf("  range_end=%llu\n",   static_cast<unsigned long long>(v->range_end()));
                break;
            }
            case syz::TypeKind::kStruct: {
                auto* v = static_cast<const syz::StructType*>(t);
                std::printf("  align_attr=%llu\n", static_cast<unsigned long long>(v->align_attr()));
                std::printf("  overlay_field=%d\n", v->overlay_field());
                std::printf("  fields=%zu\n", v->fields().size());
                for (std::size_t fi = 0; fi < v->fields().size(); ++fi) {
                    dumpField(static_cast<int>(fi), v->fields()[fi]);
                }
                break;
            }
            case syz::TypeKind::kUnion: {
                auto* v = static_cast<const syz::UnionType*>(t);
                std::printf("  fields=%zu\n", v->fields().size());
                for (std::size_t fi = 0; fi < v->fields().size(); ++fi) {
                    dumpField(static_cast<int>(fi), v->fields()[fi]);
                }
                break;
            }
            case syz::TypeKind::kVma: {
                auto* v = static_cast<const syz::VmaType*>(t);
                std::printf("  range_begin=%llu\n", static_cast<unsigned long long>(v->range_begin()));
                std::printf("  range_end=%llu\n",   static_cast<unsigned long long>(v->range_end()));
                break;
            }
        }
    }

    void dumpSyscall(int i, const syz::SyscallMeta* sc) {
        std::printf("syscall %d:\n", i);
        std::printf("  name=%s\n",         sc->name().c_str());
        std::printf("  call_name=%s\n",    sc->call_name().c_str());
        std::printf("  nr=%llu\n",         static_cast<unsigned long long>(sc->nr()));
        std::printf("  missing_args=%d\n", sc->missing_args());
        const auto& a = sc->attrs();
        std::printf("  attr_disabled=%d\n",         a.disabled ? 1 : 0);
        std::printf("  attr_timeout=%llu\n",        static_cast<unsigned long long>(a.timeout));
        std::printf("  attr_prog_timeout=%llu\n",   static_cast<unsigned long long>(a.prog_timeout));
        std::printf("  attr_ignore_return=%d\n",    a.ignore_return ? 1 : 0);
        std::printf("  attr_breaks_returns=%d\n",   a.breaks_returns ? 1 : 0);
        std::printf("  attr_no_generate=%d\n",      a.no_generate ? 1 : 0);
        std::printf("  attr_no_minimize=%d\n",      a.no_minimize ? 1 : 0);
        std::printf("  attr_no_squash=%d\n",        a.no_squash ? 1 : 0);
        std::printf("  attr_remote_cover=%d\n",     a.remote_cover ? 1 : 0);
        std::printf("  attr_automatic=%d\n",        a.automatic ? 1 : 0);
        std::printf("  attr_automatic_helper=%d\n", a.automatic_helper ? 1 : 0);
        std::printf("  attr_kfuzztest=%d\n",        a.kfuzztest ? 1 : 0);
        std::printf("  attr_fsck=%s\n",             a.fsck.c_str());
        std::printf("  attr_filesystem=%s\n",       a.filesystem.c_str());
        std::printf("  args=%zu\n", sc->args().size());
        for (std::size_t fi = 0; fi < sc->args().size(); ++fi) {
            dumpField(static_cast<int>(fi), sc->args()[fi]);
        }
        if (sc->ret() == nullptr) {
            std::printf("  ret=none\n");
        } else {
            std::printf("  ret=%d\n", typeRefId(sc->ret()));
        }
    }

    const syz::Target&                                target_;
    std::unordered_map<const syz::Type*, int>         type_id_;
    std::unordered_map<const syz::ResourceDesc*, int> res_id_;
};

} // namespace

int main() {
    const auto& target = syz::Target::linux_amd64();
    Enumerator e(target);
    e.run();
    return 0;
}
