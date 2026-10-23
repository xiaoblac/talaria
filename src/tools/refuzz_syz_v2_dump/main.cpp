// refuzz-syz-v2-dump: emit a structural summary of the new polymorphic IR
// for diffing against syzkaller pkg/prog. Used to verify
// "IR表达力 ≥ syzkaller IR (structural equivalence)".

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

namespace refuzz_syz = ::refuzz::program::syz;

namespace {

const char* kind_name(refuzz_syz::TypeKind k) {
    using K = refuzz_syz::TypeKind;
    switch (k) {
        case K::kInt:      return "Int";
        case K::kConst:    return "Const";
        case K::kFlags:    return "Flags";
        case K::kProc:     return "Proc";
        case K::kLen:      return "Len";
        case K::kCsum:     return "Csum";
        case K::kResource: return "Resource";
        case K::kBuffer:   return "Buffer";
        case K::kPtr:      return "Ptr";
        case K::kArray:    return "Array";
        case K::kStruct:   return "Struct";
        case K::kUnion:    return "Union";
        case K::kVma:      return "Vma";
    }
    return "?";
}

const char* dir_name(refuzz_syz::Dir d) {
    switch (d) {
        case refuzz_syz::Dir::kIn:    return "in";
        case refuzz_syz::Dir::kOut:   return "out";
        case refuzz_syz::Dir::kInOut: return "inout";
    }
    return "?";
}

void print_summary(const refuzz_syz::Target& t) {
    std::printf("os=%s\n",        t.os().c_str());
    std::printf("arch=%s\n",      t.arch().c_str());
    std::printf("revision=%s\n",  t.revision().c_str());
    std::printf("ptr_size=%llu\n",  (unsigned long long)t.ptr_size());
    std::printf("page_size=%llu\n", (unsigned long long)t.page_size());
    std::printf("num_pages=%llu\n", (unsigned long long)t.num_pages());
    std::printf("type_count=%zu\n",     t.type_count());
    std::printf("syscall_count=%zu\n",  t.syscall_count());
    std::printf("resource_count=%zu\n", t.resource_count());
}

void print_type_kind_histogram(const refuzz_syz::Target& t) {
    using K = refuzz_syz::TypeKind;
    int counts[16] = {};
    for (const auto& up : t.arena().types()) {
        counts[static_cast<int>(up->kind())]++;
    }
    std::printf("\n[type kind histogram]\n");
    for (int i = 0; i <= 12; ++i) {
        std::printf("  %-10s = %d\n",
                    kind_name(static_cast<K>(i)), counts[i]);
    }
}

void print_syscall_signature(const refuzz_syz::SyscallMeta& sc) {
    std::printf("syscall %s (nr=%llu, missing_args=%d, args=%zu)\n",
                sc.name().c_str(),
                (unsigned long long)sc.nr(),
                sc.missing_args(),
                sc.args().size());
    for (size_t i = 0; i < sc.args().size(); ++i) {
        const auto& f = sc.args()[i];
        const refuzz_syz::Type* t = f.type();
        std::printf("  arg[%zu] %s : %s/%s dir=%s%s\n",
                    i, f.name().c_str(),
                    t ? kind_name(t->kind()) : "?",
                    t ? t->name().c_str() : "?",
                    dir_name(f.dir(refuzz_syz::Dir::kIn)),
                    f.condition() ? " [cond]" : "");
    }
    if (sc.ret() != nullptr) {
        std::printf("  ret: %s/%s\n",
                    kind_name(sc.ret()->kind()),
                    sc.ret()->name().c_str());
    } else {
        std::printf("  ret: (none)\n");
    }
}

void print_type_recursive(const refuzz_syz::Type* t, int depth, std::set<const refuzz_syz::Type*>& seen) {
    auto indent = [&] {
        for (int i = 0; i < depth; ++i) std::printf("  ");
    };
    if (!t) { indent(); std::printf("<null>\n"); return; }

    indent();
    std::printf("%s/%s [size=%llu align=%llu opt=%d varlen=%d]",
                kind_name(t->kind()), t->name().c_str(),
                (unsigned long long)t->size(),
                (unsigned long long)t->align(),
                t->optional() ? 1 : 0,
                t->var_len() ? 1 : 0);

    if (auto* st = refuzz_syz::as_struct(t)) {
        std::printf(" fields=%zu align_attr=%llu overlay=%d\n",
                    st->fields().size(),
                    (unsigned long long)st->align_attr(),
                    st->overlay_field());
        if (seen.count(t)) { indent(); std::printf("  ...(seen)\n"); return; }
        seen.insert(t);
        for (const auto& f : st->fields()) {
            indent(); std::printf("  field %s%s:\n",
                f.name().c_str(), f.condition() ? " [cond]" : "");
            print_type_recursive(f.type(), depth + 2, seen);
        }
    } else if (auto* ut = refuzz_syz::as_union(t)) {
        std::printf(" fields=%zu cond=%d\n",
                    ut->fields().size(), ut->is_conditional() ? 1 : 0);
        if (seen.count(t)) { indent(); std::printf("  ...(seen)\n"); return; }
        seen.insert(t);
        for (const auto& f : ut->fields()) {
            indent(); std::printf("  arm %s%s:\n",
                f.name().c_str(), f.condition() ? " [cond]" : "");
            print_type_recursive(f.type(), depth + 2, seen);
        }
    } else if (auto* pt = refuzz_syz::as_ptr(t)) {
        std::printf(" elem_dir=%s sq=%d\n", dir_name(pt->elem_dir()),
                    pt->squashable_elem() ? 1 : 0);
        print_type_recursive(pt->elem(), depth + 1, seen);
    } else if (auto* at = refuzz_syz::as_array(t)) {
        std::printf(" range=[%llu,%llu] kind=%d\n",
                    (unsigned long long)at->range_begin(),
                    (unsigned long long)at->range_end(),
                    static_cast<int>(at->array_kind()));
        print_type_recursive(at->elem(), depth + 1, seen);
    } else if (auto* bt = refuzz_syz::as_buffer(t)) {
        std::printf(" buf_kind=%d sub=%s vals=%zu noz=%d\n",
                    static_cast<int>(bt->buffer_kind()),
                    bt->sub_kind().c_str(),
                    bt->values().size(),
                    bt->no_z() ? 1 : 0);
    } else if (auto* it = refuzz_syz::as_int(t)) {
        std::printf(" range=[%llu,%llu]\n",
                    (unsigned long long)it->range_begin(),
                    (unsigned long long)it->range_end());
    } else if (auto* ct = refuzz_syz::as_const(t)) {
        std::printf(" val=%llu pad=%d\n",
                    (unsigned long long)ct->val(), ct->is_pad() ? 1 : 0);
    } else if (auto* ft = refuzz_syz::as_flags(t)) {
        std::printf(" vals=%zu bitmask=%d\n",
                    ft->vals().size(), ft->bitmask() ? 1 : 0);
    } else if (auto* lt = refuzz_syz::as_len(t)) {
        std::printf(" path=[");
        for (size_t i = 0; i < lt->path().size(); ++i) {
            std::printf("%s%s", i ? "," : "", lt->path()[i].c_str());
        }
        std::printf("] bit_size=%llu offset=%d\n",
                    (unsigned long long)lt->bit_size(), lt->offset() ? 1 : 0);
    } else if (auto* rt = refuzz_syz::as_resource(t)) {
        std::printf(" res=%s\n", rt->desc() ? rt->desc()->name().c_str() : "(null)");
    } else if (auto* csm = refuzz_syz::as_csum(t)) {
        std::printf(" csum_kind=%d buf=%s proto=%llu\n",
                    static_cast<int>(csm->csum_kind()),
                    csm->buf().c_str(),
                    (unsigned long long)csm->protocol());
    } else if (auto* pr = refuzz_syz::as_proc(t)) {
        std::printf(" start=%llu per_proc=%llu\n",
                    (unsigned long long)pr->values_start(),
                    (unsigned long long)pr->values_per_proc());
    } else if (auto* vm = refuzz_syz::as_vma(t)) {
        std::printf(" range=[%llu,%llu] pages\n",
                    (unsigned long long)vm->range_begin(),
                    (unsigned long long)vm->range_end());
    } else {
        std::printf("\n");
    }
}

} // namespace

int main(int argc, char** argv) {
    const auto& target = refuzz_syz::Target::linux_amd64();

    print_summary(target);
    print_type_kind_histogram(target);

    // Probe a representative set of syscalls.
    static const char* probes[] = {
        "read", "write", "readv", "writev", "openat", "close",
        "socket$inet", "bind$inet", "connect$inet",
        "ioctl", "mmap", "munmap",
        "syz_open_dev$loop", "syz_genetlink_get_family_id$nl80211",
    };

    std::printf("\n[probes]\n");
    for (const char* name : probes) {
        const auto* sc = target.find_syscall(name);
        if (!sc) {
            std::printf("MISSING: %s\n", name);
            continue;
        }
        print_syscall_signature(*sc);
    }

    // Deep-dump one representative syscall (readv).
    if (const auto* sc = target.find_syscall("readv")) {
        std::printf("\n[deep dump: readv]\n");
        for (size_t i = 0; i < sc->args().size(); ++i) {
            const auto& f = sc->args()[i];
            std::printf("arg[%zu] %s:\n", i, f.name().c_str());
            std::set<const refuzz_syz::Type*> seen;
            print_type_recursive(f.type(), 1, seen);
        }
    }

    return 0;
}
