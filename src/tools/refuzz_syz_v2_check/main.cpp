// refuzz-syz-v2-check: integrity self-check for reFuzz v2 IR.
//
// Walks every Type and SyscallMeta in Target::linux_amd64() and asserts
// that every cross-reference (Field.type, PtrType.elem, ArrayType.elem,
// ResourceType.desc, SyscallMeta.args[].type, SyscallMeta.ret) resolves
// to a non-null pointer that is owned by the arena. Any dangling pointer
// is a codegen bug.
//
// Exit code 0 = clean; non-zero = errors with details on stderr.

#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_set>

namespace syz = ::refuzz::program::syz;

namespace {

class Checker {
public:
    Checker(const syz::Target& t) : target_(t) {
        for (const auto& up : target_.arena().types())          known_types_.insert(up.get());
        for (const auto& up : target_.resource_arena().descs()) known_resources_.insert(up.get());
    }

    int run() {
        for (const auto& up : target_.arena().types())          checkType(up.get());
        for (const auto& up : target_.resource_arena().descs()) checkResource(up.get());
        for (const auto& up : target_.syscalls())               checkSyscall(up.get());
        report();
        return errors_ == 0 ? 0 : 1;
    }

private:
    void fail(std::string ctx, std::string msg) {
        if (errors_ < 50) {
            std::fprintf(stderr, "[E] %s: %s\n", ctx.c_str(), msg.c_str());
        } else if (errors_ == 50) {
            std::fprintf(stderr, "[E] ... (truncating further errors)\n");
        }
        errors_++;
    }

    void requirePtr(const syz::Type* t, std::string ctx) {
        if (t == nullptr) {
            fail(ctx, "null Type pointer");
            return;
        }
        if (known_types_.count(t) == 0) {
            fail(ctx, "Type pointer not owned by arena");
        }
    }

    void requireResource(const syz::ResourceDesc* r, std::string ctx) {
        if (r == nullptr) {
            fail(ctx, "null ResourceDesc pointer");
            return;
        }
        if (known_resources_.count(r) == 0) {
            fail(ctx, "ResourceDesc not owned by arena");
        }
    }

    void checkType(const syz::Type* t) {
        if (t == nullptr) {
            fail("Type", "null entry in arena");
            return;
        }
        switch (t->kind()) {
            case syz::TypeKind::kPtr: {
                auto* p = static_cast<const syz::PtrType*>(t);
                requirePtr(p->elem(), "PtrType[" + t->name() + "].elem");
                break;
            }
            case syz::TypeKind::kArray: {
                auto* a = static_cast<const syz::ArrayType*>(t);
                requirePtr(a->elem(), "ArrayType[" + t->name() + "].elem");
                break;
            }
            case syz::TypeKind::kStruct: {
                auto* s = static_cast<const syz::StructType*>(t);
                for (size_t i = 0; i < s->fields().size(); ++i) {
                    requirePtr(s->fields()[i].type(),
                        "StructType[" + t->name() + "].fields[" + std::to_string(i) + "].type");
                }
                break;
            }
            case syz::TypeKind::kUnion: {
                auto* u = static_cast<const syz::UnionType*>(t);
                for (size_t i = 0; i < u->fields().size(); ++i) {
                    requirePtr(u->fields()[i].type(),
                        "UnionType[" + t->name() + "].fields[" + std::to_string(i) + "].type");
                }
                break;
            }
            case syz::TypeKind::kResource: {
                auto* r = static_cast<const syz::ResourceType*>(t);
                requireResource(r->desc(), "ResourceType[" + t->name() + "].desc");
                break;
            }
            // Leaf kinds: no outgoing references to verify.
            case syz::TypeKind::kInt:
            case syz::TypeKind::kConst:
            case syz::TypeKind::kFlags:
            case syz::TypeKind::kProc:
            case syz::TypeKind::kLen:
            case syz::TypeKind::kCsum:
            case syz::TypeKind::kBuffer:
            case syz::TypeKind::kVma:
                break;
        }
        if (t->name().empty()) {
            // Empty names are legal for anonymous types but uncommon — track.
            anon_++;
        }
    }

    void checkResource(const syz::ResourceDesc* r) {
        if (r == nullptr) {
            fail("ResourceDesc", "null entry in arena");
            return;
        }
        if (r->name().empty()) {
            fail("ResourceDesc", "empty name");
        }
        if (r->kind().empty()) {
            fail("ResourceDesc[" + r->name() + "]", "empty kind chain");
        }
        // ctors[].call may be nullptr (we don't populate it currently); skip.
    }

    void checkSyscall(const syz::SyscallMeta* sc) {
        if (sc == nullptr) {
            fail("SyscallMeta", "null entry");
            return;
        }
        if (sc->name().empty()) {
            fail("SyscallMeta", "empty name");
        }
        for (size_t i = 0; i < sc->args().size(); ++i) {
            requirePtr(sc->args()[i].type(),
                "SyscallMeta[" + sc->name() + "].args[" + std::to_string(i) + "].type");
        }
        // ret may be null (most syscalls don't return a resource).
        if (sc->ret() != nullptr) {
            if (known_types_.count(sc->ret()) == 0) {
                fail("SyscallMeta[" + sc->name() + "].ret",
                     "Type pointer not owned by arena");
            }
        }
    }

    void report() {
        std::printf("types_checked=%zu\n",     target_.arena().types().size());
        std::printf("syscalls_checked=%zu\n",  target_.syscalls().size());
        std::printf("resources_checked=%zu\n", target_.resource_arena().descs().size());
        std::printf("anonymous_types=%zu\n",   anon_);
        std::printf("errors=%d\n",             errors_);
    }

    const syz::Target&                            target_;
    std::unordered_set<const syz::Type*>          known_types_;
    std::unordered_set<const syz::ResourceDesc*>  known_resources_;
    int                                           errors_ = 0;
    size_t                                        anon_   = 0;
};

} // namespace

int main() {
    const auto& target = syz::Target::linux_amd64();
    Checker c(target);
    return c.run();
}
