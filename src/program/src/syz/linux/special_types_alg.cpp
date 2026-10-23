// Port of upstream sys/linux/init_alg.go.
//
//   sockaddr_alg     -> generateSockaddrAlg
//   alg_name         -> generateAlgName (random root category)
//   alg_aead_name    -> generateAlgAeadName    (root = AEAD)
//   alg_hash_name    -> generateAlgHashName    (root = HASH)
//   alg_skcipher_name-> generateAlgSkcipherhName (root = SKCIPHER)

#include "alg_tables.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace refuzz::program::syz::linux_special_types {

namespace {

// Mirror of fixedSizeData: pad with zero bytes or truncate to `sz`.
std::vector<std::uint8_t> fixed_size_data(const std::string& s, std::uint64_t sz) {
    std::vector<std::uint8_t> out(sz, 0);
    const std::size_t n = std::min(static_cast<std::size_t>(sz), s.size());
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<std::uint8_t>(s[i]);
    }
    return out;
}

// Mirror of generateAlgImpl: recursively expand "name(arg, arg, ...)".
std::string generate_alg_impl(Target::IGen* g, const AlgDesc& alg);

// Mirror of generateAlg: pick a random alg of a category and expand.
std::string generate_alg(Target::IGen* g, AlgKind kind) {
    const auto& algs = algs_for(kind);
    if (algs.empty()) return {};
    const int idx = g->rand(static_cast<int>(algs.size()));
    return generate_alg_impl(g, algs[idx]);
}

std::string generate_alg_impl(Target::IGen* g, const AlgDesc& alg) {
    std::string out = alg.name;
    if (!alg.args.empty()) {
        out += '(';
        for (std::size_t i = 0; i < alg.args.size(); ++i) {
            if (i != 0) out += ',';
            out += generate_alg(g, alg.args[i]);
        }
        out += ')';
    }
    return out;
}

// Mirror of generateAlgName (root): pick a category uniformly, then
// expand. Returns {category-string, alg-name-string}.
struct GeneratedRootAlg {
    std::string type_name;
    std::string alg_name;
};
GeneratedRootAlg generate_root_alg(Target::IGen* g) {
    const auto& names = alg_type_names();
    const int idx = g->rand(static_cast<int>(names.size()));
    return {names[idx].name, generate_alg(g, names[idx].kind)};
}

std::unique_ptr<DataArg> make_data(const Type* t, Dir d,
                                   std::vector<std::uint8_t> bytes) {
    auto a = std::make_unique<DataArg>();
    a->set_type(t);
    a->set_dir(d);
    a->set_data(std::move(bytes));
    return a;
}

std::unique_ptr<ConstArg> make_const(const Type* t, Dir d, std::uint64_t v) {
    auto a = std::make_unique<ConstArg>();
    a->set_type(t);
    a->set_dir(d);
    a->set_val(v);
    return a;
}

std::unique_ptr<GroupArg> make_group(const Type* t, Dir d,
                                     std::vector<std::unique_ptr<Arg>> inner) {
    auto a = std::make_unique<GroupArg>();
    a->set_type(t);
    a->set_dir(d);
    a->set_inner(std::move(inner));
    return a;
}

// Mirror of generateAlgNameStruct: a 1-field struct holding the alg
// name as a fixed-size data blob.
std::unique_ptr<Arg>
generate_alg_name_struct(Target::IGen* g, const Type* typ0, Dir dir,
                         AlgKind alg_kind) {
    if (typ0 == nullptr || typ0->kind() != TypeKind::kStruct) return nullptr;
    const auto* s = static_cast<const StructType*>(typ0);
    if (s->fields().empty()) return nullptr;
    const std::string alg = generate_alg(g, alg_kind);
    const std::uint64_t sz = s->fields()[0].type()->size();
    std::vector<std::unique_ptr<Arg>> inner;
    inner.push_back(make_data(s->fields()[0].type(), dir,
                              fixed_size_data(alg, sz)));
    return make_group(s, dir, std::move(inner));
}

std::unique_ptr<Arg>
generate_sockaddr_alg(Target::IGen* g, const Type* typ0, Dir dir,
                      const Arg* /*old*/,
                      std::vector<std::unique_ptr<Call>>* calls_out) {
    if (typ0 == nullptr || typ0->kind() != TypeKind::kStruct) return nullptr;
    const auto* s = static_cast<const StructType*>(typ0);
    if (s->fields().size() < 5) return nullptr;

    auto family = g->generate_arg(s->fields()[0].type(), dir, calls_out);
    if (family == nullptr) return nullptr;

    // feat / mask are both ConstArg(0) — generating real values almost
    // never makes a bind() succeed; upstream takes the same shortcut
    // with a 1/1000 escape hatch.
    std::unique_ptr<Arg> feat = make_const(s->fields()[2].type(), dir, 0);
    std::unique_ptr<Arg> mask = make_const(s->fields()[3].type(), dir, 0);
    if (g->n_out_of(1, 1000)) {
        feat = g->generate_arg(s->fields()[2].type(), dir, calls_out);
        mask = g->generate_arg(s->fields()[3].type(), dir, calls_out);
    }

    const auto root = generate_root_alg(g);
    auto type_data = make_data(s->fields()[1].type(), dir,
                               fixed_size_data(root.type_name,
                                               s->fields()[1].type()->size()));
    auto name_data = make_data(s->fields()[4].type(), dir,
                               fixed_size_data(root.alg_name,
                                               s->fields()[4].type()->size()));

    std::vector<std::unique_ptr<Arg>> inner;
    inner.push_back(std::move(family));
    inner.push_back(std::move(type_data));
    inner.push_back(std::move(feat));
    inner.push_back(std::move(mask));
    inner.push_back(std::move(name_data));
    return make_group(s, dir, std::move(inner));
}

std::unique_ptr<Arg>
generate_alg_name(Target::IGen* g, const Type* typ, Dir dir,
                  const Arg* /*old*/,
                  std::vector<std::unique_ptr<Call>>* /*calls*/) {
    const auto& names = alg_type_names();
    const int idx = g->rand(static_cast<int>(names.size()));
    return generate_alg_name_struct(g, typ, dir, names[idx].kind);
}

template <AlgKind K>
std::unique_ptr<Arg>
generate_alg_name_fixed(Target::IGen* g, const Type* typ, Dir dir,
                        const Arg* /*old*/,
                        std::vector<std::unique_ptr<Call>>* /*calls*/) {
    return generate_alg_name_struct(g, typ, dir, K);
}

} // namespace

Target::SpecialTypeFn make_sockaddr_alg_fn() {
    return generate_sockaddr_alg;
}

Target::SpecialTypeFn make_alg_name_fn() {
    return generate_alg_name;
}

Target::SpecialTypeFn make_alg_aead_name_fn() {
    return generate_alg_name_fixed<AlgKind::kAead>;
}

Target::SpecialTypeFn make_alg_hash_name_fn() {
    return generate_alg_name_fixed<AlgKind::kHash>;
}

Target::SpecialTypeFn make_alg_skcipher_name_fn() {
    return generate_alg_name_fixed<AlgKind::kSkcipher>;
}

} // namespace refuzz::program::syz::linux_special_types
