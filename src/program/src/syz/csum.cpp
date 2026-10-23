// Implementation of refuzz/program/syz/csum.hpp.
//
// Port of prog/checksum.go. Runs ForeachArg over a Call, builds the
// parents map (struct/union → fields), then for each CsumType either
// emits a single inet chunk or composes a pseudo-csum (ipv4/ipv6).

#include "refuzz/program/syz/csum.hpp"

#include "refuzz/program/syz/analysis.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>

namespace refuzz::program::syz {

namespace {

constexpr const char* kParentRef = "parent";

uint16_t swap16(uint16_t v) {
    return static_cast<uint16_t>(((v & 0x00FFu) << 8) | ((v & 0xFF00u) >> 8));
}

uint32_t swap32(uint32_t v) {
    return  ((v & 0x000000FFu) << 24)
          | ((v & 0x0000FF00u) << 8)
          | ((v & 0x00FF0000u) >> 8)
          | ((v & 0xFF000000u) >> 24);
}

// Returns the parent struct of arg, or nullptr.
Arg* parent_of(const std::unordered_map<Arg*, Arg*>& parents_map, Arg* a) {
    auto it = parents_map.find(a);
    return it == parents_map.end() ? nullptr : it->second;
}

// Mirror of prog.findCsummedArg.
Arg* find_csummed_arg(Arg* arg, const CsumType* typ,
                      const std::unordered_map<Arg*, Arg*>& parents_map) {
    if (typ->buf() == kParentRef) {
        Arg* p = parent_of(parents_map, arg);
        if (p == nullptr) {
            throw std::runtime_error("csum parent not in parents map");
        }
        return p;
    }
    for (Arg* parent = parent_of(parents_map, arg);
         parent != nullptr;
         parent = parent_of(parents_map, parent)) {
        if (parent->type() != nullptr && parent->type()->name() == typ->buf()) {
            return parent;
        }
    }
    throw std::runtime_error("csum field references non-existent parent: " +
                             typ->buf());
}

// Mirror of prog.getFieldByName.
Arg* get_field_by_name(GroupArg* group, const std::string& name) {
    auto* st = as_struct(group->type());
    if (st == nullptr) return nullptr;
    const auto& fields = st->fields();
    for (std::size_t i = 0; i < fields.size() && i < group->inner().size(); ++i) {
        if (fields[i].name() == name) {
            return group->inner()[i].get();
        }
    }
    return nullptr;
}

// Mirror of prog.extractHeaderParams.
struct HeaderParams { Arg* src = nullptr; Arg* dst = nullptr; };

HeaderParams extract_header_params(GroupArg* arg, uint64_t expected_size) {
    HeaderParams hp;
    hp.src = get_field_by_name(arg, "src_ip");
    hp.dst = get_field_by_name(arg, "dst_ip");
    if (hp.src == nullptr || hp.dst == nullptr) {
        throw std::runtime_error("csum: src_ip/dst_ip not found");
    }
    if (hp.src->size() != expected_size || hp.dst->size() != expected_size) {
        throw std::runtime_error("csum: src/dst_ip wrong size");
    }
    return hp;
}

CsumInfo compose_pseudo_v4(Arg* tcp_packet, Arg* src, Arg* dst, uint8_t proto) {
    CsumInfo info{CsumKind::kInet, {}};
    info.chunks.push_back({CsumChunkKind::kArg,   src,         0, 0});
    info.chunks.push_back({CsumChunkKind::kArg,   dst,         0, 0});
    info.chunks.push_back({CsumChunkKind::kConst, nullptr,
                           static_cast<uint64_t>(swap16(static_cast<uint16_t>(proto))), 2});
    info.chunks.push_back({CsumChunkKind::kConst, nullptr,
                           static_cast<uint64_t>(swap16(static_cast<uint16_t>(tcp_packet->size()))), 2});
    info.chunks.push_back({CsumChunkKind::kArg,   tcp_packet,  0, 0});
    return info;
}

CsumInfo compose_pseudo_v6(Arg* tcp_packet, Arg* src, Arg* dst, uint8_t proto) {
    CsumInfo info{CsumKind::kInet, {}};
    info.chunks.push_back({CsumChunkKind::kArg,   src,         0, 0});
    info.chunks.push_back({CsumChunkKind::kArg,   dst,         0, 0});
    info.chunks.push_back({CsumChunkKind::kConst, nullptr,
                           static_cast<uint64_t>(swap32(static_cast<uint32_t>(tcp_packet->size()))), 4});
    info.chunks.push_back({CsumChunkKind::kConst, nullptr,
                           static_cast<uint64_t>(swap32(static_cast<uint32_t>(proto))), 4});
    info.chunks.push_back({CsumChunkKind::kArg,   tcp_packet,  0, 0});
    return info;
}

} // namespace

CsumAnalysis calc_checksums_call(Call* c) {
    CsumAnalysis out;
    if (c == nullptr) return out;

    std::vector<Arg*> inet_csum_fields;
    std::vector<Arg*> pseudo_csum_fields;

    foreach_arg(c, [&](Arg* a, ArgCtx*) {
        if (auto* ct = as_csum(a->type())) {
            switch (ct->csum_kind()) {
                case CsumKind::kInet:   inet_csum_fields.push_back(a); break;
                case CsumKind::kPseudo: pseudo_csum_fields.push_back(a); break;
            }
        }
    });

    if (inet_csum_fields.empty() && pseudo_csum_fields.empty()) {
        return out;
    }

    // Build parents_map: child arg → struct arg containing it. The Go
    // version uses InnerArg(field) so pointer wrappers are stripped.
    std::unordered_map<Arg*, Arg*> parents_map;
    foreach_arg(c, [&](Arg* a, ArgCtx*) {
        if (a->type() != nullptr && a->type()->kind() == TypeKind::kStruct) {
            auto* group = static_cast<GroupArg*>(a);
            for (auto& up : group->mutable_inner()) {
                Arg* inner = inner_arg(up.get());
                if (inner != nullptr) {
                    parents_map[inner] = a;
                }
            }
        }
    });

    // Inet checksums.
    for (Arg* arg : inet_csum_fields) {
        auto* ct = as_csum(arg->type());
        Arg* csummed = find_csummed_arg(arg, ct, parents_map);
        out.csum_uses.insert(csummed);
        CsumInfo info{CsumKind::kInet, {}};
        info.chunks.push_back({CsumChunkKind::kArg, csummed, 0, 0});
        out.csum_map.emplace(arg, std::move(info));
    }

    if (pseudo_csum_fields.empty()) return out;

    // Find ipv4/ipv6 src/dst.
    Arg* ip_src = nullptr;
    Arg* ip_dst = nullptr;
    foreach_arg(c, [&](Arg* a, ArgCtx*) {
        if (a->type() == nullptr) return;
        if (a->type()->kind() != TypeKind::kStruct) return;
        std::string tn = a->type()->template_name();
        auto* group = static_cast<GroupArg*>(a);
        if (tn == "ipv4_header" || tn == "syz_csum_ipv4_header") {
            auto hp = extract_header_params(group, 4);
            ip_src = hp.src;
            ip_dst = hp.dst;
        } else if (tn == "ipv6_packet_t" || tn == "syz_csum_ipv6_header") {
            auto hp = extract_header_params(group, 16);
            ip_src = hp.src;
            ip_dst = hp.dst;
        }
    });

    if (ip_src == nullptr || ip_dst == nullptr) {
        throw std::runtime_error("pseudo csum: no ipv4 nor ipv6 header found");
    }

    for (Arg* arg : pseudo_csum_fields) {
        auto* ct = as_csum(arg->type());
        Arg* csummed = find_csummed_arg(arg, ct, parents_map);
        const auto proto = static_cast<uint8_t>(ct->protocol());
        CsumInfo info = (ip_src->size() == 4)
                ? compose_pseudo_v4(csummed, ip_src, ip_dst, proto)
                : compose_pseudo_v6(csummed, ip_src, ip_dst, proto);
        out.csum_map.emplace(arg, std::move(info));
        out.csum_uses.insert(csummed);
        out.csum_uses.insert(ip_src);
        out.csum_uses.insert(ip_dst);
    }

    return out;
}

} // namespace refuzz::program::syz
