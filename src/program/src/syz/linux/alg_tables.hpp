// Static crypto algorithm tables ported from upstream
// sys/linux/init_alg.go's allTypes + allAlgs maps. Owned by the
// linux/amd64 SpecialType bodies for sockaddr_alg + alg_*_name
// generation.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::program::syz::linux_special_types {

enum class AlgKind : uint8_t {
    kCipher   = 0,
    kSkcipher = 1,
    kAead     = 2,
    kHash     = 3,
    kRng      = 4,
};

struct AlgDesc {
    const char*           name;
    std::vector<AlgKind>  args;  // recursive parameter categories
};

struct AlgTypeName {
    const char*  name;
    AlgKind      kind;
};

const std::vector<AlgDesc>&     algs_for(AlgKind k);
const std::vector<AlgTypeName>& alg_type_names();

} // namespace refuzz::program::syz::linux_special_types
