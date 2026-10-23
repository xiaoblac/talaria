#include <llvm/Demangle/Demangle.h>

#include <string_view>

extern "C" char* RefuzzDemangleSymbol(const char* symbol)
{
    if (symbol == nullptr) {
        return nullptr;
    }
    const std::string_view name(symbol);
    if (name.rfind("_R", 0) == 0) {
        return llvm::rustDemangle(name);
    }
    if (name.rfind("_Z", 0) == 0) {
        return llvm::itaniumDemangle(name, false);
    }
    return nullptr;
}
