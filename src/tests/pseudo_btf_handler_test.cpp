// PR-A3 — syz_btf_id_by_name$bpf_lsm handler behavioral test.
//
// `ScanBtfForName` is the pure-function core of `BtfIdByName`. It takes
// a BTF blob (header + type section + string section) and looks up the
// 1-based type id of a named entry. This test drives it with a tiny
// synthetic BTF blob — no /sys/kernel/btf/vmlinux required, runs on any
// host.
//
// `ReadBtfVmlinux` (the IO half) is exercised only when the host actually
// has a BTF kernel; that's an operator-environment concern documented as
// a runtime smoke (no CI gate).

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/btf.h>
#include <vector>

namespace refuzz::worker::pseudo {
long ScanBtfForName(const char* btf, std::size_t btf_len, const char* target);
}

namespace {

// Build a minimal valid BTF blob with three types:
//   id 1: KIND_INT  name="int"          (12-byte type + 4-byte int encoding)
//   id 2: KIND_FUNC_PROTO name="target_type"  (12-byte type + 0 params)
//   id 3: KIND_INT  name="extra"        (12-byte type + 4-byte int encoding)
//
// Layout (offsets from blob base):
//   [0  .. 24)  btf_header (24 bytes)
//   [24 .. 68)  type section (44 bytes)
//   [68 .. 91)  string section (23 bytes: "\0int\0target_type\0extra\0")
std::vector<char> BuildFakeBtf()
{
    constexpr std::uint32_t kKindInt        = 1;
    constexpr std::uint32_t kKindFuncProto  = 13;

    std::vector<char> blob(91, 0);

    // Header
    auto* hdr = reinterpret_cast<::btf_header*>(blob.data());
    hdr->magic    = 0xeB9F;
    hdr->version  = 1;
    hdr->flags    = 0;
    hdr->hdr_len  = 24;
    hdr->type_off = 0;
    hdr->type_len = 44;
    hdr->str_off  = 44;
    hdr->str_len  = 23;

    // Type section
    char* type_sec = blob.data() + hdr->hdr_len;

    auto* t1 = reinterpret_cast<::btf_type*>(type_sec);
    t1->name_off = 1;                       // "int"
    t1->info     = (kKindInt << 24);        // vlen=0
    t1->size     = 4;
    // 4-byte int encoding follows t1
    *reinterpret_cast<std::uint32_t*>(type_sec + sizeof(::btf_type)) = 0x01000020U;

    auto* t2 = reinterpret_cast<::btf_type*>(type_sec + 16);
    t2->name_off = 5;                       // "target_type"
    t2->info     = (kKindFuncProto << 24);  // vlen=0 → no extra payload
    t2->size     = 0;

    auto* t3 = reinterpret_cast<::btf_type*>(type_sec + 28);
    t3->name_off = 17;                      // "extra"
    t3->info     = (kKindInt << 24);
    t3->size     = 4;
    *reinterpret_cast<std::uint32_t*>(type_sec + 28 + sizeof(::btf_type)) = 0x01000020U;

    // String section
    char* str_sec = blob.data() + hdr->hdr_len + hdr->str_off;
    str_sec[0]  = '\0';
    std::memcpy(str_sec + 1,  "int", 4);            // 1..4 + '\0'
    std::memcpy(str_sec + 5,  "target_type", 12);   // 5..16 + '\0'
    std::memcpy(str_sec + 17, "extra", 6);          // 17..22 + '\0'

    return blob;
}

void TestScanFindsFirstType()
{
    auto blob = BuildFakeBtf();
    long id = refuzz::worker::pseudo::ScanBtfForName(
        blob.data(), blob.size(), "int");
    assert(id == 1);
}

void TestScanFindsMiddleType()
{
    auto blob = BuildFakeBtf();
    long id = refuzz::worker::pseudo::ScanBtfForName(
        blob.data(), blob.size(), "target_type");
    assert(id == 2);
}

void TestScanFindsLastType()
{
    auto blob = BuildFakeBtf();
    long id = refuzz::worker::pseudo::ScanBtfForName(
        blob.data(), blob.size(), "extra");
    assert(id == 3);
}

void TestScanReturnsMinusOneOnMiss()
{
    auto blob = BuildFakeBtf();
    long id = refuzz::worker::pseudo::ScanBtfForName(
        blob.data(), blob.size(), "missing_type");
    assert(id == -1);
}

void TestScanRejectsBadMagic()
{
    auto blob = BuildFakeBtf();
    auto* hdr = reinterpret_cast<::btf_header*>(blob.data());
    hdr->magic = 0xdead;
    long id = refuzz::worker::pseudo::ScanBtfForName(
        blob.data(), blob.size(), "int");
    assert(id == -1);
}

void TestScanRejectsTruncated()
{
    auto blob = BuildFakeBtf();
    long id = refuzz::worker::pseudo::ScanBtfForName(
        blob.data(), 10, "int");  // smaller than header
    assert(id == -1);
}

void TestScanRejectsNullArgs()
{
    assert(refuzz::worker::pseudo::ScanBtfForName(nullptr, 0, "x") == -1);
    auto blob = BuildFakeBtf();
    assert(refuzz::worker::pseudo::ScanBtfForName(blob.data(), blob.size(), nullptr) == -1);
}

void TestScanRejectsOutOfBoundsSection()
{
    auto blob = BuildFakeBtf();
    auto* hdr = reinterpret_cast<::btf_header*>(blob.data());
    hdr->type_len = 0xffffffffU;  // claim type section beyond blob
    long id = refuzz::worker::pseudo::ScanBtfForName(
        blob.data(), blob.size(), "int");
    assert(id == -1);
}

void TestScanDoesNotPrefixMatch()
{
    // "int" should not match "integer" prefix when only "int" is the
    // entry name. (The reverse: search "integer" vs entry "int" → -1.)
    auto blob = BuildFakeBtf();
    long id = refuzz::worker::pseudo::ScanBtfForName(
        blob.data(), blob.size(), "in");
    // "in" is a prefix of "int" but should not match (handler enforces
    // null-terminator equality).
    assert(id == -1);
}

} // namespace

int main()
{
    TestScanFindsFirstType();
    TestScanFindsMiddleType();
    TestScanFindsLastType();
    TestScanReturnsMinusOneOnMiss();
    TestScanRejectsBadMagic();
    TestScanRejectsTruncated();
    TestScanRejectsNullArgs();
    TestScanRejectsOutOfBoundsSection();
    TestScanDoesNotPrefixMatch();
    return 0;
}
