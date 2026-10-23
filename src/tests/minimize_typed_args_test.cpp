// §3.11-C1 P4 — typed artifact per-argument minimization.
//
// These tests use small hand-built syz-v2 programs so they exercise the
// ProgramArtifact -> program::syz::Prog -> typed clone -> serialize_for_exec
// path directly. The predicate inspects exec-wire shape and rejects call
// removal, so accepted commits must come from arg minimization.

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/prog_format.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace crash = ::refuzz::crash;
namespace pr = ::refuzz::program;
namespace syz = ::refuzz::program::syz;

pr::ProgramTargetKey LinuxAmd64Key()
{
    const auto& target = syz::Target::linux_amd64();
    return pr::ProgramTargetKey{target.os(), target.arch(), target.revision()};
}

pr::ProgramArtifact BuildArtifact(std::unique_ptr<syz::Prog> prog)
{
    auto typed_mut = std::shared_ptr<syz::Prog>(std::move(prog));
    std::shared_ptr<const syz::Prog> typed = typed_mut;
    auto canonical = std::make_shared<const std::vector<std::uint8_t>>(
        std::vector<std::uint8_t>{'\n'});

    return pr::ProgramArtifact::Build(
        ::refuzz::fuzzer::ProgFormat::kSyzProg,
        LinuxAmd64Key(),
        std::static_pointer_cast<const void>(typed),
        typeid(syz::Prog),
        canonical,
        {});
}

std::unique_ptr<syz::Prog> MakeProg()
{
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&syz::Target::linux_amd64());
    return prog;
}

void SetSingleArgMeta(syz::SyscallMeta& meta,
                      const char* name,
                      std::uint64_t id,
                      const syz::Type* arg_type)
{
    meta.set_name(name);
    meta.set_call_name(name);
    meta.set_id(id);
    std::vector<syz::Field> fields;
    fields.emplace_back("arg", arg_type);
    meta.set_args(std::move(fields));
}

std::unique_ptr<syz::ConstArg> MakeConstArg(const syz::Type* type,
                                            std::uint64_t value)
{
    auto arg = std::make_unique<syz::ConstArg>();
    arg->set_type(type);
    arg->set_dir(syz::Dir::kIn);
    arg->set_val(value);
    return arg;
}

std::unique_ptr<syz::DataArg> MakeDataArg(const syz::Type* type,
                                          std::vector<std::uint8_t> data)
{
    auto arg = std::make_unique<syz::DataArg>();
    arg->set_type(type);
    arg->set_dir(syz::Dir::kIn);
    arg->set_data(std::move(data));
    return arg;
}

syz::WireProgram DecodeWire(const std::vector<std::uint8_t>& payload)
{
    auto wire_or = syz::decode_exec_wire(
        std::span<const std::uint8_t>(payload.data(), payload.size()));
    CHECK(wire_or.has_value());
    return std::move(*wire_or);
}

std::vector<const syz::WireCall*> WireCalls(const syz::WireProgram& wire)
{
    std::vector<const syz::WireCall*> calls;
    for (const auto& instr : wire.instrs) {
        if (const auto* call = std::get_if<syz::WireCall>(&instr)) {
            calls.push_back(call);
        }
    }
    return calls;
}

bool HasCopyin(const syz::WireProgram& wire)
{
    for (const auto& instr : wire.instrs) {
        if (std::holds_alternative<syz::WireCopyin>(instr)) {
            return true;
        }
    }
    return false;
}

bool FirstCallArgIsConst(const syz::WireProgram& wire, std::uint64_t value)
{
    const auto calls = WireCalls(wire);
    if (calls.size() != 1 || calls[0]->args.size() != 1) {
        return false;
    }
    const auto* arg = std::get_if<syz::WireConst>(&calls[0]->args[0]);
    return arg != nullptr && arg->val == value;
}

bool FirstCallArgIsDataLen(const syz::WireProgram& wire, std::size_t len)
{
    const auto calls = WireCalls(wire);
    if (calls.size() != 1 || calls[0]->args.size() != 1) {
        return false;
    }
    const auto* arg = std::get_if<syz::WireData>(&calls[0]->args[0]);
    return arg != nullptr && arg->data.size() == len;
}

bool FirstCallArgDataEquals(const syz::WireProgram& wire,
                            const std::vector<std::uint8_t>& data)
{
    const auto calls = WireCalls(wire);
    if (calls.size() != 1 || calls[0]->args.size() != 1) {
        return false;
    }
    const auto* arg = std::get_if<syz::WireData>(&calls[0]->args[0]);
    // WireData::data is now a std::span into the wire buffer (no operator==);
    // compare element-wise with size check.
    return arg != nullptr &&
           std::equal(arg->data.begin(), arg->data.end(),
                      data.begin(), data.end());
}

bool FirstCallArgIsAddr(const syz::WireProgram& wire, std::uint64_t addr)
{
    const auto calls = WireCalls(wire);
    if (calls.size() != 1 || calls[0]->args.size() != 1) {
        return false;
    }
    const auto* arg = std::get_if<syz::WireAddr>(&calls[0]->args[0]);
    return arg != nullptr && arg->addr == addr;
}

bool HasCopyinConstValue(const syz::WireProgram& wire, std::uint64_t value)
{
    for (const auto& instr : wire.instrs) {
        const auto* copyin = std::get_if<syz::WireCopyin>(&instr);
        if (copyin == nullptr) {
            continue;
        }
        const auto* arg = std::get_if<syz::WireConst>(&copyin->arg);
        if (arg != nullptr && arg->val == value) {
            return true;
        }
    }
    return false;
}

crash::StopFunc NeverStop()
{
    return [] { return false; };
}

void TestScalarDefaultMinimize()
{
    syz::IntType int_type;
    int_type.set_name("int64");
    int_type.set_size(8);
    int_type.set_align(8);

    syz::SyscallMeta meta;
    SetSingleArgMeta(meta, "scalar_min", 100, &int_type);

    auto prog = MakeProg();
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(MakeConstArg(&int_type, 7));
    prog->add_call(std::move(call));

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        return {FirstCallArgIsConst(DecodeWire(payload), 0), "target"};
    };

    auto result = minimizer.Minimize(BuildArtifact(std::move(prog)),
                                     std::move(test_fn),
                                     NeverStop(),
                                     crash::MinimizeMode::kCrashSnapshot,
                                     -1);

    CHECK(result.success);
    CHECK(result.minimize_stage == "arg scalar");
    CHECK(FirstCallArgIsConst(DecodeWire(result.payload), 0));
}

void TestNonOptionalProcIsNotDefaulted()
{
    syz::ProcType proc_type;
    proc_type.set_name("proc");
    proc_type.set_size(8);
    proc_type.set_align(8);
    proc_type.set_values_start(100);
    proc_type.set_values_per_proc(10);

    syz::SyscallMeta meta;
    SetSingleArgMeta(meta, "proc_min", 101, &proc_type);

    auto prog = MakeProg();
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(MakeConstArg(&proc_type, 3));
    prog->add_call(std::move(call));

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        return {!FirstCallArgIsConst(DecodeWire(payload), 103), "target"};
    };

    auto result = minimizer.Minimize(BuildArtifact(std::move(prog)),
                                     std::move(test_fn),
                                     NeverStop(),
                                     crash::MinimizeMode::kCrashSnapshot,
                                     -1);

    CHECK(result.success);
    CHECK(result.minimize_commits == 0);
    CHECK(FirstCallArgIsConst(DecodeWire(result.payload), 103));
}

void TestResourceMinimizeDropsProducerReference()
{
    syz::ResourceDesc fd_desc{"fd", {"fd"}, {0xffffffffffffffffULL}};
    syz::ResourceType fd_type;
    fd_type.set_name("fd");
    fd_type.set_size(8);
    fd_type.set_align(8);
    fd_type.set_desc(&fd_desc);

    syz::SyscallMeta producer_meta;
    producer_meta.set_name("make_fd");
    producer_meta.set_call_name("make_fd");
    producer_meta.set_id(110);
    producer_meta.set_ret(&fd_type);

    syz::SyscallMeta consumer_meta;
    SetSingleArgMeta(consumer_meta, "use_fd", 111, &fd_type);

    auto prog = MakeProg();
    auto producer = std::make_unique<syz::Call>();
    producer->set_meta(&producer_meta);
    auto ret = std::make_unique<syz::ResultArg>();
    ret->set_type(&fd_type);
    ret->set_dir(syz::Dir::kOut);
    ret->set_val(0);
    auto* ret_raw = ret.get();
    producer->set_ret(std::move(ret));
    prog->add_call(std::move(producer));

    auto consumer = std::make_unique<syz::Call>();
    consumer->set_meta(&consumer_meta);
    auto arg = std::make_unique<syz::ResultArg>();
    arg->set_type(&fd_type);
    arg->set_dir(syz::Dir::kIn);
    arg->set_res(ret_raw);
    consumer->add_arg(std::move(arg));
    prog->add_call(std::move(consumer));

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        const auto wire = DecodeWire(payload);
        const auto calls = WireCalls(wire);
        if (calls.size() != 2 || calls[1]->args.size() != 1) {
            return {false, {}};
        }
        const auto* arg0 = std::get_if<syz::WireConst>(&calls[1]->args[0]);
        return {arg0 != nullptr && arg0->val == 0xffffffffffffffffULL, "target"};
    };

    auto result = minimizer.Minimize(BuildArtifact(std::move(prog)),
                                     std::move(test_fn),
                                     NeverStop(),
                                     crash::MinimizeMode::kCrashSnapshot,
                                     -1);

    CHECK(result.success);
    CHECK(result.minimize_stage == "arg resource");
}

void TestBufferRangeShrink()
{
    syz::BufferType buffer_type;
    buffer_type.set_name("blob");
    buffer_type.set_var_len(true);
    buffer_type.set_buffer_kind(syz::BufferKind::kBlobRange);
    buffer_type.set_range(1, 4);

    syz::SyscallMeta meta;
    SetSingleArgMeta(meta, "buffer_min", 120, &buffer_type);

    auto prog = MakeProg();
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(MakeDataArg(&buffer_type, {1, 2, 3, 4}));
    prog->add_call(std::move(call));

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        return {FirstCallArgIsDataLen(DecodeWire(payload), 1), "target"};
    };

    auto result = minimizer.Minimize(BuildArtifact(std::move(prog)),
                                     std::move(test_fn),
                                     NeverStop(),
                                     crash::MinimizeMode::kCrashSnapshot,
                                     -1);

    CHECK(result.success);
    CHECK(result.minimize_stage == "arg buffer");
    CHECK(FirstCallArgIsDataLen(DecodeWire(result.payload), 1));
}

void TestFilenameTrimRemovesSpecialPad()
{
    syz::BufferType filename_type;
    filename_type.set_name("filename");
    filename_type.set_var_len(true);
    filename_type.set_buffer_kind(syz::BufferKind::kFilename);

    syz::SyscallMeta meta;
    SetSingleArgMeta(meta, "filename_min", 121, &filename_type);

    auto prog = MakeProg();
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(MakeDataArg(&filename_type, {'f', 'o', 'o', 'a', 'a', 0, 0}));
    prog->add_call(std::move(call));

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        return {FirstCallArgDataEquals(DecodeWire(payload), {'f', 'o', 'o', 0}),
                "target"};
    };

    auto result = minimizer.Minimize(BuildArtifact(std::move(prog)),
                                     std::move(test_fn),
                                     NeverStop(),
                                     crash::MinimizeMode::kCrashSnapshot,
                                     -1);

    CHECK(result.success);
    CHECK(result.minimize_stage == "arg buffer");
    CHECK(FirstCallArgDataEquals(DecodeWire(result.payload), {'f', 'o', 'o', 0}));
}

void TestStringBufferIsNotFilenameTrimmed()
{
    syz::BufferType string_type;
    string_type.set_name("string");
    string_type.set_var_len(true);
    string_type.set_buffer_kind(syz::BufferKind::kString);

    syz::SyscallMeta meta;
    SetSingleArgMeta(meta, "string_min", 122, &string_type);

    auto prog = MakeProg();
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(MakeDataArg(&string_type, {'f', 'o', 'o', 'a', 'a', 0, 0}));
    prog->add_call(std::move(call));

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        return {FirstCallArgDataEquals(DecodeWire(payload), {'f', 'o', 'o', 0}),
                "target"};
    };

    auto result = minimizer.Minimize(BuildArtifact(std::move(prog)),
                                     std::move(test_fn),
                                     NeverStop(),
                                     crash::MinimizeMode::kCrashSnapshot,
                                     -1);

    CHECK(result.success);
    CHECK(result.minimize_commits == 0);
    CHECK(FirstCallArgDataEquals(DecodeWire(result.payload),
                                 {'f', 'o', 'o', 'a', 'a', 0, 0}));
}

void TestPointerNullReplacement()
{
    syz::BufferType buffer_type;
    buffer_type.set_name("blob");
    buffer_type.set_var_len(true);
    buffer_type.set_buffer_kind(syz::BufferKind::kBlobRand);

    syz::PtrType ptr_type;
    ptr_type.set_name("ptr");
    ptr_type.set_size(8);
    ptr_type.set_align(8);
    ptr_type.set_elem(&buffer_type);
    ptr_type.set_elem_dir(syz::Dir::kIn);

    syz::SyscallMeta meta;
    SetSingleArgMeta(meta, "ptr_min", 130, &ptr_type);

    auto pointer = std::make_unique<syz::PointerArg>();
    pointer->set_type(&ptr_type);
    pointer->set_dir(syz::Dir::kIn);
    pointer->set_address(0x1000);
    pointer->set_res(MakeDataArg(&buffer_type, {1, 2, 3}));

    auto prog = MakeProg();
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(std::move(pointer));
    prog->add_call(std::move(call));

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        const auto wire = DecodeWire(payload);
        return {!HasCopyin(wire), "target"};
    };

    auto result = minimizer.Minimize(BuildArtifact(std::move(prog)),
                                     std::move(test_fn),
                                     NeverStop(),
                                     crash::MinimizeMode::kCrash,
                                     -1);

    CHECK(result.success);
    CHECK(result.minimize_stage == "arg ptr");
    CHECK(!HasCopyin(DecodeWire(result.payload)));
}

std::unique_ptr<syz::BinaryExpression> MakeCompareEq(
    std::unique_ptr<syz::Expression> left,
    std::unique_ptr<syz::Expression> right)
{
    auto expr = std::make_unique<syz::BinaryExpression>();
    expr->set_op(syz::BinaryOperator::kCompareEq);
    expr->set_left(std::move(left));
    expr->set_right(std::move(right));
    return expr;
}

std::unique_ptr<syz::ValueExpr> MakeValue(std::uint64_t value)
{
    auto expr = std::make_unique<syz::ValueExpr>();
    expr->set_value(value);
    return expr;
}

std::unique_ptr<syz::ValueExpr> MakePathValue(std::vector<std::string> path)
{
    auto expr = std::make_unique<syz::ValueExpr>();
    expr->set_path(std::move(path));
    return expr;
}

void TestScalarMinimizePatchesConditionalUnion()
{
    syz::IntType tag_type;
    tag_type.set_name("tag");
    tag_type.set_size(8);
    tag_type.set_align(8);

    syz::IntType payload_type;
    payload_type.set_name("payload");
    payload_type.set_size(8);
    payload_type.set_align(8);

    syz::ConstType void_type;
    void_type.set_name("void");
    void_type.set_size(8);
    void_type.set_align(8);
    void_type.set_val(0);

    syz::UnionType union_type;
    union_type.set_name("conditional_union");
    union_type.set_size(8);
    union_type.set_align(8);
    std::vector<syz::Field> union_fields;
    union_fields.emplace_back("value", &payload_type);
    union_fields.back().set_condition(MakeCompareEq(
        MakePathValue({"parent", "parent", "tag"}),
        MakeValue(1)));
    union_fields.emplace_back("void", &void_type);
    union_type.set_fields(std::move(union_fields));

    syz::StructType struct_type;
    struct_type.set_name("conditional_struct");
    struct_type.set_size(16);
    struct_type.set_align(8);
    std::vector<syz::Field> struct_fields;
    struct_fields.emplace_back("tag", &tag_type);
    struct_fields.emplace_back("choice", &union_type);
    struct_type.set_fields(std::move(struct_fields));

    syz::PtrType ptr_type;
    ptr_type.set_name("ptr_conditional");
    ptr_type.set_size(8);
    ptr_type.set_align(8);
    ptr_type.set_elem(&struct_type);
    ptr_type.set_elem_dir(syz::Dir::kIn);

    syz::SyscallMeta meta;
    SetSingleArgMeta(meta, "conditional_min", 131, &ptr_type);

    auto group = std::make_unique<syz::GroupArg>();
    group->set_type(&struct_type);
    group->set_dir(syz::Dir::kIn);
    group->add_inner(MakeConstArg(&tag_type, 1));

    auto union_arg = std::make_unique<syz::UnionArg>();
    union_arg->set_type(&union_type);
    union_arg->set_dir(syz::Dir::kIn);
    union_arg->set_index(0);
    union_arg->set_option(MakeConstArg(&payload_type, 0xaa));
    group->add_inner(std::move(union_arg));

    auto pointer = std::make_unique<syz::PointerArg>();
    pointer->set_type(&ptr_type);
    pointer->set_dir(syz::Dir::kIn);
    pointer->set_address(0x1000);
    pointer->set_res(std::move(group));

    auto prog = MakeProg();
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(std::move(pointer));
    prog->add_call(std::move(call));

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        const auto wire = DecodeWire(payload);
        return {HasCopyinConstValue(wire, 0) &&
                    !HasCopyinConstValue(wire, 1) &&
                    !HasCopyinConstValue(wire, 0xaa),
                "target"};
    };

    auto result = minimizer.Minimize(BuildArtifact(std::move(prog)),
                                     std::move(test_fn),
                                     NeverStop(),
                                     crash::MinimizeMode::kCrashSnapshot,
                                     -1);

    CHECK(result.success);
    CHECK(result.minimize_stage == "arg scalar");
    const auto wire = DecodeWire(result.payload);
    CHECK(HasCopyinConstValue(wire, 0));
    CHECK(!HasCopyinConstValue(wire, 1));
    CHECK(!HasCopyinConstValue(wire, 0xaa));
}

void TestArrayRemoveAllFastPath()
{
    syz::IntType int_type;
    int_type.set_name("int64");
    int_type.set_size(8);
    int_type.set_align(8);

    syz::ArrayType array_type;
    array_type.set_name("array");
    array_type.set_var_len(true);
    array_type.set_elem(&int_type);
    array_type.set_array_kind(syz::ArrayKind::kRandLen);

    syz::PtrType ptr_type;
    ptr_type.set_name("ptr_array");
    ptr_type.set_size(8);
    ptr_type.set_align(8);
    ptr_type.set_elem(&array_type);
    ptr_type.set_elem_dir(syz::Dir::kIn);

    syz::SyscallMeta meta;
    SetSingleArgMeta(meta, "array_min", 140, &ptr_type);

    auto array = std::make_unique<syz::GroupArg>();
    array->set_type(&array_type);
    array->set_dir(syz::Dir::kIn);
    array->add_inner(MakeConstArg(&int_type, 1));
    array->add_inner(MakeConstArg(&int_type, 2));
    array->add_inner(MakeConstArg(&int_type, 3));

    auto pointer = std::make_unique<syz::PointerArg>();
    pointer->set_type(&ptr_type);
    pointer->set_dir(syz::Dir::kIn);
    pointer->set_address(0x1000);
    pointer->set_res(std::move(array));

    auto prog = MakeProg();
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(std::move(pointer));
    prog->add_call(std::move(call));

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        const auto wire = DecodeWire(payload);
        return {!HasCopyin(wire) && FirstCallArgIsAddr(wire, 0x1000), "target"};
    };

    auto result = minimizer.Minimize(BuildArtifact(std::move(prog)),
                                     std::move(test_fn),
                                     NeverStop(),
                                     crash::MinimizeMode::kCrashSnapshot,
                                     -1);

    CHECK(result.success);
    CHECK(result.minimize_stage == "arg array");
    const auto wire = DecodeWire(result.payload);
    CHECK(!HasCopyin(wire));
    CHECK(FirstCallArgIsAddr(wire, 0x1000));
}

} // namespace

int main()
{
    RUN_TEST(TestScalarDefaultMinimize);
    RUN_TEST(TestNonOptionalProcIsNotDefaulted);
    RUN_TEST(TestResourceMinimizeDropsProducerReference);
    RUN_TEST(TestBufferRangeShrink);
    RUN_TEST(TestFilenameTrimRemovesSpecialPad);
    RUN_TEST(TestStringBufferIsNotFilenameTrimmed);
    RUN_TEST(TestPointerNullReplacement);
    RUN_TEST(TestScalarMinimizePatchesConditionalUnion);
    RUN_TEST(TestArrayRemoveAllFastPath);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
