// RawBytesArtifact — target-agnostic ProgramArtifact for raw-bytes formats.
//
// post-V1-retirement artifact-first universal contract (B-6).
//
// 角色：让 non-typed target（AFL-style raw input、RPC frame、VM-snapshot delta、
// script、opaque blob…）也能挂上 ProgramArtifact，使得 channel / feedback /
// crash / repro 这些跨模块代码可以"统一面对 ProgramArtifact"，不再为 typed
// （syz_v2）和 raw-bytes 写两套路径。
//
// 语义：
//   - typed view 就是字节本身（`RawBytesProgram` 包装），`As<RawBytesProgram>()`
//     返回 shared_ptr，提供给 raw-bytes 消费者读 bytes。
//   - canonical_payload 就是 bytes 自身（无 lazy provider；直接 preload）。
//   - LowerForExec 是 identity：raw-bytes 不需要再 lower，直接当 exec_payload。
//
// 与 syz_v2 的对比：
//   - syz_v2: typed view = `program::syz::Prog` （丰富 IR），canonical text =
//     .syz 文本，exec-wire = serialize_for_exec varint stream（一次性 lower）。
//   - raw-bytes: typed view = `RawBytesProgram` （字节本身），canonical text =
//     bytes，exec-wire = bytes（identity）。
//
// 这正是 §5/§6 of post_v1_retirement_followups.md 描述的"contract is general"
// 的反向证据：如果只有 syz 一种 format 能挂 ProgramArtifact，那就不是 contract，
// 是 syzkaller patchup；RawBytesArtifact 让多目标场景也满足同一不变式。

#pragma once

#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace refuzz::program {

// Typed view for raw-bytes artifacts. `As<RawBytesProgram>()` 返回 shared_ptr。
// 内容不可变（D3）—— state_ 的 typed_view 只构造一次。
struct RawBytesProgram {
    std::vector<std::uint8_t> bytes;
};

// 直接构造路径（hot-path producer 不经 registry，自己有 typed bytes）。
// `target` 由调用方指定（os/arch/revision；raw-bytes 通常 os="" arch=""
// revision=""，但调用方可填业务自己的 target key）。
ProgramArtifact MakeRawBytesArtifact(ProgramTargetKey         target,
                                     std::vector<std::uint8_t> bytes);

// Registry-driven 路径：注册到 ArtifactMaterializerRegistry 后，所有
// MakeArtifactFromCanonicalPayload(kAflRaw, ...) / MaterializeExecWire 的
// 调用都走这里。
//
// `kAflRaw` 在当前 ProgFormat 枚举里就是 "raw bytes"（AFL-style 名字保留
// 兼容；语义上等价于 raw-bytes target）。
std::unique_ptr<IArtifactMaterializer> CreateRawBytesMaterializer();

} // namespace refuzz::program
