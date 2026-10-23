// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/mutator/mutator_catalog.hpp"

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"   // kRecommendedCalls
#include "refuzz/mutator/xiuos/xiuos_mutator_engine.hpp"
#include "refuzz/program/syz/target.hpp"

#include <memory>
#include <random>

namespace refuzz::fuzzer {

void RegisterBuiltinMutatorEngines(MutatorEngineCatalog& catalog)
{
    // "syz" — v2 IR generation + mutation engine (§3.4 + §3.5).
    // corpus_store 可空：splice op (§3.5 M2) 在缺 corpus 时优雅 fallback;
    // generation 路径不依赖 corpus（与上游 syzkaller 不同）。assembler 把当前
    // session 的 corpus_store 透传过来即可启用 splice。
    {
        MutatorEngineCatalog::Entry entry;
        entry.meta = {
            "syz",
            "Syzkaller Engine",
            "v2 IR type-aware syscall generation + mutation",
        };

        // [syscall-enable-whitelist] Pseudo selection is governed by the
        // enable/disable_syscalls whitelist (ChoiceTable filter) + syz's
        // (disabled) attr — there is no capability/impl policy. Real
        // privileges come from sandbox=none at runtime, as in syzkaller.
        entry.build = [](const MutatorEngineTraits::BuildContext& ctx)
            -> core::Result<std::unique_ptr<IMutatorEngine>> {
            // [speed-compare arm D growth-parity] Generation length = syzkaller
            // `prog.RecommendedCalls = 30`, FLAT (not a range). syzkaller's
            // `Target.Generate(rs, ncalls, ct)` (prog/generation.go) generates until
            // `len >= ncalls` then trims to EXACTLY ncalls, and the fuzzer always
            // passes RecommendedCalls=30 — so every generated program is exactly 30
            // calls; variety comes from mutation, not generation length. reFuzz's
            // generate_program has the same generate-then-trim shape, so lo==hi==30
            // reproduces syzkaller exactly. (Old [2,8] → ~5 calls vs syz 30 → reFuzz
            // 2.99 vs 6.92 calls/prog, arm D.) kMaxCalls (40) caps mutation growth.
            constexpr int kGen = ::refuzz::mutator::syz_v2::kRecommendedCalls;  // 30
            return std::make_unique<SyzV2MutatorEngine>(
                ::refuzz::program::syz::Target::linux_amd64(),
                ctx.corpus_store,
                /*master_seed=*/ std::random_device{}(),
                /*ncalls_lo=*/   kGen,
                /*ncalls_hi=*/   kGen,
                /*enabled_calls=*/ ctx.enabled_calls_mask);
        };
        catalog.Register(std::move(entry));
    }

    // "xiuos" — XiUOS kernel program v1 mutator (decode wire bytes → XiUOS IR →
    // one mutation op → re-encode). corpus_store and the enable/disable_syscalls
    // globs are syz-specific knobs the XiUOS engine ignores: it
    // mutates self-contained wire payloads and has no pseudo-call / choice-table
    // concept. catalog id == XiuosMutatorEngine::Name() so the profile's
    // mutator_engine="xiuos" routes here via SwitchEngineByName.
    {
        MutatorEngineCatalog::Entry entry;
        entry.meta = {
            "xiuos",
            "XiUOS Kernel Engine",
            "XiUOS kernel-object program generation + mutation (v1)",
        };
        entry.build = [](const MutatorEngineTraits::BuildContext& /*ctx*/)
            -> core::Result<std::unique_ptr<IMutatorEngine>> {
            return std::make_unique<XiuosMutatorEngine>();
        };
        catalog.Register(std::move(entry));
    }
}

} // namespace refuzz::fuzzer
