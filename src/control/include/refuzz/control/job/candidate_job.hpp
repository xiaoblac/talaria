#pragma once
// Job-loop 重设计 Step 3 —— CandidateFeederJob(② = syz candidateQueue 的喂入)。
//
// syz 的 AddCandidates 把持久 corpus 逐个 enqueue 到 candidateQueue(fuzzer.go:373-382),
// 执行一次收集 signal;其 completion 经 processResult 决定 → triage(①)/ 重试(②)/ 丢。
// reFuzz 的 job 版:一条 feeder job 把 boot candidate 逐个 **emit** 成 ② exec(fire-and-forget,
// 结果回 catch-all = FuzzerLoop::ProcessCatchAllCompletion 的 candidate 分支)。emit 受统一
// request-window 背压,天然把 N 个 candidate 按序节流(= syz candidateQueue 增量 pull)。
//
// 分工:**syz-aware 的候选扫描/排序在 loop**(读 boot corpus 的 kBootCorpus 种子、按 call 数
// 升序 = syz manager.go:626 favorize-smaller),把就绪列表交 feeder;feeder 保持通用(emit + 归因
// + 重试重取)。归因经 on_submitted:arbiter 分配 exec_id 后 record_exec 记 candidate_exec_,使
// completion 被识别为 candidate re-verify。flaky 重试由 catch-all 排进 loop 的 retry 队列,feeder
// 每轮 drain_retries 据 seed_id 从 pending 区重取程序、重 emit ②(attempt+1)。

#include "refuzz/control/job/job_context.hpp"
#include "refuzz/program/artifact.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace refuzz::control {

class PendingSeedMap;  // full def in triage_stage.hpp(.cpp include);feeder 只持 shared_ptr

// 一个待喂的 boot candidate:seed_id + 程序 artifact(loop 扫描时从 pending 种子取,共享只读)。
struct CandidateSeed {
    std::uint64_t                                              seed_id = 0;
    std::shared_ptr<const ::refuzz::program::ProgramArtifact>  artifact;
};

struct CandidateJobDeps {
    // 首轮 bootstrap 要 emit 的 boot candidate(loop 已扫描+排序;respawn 时为空,只跑重试)。
    std::vector<CandidateSeed>                                 initial;
    // 重试重取源(与 catch-all / triage / minimize 共用那份候选区)。
    std::shared_ptr<PendingSeedMap>                            pending;
    // 归因:emit 拿到 exec_id 后登记在飞 candidate(→ FuzzerLoop::RecordCandidateExec)。
    std::function<void(std::uint64_t /*exec_id*/, std::uint64_t /*seed_id*/, int /*attempt*/)>
                                                              record_exec;
    // 取走本轮 flaky 重试({seed_id, attempt+1};→ FuzzerLoop::DrainCandidateRetries)。
    std::function<std::vector<std::pair<std::uint64_t, int>>()> drain_retries;
    std::uint32_t                                             exec_timeout_ms = 0;
};

// 造一条 candidate feeder job(返回 JobFn 交给 JobScheduler::TrySpawn)。
//   on_done  job 正常退出(本轮 initial + 重试都 emit 完)后于 control 线程经 retain 跑
//            (复位 alive → RunOnce 见还有 candidate work[未 bootstrap / 有新重试] 时重 spawn)。
job::JobFn MakeCandidateJob(CandidateJobDeps deps, std::function<void()> on_done);

}  // namespace refuzz::control
