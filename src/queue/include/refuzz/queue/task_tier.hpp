#pragma once
// [Step 5] 调度档位 —— 镜像 syzkaller 的 source Order(pkg/fuzzer/fuzzer.go:106):
//   Order(triageCandidate, candidate, triage, Alternate(smash, 3), Callback(genFuzz))
// task_queue.Pop 按此**严格优先级**取(数值小 = 优先级高);Smash 档用 Alternate(3) 每 3 次
// 让 1 次给 Explore(= syz `Alternate.Next` 每 nth 次返回 nil → 落到下一档),防 smash 永久
// 压住 gen/mut。生产者按自身语义打档:
//   ① CandidateTriage —— boot 语料 re-triage 的 continuation(syz triageCandidateQueue)
//   ② Candidate       —— boot 语料验证执行(syz candidateQueue,corpus_verify)
//   ③ Triage          —— 现场发现 seed 的 triage continuation(syz triageQueue)
//   ④ Smash           —— smash emit + hints/fault continuation(syz smashQueue,Alternate 3)
//   ⑤ Explore         —— MAB gen/mut + collide 的 emit(syz Callback(genFuzz))

#include <cstddef>
#include <cstdint>

namespace refuzz::queue {

enum class TaskTier : std::uint8_t {
    CandidateTriage = 0,
    Candidate       = 1,
    Triage          = 2,
    Smash           = 3,
    Explore         = 4,
};

inline constexpr std::size_t kTaskTierCount = 5;

}  // namespace refuzz::queue
