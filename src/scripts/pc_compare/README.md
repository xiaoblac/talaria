# PC 对比管线(paired oracle)

回答一个问题:

> **执行同一份 program 时,reFuzz worker 和 syzkaller executor 的内核执行是否一致
> —— 同一个 syscall 走了同样的内核代码?**

这是 reFuzz 保真度(execution fidelity)的度量。把同一份程序分别喂给两边,**逐
`(req_id, call_idx)` 对比**,任何差异都纯来自 worker / sandbox / 覆盖收集口径。

> 范围:本目录只做**保真 PC 对比**。吞吐/探索力对比是另一套(`scripts/speed_compare/`),本文不涉及。

---

## 0. program 执行,但按 syscall 比 —— 什么意思

**执行单位是 program**(一串 syscall,有先后、共享进程状态)。两边各自跑完整个 program。
**但 KCOV 每个 syscall 前清零、后读取**,所以每个 call 拿到自己那段 PC。trace 存
**per-(program=req_id, call_idx)** 记录,oracle 按这个键配对。差异能精确定位到"哪个
program 的第几个 call"。注意 call 间状态累积(call#5 依赖 call#0..4)。

---

## 1. 管线总览

```
 ① capture (跑 syz)        ② replay (跑 reFuzz)       ③ join (配对)           ④ 函数级分析         ⑤ 源码诊断
 exec_oracle_smoke.sh       refuzz-exec-replayer       refuzz_exec_oracle       exec_oracle_         addr2line
 syz-manager+代理executor   读同一 trace 喂 worker      按(req_id,call_idx)配对   layered_diff.py      -i 读分支
 ─► trace/*.bin             ─► ref_result.bin          ─► per-call.jsonl        ─► report.txt / tsv  定位根因
            └────────── exec_oracle_full_smoke.sh 串 ①②③(SKIP_CAPTURE=1 复用 trace)──────────┘
```

③ 只做**配对**(join + 原始 errno/jaccard),分析在 ④。

## 2. 固定分析链路(runbook —— 按此顺序跑)

> 本节 ①–⑦ 是**分析顺序**(操作 `per-call.jsonl`),与 §1 数据管线的 ①–⑤
> (capture→replay→join→分析→诊断)**不是同一套编号**。一句话:**Jaccard 不是闸门也不是
> 结论,它是"同结果桶"里的排序网 —— 敏感网在前(④),特异筛在后(⑤)。**

```
per-call.jsonl(同一条冻结 trace)
   │
   ▼ ① 闸门      全局 jaccard_mean + 分布带              整体够不够 / 有没有粗暴回归
   │
   ▼ ②③ 分桶     population() 6 桶 + 路由
   │   ├─ EXEC-GAP / ref-only   → ③a 按 |漏PC| 排序 + addr2line   能力缺口 · 不算 Jaccard
   │   └─ errno-mismatch        → ③b 按 errno-pair 计数排序        行为分歧 · Jaccard 预期低
   │
   └─ matched-success / matched-fail(同结果)
        ├─ KCOV 单边/双边空        → ③c 覆盖不可比(和空集比恒 0/1,剔出 ④ 单列计数)
        │     empty-ref=worker 可疑 · empty-syz=上游假象 · both-empty=信息低
        ▼ ④ Jaccard 排序   (仅两边都有 cover)per-(syscall,errno-pair) union+per-call   敏感网:偷工/深度差排最前
        ▼ ⑤ 一致性分类     layered_diff s/r + 三档门槛 + infra 剥离   特异筛:真分歧 vs 时序/infra 噪声
        ▼ ⑥ set-diff 诊断  syz_only/ref_only + addr2line + 子系统       看 PC 长什么样 · 定位根分支
        ▼ ⑦ 验证回路       同 trace 重放重量                          目标降 · 一致性升 · 别处不回归
```

**③c 覆盖不可比(单边空)**:两边都执行 + 同 errno,本该可比,但 KCOV 单边/双边空 —— 和空集比
jaccard 恒 0(双空恒 1),不是路径分歧,留在 ④ 排序里会霸榜(`syz_pkey_set` 案例)。所以从 ④ 剔出、
单列计数(**不静默丢**),并细分成信号通道:`**empty-ref`**(仅 reFuzz 空,执行了却 0 覆盖 = worker 侧
可疑,优先查)、`**empty-syz**`(仅 syz 空,多半上游测量假象)、`**both-empty**`(信息量低)。

**为什么 Jaccard 卡在 ④(④ 在 ⑤ 之前)**:Jaccard 在 PC 粒度上**敏感**,能同时抓"跳过整个函数"
和"进了同函数但少循环/少读块"两类偷工;⑤ 的函数级一致性**特异但盲**(进同函数即判一致)。若把
⑤ 放前面当主筛,它会在 Jaccard 看到之前就把"同函数深度差"那类 bug 丢掉。所以只能 **④ 撒网 →
⑤ 逐候选分类**:⑤ 判 `SEM@0.9` = 高置信"跳过整个函数"真分歧;⑤ 判 `no-sem` 但 ④ Jaccard 低 =
"同函数深度差"或块抖动,**必须**靠 ⑥ set-diff 才能分。

### 各指标的角色(钉死,别再混)


| 指标                                              | 角色             | 阶段  | 脚本                                                   |
| ----------------------------------------------- | -------------- | --- | ---------------------------------------------------- |
| oracle `jaccard_mean` + 分布带                     | 全局闸门           | ①   | `exec_oracle_full_smoke.sh`(stage4)                  |
| 桶计数 + EXEC-GAP 漏PC + errno-pair                 | 路由 + 优先级       | ②③  | `exec_oracle_funnel.py` / `layered_diff.py`(Layer 1) |
| per-(syscall,errno-pair) union+per-call Jaccard | 同结果桶里排候选       | ④   | `exec_oracle_pc_subsystem_sweep.py`                  |
| s/r + 三档门槛 + infra 剥离                           | 真分歧 vs 噪声      | ⑤   | `exec_oracle_layered_diff.py`(Layer 2)               |
| syz_only/ref_only + addr2line + 子系统             | 看 PC 长相 · 定根分支 | ⑥   | `exec_oracle_pc_subsystem_diff.py`                   |
| 同 trace 重放 delta                                | 确认修复           | ⑦   | full_smoke `SKIP_CAPTURE=1` 重跑 ④⑤                    |


### 三条硬规矩(否则数字不可比 / 假)

1. **trace 必须冻结**:所有对比、验证都用**同一条** `TRACE_DIR`(`SKIP_CAPTURE=1`);换 trace 数字不可比。
2. **symbolize 只跑两遍**:贵的是 KASAN vmlinux 的 addr2line(~1-3min/遍)。`sweep` 与 `layered_diff`
  各一遍 bulk pass 就够 ④⑤;`subsystem_diff` 会逐次重符号化,**只用于 ⑥ 那 1-3 个候选的手动钻取**。
3. **冻一个 baseline 当参照系**:把某条 trace 的 `per-call.jsonl` + `funnel/` 存成基线,每个改动当
  "对基线的 delta" 量(④ 目标 Jaccard 升、⑤ `SEM@0.9` 降、别处不回归),别孤立看一次数字。

### 一键跑(`exec_oracle_funnel.py`)

`funnel.py` 把 ①②③④⑤ 串起来(sweep + layered_diff 各一遍 addr2line),吐出**按 `union_jaccard`
升序、已标注 ⑤ 裁决**的候选清单:

```bash
TRACE=run/exec-oracle-sandbox-baseline/trace
RUN=run/analyze-XXXX
VM=/workspace/syzkaller/kernel/build-kasan/vmlinux

# ①②③  闸门 + 桶 + per-call.jsonl(复用冻结 trace;已有 jsonl 可跳过本步)
SKIP_CAPTURE=1 TRACE_DIR=$TRACE RUN_DIR=$RUN bash scripts/pc_compare/exec_oracle_full_smoke.sh

# ①–⑤  一键:闸门→分桶→Jaccard→一致性→候选清单
python3 scripts/pc_compare/exec_oracle_funnel.py \
  --jsonl $RUN/per-call.jsonl --vmlinux $VM --out-dir $RUN/funnel

# ⑥  只对存活候选手动钻(看 PC 长什么样)
python3 scripts/pc_compare/exec_oracle_pc_subsystem_diff.py \
  --jsonl $RUN/per-call.jsonl --vmlinux $VM --syscall <X> --errno-pair 0,0 --out-dir $RUN/drill
```

输出 `$RUN/funnel/`:`funnel_report.txt`(人读,按链路顺序)、`candidates.tsv`(机读:同结果桶按
`union_jaccard` 升序 + `verdict` + top 分歧函数),外加子工具产物 `sweep.csv` / `funcdiff/`。
迭代(只想重读、不重符号化)加 `--skip-subtools`。

## 3. 文件职责


| 文件                                                                                       | 角色                                                                  |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `exec_oracle_full_smoke.sh`                                                              | 总入口,串 ①②③。`SKIP_CAPTURE=1 TRACE_DIR=...` 复用 trace。                  |
| `exec_oracle_smoke.sh` / `syz_executor_proxied_wrapper.sh` / `bake_exec_oracle_image.sh` | ① capture(syz-manager + 代理 executor + 烤镜像)。                         |
| `exec_oracle_funnel.py`                                                                  | **总入口(§2 runbook):一键 ①②③④⑤ → `candidates.tsv`(Jaccard 升序 + ⑤ 裁决)。** |
| `exec_oracle_pc_subsystem_sweep.py`                                                      | ④ 全 (syscall×errno-pair) 的 union/per-call Jaccard(被 funnel 调)。      |
| `exec_oracle_layered_diff.py`                                                            | ⑤ 函数级一致性(Layer 2)+ ②③ 人群(Layer 1);出 `semantic[_fail]_*.tsv`。        |
| `exec_oracle_pc_subsystem_diff.py`                                                       | ⑥ 单 syscall+errno-pair 钻取(`subsystem`/`is_structural` 在这,被 ④⑤ 复用)。  |


`per-call.jsonl` 关键字段:`syscall` / `syz_executed`,`ref_executed` / `syz_err`,`ref_err`
(998=executor never-written 哨兵)/ `syz_pcs_hex`,`ref_pcs_hex`(每 16 hex 一个 PC)/ `cover_available`。

---

## 4. 第一性原理:PC 是唯一裁判,errno 只是 PC 的有损投影

每个 syscall 只有两个可观测量:**errno**(结果)、**PC 集**(走了哪段代码)。PC 决定 errno。

- **errno 相同 ≠ 行为一致**:reFuzz 可能偷工/stub,照样返回成功。
- **errno 不同 ≠ 行为不一致**:reFuzz 的错误返回是自己设计的(executor 管线差异)。

⇒ 判决只能来自 **PC**;errno 只用来"分在哪个人群上证一致"。最该抓、errno 完全看不见的
bug 是:**reFuzz 成功却没真干活**(mount 假装挂上 / kvm 少建 vcpu),只有 PC 能抓。

---

## 5. 分析框架(`exec_oracle_layered_diff.py` 怎么做)

> 注:本脚本**从"块级 PC 集差"改成了"函数级一致性"**。旧块级口径(union 所有 call 比 PC 块)
> 会把 errno 差的路径 + tomoyo 学习态抖动全涌进 syz_only,被噪声骗成假缺口(块级 25719 个
> syz_only、70% 结构噪声、tomoyo 霸榜)。下面四个决定是修正。

1. **粒度=函数(调用图),不是基本块。** PC → 所在函数(`addr2line -f`),比函数集。
  "进入函数 F"=有人调了它(调用图事实);"函数内走不同块"=数据/状态依赖(循环/which case)
   =多半噪声。两边都进 `tomoyo_check_acl`/`mas_store` → 函数级判共同,块级噪声自动消失。
2. **配对=逐 call(同一 req_id/call_idx)。** 两边跑同一 trace,`call i` 是同一次调用。
  逐 call 比,消除"跨不同程序、不同前置状态"的污染。
3. **判决=跨 call 一致性。** 对一个 syscall 的所有 matched call,比每个函数 F 两边的
  **进入率** `s=syz进F占比`、`r=reFuzz进F占比`:`s`高且`r≈0`=分歧;两边都高=一致;中间=
   时序噪声(自动落噪声,不靠启发式)。
4. **残差再拆 infra/语义。** 函数级 + 一致性后仍有"一致 syz-only"残差(状态/机制也能一致),
  按子系统拆:**infra/机制=噪声**,**语义(fs/net/drivers/block…)=候选真分歧**(见 §6)。

**门槛扫描(一次跑三档):** "syz 稳稳进入"的 bar `s_min ∈ {无拦截, 0.5, 0.9}` 一次扫完,
reFuzz "稳不进" 固定 `r≤0.1`。门槛越严,残差越收敛到"reFuzz 铁定从不进、syz 铁定进"的高置信分歧。

---

## 6. 过滤口径(**什么被过滤、为什么 —— 必须透明,因为过滤会藏东西**)

分析共有四道过滤/分流,逐道说明:

### (A) Layer 0 硬过滤 — 丢掉**不可比**的 call(report.txt 顶部逐项计数)


| 排除项    | 条件                               | 为什么丢                                                     |
| ------ | -------------------------------- | -------------------------------------------------------- |
| 998 哨兵 | `syz_err==998` 或 `ref_err==998`  | executor "never-written slot",这个 call 槽**根本没产生结果**,不是行为。 |
| 两边都没执行 | `!syz_executed && !ref_executed` | 空/跳过的槽,不是一次真实调用。                                         |


> **不在这里丢的(是信号,保留):** `syz✓ reFuzz✗`=**EXEC-GAP**(进 Layer 1);`reFuzz✓ syz✗`=ref-only-exec。

### (B) errno 分流 — 决定"在哪个人群上比 PC"(不是丢,是分桶)

两边都执行的 call 按 errno 结果分:**EXEC-GAP / errno-mismatch(行为分歧,单列,不比 PC 深度)
/ matched-success(0,0)/ matched-fail(同 errno)**。**只有 matched 两类拿来做函数级 PC 比对**
——因为只有"两边做了同一件事"时,PC 差才有意义。

### (C) 一致性过滤 — 丢掉**间歇**(时序噪声)

函数 F 若 syz/reFuzz **时有时无**地进(进入率在中间),判**间歇 = 时序/调度噪声**(async work
跑没跑完),不计入分歧。只有"syz 稳进(`s≥s_min`)且 reFuzz 稳不进(`r≤0.1`)"才算分歧。

### (D) 残差 infra/机制过滤 — 把分歧里的**非语义噪声**剥掉(`is_infra`)

对"一致分歧"的函数,按**源文件子系统 + 函数名**判是否噪声:


| 类别                | 判据                                                                                                                                       | 为什么是噪声                                                                                                                                                                                                           |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 结构/分配器            | 子系统 `is_structural`:mm、`lib/maple_tree`·`lib/xarray`·`lib/radix-tree`·`lib/find_bit`、`arch/x86`、`include`、`kernel/rcu`;以及 `mm/`*、`lib/*` | 分配器/通用数据结构/位图,进哪个函数取决于**堆/分配状态**,非语义                                                                                                                                                                             |
| LSM 学习态           | 子系统 `security/tomoyo`                                                                                                                    | TOMOYO learning-mode:两独立进程学到不同 ACL → 进不同的 condition/compare 函数,**不影响结果**                                                                                                                                         |
| 系统机制              | 子系统 `kernel/time`、`kernel/smp`、`kernel/workqueue`、`kernel/irq_work`                                                                      | 时序/IPI/异步:进与否取决于**睡没睡、跨没跨 CPU、异步跑没跑完**,非语义                                                                                                                                                                       |
| 异步唤醒回调            | **函数名** `WAKE_FUNC`:`*_wake_function`、`pollwake`、`ep_poll_callback`、`ep_pm_stay_awake`、`ep_autoremove`、`__wake_up_common`                | 等待事件发生时在 waker 路径上被异步触发;进与否取决于唤醒有没有在窗口内发生 = 时序。**按函数名剥**(不能整个 `fs/eventpoll`·`fs/select` 剥——epoll/poll syscall 本身是语义)                                                                                            |
| cgroup 计账 / blkcg | **函数名** `CGROUP_ACCT_FUNC`:`blkcg`·`blk_cgroup`·`kthread_blkcg`·`rstat`·`cgroup_base_stat`·`__cgroup_account`                            | 进与否取决于**挂了哪些 cgroup 控制器 + 调度时序**,非语义。**实证(2026-05-30):把 reFuzz 的 cgroup io 控制器修对(`io.max=1`、membership ✓)后这些函数覆盖纹丝不动** → 证明它们不由 cgroup 成员驱动,是计账基础设施。按函数名剥(blkcg 跨 block/blk-cgroup·kernel/kthread·kernel/cgroup) |


**剥完剩下的"语义真分歧"= 结论**(本 baseline:**0.9 稳稳档 = 0 个**,0.5 档仅个位数,且是 wg/skb 异步 RX、gfs2 buffer-cache 这类低置信残渣):
**同结果(matched)时 reFuzz 执行是忠实的——没有干净的高置信语义缺口。** 真正 actionable 的差异全在 **Layer 1**(EXEC-GAP 的 NFC、errno-mismatch 的 ptrace/clone/mount)。

> **教训(闭环验证的价值):** 一度把 `blkcg`/`cgroup-stat` 当"真 sandbox 缺口"(0.9 档 57 个、100% vs 0%),还据此改了 worker 的 cgroup `+io`。但**同 trace 重放重新量** → 覆盖没变 → 证明那是计账基础设施噪声,不是 cgroup 成员问题。**没有"修复→重放→重量"这步,就会发一个假胜利。**(`+io` 修复逻辑上仍对、已对齐 syz,保留;但它不是 blkcg 的解。)

---

## 7. 输出

`exec_oracle_layered_diff.py --out-dir` 落:

- `report.txt` —— 人读总报告(Layer0 过滤口径 + Layer1 人群 + Layer2 一致性证明 + 三档扫描表 + 语义明细)。
- `semantic_{无拦截,0.5,0.9}.tsv` —— matched-**success** 三档机读表(`syscall, function, subsystem, syz_rate, ref_rate, N, sample_pc`)。
- `semantic_fail_{无拦截,0.5,0.9}.tsv` —— matched-**fail** 同结构(funnel 用它给 MF 候选标 ⑤ 裁决)。

`exec_oracle_funnel.py --out-dir`(§2 runbook 总入口)额外落:`funnel_report.txt`(人读,按链路顺序)

- `candidates.tsv`(每行一个同结果 `(syscall×errno-pair)`:`syz_pc`/`ref_pc`、`union_jaccard`/`per_call_jaccard`、
`verdict` ∈ {`SEM@0.9` · `SEM@0.5` · `no-sem->6` · `empty-ref` · `empty-syz` · `both-empty`}、top 分歧函数;
可比的按 `union_jaccard` 升序在前,③c 覆盖不可比的接在后面)+ `sweep.csv` / `funcdiff/`。

```bash
python3 scripts/pc_compare/exec_oracle_layered_diff.py \
  --jsonl run/exec-oracle-<ts>/per-call.jsonl \
  --vmlinux /workspace/syzkaller/kernel/build-kasan/vmlinux \
  --out-dir run/exec-oracle-<ts>/funcdiff   [--min-calls 3] [--top 40]
```

## 8. ⑥ addr2line 源码诊断(对语义真分歧定位根因)

覆盖差 = 某个 `if` 两边走了不同侧。addr2line 把那个 `if` 的**位置**定下来:

```bash
addr2line -i -f -e <vmlinux> 0x<sample_pc>      # tsv 里有每个分歧函数的 sample_pc
```

找**调用者**(谁本该调这个函数)→ 读它那条分支条件 → 哪个状态变量两边不同。注意 PC 集无序,
找"最先岔开的根分支"还要结合 errno + call_idx 顺序。

## 9. ⑦ 怎么验证一个修复

**同一条冻结 trace 进,数字出,改对了必须降、别处不许涨**(§2 硬规矩之一):

```bash
TRACE=run/<fixed>/trace; VM=<vmlinux>
# before
SKIP_CAPTURE=1 TRACE_DIR=$TRACE RUN_DIR=run/before bash scripts/pc_compare/exec_oracle_full_smoke.sh
python3 scripts/pc_compare/exec_oracle_funnel.py --jsonl run/before/per-call.jsonl --vmlinux $VM --out-dir run/before/funnel
# 改 worker/sandbox → rebuild ivshmem_worker
SKIP_CAPTURE=1 TRACE_DIR=$TRACE RUN_DIR=run/after  bash scripts/pc_compare/exec_oracle_full_smoke.sh
python3 scripts/pc_compare/exec_oracle_funnel.py --jsonl run/after/per-call.jsonl  --vmlinux $VM --out-dir run/after/funnel
# diff run/{before,after}/funnel/candidates.tsv 与 funcdiff/report.txt 的关键数
```

主判据:目标缺口的 EXEC-GAP / errno-mismatch / **语义真分歧(`SEM@0.9`)应降,一致性证明(%)应升,
别处不回归**。infra/机制/间歇的波动不算信号。