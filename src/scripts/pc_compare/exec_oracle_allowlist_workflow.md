# exec-oracle paired equivalence + evidence-driven allowlist

这条流水是 V2 paired oracle 的对照实验入口,**唯一**正确的方式判断 reFuzz worker 跟 syzkaller 在 pseudo syscall 上是否等价,以及决定哪些 syscall 进 allowlist。

下一个 session 接手时,**先把这个 md 通读一遍**,尤其 §3 "字段陷阱" 和 §4 "运行模式"。不读会再踩一次同样的坑。

---

## 1. 七阶段流水(一张图记住)

```
exec_oracle_full_smoke.sh  driver
├─ stage 1  Capture   exec_oracle_smoke.sh  →  trace/*.bin
│           syz-manager -mode corpus-triage(自然 exit,不依赖 sleep)
├─ stage 2  Replay    refuzz-exec-replayer  →  ref_result.bin
│           reFuzz worker 用同一份 trace 重跑一遍
├─ stage 3  Oracle    refuzz_exec_oracle    →  exec-oracle-report.json
│                                              per-call.jsonl
└─ stage 4  Verdict   §13.1 three-tier gate(wire/result/coverage)

──── 下面是 allowlist 流水(手工触发,smoke 不带) ────

stage 5  Aggregate   exec_oracle_per_pseudo_aggregate.py
         → configs/pseudo_oracle_evidence.csv  (per-pseudo)
stage 6  Import      import_oracle_to_proof_status.py   (--auto-promote 默认)
         → configs/pseudo_proof_status.csv     (evidence-driven candidate growth)
stage 7  Manifest    generate_pseudo_manifest.py
         → configs/pseudo_manifest.csv
           pseudo_candidate_allowlist.txt    (observed)
           pseudo_allowlist.txt              (reviewed=allow)
           pseudo_disablelist.txt
```

## 2. 典型 workflow(一键 + 解读)

### 2a. 一键全跑

```bash
# 默认就是 corpus-triage + force-cover + vmlinux cold-fault classifier。
bash scripts/pc_compare/exec_oracle_full_smoke.sh
```

会产出 `run/exec-oracle-<ts>/{trace,ref_result.bin,exec-oracle-report.json,per-call.jsonl,...}`。

跑完不**自动**进 aggregate / import / manifest — 你得手工触发(数据可能 stale,不要让它无脑覆盖 proof_status)。

### 2b. allowlist 流水(stage 5-7)

```bash
RUN=run/exec-oracle-<ts>

# stage 5: 聚合 per-pseudo evidence
python3 scripts/pc_compare/exec_oracle_per_pseudo_aggregate.py \
  --jsonl "$RUN/per-call.jsonl" \
  --out-csv configs/pseudo_oracle_evidence.csv

# stage 6: 写 proof_status(默认 --auto-promote,observe→candidate)
python3 scripts/pc_compare/import_oracle_to_proof_status.py \
  --evidence configs/pseudo_oracle_evidence.csv
# 加 --no-auto-promote 保持 candidate set 不变(benchmark-fair runs 用)
# 加 --dry-run 只打印不写

# stage 7: 重生成 manifest + allowlist 文件
python3 scripts/generate_pseudo_manifest.py
```

### 2c. 调试用 SKIP_REPLAY(节省 capture+replay 5 分钟)

```bash
# 用历史 trace+ref_result 重跑 stage3+4(只跑 oracle + verdict)
SKIP_REPLAY=1 \
  TRACE_DIR=run/exec-oracle-<old-ts>/trace \
  REF_RESULT=run/exec-oracle-<old-ts>/ref_result.bin \
  RUN_DIR=run/exec-oracle-rerun-$(date +%s) \
  bash scripts/pc_compare/exec_oracle_full_smoke.sh
```

### 2d. 诊断分支(PC 差异根因定位 — 不进主流水)

stage 5 `exec_oracle_per_pseudo_aggregate.py` 把每 syscall 全部 hits 的 PC **不分 errno 一起 union**,jaccard 低的时候**不能区分**两种 root cause:
- (a) 真 worker 实现 gap — 同 errno pair 走不同 path
- (b) errno tier 不一致 — 走不同 errno 分支自然 PC 集不同

两个独立诊断脚本补这个缺口。**不影响 stage 5-7 主流水**,evidence csv schema 保持稳定。

#### 2d-1. errno-stratified PC overlap(全景看哪些 syscall 真分歧)

```bash
python3 scripts/exec_oracle_errno_stratified_dump.py \
  --jsonl run/exec-oracle-<ts>/per-call.jsonl \
  --out-csv /tmp/oracle_errno_stratified.csv \
  --out-txt /tmp/oracle_errno_stratified.txt
```

每个 syscall 拆 4 errno pool:

| pool | 含义 | 期望 |
|---|---|---|
| `both_ok` | syz_err=0 && ref_err=0 | PC 应高度对齐;低 jaccard = 真 worker gap |
| `syz_ok_ref_err` | syz 成功, ref 早返错 | errno tier 不一致;PC 偏差 expected |
| `syz_err_ref_ok` | syz 早返错, ref 成功 | 同上 |
| `both_err` | 两端都错 | PC 应在错路径对齐 |

每 pool 独立 `syz_pc_union` / `ref_pc_union` / `union_jaccard` / `exact_match_rate`。

TXT 输出:
- 顶部 summary header(总 syscall 数 / both_ok jaccard >0.95 / >0.90 / <0.50 计数)
- 每 syscall 一段 `═══...` 分隔,4 行 pool 对齐,按 cover_hits 倒序排

判读:
- **both_ok jaccard < 0.5** → 真 worker gap,worker epic 候选(优先打)
- **两边 fail pool 才低 jaccard** → errno tier 问题,该走 oracle 端 filter(参考 cluster_id 机制,`tools/refuzz_exec_oracle/main.go classifyClusters`)
- **`syz_pc=0` or `ref_pc=0`** → pseudo dispatcher 一端没 wire / 早 abort,worker bug 信号最强

#### 2d-2. per-syscall PC diff + addr2line(确认结构性差异 vs 真 path divergence)

```bash
python3 scripts/exec_oracle_syscall_pc_diff.py \
  --jsonl run/exec-oracle-<ts>/per-call.jsonl \
  --syscall syz_clone \
  --vmlinux kernel/build-kasan/vmlinux
  # 可选: --pool {both_ok,syz_ok_ref_err,syz_err_ref_ok,both_err,all}  (默认 both_ok)
  # 可选: --strategy {first,union}                                       (默认 first)
  # 可选: --topn 25
  # 可选: --out-dir DIR  把 ref_only/syz_only/common 三份 PC list 落盘
```

抽指定 `(syscall, pool)` records → 算 `ref_only / syz_only / common` 差集 → bulk addr2line ref_only + syz_only → top-N 函数频率打印。

`--strategy first` 抽第一个 hit 做差集(快,代表性 sample);`--strategy union` 跨全部 hits 取 union 后再差集(全景,慢)。先 first 看 pattern,再 union confirm。

**判读模板**(基于已实测的 syz_clone 案例,req=3179 both_ok first hit):

```
syz_pc=1696  ref_pc=4381  common=1667  ref_only=2714  syz_only=29
ref_only top: copy_process(30) / vms_gather_munmap_vmas(27)
             / mas_*/ma_pivots/__split_vma/vma_merge_existing_range(maple tree)
             / wp_page_copy/do_anonymous_page/do_mmap/do_mprotect_pkey(mm)
syz_only top: should_fail_alloc_page(4) / pcpu_*(几个) ... 19 unique 函数
```

3 种判读结论:

| 模式 | 含义 | 行动 |
|---|---|---|
| ref_only top 落在 `copy_process` + `vma_*` + `mas_*` + `do_mmap` 等 fork-mm 路径,syz_only 极少 (<5% of ref_only) | **结构性差异不可消除** — reFuzz worker 进程地址空间大(ivshmem + KCOV + scratch + sandbox region),fork 时 dup_mm 自然走更多 VMA maple-tree 维护;syz-executor 是 minimal 进程 path 短 | 不动 worker;oracle 端这类 syscall 单独 jaccard 阈值降到 0.3-0.5 即可 |
| ref_only top 落在 **syscall 自身 body 内的 deep logic** (例如 KVM_RUN 路径、fs body 函数) | **真 path divergence** — worker 实现走了一条 syz 端没走过的分支 | 进 worker epic 调查 |
| `syz_only` 多 (≥ 30% of syz) | **reFuzz 漏 path** — syz 端跑过的 kernel code 在 ref 端没出现 | 重大 worker bug,立刻调查 dispatcher / sandbox 是否吞了 |

`syz_only` 极少时(<5% of ref_only)说明 **ref 端是 syz 端的 superset**,worker 没漏 path 只是多走 wrapper —— 这种 PC count "ref 多 1.7-2.8x" 是 design 副作用不是 noise。

---

## 3. ★ 字段陷阱 — `_pc_count` 是 raw 还是 unique?★

**踩过坑,下次别再踩**。

### 3a. per-call.jsonl(stage 3 emit)

| 字段 | 是什么 | 用法 |
|---|---|---|
| `syz_pc_count` | **raw**(syz 端 raw,已经 dedupe 过) | 别用 |
| `ref_pc_count` | **raw**(reFuzz worker kcov ring 写入计数,**含重复**) | 别用 |
| `unique_syz_pc_count` | unique PC set 大小 | ✅ 用这个 |
| `unique_ref_pc_count` | unique PC set 大小 | ✅ 用这个 |
| `syz_pcs_hex / ref_pcs_hex` | sorted + dedupe 的 16-hex/PC 串 | parse 出来是 unique set |
| `jaccard` | unique set 上算的(set jaccard) | ✅ 直接用 |

**关键警告**:
- `ref_pc_count` 在 mount-image / KVM / USB connect 上可以是 unique 的 **10x ~ 95x**(kcov 同 PC 多次 hit)。
- `ref_pc_count / syz_pc_count = 95x` **不是**"reFuzz 累积过量 unique PC",**是 raw 写入比**。
- 实际 `unique_ref_pc_count / unique_syz_pc_count` 中位是 **0.99**(基本等价)。
- 之前用 raw ratio 排序找 "Type X 累积异常"的全部结论都要用 unique 重算。

### 3b. pseudo_oracle_evidence.csv(stage 5 emit)

aggregate 脚本**已经 unique-based**(`parse_pcs_hex` 出来是 set,union 累加也是 set):

| 字段 | 含义 |
|---|---|
| `syz_pc_count` | **per-pseudo union 后的 unique PC 数**(不是 raw) |
| `ref_pc_count` | 同上 |
| `union_jaccard` | union 集合上的 jaccard(unique) |
| `per_call_jaccard_mean/median` | 每 call 算 unique jaccard,聚合 |
| `cover_available_hits` | 真有 cover 数据的 call 数(分母用这个) |
| `kcov_overflow_hits` | 命中 kcov_buffer_cap 的 call 数(从 PC math 池剔除) |

evidence csv 里**安心用** `ref_pc_count / syz_pc_count` 算 ratio,因为它本来就是 unique。

### 3c. 一句话记忆

> 看到 `_pc_count` 在 **per-call.jsonl** 是 raw,在 **pseudo_oracle_evidence.csv** 是 unique。

---

## 4. 运行模式(corpus-triage vs 老 fuzz-window)

### 4a. corpus-triage(当前默认,推荐)

- syz-manager `-mode corpus-triage`,**跑完所有 corpus seed 自然 exit**(`CandidateTriageFinished`,15 min 左右)
- 输入完全 deterministic:`.syzkaller-pin` 锁版本 + 空 workdir → 同一份 corpus 每次跑出同一组 request
- **没 mutate / smash / hint 噪声**(corpus-triage 不进 fuzz loop)
- 可重复对照,适合 allowlist 决策
- 安全超时 `TRIAGE_TIMEOUT_S=1800`(默认 30min,只是 SIGKILL backstop,正常不到)

### 4b. 老 fuzz-window(已退役,**不要用**)

- 之前的 `FUZZ_DURATION=N` sleep 然后 SIGINT
- 跑速决定能 capture 多少,**不可重复**
- 混了 mutate/smash derivative,**不能用作 equivalence 证据**
- `FUZZ_DURATION / DRAIN_BUDGET_S` env var **已经从 smoke 脚本删掉**;遇到旧文档别复制粘贴

### 4c. force-cover 默认 ON

- `REFUZZ_FORCE_COLLECT_COVER` env 不设 = ON(默认)
- 没开:syz-manager 只给 ~14% request 设 CollectCover bit → jaccard 样本面小、偏 triage/signal job
- 开了:100% request 都带 cover → 取样无偏
- 关闭(debug 用):`REFUZZ_FORCE_COLLECT_COVER=0 bash scripts/pc_compare/exec_oracle_full_smoke.sh`

### 4d. vmlinux for cold-fault classifier 默认 ON

- `VMLINUX` env 默认 `kernel/build-kasan/vmlinux`
- oracle 加载 444k+ symbols,触发 `classifyProcessColdFault` 把 fork-child cold-start 的 page-fault outlier 归到 cold_fault bucket
- 当前 classifier prefix list 只覆盖 `do_user_addr_fault / handle_mm_fault / filemap_map_* / xas_* / folio_*` 等。**mmap 类** (`__x64_sys_mmap / arch_get_unmapped_area_topdown`) 还没加,所以部分 cold-fault 没被识别。

---

## 5. allowlist 决策语义

### 5a. proof_status.csv = single source of truth

```
candidate set = proof_status.csv 里所有 row
allowlist     = candidate 中 review_verdict='allow' 的子集
disablelist   = 全部 upstream syz_* 减 allowlist
```

任何 syscall 出现在 evidence csv → import 默认 `--auto-promote` → 自动加 proof_status row(`review_verdict='pending'`)→ manifest 加它进 candidate。

### 5b. 7 个 evidence 分类(reviewer hint)

基于 unique-based jaccard + cover_hits + unique_ratio,给 reviewer 一份分类:

| 类 | 标准 | 含义 | 建议 verdict |
|---|---|---|---|
| **G** | jacc ≥ 0.8 + ratio ∈ [0.5, 2.0] | 基本等价 | `allow` |
| **M** | jacc ∈ [0.5, 0.8] | 路径有偏差,审查 | `pending` 审查 |
| **L** | jacc < 0.5,非 stub | 内容差异大 | `pending` 审查 |
| **X1** | ref >> syz,ratio > 3 (unique) | reFuzz 额外路径,或 reFuzz 更真 | 个案 |
| **Y1** | ref_pc < syz_pc × 0.2 | **worker stub 真 bug** | `disable`(等修 worker) |
| **Y2** | ref_pc ∈ [syz_pc × 0.2, syz_pc × 0.5] | worker 浅 | `disable` 或 fix |
| **Z** | cover_hits = 0 | 无证据 | `pending`,等再跑 |

### 5c. 当前已知 Y1 family(必须 keep `disable`/`pending`,不能进 allowlist)

所有 `syz_usb_control_io$*` 系列:

```
syz_usb_control_io$hid
syz_usb_control_io$rtl8150
syz_usb_control_io$cdc_ncm
syz_usb_control_io$cdc_ecm
syz_usb_control_io$printer
syz_usb_control_io$sierra_net
syz_usb_control_io$lan78xx
syz_usb_ep_write$ath9k_ep2
```

**root cause**:reFuzz `UsbControlIo` handler(`executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp:67-106`) 跳过 `USB_RAW_IOCTL_EVENT_FETCH`,直接 `EP0_WRITE` 一次完事。syzkaller 上游(`common_usb_linux.h:433-522`)是 EVENT_FETCH → 解析 SETUP packet → routing → EP0_WRITE/READ 完整 protocol。

**修复**:重写 `UsbControlIo`,补 EVENT_FETCH + SETUP 解析。这是独立 worker epic,**不在 allowlist 流水里**。

---

## 6. 已知陷阱清单(下次别再撞)

### 6a. 跑 30s smoke 看到 capture failed

老脚本 `FUZZ_DURATION=30` 太短,VM 没起完就被 SIGINT。**现在默认 corpus-triage 不用 sleep,不会再撞**。

### 6b. 看到 ref/syz=95× 就以为 reFuzz worker 累积过量

raw 假象。用 evidence csv 里的 ratio,不用 per-call jsonl 的 `*_pc_count` 字段算 ratio。

### 6c. 看到 jaccard=1.0 就以为完美等价

vacuous match:cover_hits=0 时 union jaccard 算两个空集 = 1.0。先看 `cover_available_hits`:为 0 就是"没证据",不是"完美"。这种 syscall 不能 promote。

### 6d. layer3 脚本还在 scripts/ 但已退役

`scripts/layer3_paired_oracle.sh`、`layer3_per_pseudo_aggregate.py`(已重命名)、`import_layer3_to_proof_status.py`(已重命名)、`layer3_report_analyze.py` — 留着是为了对照参考,**不要再调用**。proof_status.csv 的 `layer3_*` 列已经 rename 到 `oracle_*`。

### 6e. classifier 默认覆盖盲点

`processColdFaultFamily` prefix list(`tools/refuzz_exec_oracle/main.go:1003`)只列了 page-fault 系列。mount-image / KVM / USB connect 的 cold-start 还混了 mmap 路径 PC,classifier 不识别。结果 `coverage_process_cold_fault_count` 偏低。要扩 list,加:

```
__x64_sys_mmap, __do_sys_mmap, arch_get_unmapped_area_topdown,
task_size_max, in_32bit_syscall, stack_guard_placement,
__pkru_allows_*, _static_cpu_has, rdpkru
```

### 6f. mount-image EBUSY 跨 program

VM serial 里看到 `misc raw-gadget: usb_gadget_register_driver returned -16` 风暴,以及 mount loop device EBUSY。这是 fork-per-program 模型在 program 之间的 state cleanup 时序问题。**不是 mount handler bug**,大多数 mount-image 的 errno mismatch 已经被 `actionable_err_mismatch` 的 mount-image `{0, EBUSY}` tolerant rule 剔掉(`main.go:mountErrnoTolerant`)。

### 6g. ivshmem_worker segfault 一次,后续继续

VM serial 里 boot 65 秒看到一次 `ivshmem_worker[N]: segfault at ...`。**不是流水 bug**,后续 worker_thread 继续跑(PID 不同)。曾经看到但不影响 corpus-triage 结果。

---

## 7. 关键路径速查表

| 想干什么 | 命令 |
|---|---|
| 全新跑一次对照 | `bash scripts/pc_compare/exec_oracle_full_smoke.sh` |
| 看 evidence + 重生成 manifest | `python3 scripts/pc_compare/exec_oracle_per_pseudo_aggregate.py --jsonl run/.../per-call.jsonl --out-csv configs/pseudo_oracle_evidence.csv && python3 scripts/pc_compare/import_oracle_to_proof_status.py --evidence configs/pseudo_oracle_evidence.csv && python3 scripts/generate_pseudo_manifest.py` |
| 复用历史 trace 重跑 oracle | `SKIP_REPLAY=1 TRACE_DIR=... REF_RESULT=... bash scripts/pc_compare/exec_oracle_full_smoke.sh` |
| frozen candidate set(benchmark-fair) | 加 `--no-auto-promote` 给 import |
| 只看 dry-run import 改动 | 加 `--dry-run` 给 import |
| dump 某条 outlier PC | `build-llvm20/refuzz_exec_oracle ... -pc-dump-dir DIR -pc-dump-force-reqs ID1,ID2` |
| 拆 errno 维度看 PC overlap(全景,§2d-1) | `python3 scripts/exec_oracle_errno_stratified_dump.py --jsonl run/.../per-call.jsonl --out-csv /tmp/x.csv --out-txt /tmp/x.txt` |
| 单 syscall PC diff + addr2line(根因,§2d-2) | `python3 scripts/exec_oracle_syscall_pc_diff.py --jsonl run/.../per-call.jsonl --syscall NAME --vmlinux kernel/build-kasan/vmlinux` |

## 8. 文件去哪找什么

```
run/exec-oracle-<ts>/
├── syz-manager.cfg              capture 用的 manager config
├── syz-manager.log              capture 日志(corpus 进度、triage 结束)
├── trace/exec_trace_*.bin       flatrpc 帧(syz 端 ground truth)
├── ref_result.bin               reFuzz worker 重放结果
├── exec-oracle-report.json      §13.1 三层 gate 聚合报告(samples cap 30)
├── per-call.jsonl               全量 per-(req, call) evidence,unique/raw 两套字段
├── oracle.stderr                oracle 运行 stderr(vmlinux load / summary)
└── replayer.log                 stage 2 replayer 摘要

run/cova/replayer-<pid>-<ts>/vm-0/serial.log
                                 replayer VM 的 console serial(看 worker EBUSY / segfault)

configs/
├── pseudo_oracle_evidence.csv   stage 5 输出,per-pseudo 13 列
├── pseudo_proof_status.csv      stage 6 写,candidate set source of truth
├── pseudo_candidate_allowlist.txt  stage 7 derived,observed
├── pseudo_allowlist.txt            stage 7 derived,reviewed=allow 子集
├── pseudo_disablelist.txt          stage 7 derived,upstream 减 allowlist
└── pseudo_manifest.csv             stage 7 输出,25 列全状态

.syzkaller-pin                    syzkaller HEAD sha,preflight 校验
```

## 9. 还在 deferred 的事(下个 session 接手前看)

- **USB control_io worker rewrite**:补 `USB_RAW_IOCTL_EVENT_FETCH` + SETUP 解析,独立 epic
- **cold-fault classifier prefix list 扩展**:加 mmap 系
- **layer3 脚本退役**:用户决定先不删
- **EBUSY raw-gadget 跨 program cleanup**:`misc raw-gadget: ... returned -16` 风暴的根因。**不影响 allowlist 流水**,但是 worker 卫生 issue
