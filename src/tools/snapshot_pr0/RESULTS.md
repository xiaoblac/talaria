# Snapshot-mode PR0 — feasibility & performance report

Backs `docs/plans/snapshot-mode.md` PR0 (backend feasibility spike). Question:
is a **Snapchange-style stock-KVM dirty-page reset** viable for reFuzz, and what
does its per-program cost look like — vs the continuous fork+wait baseline and
vs the Nyx/kAFL Intel-PT/PML production path. **Not** savevm/loadvm.

Verdict in one line: **the mechanism works on stock KVM here; throughput is great
for light programs and bad for heavy-dirty programs — but the heavy penalty is an
AMD-no-PML floor artifact that the Intel+PML production path removes.**

---

## 1. Host under test (a deliberate pessimistic floor)

- AMD Ryzen 9 7945HX, **running nested inside VMware**, **stock KVM**.
- No Intel PT (AMD) → no hardware-trace coverage; KCOV is the coverage path.
- No Intel **PML** (AMD) → KVM tracks dirty pages by **write-protecting them and
  faulting on first write**, the slow mechanism.

Every number below is therefore a **floor**. Bare-metal Intel+PML (the Nyx/kAFL
production target) will be materially faster on exactly the axis that hurts here.

Baseline to beat: continuous mode per-program **fork+wait ≈ 16 ms** (18 exec/s).

---

## 2. Capabilities (`kvm_dirty_probe.c`)

`/dev/kvm` present + r+w. `KVM_GET_API_VERSION = 12`. Even nested on AMD:

| capability | present |
|---|---|
| `KVM_CAP_USER_MEMORY` | yes |
| `KVM_CAP_IMMEDIATE_EXIT` | yes |
| `KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2` | yes |
| `KVM_CAP_DIRTY_LOG_RING` | yes (1 MB ring) |

So the *modern, efficient* dirty-log APIs are available (not just legacy bitmap
scan). NOTE: dirty-ring / manual-protect change how dirty info is *collected*;
they do **not** remove the underlying AMD write-protect tracking measured in §4.

End-to-end dirty tracking proven: a real-mode guest wrote pages 2/3/5; all
reported dirty (page 1 = code page, conservatively over-reported, harmless).
`KVM_GET_DIRTY_LOG` ≈ 0.027 ms.

---

## 3. Restore cost — copy-back half (`kvm_dirty_probe.c`)

Restore = `GET_DIRTY_LOG` scan + copy back **only dirtied pages** from the S0
baseline. Copy-back cost (≈ 12.7 GB/s here):

| dirty-set | copy-back / restore |
|---|---|
| 1 page | ~0 ms |
| 1 MB | 0.047 ms |
| 16 MB | 0.785 ms |
| 132 MB (mount-image full inflate) | **10.4 ms** |

**The copy-back half is cheap and bounded** — even the 132 MB worst case (10.4 ms)
is under the 16 ms continuous baseline.

---

## 4. Execution cost — dirty-tracking half (`kvm_track_overhead.c`)

The other half: overhead **while the guest runs** with dirty logging on. A 32-bit
guest writes N pages; we time it logging-OFF vs logging-ON, **warm/steady-state**
(re-protecting between runs, as a fuzz loop does each iteration).

| dirty | logging OFF (warm) | logging ON (warm) | **tracking delta** | per page |
|---|---|---|---|---|
| 1 MB (256 pg) | 0.007 ms | 1.63 ms | **1.6 ms** | 6.3 µs |
| 16 MB (4 K pg) | 0.035 ms | 26.5 ms | **26.5 ms** | 6.5 µs |
| 64 MB (16 K pg) | 0.17 ms | 108 ms | **108 ms** | 6.6 µs |
| 129 MB (33 K pg) | 0.24 ms | 212 ms | **212 ms** | 6.4 µs |

**~6.4 µs per dirtied page, linear** = the AMD-no-PML write-protect-fault cost.
This is the dominant term and the box's real weak spot.

---

## 5. Combined per-program cost vs continuous (this floor box)

per-restore ≈ tracking (§4, during run) + copy-back (§3, after run):

| program dirties | tracking | copy-back | snapshot total | vs continuous 16 ms |
|---|---|---|---|---|
| ~1 MB (light syscall) | 1.6 ms | 0.05 ms | **~1.7 ms** | **~9× faster** ✅ |
| ~16 MB | 26.5 ms | 0.8 ms | ~27 ms | ~1.7× slower |
| ~64 MB | 108 ms | 3.1 ms | ~111 ms | ~7× slower |
| ~129 MB (mount-image) | 212 ms | 10.4 ms | **~222 ms** | **~14× slower** ❌ |

**Crossover ≈ 2,400 dirty pages ≈ 9–10 MB.** Below it snapshot wins big; above it
snapshot loses — driven almost entirely by §4 tracking, i.e. AMD write-protect
faults.

---

## 6. Verdict

1. **Feasibility: PASS.** Stock-KVM dirty-page snapshot/restore works on this box
   (incl. nested-AMD-VMware); modern dirty-log APIs present; mechanism proven
   end-to-end. The Snapchange-style direction is sound — no patched host needed
   to build/iterate.
2. **Performance is bimodal here.** Light programs (< ~9 MB dirty) get a large
   throughput win; heavy-dirty programs (mount-image / big USB buffers) are much
   slower than continuous — **because of AMD-no-PML write-protect tracking, not
   because of snapshotting or copy-back.**
3. **The heavy penalty is a FLOOR artifact.** On Intel+PML (the Nyx/kAFL
   production target) dirty tracking is hardware-logged — the ~6.4 µs/page
   write-protect cost largely disappears, so the §4 column collapses and heavy
   programs stop being a problem. This empirically confirms the doc's premise:
   the ceiling gap between this box and the Intel path lives in the *reset/track
   mechanism*, exactly as predicted.

---

## 7. Implications for next steps

- **Use this AMD box for CORRECTNESS, not heavy-program throughput claims.** It is
  fine for: state-isolation witnesses (program A dirties mount/loop, restore,
  program B proves it gone), reset determinism, light-program perf. Do **not**
  benchmark a mount-image program here and conclude "snapshot is slow" — that is
  the floor artifact.
- **Reserve throughput numbers for an Intel+PML host.** That is also where the
  PT-coverage production path (kAFL/Nyx) lives. One provisioning step unlocks both.
- **Mitigations worth testing later** (reduce dirtied-page count = reduce §4 cost,
  even on AMD): smaller snapshot region / restrict the dirty surface; verify
  whether bare-metal Zen4 + a newer host kernel uses **NPT A/D-bit** dirty
  tracking (cheaper than write-protect) instead of the path forced here under
  nested VMware; `DIRTY_LOG_RING` for collection.
- **Does not change the plan's two-path split.** Local PR0/PR1 development +
  correctness on stock-KVM dirty-page reset + KCOV (this box); production
  throughput + PT on Intel+PML. Proceed to PR1 (`SnapshotBackend` API) using this
  box for correctness witnesses.

### Decisive open perf question — real-workload dirty-set (NOT yet measured)

Epistemic limit of this report: the §4/§5 curves measure the **mechanism**
(cost per dirtied page ≈ 6.4 µs on this host), **not the workload**. They do NOT
tell us how slow real reFuzz throughput is, because they assume synthetic
dirty-set sizes (the 132 MB case is a synthetic worst case = a mount-image fully
inflated and every page dirtied).

The number that actually decides throughput is the **dirty-page-count
distribution of real syscall programs**: per-program cost ≈ dirty_pages × 6.4 µs
(+ copy-back). If most corpus programs dirty < ~2,400 pages (< ~9 MB) they land in
the 9× faster zone even on this floor box; mount-image/USB-big-buffer programs are
the minority worst case. **Do not extrapolate aggregate throughput from the
synthetic mount-image number.**

How to get the real number, by effort:
1. **Cheap / now (stock QEMU + QMP):** run a corpus replay and sample QMP
   `calc-dirty-rate`; divide aggregate dirty-rate by exec/s → rough pages/program.
   Whole-VM, rate-based, coarse upper bound, but a real-VM ballpark with no code.
2. **Accurate (real per-program):** wire `KVM_MEM_LOG_DIRTY_PAGES` +
   per-program `KVM_GET_DIRTY_LOG` into the replayer's QEMU path at program
   boundaries → exact per-program dirty-count distribution across the corpus.
   More work (QEMU-side), but it is also the same machinery the snapshot reset
   itself needs, so it is not throwaway.

Until (1) or (2) exists, treat snapshot throughput on this box as UNKNOWN for the
real workload — proven only that the mechanism works and that its per-page cost
is an AMD-no-PML floor.

---

## 8. Reproduce

```bash
cd tools/snapshot_pr0
cc -O2 -o kvm_dirty_probe     kvm_dirty_probe.c      && ./kvm_dirty_probe
cc -O2 -o kvm_track_overhead  kvm_track_overhead.c   && ./kvm_track_overhead
```

- `kvm_dirty_probe.c`   — capabilities + end-to-end dirty-tracking proof + copy-back model (§2,§3).
- `kvm_track_overhead.c` — dirty-tracking execution overhead, off vs on, warm (§4).

Both are read-only feasibility spikes (raw `/dev/kvm`, no savevm/loadvm, no repo
build-system integration). Exit 0 = success.

---

## 9. Real-workload dirty-set — measured in the real KASAN VM (answers §7)

§5 used SYNTHETIC dirty-set sizes. To get the REAL number we instrumented the
production replay path: a gated hook in `tools/refuzz_exec_replayer` connects to
the VM's fixed QMP monitor (`REFUZZ_QMP_FIXED_PORT`, nobody else uses it),
`stop`s the vcpu and `pmemsave`s guest RAM **before** and **after** exactly one
isolated program (`REFUZZ_ONLY_REQ`), then `tools/snapshot_pr0/pagediff`
page-diffs the two dumps. A 2 GB measurement VM (`configs/exec_oracle_measure_2g.json`)
keeps all guest RAM contiguous below the PCI hole so a single `pmemsave` captures
it. A `REFUZZ_DUMP_IDLE_MS` mode brackets an idle window (no program) for the
background floor.

**Result: the per-program signal is SWAMPED by VM-config background churn — it
could NOT be cleanly isolated in the KASAN VM.**

Background floor (idle, no program), KASAN kernel:

| idle window | dirty pages | note |
|---|---|---|
| 10 ms  | 6 346  | a large fixed floor exists already at 10 ms |
| 100 ms | 11 387 | smp=2 |
| 1000 ms| 31 604 | grows ~22–56 pages/ms on top of the floor |
| 100 ms | 6 564  | **smp=1** (≈ −42 % vs smp=2) |

A "light" program's before/after window measured 35 931 pages, but with a
window-duration-dependent background of ~7 K–32 K pages the program's marginal is
not separable.

**Attribution (all VM-config, not workload):**
- A large base floor (~6.5 K pages / 100 ms even at smp=1) = **KASAN**: every
  kernel memory access also writes shadow → huge distinct-page churn.
- Per-extra-vCPU churn (~4.8 K pages / 100 ms each) = parallel kernel background.
- Worker threads are NOT it (lazy-spawned; idle before a program).

**Conclusion.** In the KASAN parity VM the snapshot reset cost is set by VM
configuration, not the program: ~28–128 MB dirtied per program-window regardless
→ on this AMD floor (~6.4 µs/page, §4) ~45–200 ms/program → snapshot non-viable
in this config. The lever for BOTH a viable snapshot AND a clean per-program
measurement is a **quiet VM**: a non-KASAN (vanilla, no-sanitizer) kernel + smp=1.
`build-kcsan`/`build-kmsan` do NOT qualify (KCSAN/KMSAN also instrument memory);
no vanilla kernel is currently built. Getting the true per-program workload
dirty-set requires building/booting such a VM (and confirming the reFuzz worker
boots on it).

Hooks added for this (all env-gated, no effect on normal runs):
- `tools/refuzz_exec_replayer/replayer.cpp`: `MeasureQmpDump` + before/after +
  `REFUZZ_DUMP_IDLE_MS` bracket.
- `executor/channel/substrate/src/runtime/vm/vm_instance.cpp`:
  `REFUZZ_QMP_FIXED_PORT` env override (pin QMP to a known port).
- `tools/snapshot_pr0/pagediff.c`: page-level dump diff (self-tested).
- `configs/exec_oracle_measure_2g.json` (2 GB) + `_cpu1.json` (smp=1).

### 9b. Literature check — this is a known problem with a known fix (Intel PML)

A web survey confirms the §9 finding is exactly the problem **Intel PML** (Page
Modification Logging) was built to solve, and that KASAN snapshot fuzzing is
industry-standard *on PML hosts*:

- **kAFL/Nyx run KASAN kernels under snapshot fuzzing** — but KASAN is used for
  *bug detection* (QEMU overwrites the guest KASAN report handler → hypercall →
  crash → reload snapshot), while **dirty tracking / fast reset uses Intel PML**,
  not KASAN's shadow and not write-protect. kAFL's stack is explicitly "Intel VT,
  **Intel PML** and Intel PT".
- PML logs dirty GPAs in **hardware** (EPT D-bit 0→1 → 4 KB log buffer), so the
  "intensive write-fault EPT violations" of the write-protect approach are
  avoided. Write-protection tracking "induces a lot of page faults … the overhead
  can be large if write operations from guest are intensive" — which is exactly
  what KASAN makes every access (shadow write), and exactly the ~6.4 µs/page we
  measured on this **AMD (no PML)** box.

**So the §9 non-viability is an AMD-no-PML artifact, not a snapshot/KASAN
artifact.** On an Intel+PML host: tracking ≈ free (hardware), and only the §3
copy-back remains (~0.3 µs/page → ~10 ms even for a 30 K-page KASAN program) →
viable. kAFL is the existence proof for KASAN-kernel snapshot fuzzing on PML.

Caveat (also in the literature): even PML has overhead for *extremely*
write-intensive guests (PML buffer fills every 512 dirty pages → an extra
VMEXIT), so a KASAN guest is heavier under snapshot than a non-KASAN guest even
on PML — viable, but not free. A non-KASAN VM is still the cheapest; KASAN+PML is
the bug-finding-capable production point.

Sources: kAFL Linux-kernel tutorial (KASAN handler interception) and kAFL docs
(VT/PML/PT) <https://intellabs.github.io/kAFL/tutorials/linux/fuzzing_linux_kernel.html>,
<https://intellabs.github.io/kAFL/>; Intel PML design
<https://arxiv.org/pdf/2001.09991>; PML KVM support
<https://lkml.kernel.org/kvm/54D30C5D.1000402@linux.intel.com/T/>; write-protect
dirty-tracking cost <https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2018/08/11/dirty-pages-tracking-in-migration>;
BoKASAN selective sanitization to cut KASAN fuzzing overhead
<https://www.usenix.org/system/files/usenixsecurity23-cho.pdf>.

## §10 savevm/loadvm feasibility — PR0 task 0 (2026-05-26)

Validates the LOCKED baseline route (doc choice A: syz-compatible
`savevm/loadvm` + qcow2, vendor-neutral). Script: `savevm_feasibility.py`.

Setup: qcow2 overlay over the raw base (`qemu-img create -f qcow2 -F raw -b
bookworm.img`), **no `-snapshot`**, `-cpu host,migratable=on,tsc=off`, `-m 2048
-smp 1`, KASAN bzImage, QMP `savevm syz`/`loadvm syz`. Host = AMD Ryzen 9 7945HX
(nested in VMware), stock KVM, QEMU 6.2.

**Result: PASS.** Booted to login; `savevm` OK (2.7s, one-time S0); `loadvm` OK
×5 = 1916/1693/1683/1744/1639 ms (median **1693 ms**, stable). Snapshot VM
size = **820 MiB**. Disk blocker resolved: savevm/loadvm work on qcow2 + KVM,
AMD, no Intel PT, no patched host.

**Interpretation.** The route works on this AMD box exactly as the doc claims.
The ~1.7s restore is the **full-state savevm cost for a fat VM** (820 MiB =
KASAN kernel + fully-booted Debian userspace, `-m 2048` touched). syzkaller's
`snapshot.h` targets a quiet VM at 132-260 MB → 150-275 ms; we are 3-6× larger
→ 3-6× slower, consistent. **Restore latency is footprint-bound, not
mechanism-bound** — the lever is PR2 footprint reduction (executor-as-init to
drop sshd/systemd/udevd per `snapshot.h:29`, smaller `-m`, fewer devices), NOT
dirty-page reset or Intel PT. Note this savevm full-state path does no
dirty-tracking, so the AMD-no-PML penalty in §4/§9 does NOT apply to the locked
baseline (it only applies to the PR3 dirty-page optimization lane).

## §11 footprint sweep — can savevm get fast? (2026-05-26)

Script: `footprint_sweep.py`. Two levers isolated against the c1 baseline.

| config | mem | boot | snap MiB | restore med ms |
|---|---|---|---|---|
| c1 full boot | 2048 | yes | 831 | 2267 |
| c2 `init=/bin/sh` | 2048 | yes | 702 | 1731 |
| c3 `init=/bin/sh` | 512 | **no** | — | KASAN panic |
| c4 `init=/bin/sh`+fewdev | 256 | **no** | — | KASAN panic |

**Findings.**
1. **`init=/bin/sh` (executor-as-init proxy) saves only ~15%** (831→702 MiB,
   2267→1731 ms). Userspace boot (systemd/sshd/udevd) is NOT the dominant cost.
2. **Small `-m` is hard-blocked by KASAN**: c3/c4 panic at
   `kasan_populate_shadow: Failed to allocate page` — KASAN can't allocate its
   shadow in 512/256 MB. So you cannot shrink the snapshot via `-m` on the KASAN
   kernel.
3. **The dominant footprint IS KASAN.** 700-830 MiB is the KASAN-kernel snapshot
   floor → ~1.7-2.3 s restore (~0.5 exec/s). snapshot.h's 132-260 MB / 150-275 ms
   target assumes a quiet **non-KASAN** VM. KASAN ≈ 3× the footprint ≈ 3× the
   restore.

**Conclusion.** Footprint reduction to the syz target is **blocked by the KASAN
kernel**; `-m`/init/device tweaks cannot overcome KASAN's shadow. The decisive
lever is a **vanilla (non-KASAN) kernel** for the snapshot VM (not currently
built) — at the cost of KASAN bug-detection. This independently confirms §9's
"snapshot cost is VM-config-bound, viable needs a quiet vanilla VM" — now via the
savevm path, not just dirty-tracking.

**But this does NOT block snapshot mode's primary value.** The doc's primary
driver (reproducibility, state isolation, stable KCOV, crash replay — PR1 witness
suite) tolerates ~1.7 s/restore: a repro/isolation witness runs a handful of
execs, not millions. Only the **throughput leg** is gated, and throughput is
continuous mode's job anyway. So: PR0/PR1 (mechanism + correctness) proceed fine
on the KASAN VM; a fast/throughput snapshot lane is a separate future task gated
on a vanilla-kernel build.

## §12 snapshot loop + state-isolation witness — PR0 increment 1 (2026-05-26)

Script: `snapshot_loop_witness.py`. The syzkaller-style snapshot LOOP, host side
(savevm S0 -> per-iteration loadvm), proven with a state-isolation witness.
Agent transport = serial console (PR0 bootstrap; ivshmem deferred).

Witness per iter: `P=lines(/tmp/W); append a line; report PRE=P POST=after`.
Isolation holds iff every iter sees `PRE=0 POST=1` (the previous iter's mutation
was wiped by the restore).

**Result: PASS.** 6/6 iters `PRE=0 POST=1`, runstate=running throughout, loadvm
~1.3-1.6 s (700 MiB KASAN snapshot). savevm leaves the VM **running** (no manual
`cont` needed). The **serial agent survives `loadvm`** — every post-restore iter
got a reply; the cheap serial-bootstrap agent works across restore, so ivshmem is
not required for the agent *signal* at this stage (it is still wanted later for
fast input injection + KCOV output).

**Diagnosis win.** First run failed (no witness reply, even iter 1 which has no
loadvm before it). A pre-savevm sanity witness isolated the cause: NOT snapshot/
pause (runstate=running), but the **`init=/bin/sh` degenerate env** — PATH unset
(`wc`/`rm` not found) + root mounted read-only (`/tmp/W` unwritable). Fix: add
`rw` to the kernel cmdline + `export PATH=...` before savevm (baked into S0, so
every restore inherits it). Method: always run a pre-snapshot sanity to separate
"guest env" from "snapshot mechanism" failures.

**Status.** The core snapshot SEMANTIC is proven on this AMD box: restore wipes
guest state -> per-testcase isolation. doc PR1 state-isolation gate met (with a
filesystem-state witness). Next: (a) strengthen to a mount/loop-device witness
(directly closes the loop on the cross-program loop-state divergence that
continuous mode could not fix); (b) replace the serial toy-agent with the real
reFuzz path — `ivshmem-plain` input/output + the worker as guest agent + wire
`savevm/loadvm` into the substrate (`qemu_args.cpp` + a snapshot driver).

## §13 snapshot KCOV end-to-end — PR0 increment 2 / option B (2026-05-26)

Scripts: `snap_kcov_agent.c` (static guest KCOV harness) + `snapshot_kcov_e2e.py`.
A real syscall program executed in snapshot mode, real KCOV collected. This is the
"can the snapshot engine fuzz?" milestone (NOT a syscall-parity oracle).

Agent delivery: read-only **ISO CD-ROM** (`genisoimage` -> `/dev/sr0`, iso9660).
Agent signal: serial console (PR0 bootstrap). savevm/loadvm via QMP.

**Result: real program + real KCOV in snapshot = PASS.**
savevm S0 = 2122 ms / 702 MiB; 5 runs from S0:
n = 19726 / 19624 / 19636 / 19715 / 19624 PCs; loadvm restore 1.3-1.6 s.
Coverage counts within **±0.5%** across restores (vs 12000-19000 jitter when
restore was broken) — restore-to-S0 strongly stabilizes coverage.

**Two infra gotchas found + fixed (both real PR0 knowledge):**
1. **tty echo** made regexes match the echoed *command* text, not output (bogus
   `XFER=FAIL`). Fix: `stty -echo` after shell ready.
2. **vvfat breaks `savevm`** — a rw vvfat disk has no internal-snapshot support, so
   `savevm` silently no-ops ("no snapshot available", 1 ms). `fat:` (ro) as an IDE
   `media=disk` is rejected ("Block node is read-only"). Fix: deliver the agent on
   a **read-only ISO CD-ROM** (`media=cdrom`); savevm skips read-only media and
   snapshots only the rootfs qcow2. Added a post-savevm assert (snapshot present +
   real MiB size) so a silent savevm failure can never again be misread as data.

**Honest nuance — coverage is NOT bit-identical across restores (~0.5% PC-set
jitter).** Same S0 + same deterministic program still gives a slightly different
PC *set* (e.g. iters 2 & 5 both n=19624 but different hashes). Cause: inherent
kernel micro-nondeterminism from an identical snapshot (timer/interrupt landing
points, slab/RNG/jiffies state). This is a known snapshot-fuzzing reality —
syzkaller itself accepts coverage is not 100% reproducible (issue #4639). So the
right bar is "coverage real + tightly reproducible distribution", not bit-equal
hashes; the script's strict hash-equality gate was too strict.

**Status.** PR0 mechanism is proven end-to-end on the AMD box: boot -> savevm S0
-> per-testcase loadvm -> execute real program -> collect real KCOV, all
vendor-neutral (stock QEMU/KVM, no Intel PT). Next toward a real component:
replace the toy serial agent with the reFuzz worker + `ivshmem-plain`
input/output, and wire `savevm/loadvm` into the substrate. Optional refinement:
quantify/reduce the ~0.5% coverage jitter (idle the VM, handle timer IRQs) if a
specific use needs tighter reproducibility.

## §14 host integration through the real reFuzz substrate — Bricks 1-3 (2026-05-26)

The Python spikes proved the mechanism; these bricks move the HOST side into
reFuzz C++ (gated by `RuntimeInstanceConfig.snapshot_fuzzing`, default off ->
continuous args byte-identical):

- **Brick 1** `runtime_config.hpp` + `qemu_args.cpp`: snapshot_fuzzing path =
  writable qcow2 + NO `-snapshot` (only one `-snapshot` literal remains, in the
  `else if (cfg.snapshot)` branch, unreachable when snapshot_fuzzing) + amd64 cpu
  rewritten to `host,migratable=on,tsc=off`.
- **Brick 2** `vm_instance.cpp`: on start(), create a fresh per-instance qcow2
  overlay (`qemu-img create -f qcow2 -F <detected> -b <base>`), boot from it; base
  stays immutable.
- **Brick 3** `tools/refuzz_snapshot_driver/main.cpp` (+ CMake target): boots a
  snapshot_fuzzing VM via `MakeVmInstanceOps`/`ops.start()` and drives
  `savevm S0` / `loadvm` over the QMP endpoint (`ops.monitor_endpoint()`; QMP
  client mirrors the replayer's).

**Result: PASS, end-to-end through reFuzz's own substrate (not Python).**
start() booted (overlay `snapshot-overlay.qcow2` created, SSH up); savevm S0 =
2567 ms / 833 MiB; loadvm x5 = 1486-1624 ms (real restores); verdict PASS.
Confirms Bricks 1+2 produce a savevm-capable VM and the substrate QMP path drives
the snapshot loop.

**Status.** Host side is integrated + validated in product code. Remaining =
**Brick 4** (guest): the reFuzz worker as the ivshmem snapshot agent (read
`ExecRequest` from `ivshmem-plain`, execute from restored S0, copy KCOV+results
back), mirroring `executor/snapshot.h`. Brick 3 alone is host-only (no program
execution yet — that is Brick 4).
