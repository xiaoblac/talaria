# Vendored: libaco

- Upstream: https://github.com/hnes/libaco
- License: Apache-2.0 (see `LICENSE`)
- Pinned commit: `d00631a9e143a8711c0a6e7b603a72b1e379b661` (v1.2.4)

Only the library sources are vendored (`aco.h`, `aco.c`, `acosw.S`,
`aco_assert_override.h`); upstream tests/tutorials are omitted.

## Why

`refuzz_control` runs each `Job` (see `control/src/job/job.cpp`) as a **stackful
coroutine** rather than a dedicated OS thread. Previously one `std::thread`
(8 MB stack) was created per in-flight Job; with tens of thousands of concurrent
Jobs this exhausted both memory (OOM) and the cgroup task limit
(`thread constructor failed: Resource temporarily unavailable`).

libaco's **shared-stack** mode fits the Job model exactly: the control loop is
the `main_co`, every Job is a non-main co, and all Jobs share **one** run-stack
(only one Job runs at a time — "strict alternation"). Each suspended Job only
keeps a copy-stack sized to its actual depth, so N Jobs cost ~N×(used bytes)
instead of N×8 MB, on a single OS thread.

## Updating

Re-copy the four source files from the pinned upstream commit and update the
commit hash above. No API shims are applied — `job.cpp` calls the upstream API
directly.
