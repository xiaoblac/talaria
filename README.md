# Talaria Evaluation Dataset

This dataset contains the data for the four experiments reported in
*Talaria: Accelerating Kernel Fuzzing through Efficient Test Execution*:

1. **RQ1: Execution efficiency** - request-path wall time, CPU time, queueing,
   and program throughput.
2. **RQ2: Resource efficiency** - full-guest CPU accounting, kernel profiles,
   and per-program/per-second resource usage.
3. **RQ3: Coverage progress** - PC and branch coverage measured during 24-hour
   campaigns on Linux v6.12, v6.18, and v7.1.
4. **RQ4: Bug discovery** - crash artifacts from eight independent 48-hour
   campaigns on Linux v7.1.

The four experiments are distributed as four self-contained archives:

| Archive | Experiments | Contents |
|---|---|---|
| `talaria-rq1-execution.tar.zst` | RQ1 | Request streams, wall-time records, queueing data, throughput data, and RQ1 reports |
| `talaria-rq2-resource.tar.zst` | RQ2 | Shared request streams and timing records plus guest CPU accounting, statistics, kernel profiles, and RQ2 reports |
| `talaria-rq3-coverage.tar.zst` | RQ3 | Coverage curves, coverage sets, PC differences, and summaries |
| `talaria-rq4-bug.tar.zst` | RQ4 | Talaria and Syzkaller crash artifacts |

RQ1 and RQ2 are distributed as 50 MiB upload parts because the source connection
cannot sustain a single multi-gigabyte upload. The logical data packages remain
the four archives above.

### Reassemble, verify, and extract

Download the release assets into one directory and reassemble the two large
archives before extraction:

```bash
cat talaria-rq1-execution.tar.zst.part-* > talaria-rq1-execution.tar.zst
cat talaria-rq2-resource.tar.zst.part-* > talaria-rq2-resource.tar.zst
sha256sum -c SHA256SUMS
sha256sum -c SHA256SUMS.parts

tar --zstd -xf talaria-rq1-execution.tar.zst
tar --zstd -xf talaria-rq2-resource.tar.zst
tar --zstd -xf talaria-rq3-coverage.tar.zst
tar --zstd -xf talaria-rq4-bug.tar.zst
```

Part files use zero-padded numeric suffixes (`part-00`, `part-01`, ...), so the
lexicographic `part-*` order is the correct concatenation order.

### Create archives and upload parts

The four logical archives can be recreated from their extracted root
directories with:

```bash
tar --zstd -cf talaria-rq1-execution.tar.zst talaria-rq1-execution
tar --zstd -cf talaria-rq2-resource.tar.zst talaria-rq2-resource
tar --zstd -cf talaria-rq3-coverage.tar.zst talaria-rq3-coverage
tar --zstd -cf talaria-rq4-bug.tar.zst talaria-rq4-bug
```

The two large archives were split and checksummed with:

```bash
mkdir -p parts
split -b 50M -d -a 2 --numeric-suffixes=0 \
  talaria-rq1-execution.tar.zst \
  parts/talaria-rq1-execution.tar.zst.part-
split -b 50M -d -a 2 --numeric-suffixes=0 \
  talaria-rq2-resource.tar.zst \
  parts/talaria-rq2-resource.tar.zst.part-

(cd parts && sha256sum talaria-rq*.part-* > ../SHA256SUMS.parts)
sha256sum talaria-rq1-execution.tar.zst \
  talaria-rq2-resource.tar.zst \
  talaria-rq3-coverage.tar.zst \
  talaria-rq4-bug.tar.zst > SHA256SUMS
```

The scripts used for the four data packages select only the RQ1-RQ4 artifacts
described below and exclude whole-run logs, duplicate request streams, runtime
work directories, and the early `_superseded/` collection runs.

## RQ1 and RQ2 performance data

RQ1 and RQ2 use the same measured runs under:

- `e2-replay/`
- `e3-scale/`
- `e3scale-matrix/`
- `reports/`

Both archives contain the two ordered request streams consumed by the experiments
(`syz-a` and `rfz-a`) and the shared timing records needed to reproduce their
respective metrics. Shared run data is intentionally duplicated so that each
experiment archive is self-contained.

The RQ1 archive focuses on execution timing, queueing, completion, and
throughput data. The RQ2 archive additionally includes the guest probe data
(`probe/gp.data`, symbol maps, `/proc/stat` snapshots, CPU attribution, and
kernel profile reports).

Each run records its code identity in `RUN.json`. The twelve
`e3scale-matrix` runs use the code identity in `CODEVER.json`. Measurement
inputs include `host_events.txt`, `worker.log`, `syz_task_trace.jsonl`,
`syz_perf_serial.log`, and the guest probe data. The archive intentionally
excludes the early `_superseded/` collection runs and legacy prototypes,
unused request streams, duplicate copies of `request_stream.bin`, and runtime
work directories. `STREAM.json` records the authoritative stream identity and
SHA-256 digest.

## RQ3 coverage data

The coverage archive contains the final coverage artifacts for nine 24-hour
paired campaigns:

- Linux v6.12: runs r1-r3
- Linux v6.18: runs r1-r3
- Linux v7.1: runs r1-r3

For each campaign it includes PC and branch coverage curves, edge counts,
final PC sets and set differences, coverage hashes, run configuration,
summaries, and the aggregate figures in `figures/`. Raw VM logs, runtime work
directories, corpus databases, and duplicated `rfz-data/` runtime trees are
not included.

## RQ4 bug data

The bug archive contains the crash artifacts from eight independent 48-hour
campaigns on Linux v7.1:

- `refuzz/`: 84 Talaria `kernel_crash` artifact directories.
- `syzkaller/`: 88 Syzkaller crash directories.

Talaria artifacts include metadata, reports, the crashing program, output,
execution history, the console tail, and the symbolized report. Syzkaller
artifacts include the description, reports, machine information, and title
statistics. Whole-run logs and Syzkaller per-reproduction `logN` files are not
included.

## Integrity

`SHA256SUMS` records the four complete archive checksums.
`SHA256SUMS.parts` records the upload-part checksums. Paths inside each archive
are rooted at the archive name without the `.tar.zst` suffix, for example
`talaria-rq1-execution/` and `talaria-rq4-bug/`.
