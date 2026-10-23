# Fixed-workload characterization

`refuzz-workload-characterize` describes the pre-execution shape of a sealed
request-stream v2 workload. It uses the production request-stream reader,
`syz::TextDecoder`, typed syscall metadata, and `syz::serialize_for_exec`.
It does not parse syzlang strings or use observed latency, CPU, coverage size,
or completion rate to classify a workload.

## Usage

```sh
build/refuzz-workload-characterize STREAM.bin WORKLOAD_ID OUTPUT_DIR
```

The tool writes two files atomically and refuses to overwrite existing output:

- `WORKLOAD_ID.records.jsonl`: one row per request, preserving the quantities
  from which every aggregate is derived.
- `WORKLOAD_ID.summary.json`: counts, percentages, and nearest-rank
  median/p95/p99 distributions.

The complete stream must pass its header, footer, record-count, and sequence
checks. Every record must also decode to a typed program and lower to the
normal exec-wire representation. Any failure invalidates the whole output.

## Dimensions

| Dimension | Typed quantities |
|---|---|
| Request footprint | Bytes produced by `syz::serialize_for_exec` |
| Program structure | Calls per program and native/pseudo-call composition |
| Declared wait budget | Nonzero syscall `timeout` and `prog_timeout` attributes |
| Intra-program concurrency | Async call properties jointly with threaded mode |
| Remote coverage | Calls whose syscall metadata carries `remote_cover` |

`timeout` is retained as a per-call attribute, with per-program sum and maximum
reported separately. `prog_timeout` is summarized by its per-program maximum,
matching executor semantics. An async call is counted as effective concurrency
only when the request also enables threaded execution. Remote-coverage incidence
is program-level because one marked call enables the additional program-level
coverage-settlement behavior; the number of marked calls is retained as a
secondary structural measurement.
