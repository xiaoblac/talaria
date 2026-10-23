#!/usr/bin/env python3
"""Focused tests for the shared E1-E9 RTT accounting."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import speed_compare as compare  # noqa: E402


class RttAccountingTest(unittest.TestCase):
    def test_syzkaller_maps_both_transport_directions(self) -> None:
        raw = {
            "enqueued_us": 1000,
            "dequeued_us": 1100,
            "sent_us": 1300,
            "executing_us": 2000,
            "slot_wait_us": 500,
            "completion_observed_us": 3000,
            "result_received_us": 3400,
            "attempt_result_us": 3500,
            "final_done_us": 3700,
            "retry_count": 0,
            "final": True,
            "elapsed_us": 950,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "syz_task_trace.jsonl"
            path.write_text(json.dumps(raw) + "\n", encoding="utf-8")
            rows = compare.parse_syz_task_trace(path)

        stats = compare.compute_rtt_percentiles(rows, tool="syzkaller")
        segments = stats["segments"]
        self.assertAlmostEqual(segments["dispatch_prep"]["p50_ms"], 0.2)
        self.assertAlmostEqual(segments["dispatch_wait"]["p50_ms"], 0.0)
        self.assertAlmostEqual(segments["transport_out"]["p50_ms"], 0.2)
        self.assertAlmostEqual(segments["slot_wait"]["p50_ms"], 0.5)
        self.assertAlmostEqual(segments["execute"]["p50_ms"], 1.0)
        self.assertAlmostEqual(segments["result_copy"]["p50_ms"], 0.4)
        self.assertAlmostEqual(segments["feedback"]["p50_ms"], 0.3)
        self.assertAlmostEqual(segments["total"]["p50_ms"], 2.7)
        self.assertAlmostEqual(stats["executor_service"]["p50_ms"], 0.95)
        self.assertEqual(stats["zones"]["complete_rows"], 1)
        self.assertAlmostEqual(stats["zones"]["queue_mean_ms"], 0.6)
        self.assertAlmostEqual(stats["zones"]["service_mean_ms"], 2.1)
        self.assertAlmostEqual(stats["zones"]["transport"]["mean_ms"], 0.6)
        self.assertAlmostEqual(stats["zones"]["orch"]["mean_ms"], 0.5)
        self.assertAlmostEqual(stats["zones"]["exec"]["mean_ms"], 1.0)

    def test_refuzz_maps_the_same_events_and_full_feedback_interval(self) -> None:
        line = "\t".join((
            "seq=1",
            "evt=task_trace",
            "path=completion",
            "submit_attempt=0",
            "worker_clock_guest=1",
            "task_queue_push_ts_us=1000",
            "task_queue_pop_ts_us=1100",
            "dispatch_prep_done_ts_us=1300",
            "data_plane_call_ts_us=1500",
            "worker_start_ack_host_ts_us=1800",
            "completion_observed_host_ts_us=3000",
            "output_copied_host_ts_us=3200",
            "worker_start_ts_us=100",
            "worker_done_ts_us=900",
            "channel_event_queued_ts_us=3300",
            "fuzzer_feedback_processed_ts_us=3500",
        ))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "host_events.txt"
            path.write_text(line + "\n", encoding="utf-8")
            rows = compare.parse_refuzz_task_trace(path)

        stats = compare.compute_rtt_percentiles(rows, tool="refuzz")
        segments = stats["segments"]
        self.assertAlmostEqual(segments["dispatch_prep"]["p50_ms"], 0.2)
        self.assertAlmostEqual(segments["dispatch_wait"]["p50_ms"], 0.2)
        self.assertAlmostEqual(segments["transport_out"]["p50_ms"], 0.3)
        self.assertAlmostEqual(segments["slot_wait"]["p50_ms"], 0.0)
        self.assertAlmostEqual(segments["execute"]["p50_ms"], 1.2)
        self.assertAlmostEqual(segments["result_copy"]["p50_ms"], 0.2)
        self.assertAlmostEqual(segments["feedback"]["p50_ms"], 0.3)
        self.assertAlmostEqual(segments["total"]["p50_ms"], 2.5)
        self.assertEqual(stats["zones"]["complete_rows"], 1)
        self.assertAlmostEqual(stats["zones"]["queue_mean_ms"], 0.3)
        self.assertAlmostEqual(stats["zones"]["service_mean_ms"], 2.2)

    def test_missing_boundary_keeps_segments_but_not_full_chain(self) -> None:
        line = "\t".join((
            "evt=task_trace",
            "path=completion",
            "submit_attempt=0",
            "worker_clock_guest=1",
            "task_queue_push_ts_us=1000",
            "task_queue_pop_ts_us=1100",
            "data_plane_call_ts_us=1500",
            "worker_start_ack_host_ts_us=1800",
            "completion_observed_host_ts_us=3000",
            "output_copied_host_ts_us=3200",
            "worker_start_ts_us=100",
            "worker_done_ts_us=900",
            "fuzzer_feedback_processed_ts_us=3500",
        ))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "host_events.txt"
            path.write_text(line + "\n", encoding="utf-8")
            rows = compare.parse_refuzz_task_trace(path)

        stats = compare.compute_rtt_percentiles(rows, tool="refuzz")
        self.assertEqual(stats["segments"]["dispatch_prep"]["samples"], 0)
        self.assertEqual(stats["segments"]["dispatch_wait"]["samples"], 0)
        self.assertEqual(stats["segments"]["transport_out"]["samples"], 1)
        self.assertEqual(stats["segments"]["result_copy"]["samples"], 1)
        self.assertEqual(stats["zones"]["complete_rows"], 0)


if __name__ == "__main__":
    unittest.main()
