#!/usr/bin/env python3
"""Validate XiUOS descriptor and seed corpus encoding."""

from corpus import load_descriptor, load_seeds, encode_seed
from worker_abi import CALL_RECORD_SIZE


def main():
    descriptor = load_descriptor()
    seeds = load_seeds(descriptor)

    if len(seeds) < 10:
        raise AssertionError(f"expected at least 10 seeds, got {len(seeds)}")

    names = {seed.name for seed in seeds}
    required = {
        "sem_create_delete",
        "sem_obtain_abandon_delete",
        "sem_set_value_then_obtain",
        "sem_invalid_slot",
        "sem_double_delete",
        "mutex_create_delete",
        "mutex_obtain_abandon_delete",
        "mutex_invalid_slot",
        "mutex_double_delete",
        "sem_mutex_interleave",
    }
    missing = sorted(required - names)
    if missing:
        raise AssertionError(f"missing required seeds: {missing}")

    for seed in seeds:
        payload = encode_seed(seed)
        expected_len = 4 + len(seed.calls) * CALL_RECORD_SIZE
        if len(payload) != expected_len:
            raise AssertionError(
                f"{seed.name}: encoded size {len(payload)} != {expected_len}"
            )
        if payload[2] != len(seed.calls):
            raise AssertionError(f"{seed.name}: encoded call count mismatch")

    print(f"PHASE1_SEED_SELFTEST_OK seeds={len(seeds)}")


if __name__ == "__main__":
    main()
