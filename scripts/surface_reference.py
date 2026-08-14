#!/usr/bin/env python3
"""Independent M2 reference model for bounded, generation-safe surface leases."""
from __future__ import annotations

import argparse
import json
import random
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "artifacts" / "surface-reference.json"


@dataclass(frozen=True)
class Token:
    pool_id: int
    slot: int
    generation: int


@dataclass
class Slot:
    generation: int = 0
    occupied: bool = False
    size: int = 0


class Pool:
    def __init__(self, pool_id: int, slots: int, per_surface: int, total: int):
        if not (1 <= slots <= 128 and 1 <= per_surface <= total <= 1024 * 1024 * 1024):
            raise ValueError("invalid config")
        self.pool_id = pool_id
        self.per_surface = per_surface
        self.total = total
        self.slots = [Slot() for _ in range(slots)]
        self.reserved = 0
        self.high_water_bytes = 0
        self.high_water_surfaces = 0
        self.acquisitions = 0
        self.releases = 0
        self.rejections = 0

    def acquire(self, size: int) -> Token | None:
        if size <= 0 or size > self.per_surface or self.reserved + size > self.total:
            self.rejections += 1
            return None
        index = next((i for i, slot in enumerate(self.slots) if not slot.occupied), None)
        if index is None:
            self.rejections += 1
            return None
        slot = self.slots[index]
        slot.generation = (slot.generation + 1) & ((1 << 64) - 1)
        if slot.generation == 0:
            slot.generation = 1
        slot.occupied = True
        slot.size = size
        self.reserved += size
        self.acquisitions += 1
        self.high_water_bytes = max(self.high_water_bytes, self.reserved)
        self.high_water_surfaces = max(self.high_water_surfaces, self.in_use)
        self.assert_invariants()
        return Token(self.pool_id, index, slot.generation)

    def release(self, token: Token) -> bool:
        if token.pool_id != self.pool_id or not (0 <= token.slot < len(self.slots)):
            return False
        slot = self.slots[token.slot]
        if not slot.occupied or slot.generation != token.generation:
            return False
        self.reserved -= slot.size
        slot.occupied = False
        slot.size = 0
        self.releases += 1
        self.assert_invariants()
        return True

    @property
    def in_use(self) -> int:
        return sum(slot.occupied for slot in self.slots)

    def assert_invariants(self) -> None:
        assert 0 <= self.in_use <= len(self.slots)
        assert self.reserved == sum(slot.size for slot in self.slots if slot.occupied)
        assert 0 <= self.reserved <= self.total
        assert all(not slot.occupied or 0 < slot.size <= self.per_surface for slot in self.slots)


def git_commit() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else None


def run(iterations: int, seed: int) -> dict[str, object]:
    rng = random.Random(seed)
    pool = Pool(pool_id=17, slots=8, per_surface=32 * 1024 * 1024, total=128 * 1024 * 1024)
    active: list[Token] = []
    historical: list[Token] = []
    stale_release_attempts = 0
    stale_release_accepted = 0
    cross_pool_attempts = 0
    cross_pool_accepted = 0

    for _ in range(iterations):
        action = rng.randrange(100)
        if action < 54:
            # Includes valid sizes, zero, per-surface overflow, and total-pressure cases.
            selector = rng.randrange(20)
            if selector == 0:
                size = 0
            elif selector == 1:
                size = pool.per_surface + rng.randrange(1, 4096)
            else:
                size = rng.randrange(1, 24 * 1024 * 1024)
            token = pool.acquire(size)
            if token is not None:
                active.append(token)
                historical.append(token)
        elif action < 84 and active:
            index = rng.randrange(len(active))
            token = active.pop(index)
            assert pool.release(token)
            stale_release_attempts += 1
            if pool.release(token):
                stale_release_accepted += 1
        elif historical:
            token = rng.choice(historical)
            stale_release_attempts += 1
            if pool.release(token):
                # A historical token can still be active. Only count acceptance as stale
                # when it is not present in the current active set.
                if token not in active:
                    stale_release_accepted += 1
                else:
                    active.remove(token)
        else:
            forged = Token(pool_id=99, slot=0, generation=1)
            cross_pool_attempts += 1
            if pool.release(forged):
                cross_pool_accepted += 1
        if rng.randrange(200) == 0:
            forged = Token(pool_id=99, slot=rng.randrange(8), generation=rng.randrange(1, 20))
            cross_pool_attempts += 1
            if pool.release(forged):
                cross_pool_accepted += 1
        pool.assert_invariants()

    for token in list(active):
        assert pool.release(token)
    active.clear()
    pool.assert_invariants()
    ok = (
        pool.in_use == 0
        and pool.reserved == 0
        and stale_release_accepted == 0
        and cross_pool_accepted == 0
        and pool.high_water_surfaces <= len(pool.slots)
        and pool.high_water_bytes <= pool.total
    )
    return {
        "schema": 1,
        "ok": ok,
        "commit": git_commit(),
        "seed": seed,
        "iterations": iterations,
        "config": {
            "slots": len(pool.slots),
            "max_bytes_per_surface": pool.per_surface,
            "max_total_bytes": pool.total,
        },
        "result": {
            "acquisitions": pool.acquisitions,
            "releases": pool.releases,
            "rejections": pool.rejections,
            "high_water_surfaces": pool.high_water_surfaces,
            "high_water_bytes": pool.high_water_bytes,
            "stale_release_attempts": stale_release_attempts,
            "stale_release_accepted": stale_release_accepted,
            "cross_pool_attempts": cross_pool_attempts,
            "cross_pool_accepted": cross_pool_accepted,
            "final_in_use": pool.in_use,
            "final_reserved_bytes": pool.reserved,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200_000)
    parser.add_argument("--seed", type=int, default=20260813)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    if args.iterations <= 0:
        parser.error("--iterations must be positive")
    report = run(args.iterations, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
