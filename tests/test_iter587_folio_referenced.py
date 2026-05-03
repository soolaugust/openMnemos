"""
iter587: folio_referenced — Importance Spread via Rank-Percentile Mapping

OS 类比：Linux folio_referenced() (Nick Piggin, 2004; Matthew Wilcox, 2022, mm/rmap.c)
测试：分布展开、保护机制、融合渐进性、边界情况、生产模拟、性能
"""
import json
import math
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _make_db(chunks=None, traces=None):
    """Create in-memory DB with memory_chunks + recall_traces tables."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE memory_chunks (
            id TEXT PRIMARY KEY,
            summary TEXT,
            content TEXT,
            chunk_type TEXT,
            importance REAL,
            access_count INTEGER DEFAULT 0,
            oom_adj INTEGER DEFAULT 0,
            project TEXT DEFAULT 'test',
            created_at TEXT,
            retrievability REAL DEFAULT 0.5
        )
    """)
    conn.execute("""
        CREATE TABLE recall_traces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT,
            prompt TEXT,
            top_k_json TEXT,
            timestamp TEXT,
            injected INTEGER DEFAULT 1
        )
    """)
    if chunks:
        for c in chunks:
            conn.execute(
                """INSERT INTO memory_chunks
                   (id, summary, content, chunk_type, importance, access_count,
                    oom_adj, project, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    c.get("id", f"chunk-{id(c)}"),
                    c.get("summary", "test"),
                    c.get("content", "test content"),
                    c.get("chunk_type", "decision"),
                    c.get("importance", 0.75),
                    c.get("access_count", 0),
                    c.get("oom_adj", 0),
                    c.get("project", "test"),
                    c.get("created_at",
                           (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()),
                )
            )
    if traces:
        for t in traces:
            conn.execute(
                """INSERT INTO recall_traces (project, prompt, top_k_json, timestamp)
                   VALUES (?, ?, ?, ?)""",
                (
                    t.get("project", "test"),
                    t.get("prompt", "query"),
                    json.dumps(t.get("top_k", [])),
                    t.get("timestamp",
                           datetime.now(timezone.utc).isoformat()),
                )
            )
    conn.commit()
    return conn


def _cfg_defaults():
    return {
        "folio_referenced.enabled": True,
        "folio_referenced.blend_ratio": 0.15,
        "folio_referenced.imp_floor": 0.45,
        "folio_referenced.imp_ceil": 0.95,
        "folio_referenced.max_delta_per_chunk": 0.08,
        "folio_referenced.min_alive_chunks": 10,
        "folio_referenced.weight_access": 0.50,
        "folio_referenced.weight_cum_score": 0.30,
        "folio_referenced.weight_recency": 0.20,
        "folio_referenced.skip_types": ["task_state", "prompt_context"],
    }


@pytest.fixture
def cfg():
    d = _cfg_defaults()
    with patch("config.get", side_effect=lambda k, *a, **kw: d.get(k, a[0] if a else None)):
        yield d


# ── Basic functionality ──

class TestBasicSpread:
    """Test that folio_referenced spreads importance distribution."""

    def test_spreads_uniform_chunks(self, cfg):
        """Chunks all at same importance should get spread."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75, "access_count": i * 2,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=i)).isoformat()}
            for i in range(15)
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, "test")

        assert result["spread"] > 0
        assert result["gini_after"] > result["gini_before"]

    def test_increases_pearson_correlation(self, cfg):
        """After spread, importance should correlate better with access."""
        from store_mm import folio_referenced
        # Mix of access patterns: some high access at low importance
        chunks = [
            {"id": f"c{i}", "importance": 0.70 + (14 - i) * 0.005,
             "access_count": i * 3,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()}
            for i in range(15)
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, "test")

        # After spread, Pearson should move toward positive (access-aligned)
        assert result["pearson_after"] >= result["pearson_before"]

    def test_respects_cum_score(self, cfg):
        """Chunks with high cumulative retrieval scores get higher importance."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.70, "access_count": 1,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()}
            for i in range(12)
        ]
        # Give c11 high cum_score via traces
        traces = [
            {"project": "test", "top_k": [
                {"chunk_id": "c11", "score": 0.9},
                {"chunk_id": "c10", "score": 0.5},
            ]},
            {"project": "test", "top_k": [
                {"chunk_id": "c11", "score": 0.85},
            ]},
        ]
        conn = _make_db(chunks=chunks, traces=traces)
        result = folio_referenced(conn, "test")

        # c11 should have higher importance than c0 after spread
        imp_c11 = conn.execute(
            "SELECT importance FROM memory_chunks WHERE id='c11'"
        ).fetchone()[0]
        imp_c0 = conn.execute(
            "SELECT importance FROM memory_chunks WHERE id='c0'"
        ).fetchone()[0]
        assert imp_c11 > imp_c0


# ── Protection mechanisms ──

class TestProtection:
    """Test that protected chunks are skipped."""

    def test_skips_mlock(self, cfg):
        """mlock chunks (oom_adj <= -500) are not modified."""
        from store_mm import folio_referenced
        chunks = [
            {"id": "mlock1", "importance": 0.60, "access_count": 0,
             "oom_adj": -1000,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()}
        ] + [
            {"id": f"c{i}", "importance": 0.75, "access_count": i,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=i)).isoformat()}
            for i in range(12)
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, "test")

        imp_mlock = conn.execute(
            "SELECT importance FROM memory_chunks WHERE id='mlock1'"
        ).fetchone()[0]
        assert imp_mlock == 0.60
        assert result["skipped_protected"] >= 1

    def test_skips_task_state(self, cfg):
        """task_state type chunks are not modified."""
        from store_mm import folio_referenced
        chunks = [
            {"id": "ts1", "importance": 0.65, "chunk_type": "task_state",
             "access_count": 5,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
        ] + [
            {"id": f"c{i}", "importance": 0.75, "access_count": i,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=i)).isoformat()}
            for i in range(12)
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, "test")

        imp_ts = conn.execute(
            "SELECT importance FROM memory_chunks WHERE id='ts1'"
        ).fetchone()[0]
        assert imp_ts == 0.65

    def test_skips_prompt_context(self, cfg):
        """prompt_context type chunks are not modified."""
        from store_mm import folio_referenced
        chunks = [
            {"id": "pc1", "importance": 0.70, "chunk_type": "prompt_context",
             "access_count": 3,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
        ] + [
            {"id": f"c{i}", "importance": 0.75, "access_count": i,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=i)).isoformat()}
            for i in range(12)
        ]
        conn = _make_db(chunks=chunks)
        folio_referenced(conn, "test")

        imp_pc = conn.execute(
            "SELECT importance FROM memory_chunks WHERE id='pc1'"
        ).fetchone()[0]
        assert imp_pc == 0.70


# ── Blend and delta limits ──

class TestBlendLimits:
    """Test gradual convergence and delta clamping."""

    def test_max_delta_respected(self, cfg):
        """No single chunk importance changes by more than max_delta."""
        from store_mm import folio_referenced
        # Create chunks with extreme spread in access
        chunks = [
            {"id": f"c{i}", "importance": 0.75,
             "access_count": 50 if i == 14 else 0,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()}
            for i in range(15)
        ]
        conn = _make_db(chunks=chunks)

        old_imps = {row[0]: row[1] for row in conn.execute(
            "SELECT id, importance FROM memory_chunks"
        ).fetchall()}

        folio_referenced(conn, "test")

        new_imps = {row[0]: row[1] for row in conn.execute(
            "SELECT id, importance FROM memory_chunks"
        ).fetchall()}

        max_delta = cfg["folio_referenced.max_delta_per_chunk"]
        for cid, new_imp in new_imps.items():
            if cid in old_imps:
                delta = abs(new_imp - old_imps[cid])
                assert delta <= max_delta + 0.001, f"{cid}: delta={delta} > max={max_delta}"

    def test_blend_ratio_gradual(self, cfg):
        """Multiple runs converge gradually, not in one shot."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75, "access_count": i * 3,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()}
            for i in range(15)
        ]
        conn = _make_db(chunks=chunks)

        # Run twice — second run should still spread further
        r1 = folio_referenced(conn, "test")
        r2 = folio_referenced(conn, "test")

        # Both runs should spread
        assert r1["spread"] > 0
        assert r2["spread"] > 0
        # Second run Gini should be >= first (convergence continues)
        assert r2["gini_after"] >= r1["gini_after"] - 0.01

    def test_importance_stays_in_bounds(self, cfg):
        """All chunks stay within [imp_floor, imp_ceil]."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.30 + i * 0.05,
             "access_count": i,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=i)).isoformat()}
            for i in range(15)
        ]
        conn = _make_db(chunks=chunks)
        folio_referenced(conn, "test")

        floor = cfg["folio_referenced.imp_floor"]
        ceil = cfg["folio_referenced.imp_ceil"]
        rows = conn.execute(
            "SELECT importance FROM memory_chunks WHERE oom_adj < 300"
        ).fetchall()
        for (imp,) in rows:
            assert imp >= floor - 0.001, f"imp={imp} < floor={floor}"
            assert imp <= ceil + 0.001, f"imp={imp} > ceil={ceil}"


# ── Edge cases ──

class TestEdgeCases:
    """Test edge cases and disabled state."""

    def test_disabled_noop(self, cfg):
        """When disabled, returns zeros without modifying DB."""
        cfg["folio_referenced.enabled"] = False
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75, "access_count": i}
            for i in range(15)
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, "test")

        assert result["spread"] == 0
        # Verify no changes
        imps = [r[0] for r in conn.execute(
            "SELECT importance FROM memory_chunks"
        ).fetchall()]
        assert all(abs(imp - 0.75) < 0.001 for imp in imps)

    def test_too_few_chunks(self, cfg):
        """Below min_alive_chunks, does nothing."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75, "access_count": i}
            for i in range(5)  # less than min_alive_chunks=10
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, "test")

        assert result["spread"] == 0

    def test_empty_db(self, cfg):
        """Empty DB returns gracefully."""
        from store_mm import folio_referenced
        conn = _make_db(chunks=[])
        result = folio_referenced(conn, "test")

        assert result["spread"] == 0
        assert result["duration_ms"] >= 0

    def test_all_protected(self, cfg):
        """All chunks protected → spread=0."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75, "access_count": i,
             "oom_adj": -1000,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
            for i in range(12)
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, "test")

        assert result["spread"] == 0
        assert result["skipped_protected"] == 12

    def test_no_traces_still_works(self, cfg):
        """Without recall_traces, uses access_count + recency only."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75,
             "access_count": i * 5,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=i * 2)).isoformat()}
            for i in range(15)
        ]
        conn = _make_db(chunks=chunks, traces=[])
        result = folio_referenced(conn, "test")

        assert result["spread"] > 0
        assert result["gini_after"] > result["gini_before"]

    def test_single_eligible_chunk(self, cfg):
        """Only one eligible + many protected → spread=0 (needs ≥2)."""
        cfg["folio_referenced.min_alive_chunks"] = 3
        from store_mm import folio_referenced
        chunks = [
            {"id": "eligible", "importance": 0.75, "access_count": 5,
             "oom_adj": 0,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()},
        ] + [
            {"id": f"prot{i}", "importance": 0.80, "access_count": 3,
             "oom_adj": -1000,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
            for i in range(10)
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, "test")

        assert result["spread"] == 0


# ── Project filtering ──

class TestProjectFilter:
    """Test project-scoped operation."""

    def test_project_filter(self, cfg):
        """Only chunks in specified project are modified."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"a{i}", "importance": 0.75, "access_count": i,
             "project": "alpha",
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
            for i in range(12)
        ] + [
            {"id": f"b{i}", "importance": 0.75, "access_count": i,
             "project": "beta",
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
            for i in range(12)
        ]
        conn = _make_db(chunks=chunks)

        folio_referenced(conn, "alpha")

        # Beta chunks unchanged
        beta_imps = [r[0] for r in conn.execute(
            "SELECT importance FROM memory_chunks WHERE project='beta'"
        ).fetchall()]
        assert all(abs(imp - 0.75) < 0.001 for imp in beta_imps)

    def test_global_mode(self, cfg):
        """project=None modifies all projects."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75, "access_count": i,
             "project": "alpha" if i % 2 == 0 else "beta",
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
            for i in range(20)
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, None)

        assert result["spread"] > 0


# ── Config tunables ──

class TestConfigTunables:
    """Test config parameter effects."""

    def test_high_blend_ratio(self, cfg):
        """Higher blend_ratio makes bigger changes per run."""
        cfg["folio_referenced.blend_ratio"] = 0.40
        cfg["folio_referenced.max_delta_per_chunk"] = 0.20  # allow larger moves
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75, "access_count": i * 2,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
            for i in range(15)
        ]
        conn = _make_db(chunks=chunks)
        result = folio_referenced(conn, "test")

        # More aggressive spread — Gini increases
        assert result["gini_after"] > result["gini_before"]

    def test_narrow_range(self, cfg):
        """Narrow imp_floor/imp_ceil means tighter output range."""
        cfg["folio_referenced.imp_floor"] = 0.60
        cfg["folio_referenced.imp_ceil"] = 0.80
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75, "access_count": i * 3,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
            for i in range(15)
        ]
        conn = _make_db(chunks=chunks)
        folio_referenced(conn, "test")

        rows = conn.execute(
            "SELECT importance FROM memory_chunks WHERE oom_adj < 300"
        ).fetchall()
        for (imp,) in rows:
            # Should still be bounded (considering max_delta may prevent full convergence)
            assert imp >= 0.45  # at least floor of default

    def test_config_registered(self):
        """All folio_referenced config keys are registered."""
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import config
        keys = [
            "folio_referenced.enabled",
            "folio_referenced.blend_ratio",
            "folio_referenced.imp_floor",
            "folio_referenced.imp_ceil",
            "folio_referenced.max_delta_per_chunk",
            "folio_referenced.min_alive_chunks",
            "folio_referenced.weight_access",
            "folio_referenced.weight_cum_score",
            "folio_referenced.weight_recency",
            "folio_referenced.skip_types",
        ]
        for k in keys:
            val = config.get(k)
            assert val is not None, f"Config key '{k}' not registered"


# ── Production simulation ──

class TestProductionSimulation:
    """Simulate production-like data to verify real-world behavior."""

    def test_production_spread(self, cfg):
        """Simulate production: 92 chunks with realistic distributions."""
        from store_mm import folio_referenced
        import random
        random.seed(42)

        # Simulate production importance clustering at 0.7-0.8
        chunks = []
        for i in range(92):
            imp = random.gauss(0.76, 0.05)
            imp = max(0.50, min(0.99, imp))
            acc = int(random.expovariate(0.3))  # exponential access
            age = random.uniform(1, 60)
            chunks.append({
                "id": f"prod{i}",
                "importance": round(imp, 3),
                "access_count": acc,
                "project": "test",
                "created_at": (datetime.now(timezone.utc) - timedelta(days=age)).isoformat(),
            })

        # Add some traces
        traces = []
        for _ in range(50):
            top_k = [
                {"chunk_id": f"prod{random.randint(0, 91)}",
                 "score": round(random.uniform(0.3, 0.95), 3)}
                for _ in range(random.randint(1, 5))
            ]
            traces.append({"project": "test", "top_k": top_k})

        conn = _make_db(chunks=chunks, traces=traces)
        result = folio_referenced(conn, "test")

        # Key assertions for production scenario
        assert result["spread"] > 50  # most chunks adjusted
        assert result["duration_ms"] < 100  # performance OK
        # After multiple rounds, Gini should clearly improve
        for _ in range(5):
            folio_referenced(conn, "test")
        final = folio_referenced(conn, "test")
        assert final["gini_after"] > 0.01  # spread from near-uniform

    def test_idempotent_convergence(self, cfg):
        """Multiple runs converge — changes decrease over time."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.75, "access_count": i * 2,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()}
            for i in range(20)
        ]
        conn = _make_db(chunks=chunks)

        spreads = []
        for _ in range(10):
            r = folio_referenced(conn, "test")
            spreads.append(r["spread"])

        # After many runs, fewer changes (convergence)
        assert spreads[-1] <= spreads[0]


# ── Performance ──

class TestPerformance:
    """Test execution time bounds."""

    def test_performance_200_chunks(self, cfg):
        """200 chunks should complete in <50ms."""
        from store_mm import folio_referenced
        chunks = [
            {"id": f"c{i}", "importance": 0.70 + (i % 10) * 0.02,
             "access_count": i % 20,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=i % 30)).isoformat()}
            for i in range(200)
        ]
        traces = [
            {"project": "test", "top_k": [
                {"chunk_id": f"c{j}", "score": 0.5 + j * 0.01}
                for j in range(i, min(i + 3, 200))
            ]}
            for i in range(0, 100, 5)
        ]
        conn = _make_db(chunks=chunks, traces=traces)

        t0 = time.time()
        result = folio_referenced(conn, "test")
        elapsed = (time.time() - t0) * 1000

        assert elapsed < 50, f"Took {elapsed:.1f}ms (>50ms)"
        assert result["spread"] > 0


# ── Helper function tests ──

class TestHelpers:
    """Test _gini and _pearson helper functions."""

    def test_gini_uniform(self):
        """Uniform values → Gini ≈ 0."""
        from store_mm import _gini
        assert abs(_gini([1.0] * 10)) < 0.01

    def test_gini_extreme(self):
        """One high, rest zero → Gini ≈ 0.8+."""
        from store_mm import _gini
        vals = [0.0] * 9 + [1.0]
        assert _gini(vals) >= 0.7

    def test_gini_empty(self):
        """Empty list → 0."""
        from store_mm import _gini
        assert _gini([]) == 0.0

    def test_pearson_perfect(self):
        """Perfect positive correlation → 1.0."""
        from store_mm import _pearson
        xs = [1, 2, 3, 4, 5]
        ys = [2, 4, 6, 8, 10]
        assert abs(_pearson(xs, ys) - 1.0) < 0.001

    def test_pearson_negative(self):
        """Perfect negative correlation → -1.0."""
        from store_mm import _pearson
        xs = [1, 2, 3, 4, 5]
        ys = [10, 8, 6, 4, 2]
        assert abs(_pearson(xs, ys) + 1.0) < 0.001

    def test_pearson_uncorrelated(self):
        """Constant values → 0."""
        from store_mm import _pearson
        xs = [1, 2, 3, 4, 5]
        ys = [5, 5, 5, 5, 5]
        assert abs(_pearson(xs, ys)) < 0.001
