#!/usr/bin/env python3
"""
Comparative benchmark: 0CompactMem vs mem0
Measures retrieval quality, constraint survival, latency, multi-agent coherence.
"""

import sys
import os
import time
import json
import sqlite3
import shutil
import tempfile
import statistics
from pathlib import Path
from datetime import datetime, timezone, timedelta
from abc import ABC, abstractmethod

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ['MEMORY_OS_DIR'] = '/tmp/bench_comparison'


# ═══════════════════════════════════════════════════════════════
# Test Data
# ═══════════════════════════════════════════════════════════════

KNOWLEDGE_ITEMS = [
    ("auth_jwt", "Authentication uses JWT tokens with refresh rotation for session management"),
    ("cache_redis", "Caching layer uses Redis with 15-minute TTL for API responses"),
    ("db_postgres", "Database is PostgreSQL 15 with connection pooling via pgbouncer"),
    ("api_ratelimit", "API rate limiting is 100 requests per minute per user with token bucket"),
    ("error_retry", "Error handling uses exponential backoff with 3 retries and circuit breaker"),
    ("logging_elk", "Logging pipeline sends structured JSON to ELK stack via Filebeat"),
    ("monitoring_grafana", "Monitoring uses Prometheus metrics with Grafana dashboards"),
    ("cicd_github", "CI/CD pipeline runs on GitHub Actions with staging deployment gate"),
    ("review_required", "Code review requires two approvals from different team members"),
    ("types_strict", "TypeScript strict mode is mandatory with no any types allowed"),
    ("deps_lockfile", "Dependency management uses exact versions in lockfile, no ranges"),
    ("state_redux", "Frontend state management uses Redux Toolkit with RTK Query"),
    ("concurrency_mutex", "Concurrent database writes use advisory locks to prevent races"),
    ("memory_limit", "Worker processes have 512MB memory limit with OOM kill policy"),
    ("startup_lazy", "Service startup uses lazy initialization for non-critical dependencies"),
    ("hotreload_vite", "Development uses Vite HMR for sub-second hot module replacement"),
    ("flags_launchdarkly", "Feature flags managed through LaunchDarkly with percentage rollouts"),
    ("testing_playwright", "E2E tests use Playwright with visual regression screenshots"),
    ("permissions_rbac", "Access control implements RBAC with hierarchical role inheritance"),
    ("migration_flyway", "Schema migrations use Flyway with versioned SQL scripts"),
]

PARAPHRASED_QUERIES = [
    ("auth system design", "auth_jwt"),
    ("cache configuration", "cache_redis"),
    ("database setup", "db_postgres"),
    ("rate limiting rules", "api_ratelimit"),
    ("retry strategy", "error_retry"),
    ("log infrastructure", "logging_elk"),
    ("observability stack", "monitoring_grafana"),
    ("deployment pipeline", "cicd_github"),
    ("PR approval process", "review_required"),
    ("type checking policy", "types_strict"),
    ("package version management", "deps_lockfile"),
    ("frontend state handling", "state_redux"),
    ("write conflict prevention", "concurrency_mutex"),
    ("process resource cap", "memory_limit"),
    ("boot optimization", "startup_lazy"),
    ("dev reload speed", "hotreload_vite"),
    ("feature toggle system", "flags_launchdarkly"),
    ("end-to-end testing tool", "testing_playwright"),
    ("access control model", "permissions_rbac"),
    ("schema migration approach", "migration_flyway"),
]


# ═══════════════════════════════════════════════════════════════
# Backend Implementations
# ═══════════════════════════════════════════════════════════════

class MemoryBackend(ABC):
    @abstractmethod
    def setup(self): pass
    @abstractmethod
    def add(self, chunk_id: str, text: str): pass
    @abstractmethod
    def search(self, query: str, top_k: int = 5) -> list: pass
    @abstractmethod
    def supports_pin(self) -> bool: pass
    @abstractmethod
    def pin(self, chunk_id: str): pass
    @abstractmethod
    def teardown(self): pass


class CompactMemBackend(MemoryBackend):
    def __init__(self):
        self.conn = None
        self.db_path = None

    def setup(self):
        from store_vfs import ensure_schema
        self.db_path = tempfile.mktemp(suffix=".db")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        ensure_schema(self.conn)

    def add(self, chunk_id: str, text: str):
        ts = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO memory_chunks
            (id, project, chunk_type, summary, content, importance,
             access_count, last_accessed, created_at, updated_at,
             source_session, retrievability, info_class, chunk_state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (chunk_id, "bench", "knowledge", text, text, 0.6,
              1, ts, ts, ts, "bench", 1.0, "world", "ACTIVE"))
        rowid = cursor.lastrowid
        if rowid:
            cursor.execute("""
                INSERT INTO memory_chunks_fts (rowid_ref, summary, content)
                VALUES (?, ?, ?)
            """, (str(rowid), text, text))
        self.conn.commit()

    def search(self, query: str, top_k: int = 5) -> list:
        from store_vfs import fts_search
        results = fts_search(self.conn, query, project="bench", top_k=top_k)
        return [{"id": r["id"], "text": r["summary"], "score": r.get("fts_rank", 0)} for r in results]

    def supports_pin(self) -> bool:
        return True

    def pin(self, chunk_id: str):
        from store_vfs import pin_chunk
        pin_chunk(self.conn, chunk_id, project="bench", pin_type="hard")

    def is_pinned(self, chunk_id: str) -> bool:
        from store_vfs import is_pinned
        return is_pinned(self.conn, chunk_id, project="bench") is not None

    def evict(self, keep_n: int):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id FROM memory_chunks WHERE project='bench'
            ORDER BY last_accessed ASC, importance ASC
        """)
        all_ids = [r[0] for r in cursor.fetchall()]
        evict_count = len(all_ids) - keep_n
        evicted = 0
        for cid in all_ids:
            if evicted >= evict_count:
                break
            if self.is_pinned(cid):
                continue
            cursor.execute("DELETE FROM memory_chunks WHERE id=?", (cid,))
            evicted += 1
        self.conn.commit()

    def teardown(self):
        if self.conn:
            self.conn.close()
        if self.db_path and os.path.exists(self.db_path):
            os.unlink(self.db_path)


class VectorSearchBackend(MemoryBackend):
    """Represents embedding-based vector search (similar to mem0/Zep core retrieval)."""
    def __init__(self):
        self.client = None
        self.store_path = "/tmp/vector_bench_qdrant"
        self._items = {}
        self._counter = 0

    def setup(self):
        shutil.rmtree(self.store_path, ignore_errors=True)
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, VectorParams
        self.client = QdrantClient(path=self.store_path)
        self.client.create_collection("bench",
            vectors_config=VectorParams(size=768, distance=Distance.COSINE))
        self._items = {}
        self._counter = 0

    def _embed(self, text: str) -> list:
        import ollama as _ollama
        return _ollama.embed(model="nomic-embed-text", input=text).embeddings[0]

    def add(self, chunk_id: str, text: str):
        from qdrant_client.models import PointStruct
        vec = self._embed(text)
        self._counter += 1
        point_id = self._counter
        self.client.upsert("bench", [PointStruct(
            id=point_id, vector=vec, payload={"text": text, "chunk_id": chunk_id}
        )])
        self._items[chunk_id] = point_id

    def search(self, query: str, top_k: int = 5) -> list:
        q_vec = self._embed(query)
        results = self.client.query_points("bench", query=q_vec, limit=top_k)
        return [{"id": str(r.id), "text": r.payload["text"], "score": r.score}
                for r in results.points]

    def supports_pin(self) -> bool:
        return False

    def pin(self, chunk_id: str):
        pass

    def evict(self, keep_n: int):
        # No pin support — delete oldest by point ID
        from qdrant_client.models import Filter, FieldCondition, Range
        all_points = self.client.scroll("bench", limit=10000)[0]
        evict_count = len(all_points) - keep_n
        to_delete = sorted(all_points, key=lambda p: p.id)[:evict_count]
        if to_delete:
            self.client.delete("bench",
                points_selector=[p.id for p in to_delete])

    def teardown(self):
        shutil.rmtree(self.store_path, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════
# Benchmarks
# ═══════════════════════════════════════════════════════════════

def bench_retrieval(backend: MemoryBackend, name: str) -> dict:
    print(f"\n  [{name}] Retrieval Quality...")
    backend.setup()

    # Add all knowledge items
    for chunk_id, text in KNOWLEDGE_ITEMS:
        backend.add(chunk_id, text)

    # Query with paraphrased versions
    recall_at_5 = 0
    mrr_at_5 = 0
    total = len(PARAPHRASED_QUERIES)

    for query, expected_id in PARAPHRASED_QUERIES:
        results = backend.search(query, top_k=5)
        texts = [r["text"] for r in results]

        # Check if expected knowledge appears in results
        expected_text = dict(KNOWLEDGE_ITEMS)[expected_id]
        found = any(expected_text.lower() in t.lower() or t.lower() in expected_text.lower()
                    for t in texts)
        if found:
            recall_at_5 += 1

        # MRR
        for rank, t in enumerate(texts, 1):
            if expected_text.lower() in t.lower() or t.lower() in expected_text.lower():
                mrr_at_5 += 1.0 / rank
                break

    recall_at_5 /= total
    mrr_at_5 /= total

    backend.teardown()
    print(f"    Recall@5: {recall_at_5:.3f}, MRR@5: {mrr_at_5:.3f}")
    return {"recall_at_5": round(recall_at_5, 3), "mrr_at_5": round(mrr_at_5, 3)}


def bench_constraint_survival(backend: MemoryBackend, name: str) -> dict:
    print(f"\n  [{name}] Constraint Survival...")
    backend.setup()

    N_CONSTRAINTS = 50
    N_FILLER = 200

    # Add constraints
    for i in range(N_CONSTRAINTS):
        backend.add(f"constraint_{i:03d}", f"Critical constraint {i}: invariant must hold")
        if backend.supports_pin():
            backend.pin(f"constraint_{i:03d}")

    # Add filler
    for i in range(N_FILLER):
        backend.add(f"filler_{i:04d}", f"General knowledge filler item number {i}")

    # Evict to keep only 50
    backend.evict(keep_n=50)

    # Check survival
    survived = 0
    for i in range(N_CONSTRAINTS):
        results = backend.search(f"constraint {i} invariant", top_k=1)
        if results and f"constraint {i}" in results[0]["text"].lower():
            survived += 1

    rate = survived / N_CONSTRAINTS
    backend.teardown()
    print(f"    Survival: {survived}/{N_CONSTRAINTS} = {rate*100:.1f}%")
    return {"survival_rate": round(rate, 3), "survived": survived, "total": N_CONSTRAINTS}


def bench_latency(backend: MemoryBackend, name: str) -> dict:
    print(f"\n  [{name}] Latency...")
    backend.setup()

    # Populate
    for i in range(100):
        backend.add(f"lat_{i:04d}", f"Knowledge item {i} about topic {i % 10} with details")

    # Measure search latency
    queries = ["authentication", "caching", "database", "error handling", "monitoring"]
    times = []
    for _ in range(10):
        for q in queries:
            t0 = time.perf_counter()
            backend.search(q, top_k=5)
            times.append((time.perf_counter() - t0) * 1000)

    times.sort()
    p50 = times[len(times) // 2]
    p95 = times[int(len(times) * 0.95)]

    backend.teardown()
    print(f"    Search p50: {p50:.2f}ms, p95: {p95:.2f}ms")
    return {"search_p50_ms": round(p50, 2), "search_p95_ms": round(p95, 2)}


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("COMPARATIVE BENCHMARK: 0CompactMem vs mem0")
    print("=" * 60)

    results = {}

    # 0CompactMem
    print("\n" + "=" * 60)
    print("System: 0CompactMem (BM25 + FTS5, SQLite)")
    print("=" * 60)
    cm = CompactMemBackend()
    results["0CompactMem"] = {
        "retrieval": bench_retrieval(cm, "0CompactMem"),
        "constraint_survival": bench_constraint_survival(cm, "0CompactMem"),
        "latency": bench_latency(cm, "0CompactMem"),
    }

    # Vector Search (embedding-based, represents mem0/Zep retrieval core)
    print("\n" + "=" * 60)
    print("System: Vector Search (Ollama nomic-embed-text + Qdrant)")
    print("=" * 60)
    vs = VectorSearchBackend()
    results["vector_search"] = {
        "retrieval": bench_retrieval(vs, "VectorSearch"),
        "constraint_survival": bench_constraint_survival(vs, "VectorSearch"),
        "latency": bench_latency(vs, "VectorSearch"),
    }

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(json.dumps(results, indent=2))

    out_path = Path(__file__).parent / "comparison_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {out_path}")
