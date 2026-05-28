#!/usr/bin/env python3
"""
FluxMem PoC — simplified implementation of the connectivity-evolving memory framework.

Based on "Rethinking Memory as Continuously Evolving Connectivity" (Fang et al., 2026,
arXiv:2605.28773). Implements the core 3-layer heterogeneous graph with hybrid retrieval.

Simplifications:
  - No LLM-based verification (uses embedding similarity + BM25 only)
  - No procedural skill distillation (Stage III skipped)
  - No feedback-driven refinement (Stage II skipped)
  - Focus: Stage I retrieval comparison against 0CompactMem

This PoC answers: does the graph structure + embedding retrieval outperform
flat BM25 (0CompactMem) or flat embedding (vector search)?
"""

import os
import sys
import json
import time
import shutil
import numpy as np
from pathlib import Path
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ['MEMORY_OS_DIR'] = '/tmp/fluxmem_bench'


@dataclass
class MemNode:
    id: str
    layer: str  # "semantic", "episodic", "procedural"
    text: str
    embedding: list = field(default_factory=list)


@dataclass
class MemEdge:
    source_id: str
    target_id: str
    edge_type: str  # "grounding" (sem->epi) or "distillation" (epi->proc)


class FluxMemGraph:
    """Simplified FluxMem heterogeneous graph."""

    def __init__(self):
        self.nodes: dict[str, MemNode] = {}
        self.edges: list[MemEdge] = []
        self._embed_cache = {}

    def _embed(self, text: str) -> list:
        if text not in self._embed_cache:
            import ollama
            self._embed_cache[text] = ollama.embed(
                model="nomic-embed-text", input=text
            ).embeddings[0]
        return self._embed_cache[text]

    def add_semantic(self, node_id: str, text: str):
        vec = self._embed(text)
        self.nodes[node_id] = MemNode(id=node_id, layer="semantic", text=text, embedding=vec)

    def add_episodic(self, node_id: str, text: str, grounding_ids: list = None):
        vec = self._embed(text)
        self.nodes[node_id] = MemNode(id=node_id, layer="episodic", text=text, embedding=vec)
        if grounding_ids:
            for sid in grounding_ids:
                if sid in self.nodes:
                    self.edges.append(MemEdge(source_id=sid, target_id=node_id, edge_type="grounding"))

    def add_procedural(self, node_id: str, text: str, episodic_ids: list = None):
        vec = self._embed(text)
        self.nodes[node_id] = MemNode(id=node_id, layer="procedural", text=text, embedding=vec)
        if episodic_ids:
            for eid in episodic_ids:
                if eid in self.nodes:
                    self.edges.append(MemEdge(source_id=eid, target_id=node_id, edge_type="distillation"))

    def retrieve(self, query: str, top_k: int = 5) -> list[dict]:
        """
        FluxMem Stage I retrieval: hybrid scoring across all layers.
        Score = embedding_similarity + edge_bonus (connected nodes get boost).
        """
        q_vec = np.array(self._embed(query))
        scores = []

        for nid, node in self.nodes.items():
            n_vec = np.array(node.embedding)
            # Cosine similarity
            sim = float(np.dot(q_vec, n_vec) / (np.linalg.norm(q_vec) * np.linalg.norm(n_vec) + 1e-9))

            # Edge bonus: nodes with more connections get a small boost
            edge_count = sum(1 for e in self.edges if e.source_id == nid or e.target_id == nid)
            edge_bonus = min(edge_count * 0.05, 0.15)

            # Layer weighting: semantic > episodic > procedural for factual queries
            layer_weight = {"semantic": 1.0, "episodic": 0.9, "procedural": 0.8}
            final_score = sim * layer_weight[node.layer] + edge_bonus

            scores.append({"id": nid, "text": node.text, "score": final_score, "layer": node.layer})

        scores.sort(key=lambda x: x["score"], reverse=True)
        return scores[:top_k]

    def supports_pin(self) -> bool:
        return False

    def evict(self, keep_n: int):
        """Remove nodes with lowest connectivity (no pin support)."""
        if len(self.nodes) <= keep_n:
            return
        # Score by edge count (more connected = more important)
        node_scores = []
        for nid in self.nodes:
            edge_count = sum(1 for e in self.edges if e.source_id == nid or e.target_id == nid)
            node_scores.append((nid, edge_count))
        node_scores.sort(key=lambda x: x[1])
        # Remove least connected
        to_remove = len(self.nodes) - keep_n
        for nid, _ in node_scores[:to_remove]:
            del self.nodes[nid]
            self.edges = [e for e in self.edges if e.source_id != nid and e.target_id != nid]


# ═══════════════════════════════════════════════════════════════
# Benchmark
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


def build_fluxmem_graph() -> FluxMemGraph:
    """Build a FluxMem graph with semantic nodes + episodic connections."""
    g = FluxMemGraph()

    # Add as semantic nodes
    for item_id, text in KNOWLEDGE_ITEMS:
        g.add_semantic(f"sem_{item_id}", text)

    # Add episodic nodes (simulating "when this decision was made")
    episodes = [
        ("epi_auth_session", "During auth design session, chose JWT over session cookies",
         ["sem_auth_jwt"]),
        ("epi_infra_review", "Infrastructure review decided on Redis + PostgreSQL + ELK",
         ["sem_cache_redis", "sem_db_postgres", "sem_logging_elk"]),
        ("epi_perf_tuning", "Performance tuning session: rate limits, circuit breakers, lazy init",
         ["sem_api_ratelimit", "sem_error_retry", "sem_startup_lazy"]),
        ("epi_dx_setup", "Developer experience setup: Vite, TypeScript strict, Playwright",
         ["sem_hotreload_vite", "sem_types_strict", "sem_testing_playwright"]),
        ("epi_deploy_pipeline", "Deployment pipeline design: GitHub Actions + staging gate + flags",
         ["sem_cicd_github", "sem_flags_launchdarkly"]),
    ]
    for eid, text, groundings in episodes:
        g.add_episodic(eid, text, grounding_ids=groundings)

    return g


def bench_fluxmem_retrieval():
    """Benchmark FluxMem retrieval quality."""
    print("\n  [FluxMem] Building graph...")
    g = build_fluxmem_graph()
    print(f"    Nodes: {len(g.nodes)}, Edges: {len(g.edges)}")

    recall_at_5 = 0
    mrr_at_5 = 0
    total = len(PARAPHRASED_QUERIES)

    print("  [FluxMem] Running queries...")
    for query, expected_id in PARAPHRASED_QUERIES:
        results = g.retrieve(query, top_k=5)
        texts = [r["text"] for r in results]

        expected_text = dict(KNOWLEDGE_ITEMS)[expected_id]
        found = any(expected_text.lower() in t.lower() or t.lower() in expected_text.lower()
                    for t in texts)
        if found:
            recall_at_5 += 1
        for rank, t in enumerate(texts, 1):
            if expected_text.lower() in t.lower() or t.lower() in expected_text.lower():
                mrr_at_5 += 1.0 / rank
                break

    recall_at_5 /= total
    mrr_at_5 /= total
    print(f"    Recall@5: {recall_at_5:.3f}, MRR@5: {mrr_at_5:.3f}")
    return {"recall_at_5": round(recall_at_5, 3), "mrr_at_5": round(mrr_at_5, 3)}


def bench_fluxmem_constraint_survival():
    """Benchmark constraint survival (no pin support in FluxMem)."""
    print("\n  [FluxMem] Constraint survival test...")
    g = FluxMemGraph()

    # Add 50 constraints as semantic nodes
    for i in range(50):
        g.add_semantic(f"constraint_{i:03d}", f"Critical constraint {i}: invariant must hold")

    # Add 200 filler (more connected = survives eviction)
    for i in range(200):
        g.add_semantic(f"filler_{i:04d}", f"General knowledge filler item number {i}")

    # Add episodic nodes linking filler (giving them more edges)
    for i in range(0, 200, 10):
        g.add_episodic(f"epi_filler_{i}", f"Session that produced fillers {i}-{i+9}",
                       [f"filler_{j:04d}" for j in range(i, min(i+10, 200))])

    # Evict to keep 50
    g.evict(keep_n=50)

    # Check constraint survival
    survived = sum(1 for i in range(50) if f"constraint_{i:03d}" in g.nodes)
    rate = survived / 50
    print(f"    Survived: {survived}/50 = {rate*100:.1f}%")
    return {"survival_rate": round(rate, 3), "survived": survived}


def bench_fluxmem_latency():
    """Measure retrieval latency."""
    print("\n  [FluxMem] Latency test...")
    g = build_fluxmem_graph()

    queries = ["authentication", "caching", "database", "error handling", "monitoring"]
    times = []
    for _ in range(5):
        for q in queries:
            t0 = time.perf_counter()
            g.retrieve(q, top_k=5)
            times.append((time.perf_counter() - t0) * 1000)

    times.sort()
    p50 = times[len(times) // 2]
    p95 = times[int(len(times) * 0.95)]
    print(f"    Search p50: {p50:.2f}ms, p95: {p95:.2f}ms")
    return {"search_p50_ms": round(p50, 2), "search_p95_ms": round(p95, 2)}


if __name__ == "__main__":
    print("=" * 60)
    print("FluxMem PoC Benchmark")
    print("=" * 60)

    results = {
        "retrieval": bench_fluxmem_retrieval(),
        "constraint_survival": bench_fluxmem_constraint_survival(),
        "latency": bench_fluxmem_latency(),
    }

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(json.dumps(results, indent=2))

    out_path = Path(__file__).parent / "fluxmem_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to: {out_path}")
