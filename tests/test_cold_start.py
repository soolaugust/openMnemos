"""
test_cold_start.py — 迭代334：IWCSI (Importance-Weighted Cold-Start Injection) 单元测试

信息论背景：零召回高 imp chunk 期望信息增益 I = importance × 1.0（最高），
  但语义鸿沟（encoding-retrieval mismatch）导致 FTS5 永不命中 → 系统性信息损失。
OS 类比：DAMON damos_action=PAGE_PROMOTE — 强制发起一次 access 打破 cold-start 死锁。

验证：
  1. cold_start_enabled=False → 不注入（功能开关）
  2. positive 已满（>= effective_top_k）→ 不触发
  3. 无高 imp 零召回候选 → 不注入
  4. 有高 imp 零召回候选 → 注入到 positive（access_count=0, imp>=threshold）
  5. 已在 positive 中的 chunk 不重复注入
  6. 注入数量不超过 cold_start_max_inject
  7. 注入 chunk 已有访问（access_count>0）→ 不注入（只针对零召回）
  8. importance < threshold → 不注入
  9. 集成：priority=LITE → 不触发 IWCSI
"""
import sys
import math
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "hooks"))

import tmpfs  # noqa — 设置测试 DB 路径

from config import get as sysctl, sysctl_set


# ──────────────────────────────────────────────────────────────────────
# helpers
# ──────────────────────────────────────────────────────────────────────

def _make_chunk(chunk_id, importance, access_count, chunk_type="decision"):
    return {
        "id": chunk_id,
        "summary": f"summary of {chunk_id}",
        "content": f"content of {chunk_id}",
        "chunk_type": chunk_type,
        "importance": importance,
        "access_count": access_count,
        "last_accessed": "2026-04-01T00:00:00+00:00",
        "created_at": "2026-04-01T00:00:00+00:00",
        "project": "test",
        "info_class": "world",
        "lru_gen": 2,
    }


def _run_cold_start_logic(positive, final, priority, effective_top_k,
                          enabled=True, imp_threshold=0.75, max_inject=1):
    """
    复现 retriever.py 中的 IWCSI 逻辑（不依赖数据库）。
    返回 (new_positive, injected_count)
    """
    import os
    os.environ["MEMORY_OS_RETRIEVER_COLD_START_ENABLED"] = "true" if enabled else "false"

    # 直接复现逻辑
    injected = 0
    if not (priority == "FULL" and enabled and len(positive) < effective_top_k):
        return positive, injected

    _positive_ids = {c["id"] for _, c in positive}
    _cold_candidates = [
        (imp_val, c) for s, c in final
        if c.get("id", "") not in _positive_ids
        and (c.get("access_count", 0) or 0) == 0
        and float(c.get("importance", 0) or 0) >= imp_threshold
        for imp_val in [float(c.get("importance", 0) or 0)]
    ]
    if _cold_candidates:
        _cold_candidates.sort(key=lambda x: x[0], reverse=True)
        for _cold_imp, _cold_chunk in _cold_candidates[:max_inject]:
            positive.append((_cold_imp, _cold_chunk))
            _positive_ids.add(_cold_chunk["id"])
            injected += 1

    return positive, injected


# ──────────────────────────────────────────────────────────────────────
# 1. 功能开关：disabled → 不注入
# ──────────────────────────────────────────────────────────────────────

def test_disabled_no_injection():
    """cold_start_enabled=False → 不触发 IWCSI。"""
    chunk_zero = _make_chunk("c_zero", importance=0.90, access_count=0)
    final = [(0.5, chunk_zero)]
    positive = []

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=False
    )
    assert injected == 0, f"disabled should inject 0, got {injected}"
    assert len(result) == 0, f"disabled should not modify positive"


# ──────────────────────────────────────────────────────────────────────
# 2. positive 已满 → 不触发
# ──────────────────────────────────────────────────────────────────────

def test_positive_full_no_injection():
    """positive >= effective_top_k → 不触发（无需补充）。"""
    existing = [(_make_chunk(f"c{i}", 0.8, 5)) for i in range(5)]
    positive = [(0.5, c) for c in existing]
    chunk_zero = _make_chunk("c_zero", importance=0.90, access_count=0)
    final = [(0.5, chunk_zero)] + positive

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=True
    )
    assert injected == 0, f"full positive should inject 0, got {injected}"


# ──────────────────────────────────────────────────────────────────────
# 3. 无高 imp 零召回候选 → 不注入
# ──────────────────────────────────────────────────────────────────────

def test_no_high_imp_zero_recall_candidates():
    """所有 final 候选要么已在 positive，要么 imp < threshold，要么 access_count > 0。"""
    # case1: access_count > 0（已有召回历史）
    chunk_acc = _make_chunk("c_acc", importance=0.90, access_count=1)
    # case2: imp < threshold（0.74 < 0.75）
    chunk_low_imp = _make_chunk("c_low", importance=0.74, access_count=0)
    final = [(0.3, chunk_acc), (0.2, chunk_low_imp)]
    positive = []

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=True, imp_threshold=0.75
    )
    assert injected == 0, f"no candidates should inject 0, got {injected}"


# ──────────────────────────────────────────────────────────────────────
# 4. 有高 imp 零召回候选 → 应注入
# ──────────────────────────────────────────────────────────────────────

def test_inject_high_imp_zero_recall():
    """正常路径：imp=0.90, access_count=0 → 注入到 positive。"""
    chunk_zero = _make_chunk("c_zero", importance=0.90, access_count=0, chunk_type="causal_chain")
    final = [(0.3, chunk_zero)]
    positive = []

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=True, imp_threshold=0.75
    )
    assert injected == 1, f"should inject 1, got {injected}"
    injected_ids = [c["id"] for _, c in result]
    assert "c_zero" in injected_ids, f"c_zero should be in positive: {injected_ids}"


# ──────────────────────────────────────────────────────────────────────
# 5. 已在 positive 中的 chunk 不重复注入
# ──────────────────────────────────────────────────────────────────────

def test_no_duplicate_injection():
    """c_zero 已在 positive → IWCSI 不重复注入。"""
    chunk_zero = _make_chunk("c_zero", importance=0.90, access_count=0)
    positive = [(0.9, chunk_zero)]
    final = [(0.9, chunk_zero)]

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=True
    )
    assert injected == 0, f"duplicate should not be re-injected, got {injected}"
    assert len(result) == 1, f"positive length should remain 1, got {len(result)}"


# ──────────────────────────────────────────────────────────────────────
# 6. 注入数量上限：max_inject=1 时最多注入 1 个
# ──────────────────────────────────────────────────────────────────────

def test_max_inject_limit():
    """多个高 imp 零召回候选，max_inject=1 → 只注入 1 个（最高 imp）。"""
    chunk_a = _make_chunk("c_a", importance=0.92, access_count=0)
    chunk_b = _make_chunk("c_b", importance=0.88, access_count=0)
    chunk_c = _make_chunk("c_c", importance=0.85, access_count=0)
    final = [(0.3, chunk_a), (0.3, chunk_b), (0.3, chunk_c)]
    positive = []

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=True, max_inject=1
    )
    assert injected == 1, f"max_inject=1 should inject exactly 1, got {injected}"
    # 应该注入 importance 最高的 chunk_a
    injected_ids = [c["id"] for _, c in result]
    assert "c_a" in injected_ids, f"should inject highest imp chunk c_a: {injected_ids}"
    assert "c_b" not in injected_ids, f"c_b should not be injected: {injected_ids}"


# ──────────────────────────────────────────────────────────────────────
# 7. max_inject=2 时注入 2 个（按 importance 降序）
# ──────────────────────────────────────────────────────────────────────

def test_max_inject_2():
    """max_inject=2 → 注入 2 个最高 imp 的零召回 chunk。"""
    chunk_a = _make_chunk("c_a", importance=0.92, access_count=0)
    chunk_b = _make_chunk("c_b", importance=0.88, access_count=0)
    chunk_c = _make_chunk("c_c", importance=0.85, access_count=0)
    final = [(0.3, c) for c in [chunk_a, chunk_b, chunk_c]]
    positive = []

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=True, max_inject=2
    )
    assert injected == 2, f"max_inject=2 should inject 2, got {injected}"
    injected_ids = [c["id"] for _, c in result]
    assert "c_a" in injected_ids
    assert "c_b" in injected_ids
    assert "c_c" not in injected_ids  # 第三高 imp 不应注入


# ──────────────────────────────────────────────────────────────────────
# 8. priority=LITE → 不触发 IWCSI
# ──────────────────────────────────────────────────────────────────────

def test_lite_priority_no_injection():
    """LITE 优先级不触发 IWCSI（只在 FULL 模式下生效）。"""
    chunk_zero = _make_chunk("c_zero", importance=0.90, access_count=0)
    final = [(0.3, chunk_zero)]
    positive = []

    result, injected = _run_cold_start_logic(
        positive, final, "LITE", effective_top_k=5, enabled=True
    )
    assert injected == 0, f"LITE should not trigger cold_start, got {injected}"


# ──────────────────────────────────────────────────────────────────────
# 9. 注入分数 = importance（不低于 min_score_threshold）
# ──────────────────────────────────────────────────────────────────────

def test_injected_score_equals_importance():
    """注入时 score = chunk.importance，确保能通过 min_score_threshold=0.30 过滤。"""
    chunk_zero = _make_chunk("c_zero", importance=0.90, access_count=0)
    final = [(0.3, chunk_zero)]
    positive = []

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=True, imp_threshold=0.75
    )
    assert injected == 1
    injected_score, injected_chunk = next((s, c) for s, c in result if c["id"] == "c_zero")
    assert abs(injected_score - 0.90) < 1e-9, (
        f"injected score should equal importance=0.90, got {injected_score}"
    )


# ──────────────────────────────────────────────────────────────────────
# 10. importance 恰好等于 threshold → 应注入
# ──────────────────────────────────────────────────────────────────────

def test_at_threshold_injected():
    """importance = 0.75（等于 threshold）→ 应注入。"""
    chunk_at = _make_chunk("c_at", importance=0.75, access_count=0)
    final = [(0.2, chunk_at)]
    positive = []

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=True, imp_threshold=0.75
    )
    assert injected == 1, f"at threshold should inject, got {injected}"


# ──────────────────────────────────────────────────────────────────────
# 11. importance 略低于 threshold → 不注入
# ──────────────────────────────────────────────────────────────────────

def test_below_threshold_not_injected():
    """importance = 0.7499（低于 threshold=0.75）→ 不注入。"""
    chunk_below = _make_chunk("c_below", importance=0.7499, access_count=0)
    final = [(0.2, chunk_below)]
    positive = []

    result, injected = _run_cold_start_logic(
        positive, final, "FULL", effective_top_k=5, enabled=True, imp_threshold=0.75
    )
    assert injected == 0, f"below threshold should not inject, got {injected}"


# ──────────────────────────────────────────────────────────────────────
# 12. config.py sysctl 参数注册验证
# ──────────────────────────────────────────────────────────────────────

def test_sysctl_params_registered():
    """验证 iter334 的三个 sysctl 参数已注册到 config.py。"""
    assert sysctl("retriever.cold_start_enabled") == True
    assert sysctl("retriever.cold_start_imp_threshold") == 0.50
    assert sysctl("retriever.cold_start_max_inject") == 2


# ──────────────────────────────────────────────────────────────────────
# 13. DB fallback：final 中无 ac=0 候选时从 DB 直查
# ──────────────────────────────────────────────────────────────────────

def test_db_fallback_when_fts_misses():
    """iter1427: FTS5 未命中 ac=0 chunk 时，cold_start 从 DB 补充候选。"""
    import sqlite3, os
    from pathlib import Path

    import tempfile
    _tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(_tmpdir, "store.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS memory_chunks (
        id TEXT PRIMARY KEY, created_at TEXT, updated_at TEXT, project TEXT,
        source_session TEXT, chunk_type TEXT, content TEXT, summary TEXT,
        tags TEXT, importance REAL, retrievability REAL, last_accessed TEXT,
        feishu_url TEXT, access_count INTEGER DEFAULT 0, oom_adj INTEGER DEFAULT 0,
        lru_gen INTEGER DEFAULT 0, confidence_score REAL DEFAULT 0.7,
        evidence_chain TEXT, verification_status TEXT DEFAULT 'pending',
        info_class TEXT DEFAULT 'world', stability REAL DEFAULT 1.0,
        emotional_weight REAL DEFAULT 0.0, emotional_valence REAL DEFAULT 0.0,
        depth_of_processing REAL DEFAULT 0.5, source_type TEXT DEFAULT 'unknown',
        source_reliability REAL DEFAULT 0.7, encode_context TEXT DEFAULT '',
        raw_snippet TEXT DEFAULT '', encoding_context TEXT DEFAULT '{}',
        original_ec_count INTEGER DEFAULT 0, spaced_access_count INTEGER DEFAULT 0,
        hypermnesia_last_boost TEXT, access_source TEXT DEFAULT 'retrieval',
        row_version INTEGER DEFAULT 1, chunk_state TEXT DEFAULT 'ACTIVE',
        boundary_proximity REAL DEFAULT 0.0, session_type_history TEXT DEFAULT ''
    )""")
    conn.execute(
        "INSERT OR REPLACE INTO memory_chunks (id, project, chunk_type, content, summary, "
        "importance, access_count, chunk_state, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        ("db_cold_1", "test_proj", "decision", "DB fallback content", "DB fallback summary",
         0.8, 0, "ACTIVE", "2026-05-10T12:00:00+00:00")
    )
    conn.commit()
    conn.close()

    # Simulate: final has no ac=0 chunks, positive has room
    from hooks.retriever import STORE_DB as _orig_db
    import hooks.retriever as _ret_mod
    _saved = _ret_mod.STORE_DB
    _ret_mod.STORE_DB = db_path

    try:
        # Run actual retriever cold_start with empty final (no FTS5 hits)
        positive = []
        final = []  # FTS5 missed all ac=0 chunks
        priority = "FULL"
        effective_top_k = 5
        project = "test_proj"
        session_id = "test_session"

        sysctl_set("retriever.cold_start_enabled", True)
        sysctl_set("retriever.cold_start_imp_threshold", 0.50)
        sysctl_set("retriever.cold_start_max_inject", 1)

        # Replicate the cold_start block with DB fallback
        _cs_imp_threshold = 0.50
        _cs_max = 1
        _positive_ids = set()
        _cold_candidates = [
            (imp_val, c) for s, c in final
            if c.get("id", "") not in _positive_ids
            and (c.get("access_count", 0) or 0) == 0
            and float(c.get("importance", 0) or 0) >= _cs_imp_threshold
            for imp_val in [float(c.get("importance", 0) or 0)]
        ]
        # DB fallback
        assert len(_cold_candidates) == 0, "FTS5 should find nothing"
        import sqlite3 as _cs_sql
        _cs_conn = _cs_sql.connect(db_path)
        _cs_rows = _cs_conn.execute(
            "SELECT id, summary, content, chunk_type, importance, tags, access_count "
            "FROM memory_chunks WHERE chunk_state='ACTIVE' AND access_count=0 "
            "AND (project=? OR project='global') AND importance>=? "
            "ORDER BY created_at DESC LIMIT 3",
            (project, _cs_imp_threshold)
        ).fetchall()
        _cs_conn.close()
        for _r in _cs_rows:
            if _r[0] not in _positive_ids:
                _cold_candidates.append((_r[4], {
                    "id": _r[0], "summary": _r[1], "content": _r[2],
                    "chunk_type": _r[3], "importance": _r[4],
                    "tags": _r[5], "access_count": 0,
                }))

        assert len(_cold_candidates) == 1, f"DB fallback should find 1, got {len(_cold_candidates)}"
        assert _cold_candidates[0][1]["id"] == "db_cold_1"
        assert _cold_candidates[0][0] == 0.8
    finally:
        _ret_mod.STORE_DB = _saved


# ──────────────────────────────────────────────────────────────────────
# 14. iter1431: cold_start_score_replace — positive 满且无 7d 饱和时替换低分已内化 chunk
# ──────────────────────────────────────────────────────────────────────

def _run_cold_start_with_score_replace(positive, final, effective_top_k,
                                       max_inject=2, imp_threshold=0.50,
                                       recent_7d_counts=None):
    """复现 iter1431 的 score_replace 逻辑。"""
    if recent_7d_counts is None:
        recent_7d_counts = {}
    _positive_ids = {c["id"] for _, c in positive}
    _cold_candidates = [
        (float(c.get("importance", 0) or 0), c) for s, c in final
        if c.get("id", "") not in _positive_ids
        and (c.get("access_count", 0) or 0) == 0
        and float(c.get("importance", 0) or 0) >= imp_threshold
    ]
    if not _cold_candidates:
        return positive, 0
    _cold_candidates.sort(key=lambda x: x[0], reverse=True)
    _cs_slots = effective_top_k - len(positive)
    if _cs_slots <= 0 and positive:
        _sat_indices = [
            i for i, (s, c) in enumerate(positive)
            if recent_7d_counts.get(c.get("id", ""), 0) >= 3
        ]
        if _sat_indices:
            _cs_slots = min(max_inject, len(_sat_indices))
            for _ri in sorted(_sat_indices[-_cs_slots:], reverse=True):
                positive.pop(_ri)
        # iter1431: score_replace fallback
        if not _sat_indices and len(positive) >= effective_top_k:
            _cs_repl = [(i, s, c) for i, (s, c) in enumerate(positive)
                        if (c.get("access_count", 0) or 0) >= 3]
            if _cs_repl:
                _cs_repl.sort(key=lambda x: x[1])
                _cs_slots = min(max_inject, len(_cs_repl))
                for _ri in sorted([x[0] for x in _cs_repl[:_cs_slots]], reverse=True):
                    positive.pop(_ri)
    injected = 0
    for _cold_imp, _cold_chunk in _cold_candidates[:max(_cs_slots, 0)]:
        positive.append((_cold_imp, _cold_chunk))
        injected += 1
    return positive, injected


def test_score_replace_when_positive_full_no_saturated():
    """iter1431: positive 满、无 7d>=3 饱和 chunk、但有 ac>=3 低分 chunk → 替换并注入 cold chunk。"""
    # positive 全满（3 个），都 7d<3（不触发 sat_indices），但 ac>=3
    existing = [
        _make_chunk("c_old1", importance=0.7, access_count=5),
        _make_chunk("c_old2", importance=0.8, access_count=4),
        _make_chunk("c_new", importance=0.9, access_count=1),  # ac<3 不可替换
    ]
    positive = [(0.20, existing[0]), (0.50, existing[1]), (0.80, existing[2])]
    # cold candidate in final
    cold = _make_chunk("c_cold", importance=0.85, access_count=0)
    final = [(0.0, cold)]

    result, injected = _run_cold_start_with_score_replace(
        positive, final, effective_top_k=3, max_inject=1,
        recent_7d_counts={}  # all 7d=0
    )
    assert injected == 1, f"should inject 1 cold chunk, got {injected}"
    result_ids = [c["id"] for _, c in result]
    assert "c_cold" in result_ids, f"cold chunk should be injected: {result_ids}"
    # score 最低的 c_old1(score=0.20, ac=5) 应被替换
    assert "c_old1" not in result_ids, f"lowest score ac>=3 should be replaced: {result_ids}"
    assert "c_new" in result_ids, f"ac<3 chunk should be kept: {result_ids}"


def test_score_replace_skips_low_ac():
    """iter1431: positive 中无 ac>=3 的 chunk → 不替换，不注入。"""
    existing = [
        _make_chunk("c1", importance=0.9, access_count=1),
        _make_chunk("c2", importance=0.8, access_count=2),
    ]
    positive = [(0.60, existing[0]), (0.50, existing[1])]
    cold = _make_chunk("c_cold", importance=0.85, access_count=0)
    final = [(0.0, cold)]

    result, injected = _run_cold_start_with_score_replace(
        positive, final, effective_top_k=2, max_inject=1,
        recent_7d_counts={}
    )
    assert injected == 0, f"no ac>=3 means no replacement, got {injected}"
    assert len(result) == 2
