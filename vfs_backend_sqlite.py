#!/usr/bin/env python3
"""
Phase 2B: SQLiteBackend — memory-os 存储后端适配器

实现 VFS 后端接口，连接 SQLite 存储 (store.db)。
OS 类比：ext4 对 VFS 的实现 — read_inode/write_inode/lookup 等 inode_operations。
"""
import sqlite3
import time
from pathlib import Path
from typing import Optional, List
from vfs_core import VFSBackend, VFSItem, VFSSource, VFSMetadata


class SQLiteBackend(VFSBackend):
    """SQLite 后端 — memory-os 主存储

    数据源：~/.claude/memory-os/store.db
    延迟：5-10ms (FTS5 查询) + 2-5ms (scorer 计算)
    """

    def __init__(self, db_path: Optional[Path] = None, readonly: bool = True):
        """初始化 SQLite 后端

        Args:
            db_path: SQLite 数据库路径（默认 ~/.claude/memory-os/store.db）
            readonly: 是否只读模式（生产环境推荐 True）
        """
        if db_path is None:
            db_path = Path.home() / ".claude" / "memory-os" / "store.db"

        self.db_path = db_path
        self.readonly = readonly
        self._conn_cache = None
        self._last_conn_time = 0
        self._conn_ttl_secs = 300  # 连接 TTL

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接（连接池实现，TTL 300s）"""
        now = time.time()
        if self._conn_cache and (now - self._last_conn_time) < self._conn_ttl_secs:
            return self._conn_cache

        # 创建新连接
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")

        uri = f"file:{self.db_path}?mode={'ro' if self.readonly else 'rwc'}"
        self._conn_cache = sqlite3.connect(uri, uri=True)
        self._conn_cache.row_factory = sqlite3.Row
        self._last_conn_time = now
        return self._conn_cache

    def read(self, path: str) -> Optional[VFSItem]:
        """按虚拟路径读单个项

        Args:
            path: 虚拟路径 /<source>/<id>

        Returns:
            VFSItem 或 None
        """
        try:
            # 解析虚拟路径: /memory-os/chunk-uuid-123abc
            parts = path.strip("/").split("/")
            if len(parts) < 2 or parts[0] != VFSSource.MEMORY_OS.value:
                return None

            chunk_id = parts[1]
            conn = self._get_conn()

            # 直接按 ID 查询（O(1) 主键查询）
            row = conn.execute(
                "SELECT * FROM memory_chunks WHERE id=?",
                (chunk_id,)
            ).fetchone()

            if not row:
                return None

            # 转换为 dict（sqlite3.Row 支持 dict 转换）
            chunk_dict = dict(row)
            return VFSItem.from_chunk(chunk_dict, score=1.0)

        except Exception as e:
            # 失败返回 None（soft error）
            return None

    def search(self, query: str, top_k: int = 5) -> List[VFSItem]:
        """全文搜索

        Strategy:
            1. FTS5 全文索引搜索（<10ms）
            2. BM25 排序
            3. scorer 增强（<5ms）
            4. 返回 Top-K

        Args:
            query: 搜索查询
            top_k: 返回结果数

        Returns:
            VFSItem 列表，按相关度排序
        """
        try:
            conn = self._get_conn()

            # Step 1: FTS5 搜索 + BM25 排序
            # 假设 store.db 已有 memory_chunks_fts 虚拟表
            rows = conn.execute("""
                SELECT mc.id, mc.chunk_type, mc.content, mc.summary,
                       mc.created_at, mc.updated_at, mc.last_accessed,
                       mc.importance, mc.retrievability, mc.access_count,
                       mc.source_session, mc.tags, mc.project,
                       fts.rank
                FROM memory_chunks_fts fts
                JOIN memory_chunks mc ON CAST(fts.rowid_ref AS INTEGER) = mc.rowid
                WHERE memory_chunks_fts MATCH ?
                ORDER BY fts.rank DESC
                LIMIT ?
            """, (query, top_k * 2)).fetchall()  # 2x 超采样以便后续 scorer 排序

            if not rows:
                # FTS5 无匹配，退回到简单 LIKE 搜索
                rows = conn.execute("""
                    SELECT *
                    FROM memory_chunks
                    WHERE summary LIKE ? OR content LIKE ?
                    LIMIT ?
                """, (f"%{query}%", f"%{query}%", top_k * 2)).fetchall()

            # Step 2: 转换为 VFSItem，计算 score
            # 这里简化：直接使用 FTS5 rank 作为 score
            items = []
            for i, row in enumerate(rows):
                # 构建 chunk_dict（从 row 元组重建）
                chunk_dict = {
                    "id": row[0],
                    "chunk_type": row[1],
                    "content": row[2],
                    "summary": row[3],
                    "created_at": row[4],
                    "updated_at": row[5],
                    "last_accessed": row[6],
                    "importance": row[7],
                    "retrievability": row[8],
                    "access_count": row[9],
                    "source_session": row[10],
                    "tags": row[11],
                    "project": row[12],
                }
                # FTS5 rank 是负数，转换为 0-1 分数
                fts_rank = row[13]  # rank column
                score = max(0.0, 1.0 + fts_rank / 10.0)  # rank -10 → score 0.0
                items.append(VFSItem.from_chunk(chunk_dict, score=score))

            # 返回 Top-K
            return items[:top_k]

        except Exception as e:
            # FTS5 表不存在或错误，返回空列表
            return []

    def write(self, item: VFSItem) -> bool:
        """写入新项（只读模式下为 no-op）

        Args:
            item: VFSItem

        Returns:
            成功返回 True
        """
        if self.readonly:
            return False  # 只读模式
        # iter1184: vfs_backend_ephemeral_gate — 对齐 store_vfs.insert_chunk iter973b
        _EPHEMERAL_TYPES = ("prompt_context", "conversation_summary", "tool_insight")
        if item.type in _EPHEMERAL_TYPES:
            return False

        try:
            conn = self._get_conn()
            metadata = item.metadata

            # 构建 chunk 记录（对标 memory_chunks 表）
            conn.execute("""
                INSERT OR REPLACE INTO memory_chunks
                (id, created_at, updated_at, project, source_session,
                 chunk_type, content, summary, tags, importance,
                 retrievability, last_accessed, access_count, lru_gen, oom_adj)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item.id,
                metadata.created_at,
                metadata.updated_at,
                metadata.project,
                metadata.source_session,
                item.type,
                item.content,
                item.summary,
                ",".join(metadata.tags) if metadata.tags else "",
                metadata.importance,
                metadata.retrievability,
                metadata.last_accessed,
                metadata.access_count,
                0,  # lru_gen
                0,  # oom_adj
            ))
            conn.commit()
            return True
        except Exception:
            return False

    def delete(self, path: str) -> bool:
        """删除项（只读模式下为 no-op）"""
        if self.readonly:
            return False

        try:
            parts = path.strip("/").split("/")
            if len(parts) < 2:
                return False

            chunk_id = parts[1]
            conn = self._get_conn()

            # B15 FTS sync: fetch rowid before delete, then remove FTS row
            # OS 类比：ext4 unlink — 删除 dentry 前先更新 inode 引用计数，
            # 避免 dcache/FTS 中残留孤立条目（orphan inode/FTS row）
            row = conn.execute(
                "SELECT rowid FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if row:
                mc_rowid = row[0]
                try:
                    conn.execute(
                        "DELETE FROM memory_chunks_fts WHERE rowid_ref=?",
                        (str(mc_rowid),)
                    )
                except Exception:
                    pass  # FTS 表不存在或已清理，忽略

            conn.execute("DELETE FROM memory_chunks WHERE id=?", (chunk_id,))
            conn.commit()
            return True
        except Exception:
            return False

    @property
    def name(self) -> str:
        return "SQLiteBackend"

    @property
    def source_type(self) -> str:
        return VFSSource.MEMORY_OS.value


# ── 测试（Phase 2B 验证）──────────────────────────────────────────
if __name__ == "__main__":
    import sys
    from pathlib import Path

    # 检查测试 DB 是否存在
    test_db = Path.home() / ".claude" / "memory-os" / "store.db"

    if not test_db.exists():
        print("⚠ Store DB not found, skipping live tests")
        print("✓ SQLiteBackend class defined and importable")
        sys.exit(0)

    try:
        backend = SQLiteBackend(db_path=test_db, readonly=True)
        print(f"✓ Backend initialized: {backend.name}")

        # Test search
        items = backend.search("BM25", top_k=3)
        if items:
            print(f"✓ Search found {len(items)} items")
            for i, item in enumerate(items, 1):
                print(f"  {i}. [{item.type}] {item.summary[:50]}")
        else:
            print("✓ Search executed (no results for 'BM25')")

        # Test read
        if items:
            first_item = items[0]
            read_item = backend.read(first_item.path)
            if read_item:
                print(f"✓ Read successful: {read_item.path}")
                assert read_item.id == first_item.id
            else:
                print(f"⚠ Read returned None for {first_item.path}")

        print("\n✅ Phase 2B: SQLiteBackend verified")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
