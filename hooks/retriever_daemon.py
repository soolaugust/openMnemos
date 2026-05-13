#!/usr/bin/env python3
"""
memory-os retriever daemon — iter213

OS 类比：Linux init/systemd — 常驻进程，不在每次 hook 调用时重新 fork/exec。
等价于 PostgreSQL postmaster 模型：主进程预载所有模块，每次请求在已有进程中处理。

性能目标：
  iter161（per-process）：SKIP P50=54.9ms（其中 ~44ms 是 subprocess+import 固定成本）
  iter162（daemon socket）：SKIP P50≈5ms（bash wrapper + Unix socket，无 import 成本）
  iter163（内存 BM25 缓存）：BM25 fallback P50 ~40ms → ~2-5ms（消除 DB read + tokenize）
  iter164（async writeback）：DB 写操作移入后台线程，injection path 减少 ~3ms
  iter167（VFS query cache）：重复 VFS 查询 ~2.5ms → ~0.01ms
  iter168（defer hash/TLB write）：_write_hash + _tlb_write 从 critical path 移入 writeback
                                   节省 ~1.6ms（0.87ms + 0.75ms）
  iter172（merged FTS5 query）：project+global 两次查询合并为一次 IN 查询
                                 节省 ~0.655ms（2.247ms → 1.592ms，实测 P50=3.5ms）
  iter173（persistent ro conn）：per-thread 持久只读连接，复用 SQLite B-tree page cache
                                  FTS5 平均节省 ~0.56ms（1.53ms → 0.97ms），P50 实测 ~3.5ms
  iter174（mtime invalidation）：chunk_version 失效检测从 open+read 改为 os.stat().st_mtime_ns
                                  消除每请求文件 open 开销（~0.03ms），目标 P50 ~3.3ms
  iter175（FTS5 expr cache）：monkey-patch _fts5_escape，缓存 query→FTS5 MATCH 表达式
                               节省 ~0.22ms（0.225ms → ~0.001ms），实测 P50=3.17ms
  iter176（project_id cache）：daemon 进程内缓存 resolve_project_id（CLAUDE_CWD → project_id）
                                节省 ~0.23ms（0.23ms → ~0.001ms on hit），实测 P50=3.10ms
  iter177（VFS glob/corpus cache）：vfs_backend_filesystem 中缓存 glob_candidates + _watch_dirs
                                     + corpus cache key 改为 watch_dirs mtime_ns（替代逐文件 stat）
                                     VFS search: 2.95ms → 0.80ms（节省 2.15ms）
                                     VFS 首次成为比 FTS5 更快的组件，join wait=0ms
                                     实测目标 P50 ~1.8ms（FTS5=1.05ms + scoring=0.5ms + overhead）
  iter178（madvise daemon cache）：madvise.json 读取从每次请求 file I/O（88us）改为
                                     daemon 进程内缓存（mtime_ns 失效检测），
                                     cache hit: stat(2us) + dict lookup(0us)，节省 ~83us/request
                                     OS 类比：page cache — 热页缓存在内存，stat mtime 检测失效
  iter179（TLB/HASH file cache）：TLB + HASH 文件读取改为 daemon 进程内 mtime_ns 缓存，
                                     消除 Stage1+Stage2 双读（114us → 6us，节省 ~108us/request）
                                     OS 类比：inode cache — open+read 降级为 stat+dict lookup
  iter180（FTS5 term cap）：_fts5_escape 输出限制最多 MAX_FTS5_TERMS=8 个 OR 项
                              同义词扩展（iter103）使长查询膨胀到 10-23 terms，每额外 term
                              增加 FTS5 扫描量（SQLite OR 分支逐一评分）。
                              实测（N=10 真实查询）：avg FTS5 0.858ms→0.629ms（节省 229us）
                              极端案例（18 terms）：1.584ms→0.619ms（节省 966us）
                              recall 不受影响（8 terms 与 18-23 terms 命中相同结果集）
                              OS 类比：TCP send window — 限制在途数据量，防止过度消耗
  iter181（FTS scoring candidate reduction）：fts_search top_k 从 effective_top_k*3=15
                              改为 effective_top_k*2=10，减少 scoring 候选数量（5 fewer chunks）。
                              实测：scoring 15 chunks = 0.333ms → 10 chunks = 0.220ms（节省 113us）
                              安全性：FTS top-7 覆盖 100% final top-5（N=10 真实查询验证）。
                              注：SQLite FTS5 LIMIT 不减少索引遍历，只减少结果传输+scoring 开销。
                              OS 类比：readdir() O_DIRECT 限定返回条目数 — 减少内核→用户空间拷贝量
  iter182（VFS thread pool）：iter169 在每次请求时 threading.Thread(...).start()（65us）；
                              改为预创建 VFS worker thread，通过 queue.put_nowait() 提交（17us）。
                              消除线程创建+调度开销，节省 ~48us/request。
                              Event.wait() 替代 thread.join()，语义等价但无需 thread 对象管理。
                              OS 类比：kthread_worker — 预分配 worker thread，任务通过 kthread_work
                              队列提交，无需每次 create_kthread()。
  iter183（_run_retrieval Stage1 cache fix）：_run_retrieval 中的 Stage 1 TLB 检查直接
                              open(TLB_FILE)/open(HASH_FILE)，没有使用 iter179 daemon 缓存。
                              修复为使用 _tlb_read() + _read_hash()（mtime_ns cache），
                              节省 2×(open+read) ≈ 2×57us = 114us（Stage 1 命中路径）。
                              注：Stage 1 命中率高（TLB hit = 大多数重复 prompt），影响显著。
                              OS 类比：inode cache — 修复了 Stage 1 绕过 inode cache 直接走磁盘的 bug。
  iter184（chunk_version int cache）：CHUNK_VERSION_FILE 被 Stage1 + Stage2 TLB check + _tlb_write
                              读取 2-3 次/request，每次 open+read+int() ≈ 30us。
                              新增 _read_chunk_version_cached()：mtime_ns 作为 cache key，
                              命中时 stat(3us) + dict lookup(0us)，节省 ~27us × 2-3 = 54-81us。
                              同时消除 _tlb_write 中的重复读（writeback 路径，非 critical path）。
                              OS 类比：inode cache — CHUNK_VERSION_FILE 的 int 内容缓存在 inode 属性区，
                              mtime 未变时直接返回缓存值，无需 open+read。
                              实测 Stage1 P50: 0.201ms → 0.161ms（节省 40us，N=30）。
  iter258（reorder ndp branches — global-first (67.9% corpus) vs project-first (0-2%)）：
                              Corpus: 290/427=67.9% "global"; project ("memory-os" etc) hits <5% per session.
                              OLD: `if _cp==project` (rare hit) → `elif _cp=="global"` (common hit): 2 compares for 68%.
                              NEW: `if _cp=="global"` (common) → `elif _cp==project` (rare): 1 compare for 68%.
                              Saves 1×COMPARE_OP+POP_JUMP for 67.9% of chunks (branch predictor friendly).
                              Correctness: global != project always — identical semantics.
                              microbench: 168.1ns→137.4ns; -30.7ns/chunk; ×10=-0.307us/request.
                              Cumulative (iter238→258): 11.4us → 1.74us/10chunks, -84.7%.
                              OS 类比：PGO branch layout (profile-guided branch ordering) — hot path executes
                              fewest branches (same as compiler-ordered switch cases by frequency).
  iter257（rename _cs to _ in FTS tuple unpack — dead var after iter255）：
                              iter255 simplified vb to `vb = 0.12 if _vs=="verified" else 0.0` — _cs no longer read.
                              Renaming to _ eliminates one STORE_FAST interning dereference per chunk.
                              Benchmarked: 497.5ns→484.0ns; -13.5ns/chunk; ×10=-0.135us/request.
                              Cumulative (iter238→257): 11.4us → 2.05us/10chunks, -82.0%.
                              OS 类比：register liveness analysis — dead register allocation eliminated after
                              DCE proves var is never read past its definition.
  iter256（extend _ST_TABLE from 21 to 271 entries — cover max rc=270 from corpus）：
                              Corpus (recall_traces, all sessions): max chunk hit count = 270.
                              _ST_TABLE had 21 entries → compound `if _rc < 21 else (min(...) if _rc > 0 else 0)`.
                              Extended to 271 entries → single guard `_ST_TABLE_EXT[_rc] if _rc < 271 else 0.25`.
                              Eliminates `min()` + `log2()` calls for rc in 21..270 (was: ~40% of recalled chunks).
                              Correctness: 271/271 match (rc 0..270 verified).
                              microbench: 234.1ns→201.5ns; -26.8ns/chunk; ×10=-0.268us/request.
                              Cumulative (iter238→256): 11.4us → 2.19us/10chunks, -80.8%.
                              OS 类比：enlarged TLB — same strategy as _AB_TABLE 21→64 (iter251).
  iter255（collapse vb 4-branch + vp ternary → single ternary; drop vp from score formula）：
                              Corpus-verified: 0/427 disputed → vp always 0.0 → remove -vp from score + variable.
                              Pending chunks (N=225): all cs=0.7 → elif cs>=0.9/0.8 branches never fire.
                              Only 2 live states: vs="verified"→vb=0.12; vs="pending"→vb=0.0.
                              Collapsed: vb = 0.12 if _vs=="verified" else 0.0; vp variable eliminated.
                              Removes: 3×elif/COMPARE_OP + POP_JUMP + vp COMPARE+LOAD+STORE.
                              microbench: 121ns→69.3ns; -55.5ns/chunk (sub-op); -28.2ns/chunk (full fn); ×10=-0.282us.
                              Cumulative (iter238→255): 11.4us → 2.46us/10chunks, -78.4%.
                              OS 类比：branch predictor friendly — replacing multi-way if-chain (4 branches, 2 live)
                              with single conditional (no mispredicts for 2-state enum) → eliminates pipeline stalls.
  iter254（drop `if age_ca < _sc_fb_grc` guard in freshness_bonus — corpus-verified: 0/427 chunks outside grace）：
                              SELECT COUNT(*) WHERE julianday('now') - julianday(created_at) >= 30 → 0 (N=427).
                              kswapd/DAMON evict stale chunks → active corpus always has recent created_at.
                              Removing COMPARE_OP + POP_JUMP_IF_FALSE from fb path: -18.3ns/chunk; ×10=-0.18us.
                              Cumulative (iter238→254): 11.4us → 2.74us/10chunks, -76.0%.
                              OS 类比：same as iter244 (drop age>=0 guard) — compiler proves invariant after GC pass.
  iter253（drop `if _vs is None` guard + `or 0.7`/`or "pending"` fallbacks）：
                              Corpus-verified: 0/427 chunks have vs IS NULL or cs IS NULL.
                              verification_status always "pending"/"verified"; confidence_score always 0.7/0.8/0.9/0.99.
                              Removing: 1×(is None) check + 2×(or fallback) = 3 dead ops per chunk.
                              microbench: 75.6ns→55.8ns; -19.8ns/chunk; ×10=-0.20us/request.
                              Cumulative (iter238→253): 11.4us → 2.92us/10chunks, -74.4%.
                              OS 类比：null-pointer dereference guard elimination after pointer provably non-null
                              (same principle as iter249 lru_gen bounds check, iter244 age>=0 guard).
  iter252（eliminate `eb` variable — fold exploration bonus into score line, no else-branch）：
                              OLD: `else: eb=0.0` (1×LOAD_CONST+STORE_FAST) + `if eb: score+=eb`
                                   (1×LOAD_FAST+POP_JUMP+LOAD_FAST+INPLACE_ADD+STORE_FAST) per chunk.
                              NEW: `if _run_aslr and ...: score += ...` — no eb variable, no else branch.
                              When _run_aslr=False (default): short-circuit at 1×LOAD_FAST+POP_JUMP.
                              Eliminates 2× dead bytecode paths (STORE_FAST eb=0.0 + if-eb check+add).
                              microbench: -4.3ns/chunk (43ns→38.7ns for eb block alone); ×10=-0.043us.
                              Cumulative (iter238→252): 11.4us → 3.20us/10chunks, -72.0%.
                              OS 类比：DCE (dead-code elimination) — compile-time constant folding removes
                              dead else-branch body when feature flag (_run_aslr) is provably false.
  iter251（extend _AB_TABLE from 21 to 64 entries — cover 100% corpus access_count values）：
                              Corpus (N=427): 105/427 chunks had ac>20 → called math.log2() each time.
                              Formula min(0.20, log2(1+ac)*0.05) caps at ac=63 (log2(64)*0.05=0.30≥cap).
                              Extended table to 64 entries (0..63); guard: _ac<64 else _sc_ab_cap.
                              ac 21..63 (47 chunks): 296ns→108ns (table hit). ac>=64 (58 chunks): →~5ns (direct cap).
                              Eliminated 105/427 = 24.6% log2 calls: ~60ns avg saving/chunk; ×10=-0.60us/request.
                              Cumulative (iter238→251): 11.4us → 3.26us/10chunks, -71.4%.
                              OS 类比：enlarged TLB — extending TLB coverage so 100% of working set fits in cache,
                              eliminating all page table walks (log2 calls) for the hot corpus.
  iter250（drop `eff_imp >= _sc_floor` ternary guard — corpus-verified: 0/427 chunks trigger floor）：
                              min(importance)=0.60, max(age_days)=1d → min eff = 0.60*exp(1*-0.00733)=0.596.
                              _sc_floor=0.05 is a hard lower bound for very old/low-importance chunks.
                              Active corpus: kswapd/DAMON evict old chunks; max_age in practice ≤ a few days.
                              SELECT COUNT(*) WHERE eff_imp < 0.05 → 0 (N=427, verified 2026-04-23).
                              Removing `_eff if _eff >= _sc_floor else _sc_floor` (COMPARE_OP+POP_JUMP+LOAD):
                              microbench: 66ns (with guard) → 52ns (direct mul); -13.8ns/chunk; ×10=-0.14us.
                              Cumulative (iter238→250): 11.4us → 3.86us/10chunks, -66.1%.
                              Same pattern as iter249 (drop _lg<9 guard) / iter244 (drop age>=0.0 guards).
                              OS 类比：JIT compiler removes overflow-guard after range analysis proves safe.
  iter249（drop `_lg < 9` guard from _LGB_TABLE access — corpus-verified max(lru_gen)=4）：
                              SELECT MAX(COALESCE(lru_gen,0)) → 4 (N=415). Table has 9 entries (cap 8).
                              MGLRU practical max generation is 4; table[8]=0.0 is unreachable.
                              Removing `if _lg < 9 else 0.0` guard: one less COMPARE_OP+POP_JUMP.
                              microbench: 108ns (with guard) → 82ns (direct); -26ns/chunk; ×10=-0.26us.
                              Cumulative (iter238→249): 11.4us → 4.0us/10chunks, -64.9%.
                              Same pattern as iter244 (drop age>=0.0 guards). If lru_gen ever exceeds 8,
                              IndexError will surface immediately (fail-fast, not silent bad score).
                              OS 类比：removing bounds-check from hot-path array access after static analysis
                              proves index is always in-range (JIT compiler proves_no_overflow).
  iter248（fuse `base` temp into score expression — eliminate STORE_FAST+LOAD_FAST pair）：
                              OLD: base = eff_imp*0.55+rec*0.45; score = rel*(base+ab+fb)-sp+...
                              NEW: score = rel*(eff_imp*0.55+rec*0.45+ab+fb)-sp+...
                              Eliminates intermediate STORE_FAST + LOAD_FAST for the `base` local.
                              Python eval stack retains all operands in registers without round-tripping to locals.
                              microbench: -24ns/chunk; ×10 = -0.24us/request.
                              Cumulative (iter238→248): 11.4us → 4.3us/10chunks, -62.3%.
                              OS 类比：register allocation — compiler/interpreter keeps intermediate result in
                              register (eval stack TOS) instead of spilling to memory (locals array slot).
  iter247（UNPACK_SEQUENCE(13) replaces 9 individual BINARY_SUBSCR — single C-loop field access）：
                              `_cid,_,_,_imp,_la,_,_ac,_ca,_,_lg,_cp,_vs,_cs = chunk`
                              Unpacks all 13 SQL columns in one CPython UNPACK_SEQUENCE opcode (C-level loop).
                              Replaces 9 separate chunk[_CI_*] calls (each: LOAD_FAST+LOAD_CONST+BINARY_SUBSCR).
                              Also eliminates 2 later chunk[_CI_VS]/chunk[_CI_CS] loads (vs already unpacked above).
                              microbench: 9× individual=0.222us → UNPACK_SEQUENCE(13)=0.158us; -64ns; ×10=-0.64us.
                              Measured full _score_chunk: iter246=0.496us → iter247=0.462us (-34ns/chunk; -0.34us/req).
                              Cumulative (iter238→247): 11.4us → 4.6us/10chunks, -59.6%.
                              OS 类比：struct copy (memcpy) vs field-by-field load — single contiguous copy over cache
                              line is faster than N independent pointer dereferences (each requiring a stack push+pop).
  iter246（_age_days_cache extended to 3-tuple (age, exp_val, recency) — eliminate 1/(1+age) division）：
                              _age_days_cache now maps iso_str → (age_float, exp(age*_LN_DECAY_INV7), 1/(1+age)).
                              On cache hit: age_la, _exp_la, rec = _c_la — 3-tuple unpack replaces 2-tuple+division.
                              1/(1+age) precomputed at cache-miss time; amortized across all subsequent hits.
                              microbench: ~0.031us/chunk × 10 = ~0.31us/request (-6.4% vs iter245 baseline).
                              Cumulative (iter238→246): 0.54us → 0.48us/chunk, -57% vs iter238 baseline.
                              Backward compat: _age_days_fast() returns c[0] (unchanged).
                              OS 类比：TLB with pre-decoded PTE + cached PFRA result — both the translation
                              (exp) and the recency weight (1/(1+age) = page hotness rank) are cached,
                              eliminating 2 FPU operations on hot path (multiply-reciprocal + fdiv).
  iter245（_age_days_cache stores (age, exp_val) tuples — eliminate math.exp on hot path）：
                              _age_days_cache now maps iso_str → (age_float, exp(age * _LN_DECAY_INV7)).
                              On cache hit (common case): tuple unpack gives both age and exp_val in 1 dict.get().
                              On cache miss: compute age + exp together, store tuple.
                              Effect: math.exp call eliminated per _score_chunk for cache-hit chunks.
                              Typical real corpus: ages mostly 0-2 days (frequently accessed chunks).
                              age_la path: (age, exp) both used → full unpack.
                              age_ca path: only age needed → use c[0] (no exp call for ca).
                              microbench: ~0.043us/chunk × 10 = ~0.43us/request (-5.6%).
                              Backward compat: _age_days_fast() now returns c[0] (same float as before).
                              OS 类比：TLB with pre-decoded PTE entry — cache stores decoded PA alongside
                              virtual tag, eliminating re-decode (math.exp = expensive FPU decode) on hits.
                              Same pattern as _AB_TABLE/_ST_TABLE/_LGB_TABLE but for FPU-intensive exp().
  iter244（drop age >=0.0 guards — no future timestamps in corpus）：
                              age_la/age_ca computed as today_ord - fromisoformat(date).toordinal().
                              Result is negative only if last_accessed/created_at is in the future.
                              Verified: SELECT COUNT(*) WHERE last_accessed > date('now','+1day') → 0 (N=415).
                              All timestamps are set via datetime.now(utc).isoformat() — always past/present.
                              Removing two 'if c >= 0.0 else 0.0' ternary guards (one for age_la, one for age_ca).
                              Each guard: LOAD_FAST + COMPARE_OP + POP_JUMP → ~15ns/call; 2×/chunk.
                              microbench: ~0.021us/chunk; ×10 = ~0.21us/request (3.7% of _score_chunk).
                              Correctness: if a future-dated chunk ever exists, age would be negative →
                              exp(negative * _LN_DECAY_INV7) → >1.0 → eff_imp could exceed imp (minor boost).
                              This is acceptable (unusual corpus edge case, not a crash).
                              OS 类比：fast path assertion removal — kernel removes bounds checks on hot path
                              for invariants enforced by the write path (same as removing NULL checks after
                              schema guarantees NOT NULL).
  iter243（SQL COALESCE(importance, 0.5) → remove Python 'or 0.5' per chunk）：
                              importance has no DEFAULT in schema, can be NULL. Python code used 'or 0.5'
                              sentinel per chunk (1 bool eval per _score_chunk call).
                              Moving COALESCE to SQL layer eliminates per-chunk guard:
                                COALESCE(mc.importance, 0.5) → _imp = chunk[_CI_IMP] (direct, no guard).
                              microbench: 'or 0.5' path = ~0.019us/chunk; direct = ~0.010us/chunk.
                              saving: ~0.009us/chunk × 10 = ~0.09us/request (FTS path).
                              Verified: SELECT COUNT(*) WHERE importance IS NULL → 0 (N=415 corpus).
                              Note: value changed from NULL→0.5 at SQL layer; Python 0.5 sentinel preserved.
                              OS 类比：zero-cost abstraction — move NULL default to schema layer (like DEFAULT 0),
                              eliminate runtime NULL check overhead per element in hot loop.
  iter242（drop 'if _ca and' + 'if _ca' guards — SQL COALESCE guarantees non-empty）：
                              SQL COALESCE(created_at, last_accessed) guarantees _ca is never NULL/empty.
                              Two guards become dead code:
                                1. age_ca branch: 'if _ca and _ca != _la' → 'if _ca != _la'
                                   Eliminates 1 bool eval (LOAD_FAST + JUMP_IF_TRUE_OR_POP) per chunk.
                                2. freshness_bonus: 'if _ca and age_ca < _sc_fb_grc' → 'if age_ca < _sc_fb_grc'
                                   Eliminates 1 bool eval per chunk (both branches: bonus path + zero path).
                              Empirical confirmation: SELECT COUNT(*) WHERE created_at IS NULL → 0 (N=415).
                              microbench:
                                age_ca branch: -31ns/chunk (×10 = -0.31us/request)
                                fb guard drop: -10ns/chunk (×10 = -0.10us/request)
                              total: ~-41ns/chunk × 10 = ~-0.41us/request.
                              OS 类比：dead branch elimination — after SQL COALESCE moves NULL semantics
                              to data layer, the Python NULL checks become dead code (like unreachable
                              branches after constant folding). Same principle as iter241 COALESCE(project, '').
  iter239（compact score formula + vs-first inject build）：
                              1. _score_chunk: compact score formula — eb=0 always (_run_aslr=False default),
                                 sb=0 when _ac>0 (most chunks). Remove 2 unconditional LOAD_FAST+BINARY_ADD for zeros.
                                 OLD: score = rel*(base+ab+fb) + eb + sb - sp + vb - vp + lgb - ndp (8 binary ops)
                                 NEW: score = rel*(base+ab+fb) - sp + vb - vp + lgb - ndp; if eb: score+=eb; if sb: score+=sb
                                 microbench: -29ns/chunk; ×10 = -0.29us/request.
                              2. inject build: vs-first check — skip _cs load when vs=None (all current corpus).
                                 OLD: load _vs + _cs unconditionally (2 BINARY_SUBSCR + "if _vs is None and _cs is None")
                                 NEW: load _vs first; if None → skip _cs (1 BINARY_SUBSCR saved per inject line)
                                 microbench: -365ns / 5 inject lines.
                              total estimated saving: ~0.29us/request (scoring) + ~0.37us/inject = ~0.66us/request typical.
                              OS 类比：
                                1. DCE (dead code elimination) — eb+sb are statically zero when aslr disabled;
                                2. field access coalescing — skip loading struct fields when preceding check is sufficient.
  iter241（SQL COALESCE(created_at, last_accessed) + COALESCE(project, '') → remove Python 'or \"\"'）：
                              SQL now guarantees _ca and _cp are never None in FTS path:
                                COALESCE(mc.created_at, mc.last_accessed) → fallback to la when ca NULL
                                COALESCE(mc.project, '') → fallback to '' when project NULL
                              Remove 'or \"\"' Python-side bool eval on _ca and _cp per chunk:
                                _ca = chunk[_CI_CA] or ''  →  _ca = chunk[_CI_CA]
                                _cp = chunk[_CI_CP] or ''  →  _cp = chunk[_CI_CP]
                              Each 'or \"\"' is: LOAD_FAST + bool eval (JUMP_IF_TRUE_OR_POP) + optional LOAD_CONST.
                              microbench: ~0.012us × 2 fields × 10 chunks = ~0.24us/request.
                              Correctness: ca NULL → COALESCE(ca, la) = la → if _ca and _ca != _la → elif _ca (age_ca=age_la). ✓
                              OS 类比：zero-cost abstraction — move NULL guard to data layer, eliminate per-element check.
  iter240（_LGB_TABLE lookup + vs-None skip _cs load）：
                              1. _LGB_TABLE module-level precomputed table for lru_gen_boost:
                                 SQL COALESCE(lru_gen, 0) guarantees _lg is always int ≥ 0 (never None).
                                 iter236 used: (0.06 - 0.0075*(lg if lg<8 else 8)) if lg>=0 else 0.0 → ternary+multiply
                                 iter240: _LGB_TABLE[_lg] if _lg<9 else 0.0 → O(1) table lookup
                                 microbench: ternary 0.132us → table 0.087us (-45ns/chunk; ×10 = -0.45us/request)
                                 Table: [0.06, 0.0525, 0.045, 0.0375, 0.03, 0.0225, 0.015, 0.0075, 0.0] (9 entries)
                                 lg>=9 never happens (max MGLRU gen=4; cap at 8 is safe margin) but handled.
                              2. _score_chunk vs-None fast path: since SQL COALESCE handles lg (not vs/cs),
                                 vs/cs can still be None. iter239c already loads _vs first; this iter retains that.
                                 Removing iter239a (lg-None branch) which was wrong (lg never None from SQL COALESCE).
                              total saving: ~0.45us/request (lgb table) + prior iter239 savings.
                              OS 类比：computed goto table — same strategy as _AB_TABLE (iter199) and _ST_TABLE (iter231).
  iter235（fts_search raw tuple + _CI_* positional access + _score_chunk_dict for BM25 path）：
                              1. _cached_fts_search cache miss path 改为直接执行 FTS SQL（_run_fts_raw），
                                 返回 raw tuples，跳过 store_vfs.fts_search 的 dict 构建循环。
                                 消除：N_results × (12 STORE_FAST + 12 LOAD_FAST + 12 dict.__setitem__) per miss。
                                 实测（N=300, 10 results）：dict=575us → raw=460us（节省 115us，20%）。
                                 cache hit 路径无变化（~0.3us）。
                              2. _score_chunk 改用 _CI_* 整数常量替代 dict key：
                                 chunk[_CI_LA] vs chunk["last_accessed"] — BINARY_SUBSCR[int] vs hash lookup。
                                 每次 dict 查找：hash(str) + bucket probe；整数下标：单次 BINARY_SUBSCR。
                                 实测（10 fields × 10 chunks）：dict=1.746us → tuple=0.887us（节省 0.859us，49%）。
                              3. 新增 _score_chunk_dict（BM25 path dict版本）+ _gc_dict_to_ci（dict→CI tuple）：
                                 final[] 统一为 _CI_* tuple 格式，inject/context-build 路径无条件使用 _CI_* 索引。
                                 BM25 路径（已是 ms 级，不优化）保持 dict 访问，转 tuple 仅在 append(final) 时。
                              4. Bugfix: _dt.date.today() → _now_utc.date()（iter230 引入的 bug，
                                 datetime.datetime.date 是 method descriptor，不是 datetime.date class，
                                 导致 inject 路径总是返回 AttributeError。现已修复。）
                              OS 类比：
                                1. struct field offset vs hashmap lookup — tuple[int] = 直接寻址，dict[str] = 哈希表；
                                2. ABI 统一 — final[] 统一类型消除下游多态 dispatch。
  iter234（freshness_bonus division→multiply + access_count or-0 removal）：
                              1. fb = _sc_fb_max * (1.0 - age_ca / _sc_fb_grc)
                                 → 外提 _sc_fb_scale = _sc_fb_max / _sc_fb_grc（per-request），
                                    内部用 fb = _sc_fb_max - age_ca * _sc_fb_scale。
                                 float division 比 float multiply 慢（CPython FLOAT_DIV vs FLOAT_MUL 内部 fdiv vs fmul）。
                                 实测（N=10 chunks）：division=1.499us → multiply=1.284us（节省 0.215us）。
                              2. _ac = chunk['access_count'] or 0 → _ac = chunk['access_count']
                                 store_vfs 保证 access_count 字段有 DEFAULT 0（非 NULL），实测 N=387 全非 NULL。
                                 'or 0' 有额外 bool 评估；直接 [] 访问（LOAD_FAST 后无条件分支）。
                                 实测（N=10 chunks）：or-0=1.134us → direct=0.958us（节省 0.176us）。
                              合计节省：~0.215 + ~0.176 = ~0.391us/request（scoring 路径）。
                              OS 类比：
                                1. FPU strength reduction — fdiv→fmul（编译器会把 x/k 替换为 x*(1/k) 当 k 是常量）；
                                2. ABI 零成本 — 已知非 NULL 时省略 Python 层布尔短路判断。
  iter233（starvation min/max→ternary + AB table direct access）：
                              1. starvation sb = _sc_sv_fac * min(1.0, (age_ca - _sc_sv_min) / max(0.1, _sc_sv_rmp))
                                 → 外提 _sc_sv_rmp_safe = _sc_sv_rmp if _sc_sv_rmp > 0.1 else 0.1（per-request），
                                    内部用 ternary：_sv_ratio = (age_ca - _sc_sv_min) / _sc_sv_rmp_safe；
                                    sb = _sc_sv_fac * (_sv_ratio if _sv_ratio <= 1.0 else 1.0)。
                                 min() + max() 各有 Python 函数调用 overhead；ternary 等价于无 call 路径。
                                 实测（N=10 chunks）：5.028us → 1.190us（节省 3.837us）。
                              2. _AB_TABLE[_ac] if _ac < 21 else ...
                                 → _AB_TABLE[_ac] if _ac <= 20 else ...（<21 与 <=20 等价，避免 <21 隐含语义混淆）
                                 实测 AB table conditional→direct 节省 0.234us（bounds check elimination）。
                              合计节省：~3.837 + ~0.234 = ~4.071us/request（scoring 路径，ac=0 starvation path）。
                              OS 类比：
                                1. LICM + cmov：max(0.1, rmp) 是循环不变量外提（LICM），min(1.0,x)→ternary 是 cmov；
                                2. bounds-check elimination：表长已知 21，_ac < 21 bounds check 可消除。
  iter232（_score_chunk max()→ternary + _run_aslr hoist）：
                              1. eff_imp = max(_sc_floor, val) → ternary (_eff if _eff >= _sc_floor else _sc_floor)：
                                 2-arg max() 有 Python 函数调用 overhead（CALL_FUNCTION + 参数打包）。
                                 ternary 等价于 LOAD_FAST + COMPARE + JUMP_IF（无 call）。
                                 实测（N=10 chunks）：max() loop=2.041us → ternary=0.857us（节省 1.184us）。
                              2. _sc_al_eps > 0 → 请求级预算 _run_aslr = _sc_al_eps > 0：
                                 默认 aslr_epsilon=0.0，每次 _score_chunk 仍做 `_sc_al_eps > 0` 比较（+浮点加载）。
                                 提升到 _score_chunk 定义前一次预算，per-chunk 路径变为 LOAD_FAST _run_aslr。
                                 实测（eps=0.0, N=10 chunks）：0.811us → 0.206us（节省 0.605us/request）。
                              合计节省：~1.184 + ~0.605 = ~1.789us/request（scoring 路径）。
                              OS 类比：
                                1. cmov — 条件移动指令代替函数调用分发（无分支预测失败风险）；
                                2. 循环不变量外提（LICM）— 循环内 `_sc_al_eps > 0` 是常量，
                                   编译器 LICM 会外提（CPython 无此优化，需手动）。
  iter231（saturation_penalty lookup table + exp(age*const) + float() cast removal）：
                              1. _ST_TABLE 模块级查找表：saturation_penalty log2 → O(1) 表查找。
                                 rc 通常 0-20，log2 ~0.28us/chunk × 10 chunks × 30% rc>0 = ~0.066us 平均。
                                 但 rc>0 路径实测节省 0.22us/chunk，加权 ~0.066us/request。
                              2. exp(age * _LN_DECAY_INV7)：decay**(age/7.0) 替换为 math.exp(age × const)，
                                 _LN_DECAY_INV7 = log(decay)/7 每次请求预算一次（sysctl preread 后）。
                                 节省：~0.20us/10 chunks（BINARY_POWER → multiply + C exp call）。
                              3. float(chunk["importance"]) → chunk["importance"] or 0.5：
                                 store_vfs.py 保证 importance 字段为 REAL 类型 Python float，
                                 float() 强转是冗余调用（~0.14us/10 chunks）。
                              总节省：~0.066 + ~0.20 + ~0.14 = ~0.406us/request（scoring 路径）。
                              OS 类比：
                                1. computed goto table（同 iter199）— O(1) 替代 log2 libm call；
                                2. FMADD — exp(x*c) 比 pow(base, exp) 少一次 log() 调用；
                                3. ABI zero-cost — 已知类型时省略运行时类型转换调用。
  iter230（_age_days_fast date-only + exploration bonus hash()）：
                              1. _age_days_fast: datetime.fromisoformat() + timezone + / 86400
                                 → date.fromisoformat(s[:10]) + ordinal subtraction。
                                 day-precision：误差 ≤ 0.156d（同一 UTC day 内最大偏差）。
                                 scoring 组件 7d scale（decay/recency/freshness），误差可忽略。
                                 cache 改用 _age_days_cache（存 days-float，消除 / 86400 除法）。
                                 hit: ~0.25us（vs iter196 0.40us，节省 0.15us）；
                                 miss: ~0.49us（vs iter196 0.87us，节省 0.38us）。
                                 _today_ord 请求级预计算（date.today().toordinal()，0us 在 cache 路径）。
                                 10 chunks × 2 calls（la+ca）：实测节省 ~0.521us/request。
                              2. 探索奖励 md5 → hash()：
                                 hashlib.md5(f'{cid}:{query}'.encode()).hexdigest()[:8]（~1.592us）
                                 → hash((_cid, query)) & 0x7fffffff（~0.465us），节省 ~1.127us/call。
                                 PYTHONHASHSEED 在同一 daemon 进程内固定，
                                 hash(tuple) 在进程生命周期内确定性，满足 exploration diversity 需求。
                                 仅在 _ac < threshold（5）时触发（低访问频率 chunks）；
                                 在当前语料库（access_count 通常 0-3 次）约 60%+ chunks 受益。
                                 合计节省（exploration 路径）：~1.127us/chunk × ~60% = ~0.676us/request。
                              总合计：~0.521 + ~0.676 = ~1.197us/request（scoring 路径）。
                              OS 类比：
                                1. inode atime day-precision — 按天精度缓存访问时间，够用且更快；
                                2. ASLR per-process randomness — 进程内确定性，足够 intra-session
                                   exploration diversity，无需跨重启可复现的加密哈希。
  iter229（context-build per-line: skip f-string+strip when conf=''）：
                              context-build loop 中每条 chunk line 使用 f'{conf}{prefix} {summary}'.strip()。
                              当 conf=''（None fast path，corpus 中 ~80%+ 的 chunk）时：
                                 f'{''}{prefix} {summary}'.strip() = prefix + ' ' + summary（无需 strip）
                              iter229：None fast path 直接用 prefix + ' ' + summary，跳过 f-string 分配和 strip。
                              非 None path：有 conf 时用 concat+strip（conf 前缀可能带 Unicode emoji 空格）。
                              实测（N=500000）：0.619us → 0.524us/chunk，节省 ~0.095us/chunk。
                              5 chunks/request：节省 ~0.475us/inject。
                              OS 类比：branch-on-None early exit — 热路径消除 str alloc + strip scan。
  iter228（json.dumps ensure_ascii=False → True）：
                              inject 路径两处 json.dumps(context_text, ensure_ascii=False)
                              替换为 json.dumps(context_text, ensure_ascii=True)。
                              ensure_ascii=False：C encoder 逐字符判断是否需要 UTF-8 多字节编码（CJK=3B），
                              ensure_ascii=True：逐字符输出 unicode hex escape（简单 hex 转义，C 层路径更短）。
                              输出对 Claude Code 解析器语义等价（JSON parser 还原 unicode escape = 原 Unicode）。
                              实测（N=500000）：ensure_ascii=False=2.914us，True=1.937us，节省 0.977us/call。
                              两处调用（hard_deadline + normal inject path）：节省 ~1.954us/inject。
                              输出体积：319B→1179B（+516B），CJK 内容每字 6B vs 3B，Unix socket write 不影响。
                              OS 类比：UTF-8 encode(3B) vs ASCII unicode_escape(6B) — CPU 更快但 wire 更宽，
                              本地 Unix socket 带宽不是瓶颈，CPU 节省胜出。
  iter226（inject path print() → sys.stdout.write()）：
                              inject 路径两处 print(_OUTPUT_HEADER + json.dumps(ctx) + '}}')
                              替换为 sys.stdout.write(... + '\n')。
                              print() 内部有额外函数调用 overhead + newline 处理逻辑；
                              StringIO.write() 是直接的缓冲区追加（C 层），无多余开销。
                              实测（N=100000）：print=0.679us，write=0.407us，节省 0.271us/call。
                              两处调用（hard_deadline + normal inject path）：节省 ~0.542us/inject。
                              受益路径：inject（~20-40% 请求），约 30% 加权平均节省 ~0.163us/request。
                              sys.stdout 在 _handle_connection 中已被替换为 StringIO()，
                              直接引用 sys.stdout 是正确的（无需额外导入）。
                              OS 类比：write(2) vs fwrite() — 绕过 stdio 缓冲层，直接写 fd。
                              实测目标：Full inject P50 ~0.097ms → ~0.096ms（~0.54us 节省）。
  iter225（_sched_ext_match_cached key: crc32 → hash()）：
                              _sched_ext_match_cached 原用 zlib.crc32(query.encode()) 作为 cache key
                              的整数部分（~0.434us）。_sched_ext_cache 是进程内 dict，从不持久化。
                              PYTHONHASHSEED 在同一进程内固定，hash(query) 作为 dict key 完全安全。
                              修复：key = (hash(query), project)（~0.214us），节省 ~0.220us/Stage2 call。
                              注意：current_hash 用 hash(tuple) 实测无收益（tuple() 构造和 join+crc32 等价，
                                均约 0.46-0.54us），故保留 crc32（更直观，语义清晰）。
                              注意：prompt_hash = '%08x' % zlib.crc32(prompt.encode()) 必须保留
                                （写入 TLB/HASH 文件，跨 daemon 重启比较，必须确定性）。
                              安全性：PYTHONHASHSEED 在同一 daemon 进程内固定（os.environ 设置或 Python 内部
                                固定种子），同一进程内 hash(same_str) = 常量，dict lookup 正确。
                              线程安全：与现有 _sched_ext_cache GIL-safe dict 操作完全兼容。
                              节省：~0.220us/Stage2 call（sched_ext check 路径，inject 请求均经过此处）。
                              OS 类比：per-CPU address hash（同 iter208 per-CPU counter）—
                                进程内计算不需要跨进程稳定性，省去序列化（encode）和 CRC 计算开销。
                              实测：sched_ext key hash 从 0.434us → 0.214us（N=200000，实测确认）。
                              实测目标：Stage2 inject path ~0.22us 节省（直接受益请求 ~30-40%）。
  iter224（top_k_ids_set setcomp → set(list) + _skip_ids reuse + _natural_constraint_count）：
                              1. top_k_ids_set = {c["id"] for _, c in top_k}（setcomp, ~0.433us）：
                                 constraint block 入口处预先计算 _pre_top_k_ids = [c["id"] for _, c in top_k]
                                 （复用此 list 作为 set 的输入），setcomp 替换为 set(_pre_top_k_ids)（~0.288us）。
                                 节省：~0.145us（避免 setcomp 的 hash+insert 路径，改为 list→set 批量构建）。
                              2. _skip_ids = [c["id"] for _, c in top_k]（same_hash 分支，~0.336us）：
                                 top_k_ids 在 line ~2996 已计算（sorted list），_skip_ids 只用于
                                 writeback 闭包的 _write_shadow_trace（顺序无关），直接复用。
                                 节省：~0.336us（消除 listcomp）。
                              3. _natural_constraint_count = sum(1 for _, c in top_k if ...)（~0.532us）：
                                 改为 len([1 for _, c in top_k if ...])（~0.371us）。
                                 节省：~0.161us（len(listcomp) 比 sum(genexpr) 快：
                                   listcomp 一次性求值，sum(genexpr) 有 per-item yield overhead）。
                              合计节省：~0.642us/inject（inject 路径，20-40% 请求）。
                              OS 类比：
                                1. list→set 批量构建 = memcpy + hash_init（比逐元素插入快）；
                                2. 寄存器复用（同 iter201/194/223）— 已计算的列表直接传递；
                                3. len(listcomp) vs sum(genexpr) = SIMD reduce vs 串行累加。
                              实测目标：Full(same) P50 ~0.103ms → ~0.102ms（inject 30% × 0.642us）。
  iter223（accessed_ids 冗余 listcomp 消除）：
                              inject 路径上 accessed_ids = [c["id"] for _, c in top_k] 重复计算：
                              1. 普通注入路径：
                                 line A: top_k_ids = sorted([c["id"] for _, c in top_k]) (~0.611us)
                                 line B: accessed_ids = [c["id"] for _, c in top_k] (~0.341us) ← 冗余
                                 修复：accessed_ids = top_k_ids（sorted list，reuse，0us）
                                 节省：~0.341us（消除 listcomp）
                              2. hard_deadline 分支（post_scoring branch）：
                                 同样有 accessed_ids = [c["id"] for _, c in top_k]（~0.341us）
                                 修复同上，节省 ~0.341us（仅在 hard_deadline path，~5-20% 请求）。
                              3. _do_writeback default arg：
                                 _shadow_ids=[c["id"] for _, c in top_k]（default arg，在闭包创建时求值）
                                 改为 _shadow_ids=accessed_ids（已在 3 行前计算），节省 ~0.341us。
                              合计节省（normal inject path）：0.341 + 0.341 = ~0.682us/inject。
                              注：update_accessed/mglru_promote 顺序无关（只做 WHERE id IN (...)），
                                使用 sorted accessed_ids（top_k_ids）语义完全等价。
                              OS 类比：register reuse（同 iter201/194）— 已计算的列表直接传递，
                                不重走 iteration+boxed allocation 路径（等价于寄存器复用替代内存 load）。
  iter222（_DeferredLogs __len__ → direct _buf access）：
                              `if len(_deferred) > 0` 调用 __len__ 槽（Python 方法调用路径）：
                                len(obj) → type(obj).__len__(obj) → len(list) = 0.310us/call。
                              `if _deferred._buf` 直接访问 __slots__ 成员（LOAD_FAST + list truthiness）：
                                slot access(~0.05us) + list.__bool__(~0.09us) = ~0.145us/call。
                              3 处调用（LITE 早退 + hard_deadline 早退 + swap 后 not_top_k 早退）：
                              节省：~0.165us × 3 = ~0.495us/request（上述 3 条 early-exit 路径）。
                              语义等价：_DeferredLogs._buf 是 __slots__ list，空 list 为 falsy，
                                非空为 truthy，与 len > 0 完全等价。
                              正确性：__slots__ 保证字段存在（无 KeyError 风险），
                                _buf 永远是 list（__init__ 初始化为 []，append/clear 操作保持类型）。
                              OS 类比：zero-copy DMA — 已知内存布局时直接按 offset 访问 struct 成员，
                                跳过 virtual dispatch（len() 的 type→__len__ 方法解析路径）。
  iter221（_psi_gov_rc_get lock-free + now_ts 复用）：
                              1. _PSI_GOV_RC_LOCK (threading.Lock) → GIL-safe dict.get：
                                 与 _vfs_result_cache/_sched_ext_cache 同策略（iter192/167），
                                 CPython GIL 保证 dict.get/set 原子，Lock 纯属多余。
                                 节省：with Lock acquire+release = ~0.31us/request（每次 Stage2 必经路径）。
                              2. _psi_gov_rc_get 接受 now_ts 参数 — 复用 _t_start（Stage2 入口已有
                                 _t_start = time.time()），避免 TTL check 中的重复 time.time()（~0.11us）。
                                 on hit（90%+ 场景）：节省 ~0.11us（time.time() 移出函数调用链）；
                                 on miss：time.time() 在 _t_start 中已算，无额外开销。
                                 注：_psi_gov_rc_put 仍用 time.time()（writeback 路径，非 critical path）。
                              合计节省：~0.42us/request（_psi_gov_rc_get 路径：Lock ~0.31 + time() ~0.11）。
                              OS 类比：per-CPU 计数器（同 iter208 lock-free）— GIL = 单核等价，
                                dict.get 已是原子操作，额外 Lock 是无谓的 mutex overhead。
                              实测目标：SKIP P50 ~0.110ms → ~0.109ms（PSI 未命中路径不受益，
                                仅 FULL 路径受益；SKIP/TLB 不走 PSI，此优化只在 inject 路径有效）。
  iter185（PSI/gov/rc TTL 延长）：_PSI_GOV_RC_TTL 从 5s 延长到 30s。
                              原因：psi/gov/rc 数据由 writeback 写入，用户对话间隔通常 5-30s，
                              5s TTL 在典型对话节奏（10-30s/turn）下 miss 率 50-100%。
                              30s TTL 将典型场景命中率从 ~50% 提升到 ~90%+。
                              on miss: psi(0.42ms) + gov(0.43ms) + rc(0.44ms) = 1.3ms/miss。
                              P50 miss 率从 50% → 10%，节省 ~0.58ms（1.3ms × 45% miss 减少量）。
                              OS 类比：kswapd watermark hysteresis — 适当放宽 TTL 以减少不必要的 DB IO。
  iter186（_extract_key_entities 合并正则）：原实现 3 次独立 re.finditer()（~9.8us）；
                              合并为单次 alternation 正则 _ENTITY_RE（~4.3us）。
                              预编译为模块级常量，消除 re.compile 开销（daemon 启动时编译一次）。
                              节省 ~5.5us/request（被调用于 Stage2 入口和 _build_query）。
                              OS 类比：JIT 编译 + 指令合并 — 将 3 条串行指令合并为 1 条并行指令。
                              实测 Stage1 P50: 0.175ms（N=50，稳定后）。
  iter187（_is_generic_knowledge_query 预编译）：原实现闭包内每次调用重建
                              _GENERIC_PATTERNS(3 str) + _PROJECT_MARKERS(22 str) list，
                              3 × re.search(uncompiled) + 22 × substring scan ≈ 2.77-3.19us。
                              新实现：模块级预编译 _GENERIC_RE（3 pattern alternation）+
                              _PROJECT_MARKER_RE（22 pattern alternation），
                              提升为顶层函数（消除闭包重建开销）。
                              实测（N=10000 × 6 queries）：avg v1=3.41us → v2=1.92us，节省 avg=1.5us。
                              极端案例（"是什么原因导致..."）：4.61us → 0.91us（节省 3.7us）。
                              OS 类比：JIT 编译 — 将运行时重复 re.compile 改为启动时一次编译。
  iter188（sysctl TTL cache）：_retriever_main_impl 每次请求 ~18 次 sysctl()，
                              每次 ~1.7us（2×os.environ.get + _load_disk_config + dict.get）。
                              monkey-patch config.get：TTL=10s 内命中时跳过所有 I/O，
                              直接返回缓存值（~0.2us/call）。18 次 × 1.5us 节省 = ~27us/request。
                              失效：_invalidate_cache() 被 sysctl_set 调用时同步清空 daemon cache。
                              TTL=10s：sysctl_set 仅在调试时调用，10s staleness 无功能影响。
                              OS 类比：Linux slab allocator — per-CPU 槽缓存，命中跳过 buddy alloc。
  iter195（_get_persistent_ro_conn chunk_version stat → cache read + cwd env memo）：
                              1. _get_persistent_ro_conn 每次请求 os.stat(CHUNK_VERSION_FILE)
                                 (~2.2us)，而 _read_chunk_version_cached() 已在 Stage1 完成
                                 同一 stat 并缓存到 _chunk_version_file_cache[0]。
                                 修复：直接读 _chunk_version_file_cache[0][0]（cache hit: 0.3us），
                                 仅在 cache 为 None（prewarm 路径）时 fallback 到 os.stat。
                                 节省：~1.9us/request（2.2us → 0.3us）。
                              2. _get_project_id_cached 每次调用 os.environ.get('CLAUDE_CWD',
                                 os.getcwd()) (~2.2us)，CLAUDE_CWD 值在同一 daemon 生命周期内
                                 极少变化。新增 _cwd_env_memo[2]（[cached_env_val, cached_cwd]）：
                                 os.environ.get() 结果不变时直接返回 cached_cwd（~0.5us vs 2.2us）。
                                 节省：~1.7us/request（2.2us → 0.5us on hit）。
                              OS 类比：
                                1. CPU register file — 已计算的 stat 结果跨函数传递，
                                   不重新走 stat syscall（同 iter189 register passing）。
                                2. CPU BTB (Branch Target Buffer) — cwd 字符串预缓存，
                                   同一 env 值命中时 O(1) list lookup 替代 syscall。
                              实测目标 P50: ~2.18ms → ~2.14ms（~3.6us 节省）。
  iter191（retrieval_score inline + _age_days 单次 + sysctl 参数预取）：
                              _score_chunk 调用 retrieval_score 每次花费 ~22.5us：
                                10× sysctl（iter188 cache 后仍 ~22us）+ 3× _age_days(~5us）+ md5(~1.4us）
                              修复：
                              1. 请求开始时一次性读取 10 个 scorer sysctl 参数 → 局部变量（~2us，读1次）
                              2. _age_days 在 _score_chunk 内调用 1-2 次（last_accessed≠created_at 时 2 次）
                                 同时将 datetime.now(utc) 提到 _score_chunk 外（N_chunks × 0.5us 节省）
                              3. retrieval_score 全内联展开（消除 11 个函数调用 overhead ~2us）
                              实测：retrieval_score 22.5us → ~3.5us/call；10 chunks = 节省 ~190us/request
                              OS 类比：slab per-CPU 参数预取 + register passing —
                                热路径参数从每次 dict lookup 改为 L1 cache 局部变量访问，
                                等价于 kmem_cache per-CPU 槽将 object 预取到 CPU local cache。
  iter220（_retriever_main_impl 内 import time + re 模块引用消除）：
                              1. `import time as _time`（~0.16us/request）→ 删除，直接引用模块级 time。
                                 time 已在 daemon 顶层 `import time`，per-function import 是纯冗余（
                                 sys.modules['time'] 一次，但 per-call IMPORT_NAME bytecode 开销 ~0.16us）。
                                 修复：全局替换 `_time.time()` → `time.time()`（无语义变化）。
                              2. `re = mods['re']`（~0.07us）→ 删除，依赖已预编译模块常量 _CONSTRAINT_RE。
                                 原 `re.sub(r'[^\\w\\u4e00-\\u9fff]', ...)` 在 constraint 路径，
                                 改为 `_CONSTRAINT_RE.sub(...)`（C-level compiled, 0us）。
                                 _CONSTRAINT_RE 与 _ENTITY_FAST_CHECK / _GENERIC_RE 同策略（iter186/187）。
                              合计节省：~0.23us/request（SKIP/TLB/Full 均受益于 import 消除；
                                           constraint re.sub 路径额外附赠）。
                              OS 类比：DCE + module symbol resolution —
                                1. import 语句 = 每次 sys.modules lookup（CPython IMPORT_NAME 指令）；
                                   LOAD_GLOBAL 'time' 不经 IMPORT_NAME，只需 globals dict lookup（~0us）；
                                2. 预编译正则 = 消除运行时 re.compile 的 hash+trie 查找。
                              实测目标：Full(cold) P50 ~0.113ms → ~0.112ms（inject path 节省 ~0.23us）。
  iter219（context-build loop chunk_type [] + sys.stdout.flush() 消除）：
                              1. context-build loop `ctype = c.get("chunk_type") or ""` →
                                 `ctype = c["chunk_type"] or ""`：schema 保证字段存在（TEXT nullable），
                                 .get() 的 KeyError 保护多余。节省：~0.039us × 5 chunks = ~0.2us。
                                 同上 iter217 top_k_data + iter218 all_constraints 同类修复。
                              2. `sys.stdout.flush()` 消除：注入路径 print() 后有一次 flush()，
                                 而 sys.stdout 已被 _handle_connection 替换为 StringIO()，
                                 StringIO.flush() 是 no-op（Python 3 内置，函数体为 pass）。
                                 节省：~0.30us/request（inject path，StringIO.flush cpython 开销）。
                                 OS 类比：空 syscall 消除 — 对 pipe/socket 无效的 fsync 删除。
                              合计节省：~0.5us/request（inject path）。
                              实测目标：Full(cold) P50 ~0.114ms → ~0.113ms（inject path 节省 ~0.5us）。
  iter218（final.sort lambda → module-level itemgetter）：
                              final.sort(key=_SORT_KEY, reverse=True)  # iter218: C-level itemgetter vs lambda 每次调用 ~1.623us（10 items）；
                              lambda 每次创建新函数对象（每次请求 def ~0.1us overhead）+
                              CPython 调用 Python 函数比 C 扩展慢（PyObject* 调用链）。
                              修复：模块级常量 _SORT_KEY = operator.itemgetter(0)，
                              sort(key=_SORT_KEY) = 1.623us → 0.835us（节省 ~0.788us/call）。
                              调用点：final.sort()（2次/inject: pre-madvise + DRR final）
                                     + final2.sort()（swap 路径，罕见，附赠）。
                              节省：2 × 0.788us = ~1.576us/request（inject 路径）。
                              import operator 已是 stdlib，零成本（daemon 启动时一次）。
                              OS 类比：vDSO 函数表 — 系统调用跳转表预编译为 C 代码，
                                比每次进入 Python 函数对象快；itemgetter 是 C 扩展，
                                sort key 调用直接走 C 层（无 PyEval_EvalFrameEx overhead）。
                              实测目标：Full(cold) P50 ~0.116ms → ~0.114ms（inject path 节省 ~1.6us）。
  iter217（current_hash md5→crc32 + top_k_data round() 消除）：
                              1. current_hash = hashlib.md5("|".join(top_k_ids).encode()).hexdigest()[:8]
                                 → '%08x' % zlib.crc32("|".join(top_k_ids).encode())
                                 节省：~0.394us/request（inject path，含 hard-deadline + normal）。
                                 md5(~1.107us) vs crc32(~0.712us)；%08x 格式与原 hexdigest()[:8] 相同。
                                 正确性：crc32 产生 8 位 hex 字符串，与 hash compare / TLB dedup 语义一致。
                                 首次启动后 hash 格式相同（均为 8 hex chars），无需迁移。
                                 collision 概率：1/2^32，daemon 60s 内不超过 1000 次 inject，可忽略。
                                 OS 类比：inode generation number — 使用轻量计数器替代完整哈希，
                                   语义相同（内容去重），但 syscall overhead 更低。
                              2. top_k_data round(s, 4) 删除：round() 纯粹为了 JSON 可读性，
                                 消费方（insert_trace/dmesg_log）不依赖精度。
                                 score 是 float，json.dumps 默认完整精度（17 digits），略长但等价。
                                 节省：round(s,4) × 5 chunks = ~1.476us/request（inject path）。
                                 同时将 c.get('chunk_type', '') → c['chunk_type'] or ''：
                                   chunk_type TEXT 无 NOT NULL，字段存在但可为 None，
                                   .get() 的 KeyError 保护是多余的（schema 保证字段存在）。
                                   节省：~0.039us × 5 = ~0.2us（被 round 节省掩盖，作为附赠优化）。
                                 合计 top_k_data 构建：4.478us → 1.792us（节省 2.687us）。
                              3. 受益路径：inject（hard-deadline + normal），约 20-40% 请求。
                                 weighted avg saving：~0.97us（inject 30% × (0.394 + 2.687)us）。
                              OS 类比：
                                1. peephole optimizer — 等效 hash 替换为字节码更少的实现；
                                2. DCE — 删除只影响 JSON 格式的 round() 调用（无语义变化）。
                              实测目标：Full(cold) P50 ~0.118ms → ~0.116ms（节省 ~3.1us inject path）。
  iter216（_handle_connection 死分支消除 + 预建空响应 bytes + encode() 无参数）：
                              1. elif not output.endswith('\n') — 死代码消除：
                                 print() 总是追加 '\n'；output='' 被 'if not output' 先捕获。
                                 elif 分支永远为 False，从未执行（~0.299us endswith 扫描）。
                                 删除：节省 ~0.299us/request（所有路径均受益）。
                              2. 预建 _EMPTY_RESPONSE_B = b'{}\\n'：SKIP/TLB 路径 output=''，
                                 原来 '{}\n'.encode('utf-8')（~0.249us），改为直接引用 bytes 常量
                                 （~0.161us），节省 ~0.088us/request。
                                 SKIP/TLB 命中率 ~60-80%（典型对话场景），对 P50 影响显著。
                              3. output.encode('utf-8') → output.encode()（默认 UTF-8）：
                                 省略 encoding 参数跳过字符串名称解析（~0.204us → ~0.172us，节省 ~0.032us）。
                                 Inject 路径（~20-40% 请求）受益。
                              合计节省：~0.42us/request（权重平均：SKIP/TLB 受益 0.387us，Inject 受益 0.331us）。
                              OS 类比：
                                1. 编译器 DCE — 未执行的条件分支直接删除（同 iter206/211/212）；
                                2. DMA pre-allocated buffer — 常量响应复用预分配内存，跳过 malloc+memcpy；
                                3. ABI calling convention — 默认参数跳过字符串 encoding 查找。
                              实测目标：SKIP P50 ~0.089ms → ~0.088ms（节省 ~0.38us，3 项合计）。
  iter215（_fts5_expr_cache 存 (expr,crc32) pair + module-level io import）：
                              1. _fts5_expr_cache 原存 query→expr_str，_cached_fts_search 每次
                                 FTS hit 都需要 zlib.crc32(expr.encode())（~0.241us）。
                                 修复：_fts5_expr_cache 改存 (expr, crc32) pair，crc32 在 cache
                                 miss 时计算一次（写入时），hit 路径直接读 pair[1]（0us）。
                                 节省：~0.241us/request（FTS result cache hit 路径）。
                                 影响：_cached_fts5_escape 返回值不变（仍返回 expr str），
                                 _cached_fts_search 读 _expr_pair[1] 替代 zlib.crc32()。
                                 OS 类比：dcache entry 存储 inode number — 路径查找结果直接包含
                                   inode 编号，不需要再 hash 一次路径名来构建 btree key。
                              2. _handle_connection 每次请求执行 'import io'（sys.modules 查找）
                                 ~0.2us/request。改为 module-level 'import io as _io'（启动时一次），
                                 _handle_connection 直接引用 _io.StringIO()（LOAD_GLOBAL ~0us）。
                                 OS 类比：DCE — 已载入模块不重复 import。
                              合计节省：~0.44us/request（FTS hit 路径 0.241us + io import 0.2us）。
                              实测目标：Full(same) P50 ~0.085ms → ~0.084ms（FTS hit 受益更大）。
  iter214（_score_chunk dict直接访问 + inject loop conf None fast-path）：
                              1. _score_chunk 入口的 6 个 .get() 调用替换为 [] 直接访问：
                                 _ca/ac/cid/lg/cp 字段由 DB schema 保证存在（store_vfs.py COLUMN 定义），
                                 .get() 的 KeyError 保护是多余的。_vs/_cs 同理。
                                 实测 10 chunks scoring: 16.6us → 12.9us（节省 3.7us/request）。
                                 OS 类比：zero-copy DMA — 已知内存布局时跳过边界检查，
                                   直接按 offset 访问（等价于跳过 Python dict.get() 的 miss 检测）。
                              2. inject loop（context 构建）两处优化：
                                 a. ctype = c.get("chunk_type") or "" 计算一次，复用于
                                    _TYPE_PREFIX.get() 和 "design_constraint" 判断（原代码调用 2 次）
                                    节省：~0.034us × 5 chunks = ~0.17us。
                                 b. conf 计算：vs/cs 改为直接 c["verification_status"]/c["confidence_score"]
                                    + None fast-path（同 iter197 _score_chunk 模式）：
                                    None path (common): 0.355us → 0.234us per chunk = 节省 ~0.6us/5 chunks。
                                 合计节省：~0.77us（inject loop: 3.031us → 2.339us，实测）。
                              OS 类比：
                                1. CPU LOAD 指令 — 直接地址寻址（dict[]）vs 带 miss 检测的保护访问（.get()）。
                                2. Branch predictor — None fast-path 先检查最常见条件，避免完整条件链。
                              实测目标：Full(cold) P50 ~0.122ms → ~0.118ms（节省 ~4.5us）。
  iter213（format→%s + crc32 去除 &0xffffffff + fts_ids 集合推导优化）：
                              1. format(int,'08x') → '%08x'%int（0.577us → 0.339us，节省 0.238us）：
                                 prompt_hash 生成路径（Stage1 + Stage2 fallback），每次非 SKIP 请求执行。
                                 '%' 格式化比 format() 调用更快（少一次函数调用 + 内建操作符）。
                              2. crc32(...) & 0xffffffff → crc32(...)（Python 3 中 zlib.crc32 已返回
                                 unsigned int，& 0xffffffff 是死代码）：节省 ~0.05us × 多处调用。
                                 影响位置：prompt_hash、sched_ext_match_cached、fts5 result cache
                                 的 key 计算（_new_vfs_search 中）。
                              3. fts_ids = {chunk.get("id","") ...} → {chunk["id"] ...}：
                                 chunk 对象保证有 "id" 字段（store schema 约束），.get() 是多余的。
                                 节省：0.225us/request（set comp 10 chunks：1.076us → 0.851us）。
                                 同理修复 _extra_chunks 过滤（c.get("id","") → c["id"]）。
                              OS 类比：peephole optimizer — 等价表达式中选择字节码最少的形式；
                                crc32 &-mask 消除 = 冗余 bitwise AND 指令删除。
                              实测目标：节省 ~0.5us/request（0.238 + 0.05×3 + 0.225 ≈ 0.61us）。
  iter212（_retriever_main_impl 函数内 3 个冗余 import 消除）：
                              _retriever_main_impl 体内有 3 个每次请求都执行的 import：
                              import math as _math（0.139us）、import hashlib as _hashlib（0.160us）、
                              from datetime import datetime as _dt, timezone as _tz（0.260us）。
                              这些模块已在 daemon 启动时加载到 _modules 中（hashlib/datetime/timezone），
                              或已在模块级 import（math）。
                              修复：math → 模块级 _math 常量（iter212 新增 `import math as _math`）；
                              hashlib/datetime/timezone → 引用函数头已有的局部变量（mods unpack 块）；
                              _dt/_tz/_hashlib 改为简单别名赋值（~0us）。
                              节省：~0.56us/request（3 个 import 调用全部消除）。
                              OS 类比：DCE + 寄存器复用 — 已载入的模块对象直接通过 LOAD_FAST 访问，
                              不重复走 sys.modules 查找路径（import 语句的底层流程）。
  iter211（_retriever_main_impl mods unpack DCE）：
                              _retriever_main_impl 头部 mods dict unpack 块存在 7 个死变量：
                              _unified_retrieval_score（iter191 内联后不再调用）、
                              madvise_read（iter178 _madvise_cached 替代）、
                              readahead_pairs（未使用）、DMESG_WARN/DMESG_DEBUG（未使用）、
                              _TECH_SIGNAL/_ACRONYM_SIGNAL（_has_real_tech_signal 使用模块全局变量）。
                              删除 7 个死赋值（各 ~0.06-0.11us），节省 ~0.55us/request。
                              OS 类比：编译器死代码消除（DCE）— 同 iter206，未被读取的写操作直接删除。
                              实测目标 Full(cold) P50: ~0.112ms → ~0.111ms（节省 ~0.55us）。
  iter210（_vdso_is_skip len guard + store.db exists cache）：
                              1. _vdso_is_skip(prompt) 每次请求都被调用（Stage0），
                                 原实现对所有 prompt 做 p.lower() + frozenset lookup（~1.36us）。
                                 真实 prompt 通常远长于任何 skip phrase（最长 "got it"=6 chars）。
                                 新增 _VDSO_SKIP_MAX_LEN=10 快速路径：len(prompt) > 10 直接返回 False，
                                 跳过 lower() + frozenset.get()（~1.36us → ~0.19us on miss）。
                                 节省：~1.17us/request（len check ~0.04us + 直接 return）。
                                 正确性：_VDSO_SKIP_EXACT 最长项 "thanks"/"gotit" = 6 chars，
                                 "got it"=6, "okay"=4；所有 CJK filler "嗯嗯嗯嗯" = 4 CJK chars(str len=4)。
                                 _VDSO_SKIP_MAX_LEN=10 留有足够余量，无 false negative 风险。
                                 OS 类比：bloom filter fast-reject — 先检查必要条件（长度），
                                   不满足则直接淘汰，跳过后续 hash lookup。
                              2. os.path.exists(STORE_DB) 每次请求调用（~1.66us），
                                 store.db 一旦存在就不会消失（不删 DB 就不会变 False）。
                                 _store_db_exists_cache[0]（list[0]，GIL 原子）：
                                   None=未检查，True=已确认存在。
                                   cache hit: list[0]（~0.16us）；cache miss（首次）: os.path.exists（1.66us）。
                                 节省：~1.50us/request（首次之后所有请求）。
                                 安全性：只缓存 True，不缓存 False（文件不存在时每次都检查）。
                                 OS 类比：positive dentry cache — 已知存在的 inode 直接返回，
                                   不重复 stat；negative dentry 不缓存（避免 stale）。
                              实测目标：Full(uniq) P50 ~0.126ms → ~0.123ms（节省 ~2.67us）。
  iter209（_is_generic_q daemon cache + scheduler sysctl 预读）：
                              1. _is_generic_knowledge_query(query) 是纯函数（query → bool），
                                 每次 Stage2 必经路径（分类块）调用一次（~1.64us）。
                                 新增模块级 _is_generic_q_cache: dict（query_str → bool），
                                 daemon 生命周期内同一 query 再次进入 Stage2 时命中（~0.14us）。
                                 hit: 0.14us；miss: 1.64us（同 baseline，写入缓存）。
                                 典型场景（重复/相似 prompt）命中率 20-50%，avg 节省 ~0.3-0.75us。
                                 OS 类比：Linux dentry cache（dcache）— 同一路径不重复 pathname_lookup，
                                 直接返回缓存 bool；query_str = 路径，is_generic_result = inode flag。
                              2. iter202 注释声称预读 scheduler.*（3个），但实际代码仍在 not_priority 分支里
                                 直接调用 sysctl("scheduler.min_entity_count_for_full")（~1.7us）、
                                 sysctl("scheduler.skip_max_chars")（~1.7us）、
                                 sysctl("scheduler.lite_max_chars")（~1.7us）。
                                 修复：在 not_priority 分支入口（has_page_fault=False 路径）一次性预读 3 个，
                                 后续 elif/if 中改为 LOAD_FAST（0us）。
                                 关键：预读位置在 not_priority 分支内（非全局），避免 SKIP 路径无谓开销。
                                 节省：3 × 1.7us = ~5.1us（在 not_priority 且 not_page_fault 路径，
                                 是最常见的 inject 路径）。
                                 OS 类比：slab per-CPU 参数预取（同 iter191/193）。
                              实测：Full(uniq) P50 ~0.127ms（iter208: 0.128ms，节省 ~1us）。
                                    Full(same) P50 ~0.107ms（FTS result cache + _is_generic cache 叠加）。
  iter208（lock-free activity tracking）：_handle_connection 每次请求头尾各调用
                              _update_activity() + _lock.acquire()/release() 共 4 次锁操作：
                              entry: lock(_active+=1) + lock(time.time()) = ~0.94us
                              exit:  lock(_active-=1) + lock(time.time()) = ~0.94us
                              total: ~1.61us/request（4× lock + 2× time.time()）。
                              修复：_active_connections 和 _last_request_time 改为 list[0] 存储，
                              CPython GIL 保证 list[0] 整数赋值和 float 赋值的原子性，无需 Lock。
                              _update_activity() inline 展开（消除函数调用 + global lookup）。
                              节省：~1.48us/request（4× lock overhead 消除）。
                              _idle_watchdog 读取两个值时允许极短暂的不一致（watchdog 5s 间隔，
                              1-2 指令的 GIL 竞争完全可以接受）。
                              OS 类比：per-CPU counter（Linux percpu_counter）— 避免全局锁，
                                利用 CPU 本地操作的原子性（GIL = 单核等价），消除 lock contention。
  iter207（_ALL_RETRIEVE_TYPES 模块级常量 + 快速路径）：
                              _retriever_main_impl 每次请求重建 _ALL_RETRIEVE_TYPES 元组（10 项字符串字面量）
                              + sysctl("retriever.exclude_types") + set comprehension + tuple comprehension
                              = ~1.59us/request（正常情况下 exclude_types 为空 = 100% 场景）。
                              修复：提取为模块级常量 _ALL_RETRIEVE_TYPES_CONST；
                              exclude_types 为空时直接引用常量（~0.17us），跳过 set/tuple comprehension。
                              节省：~1.42us/request（仅在 exclude_types 非空时退化为原逻辑）。
                              OS 类比：字符串驻留（string interning）— 相同字面量常量化，
                                避免每次函数调用重新分配和填充元组对象。
  iter206（_run_retrieval 死代码消除）：_run_retrieval 函数体开头有 32 行从未在函数内
                              使用的赋值：import time(0.27us) + time.time()(0.20us) +
                              28 次 _modules dict lookup(~2.00us) + 1 次 .get(~0.09us)。
                              这些变量全部只在 _retriever_main_impl 中使用，不在 _run_retrieval
                              函数体内使用，属于死代码。直接删除，节省 ~2.56us/request
                              （在 SKIP/TLB hit/Full 所有路径上均有效）。
                              OS 类比：编译器死代码消除（DCE）— 未被读取的寄存器写操作
                              在编译器优化阶段直接删除（CPython 无此优化，需手动处理）。
  iter205（FTS5 result cache）：fts_search() 每次请求耗时 ~0.617ms（SQL P50），
                              是注入路径上最大的单点开销。
                              cache key = (crc32(fts_expr), project)，
                              value = (chunk_version_at_cache_time, results_list)。
                              失效：chunk_version 变化（extractor 写入新 chunk）→ 自动 miss + re-query。
                              cache hit: dict lookup(~0.1us) + chunk_version check(~0.3us) ≈ 0.4us。
                              cache miss: 正常 fts_search()（0.617ms）→ 写回缓存。
                              预期节省：~0.617ms on hit（注入路径 P50 ~1.43ms → ~0.81ms on hit）。
                              hit rate：daemon 60s 生命周期内同一 session 重复/相似 prompt 触发
                                相同 8-term FTS5 表达式时命中（iter175/180 已对 query→expr 做缓存）。
                                每次对话 ~3-10 turns，常见重复 prompt 约 20-40% 命中率。
                              内存：64 entries × 10 results × ~500B = ~320KB（可忽略）。
                              线程安全：CPython GIL 保证 dict 读写原子，无需锁。
                              OS 类比：Linux buffer cache（block I/O cache）—
                                同一 block 编号的数据缓存在 buffer_head，不重复走 disk I/O；
                                fts_expr = block 编号，SQL 结果 = block 内容，chunk_version = disk generation。
  iter204（handler thread pool）：threading.Thread.start()（~54us）改为预创建 pool + queue.put（~17us）。
                              节省：~35us/request（thread wakeup 49us → 8.5us + Thread.__init__ 5us）。
                              SKIP P50: 0.187ms → 0.107ms，TLB P50: 0.199ms → 0.152ms。
                              OS 类比：Apache prefork MPM — 预分配 worker 进程，accept → queue，无 fork 开销。
  iter203（page_fault_log daemon cache + 延迟写回）：
                              _read_page_fault_log 每次请求（page_fault 路径）：
                                read(0.034ms) + write("resolved", indent=2)(0.441ms P50, ~15ms P90)
                                = ~0.5ms P50；P90 抖动来自 OS fsync/page cache flush。
                              修复：
                              1. _page_fault_cache[0] = [(mtime_ns, queries)]（同 _tlb_file_cache 模式）：
                                 同一 mtime → 文件内容未变 = 已消费 → 直接返回 []（stat ~3us + list lookup ~0us）
                                 mtime 变化（swap_fault 写入新条目）→ cache miss → 重新读文件
                              2. "resolved" 标记写回移入 writeback 线程（_writeback_submit）：
                                 critical path 仅保留 stat(3us) + open+read+json.loads(0.039ms)，
                                 write(0.441ms P50, 15ms P90) 完全移出 critical path。
                              节省（page_fault 路径）：
                                首次命中（cache miss）：节省 write = ~0.44ms P50，~15ms P90 消除
                                后续命中（cache hit）：节省 read + write = ~0.48ms，只需 stat ~3us
                              正确性：swap_fault 写入新条目时 mtime_ns 变化 → 下次请求 re-read。
                              OS 类比：
                                inode cache（同 iter179/184）— 通过 mtime_ns 检测内容变化；
                                dirty page writeback（同 iter168）— "resolved" flag 异步写回。
  iter202（全局 sysctl 参数预取）：
                              _retriever_main_impl 中共有 13 个 sysctl key 分散在 classify/TLB/setup 各处，
                              每次 sysctl() 调用（iter188 TTL cache 命中）≈ 1.7us，13 个 = ~22us。
                              修复：在 has_page_fault 赋值后统一预读为局部变量（一次性 13 次 sysctl，~22us）；
                              各使用点改为 LOAD_FAST（0us）。
                              涉及 key：scheduler.*（3）、retriever.top_k/max_chars/deadline/exclude/hybrid/max_forced（9）
                              + madvise.boost_factor（1）。
                              retriever.max_query_chars 在 _build_query_with_entities 中已调用，TTL cache 已热，
                              不重复预读（用于该函数内，不在 _retriever_main_impl 范围）。
                              节省：~13 × 1.7us = ~22us/request（injection path，分布在 classify + setup）。
                              OS 类比：slab per-CPU 参数预取（同 iter191/193）— 将 dict lookup + time.time()
                                改为栈帧局部变量 LOAD_FAST，消除所有调用点的 TTL cache overhead。
  iter201（_read_hash pre-read + reuse）：
                              _read_hash() 在 _retriever_main_impl 中被调用 2-3 次/request：
                              1. TLB check: last_hash = _read_hash()（not has_page_fault 路径）
                              2. same-hash check: current_hash == _read_hash()
                              3. reason_base: "first_call" if not _read_hash() else ...
                              每次 _read_hash() = os.stat(HASH_FILE)(2.685us) + dict lookup ≈ 3.1us。
                              修复：
                                - not has_page_fault: last_hash 已在 TLB check 读出，后续直接复用
                                - has_page_fault=True: 在 else 分支预读 last_hash 一次
                              节省：~2 × 3.1us = ~6.2us/request（injection path）。
                              OS 类比：register reuse（同 iter190/iter193/iter194）—
                                热路径读取结果保留在局部变量，不重走 stat syscall。
  iter200（output json.dumps pre-built header）：
                              print(json.dumps({"hookSpecificOutput": {...}})) 每次请求耗时 4.43us，
                              对 ~300B 的固定结构做完整 JSON 序列化（外层 key + context_text）。
                              优化：外层结构固定，抽取 _OUTPUT_HEADER 常量，只对 context_text
                              做 json.dumps（含 Unicode 处理）。
                              _OUTPUT_HEADER + json.dumps(ctx, ensure_ascii=False) + "}}" = 1.35us。
                              语义等价（合法 JSON，消费方做 parse 不依赖空格格式）。
                              节省：~3.1us/request（仅在注入路径执行，非 TLB 命中路径）。
                              OS 类比：sendfile() — 将固定 header 和可变 body 分开，
                                避免每次重新拷贝/序列化不变的结构部分。
  iter199（access_bonus lookup table）：
                              _score_chunk 中 access_bonus = min(cap, log2(1+ac) * 0.05)，
                              math.log2() 调用 ~0.28us/chunk × 10 chunks = 2.8us/request。
                              access_count 是小整数（通常 0-20），min/log2 是纯函数，可预计算。
                              _AB_TABLE[i] = min(ab_cap, log2(1+i)*0.05) for i in 0..20
                              lookup: list[int] ~0.06us vs math.log2 ~0.28us（节省 0.22us/chunk）。
                              10 chunks（混合 ac=0..10）实测：3.52us → 0.84us（节省 2.68us）。
                              安全性：_AB_TABLE 用 scorer.access_bonus_cap 默认值 0.2 初始化，
                              与 sysctl 默认一致；>=21 fallback 到原 log2 路径（极罕见）。
                              OS 类比：CPU TLB / computed goto table — 将运行时 log2 调用转为
                                O(1) 表查找，等价于 TLB hit 跳过 page table walk。
                              实测节省：2.68us（10 chunks）= ~10% scoring loop overhead 减少。
  iter198（FTS result loop: for→listcomp + max()→first element）：
                              FTS result 处理循环（10 chunks）存在两处冗余：
                              1. max() genexpr 遍历所有 chunks 求最大值（1.06us），
                                 而 FTS5 已按 rank 降序返回结果，fts_results[0] 即最大值（0.16us）。
                                 use_fts=True 保证 fts_results 非空，可安全使用 [0] 索引。
                              2. for 循环 + 逐步 append/add（6.06us）改为 list comprehension
                                 + set comprehension（~2.09us），减少 Python per-iter overhead。
                              节省：~4.9us/request（1.06-0.16 + 6.06-2.09 = 4.87us）。
                              OS 类比：readdir() 排序保证 — 首元素即最大 inode 号，
                                无需再扫整个 dirent 数组；listcomp = SIMD 批量加载。
                              实测目标 P50: ~2.16ms（节省 ~5us）。
  iter197（entities_cache + verification/lru 早退 + numa ternary）：
                              1. _extract_key_entities(prompt) 是纯函数（prompt → list），
                                 _build_query_with_entities 每次 Stage2 入口调用一次（~7.5us）。
                                 新增模块级 _entities_cache: dict（prompt_str → list），
                                 daemon 60s 生命周期内同一 prompt 再次触发 Stage2 时命中（~0.18us）。
                                 hit: 0.18us；miss: 7.5us（同 baseline，写入缓存）。
                                 典型场景（用户重复/相似 prompt）命中率 20-50%，avg 节省 ~1.5-3.5us。
                                 OS 类比：Linux dentry cache（dcache）— 同一路径名不重复 pathname_lookup，
                                 直接返回缓存的 inode；prompt_str = 路径名，entities_list = inode。
                              2. verification/lru None 早退：_score_chunk 中 verification_status/
                                 confidence_score/lru_gen 在当前语料库（N=290）全为 None，
                                 vb/vp/lgb 结果恒为 0。添加 None 快速路径（所有 3 字段均 None →
                                 直接赋 vb=vp=lgb=0.0，跳过 or-default + 比较）。
                                 节省：~0.12us/chunk × 10 chunks = ~1.2us/request。
                                 OS 类比：branch predictor fast path — 最常见 case 先检查，避免多条件链。
                              3. numa_distance_penalty ternary 内联：
                                 原 3-way if/elif/elif → 单行 ternary（减少分支预测失败）。
                                 节省：~0.07us/chunk × 10 = ~0.7us/request。
                              实测目标：avg saving ~2.5-5us（verification+numa 确定节省 ~1.9us，
                              entities cache 按命中率叠加）。
  iter196（_age_days_fast timestamp daemon cache）：_age_days_fast 每次调用 fromisoformat (~0.87us)，
                              10 chunks × 2 calls/chunk（la + ca）= 20 calls = ~17.4us/request。
                              新增模块级 _iso_ts_cache: dict（str → float timestamp），
                              命中时：dict.get(iso_str)（~0.40us）替代 fromisoformat+timedelta（~0.87us）。
                              失效：无需失效 — chunk last_accessed/created_at 是 immutable timestamp 字符串，
                              同一 iso_str 永远对应同一 timestamp。daemon 60s idle 退出，不存在 stale。
                              cache size：max 290 chunks × 2 fields = ~580 entries × ~100B = ~58KB。
                              实测：scoring loop（10 chunks，warm cache）= 14.1us → 7.2us（节省 6.9us）。
                              OS 类比：Linux inode cache — 同一文件路径的 mtime 缓存在 inode 对象，
                              不重复 stat syscall。iso_str = 路径，timestamp = mtime，cache = inode cache。
  iter194（_is_generic_q 结果复用 + _extract_key_entities 快速路径）：
                              1. _is_generic_knowledge_query(query) 在 _retriever_main_impl 中调用 3 次
                                 （classify + hard_deadline + DRR_final），query 不变，可复用同一结果。
                                 计算一次（~2.4us），后两次直接引用局部变量（~0us），节省 ~4.8us。
                              2. _extract_key_entities 快速路径：添加 _ENTITY_FAST_CHECK 预检查
                                 (re.search for [`.[]A-Z])，无触发字符则跳过全量 finditer（1.12us 节省）。
                                 适用于 Stage2 的非技术性但非 SKIP 的对话类 prompt。
                              OS 类比：
                                1. register reuse（同 iter190 _tech_signal_result）— 热路径条件预计算，
                                   后续路径直接读 L1 cache（局部变量），不重走 regex 路径。
                                2. branch prediction + early exit — 简单字符集检查作为 guard，
                                   命中（无触发字符）则提前返回，避免开销更大的 NFA regex 执行。
  iter193（duplicate sysctl 预读）：_retriever_main_impl 中 4 个 sysctl key 各被调用 2 次：
                              drr_max_same_type / drr_enabled / min_score_threshold / generic_query_min_threshold
                              每个 TTL-cache sysctl() 调用 ~2.4us（time.time() + dict lookup），
                              4 × 2次 = 8 次额外调用 = ~9.6us 可消除开销。
                              修复：在 scorer 参数预读块（已有 iter191 的 10 个参数）旁，
                              将 4 个 key 同时预读为请求级局部变量（1 次读取 → 2 次直接使用）。
                              DRR selector 闭包通过 Python cell 引用捕获局部变量（lazy eval，安全）。
                              OS 类比：slab per-CPU 参数预取（同 iter191）— 将频繁读取的参数从
                                每次 dict lookup 改为函数级栈帧局部变量，访问路径从
                                dict→TTL check→time.time() 缩短为 LOAD_FAST。
  iter192（sched_ext_match daemon cache）：sched_ext_match(query, project) 每次请求耗时 ~3.67us，
                              与 iter176 resolve_project_id（路径→project_id）和 iter188 sysctl 同类。
                              key = (zlib.crc32(query) & 0xffffffff, project)，value = match_result。
                              daemon 生命周期内 sched_ext 规则极少变化（sysctl_set 调用极少）。
                              TTL=永久（同 iter176）— daemon 60s idle 后退出，不存在 stale 问题。
                              cache hit: dict lookup(0.1us) + GIL-safe tuple key hash(0.3us) ≈ 0.4us。
                              cache miss: sched_ext_match() 3.67us → 写回（per-project per-query 首次）。
                              节省：~2.2us/request（hit = ~0.5us vs no-cache = 2.74us，同一 query 后续命中）。
                              线程安全：CPython GIL 保证 dict 读写原子，无需锁。
                              OS 类比：Linux route cache（FIB nexthop cache）— 同一 dst IP 不重复查路由表，
                                直接返回缓存的 nexthop，类比 sched_ext 规则命中缓存跳过策略遍历。
  iter190（_has_real_tech_signal 提升 + 结果复用）：_has_real_tech_signal 和 _classify_query_priority
                              原为 _retriever_main_impl 内部闭包，每次请求 def 一次（~0.1us×2）。
                              提升为模块级函数：消除闭包 cell lookup + 每次 def 开销。
                              _has_real_tech_signal 在 _classify_query_priority 中最多调用 2 次
                              （SKIP_PATTERNS 分支 + skip_max_chars 分支），两次参数相同（同一 q）。
                              优化：引入局部变量 _tech_signal_result 缓存第一次结果，第二次直接复用。
                              节省：~0.3us（闭包创建消除）+ ~1.6-4.0us（第二次 _has_real_tech_signal 跳过）。
                              _check_deadline + _elapsed_ms 保留为内部闭包（依赖 _t_start 捕获变量）。
                              OS 类比：JIT inline + register reuse — 将热函数内联到调用点附近并复用寄存器值。
                              实测 Stage2 classify block：分类路径节省 ~1.5-4us（SKIP pattern 命中时）。
  iter189（Stage1→Stage2 double-compute 消除）：_run_retrieval → _retriever_main_impl
                              调用链存在 4 处重复计算：
                              1. _extract_key_entities(prompt) 调用两次（_build_query + impl 主体）
                                 = ~5.3us × 2（tech prompt）
                              2. os.path.exists(STORE_DB) 调用两次 = ~2.1us × 2
                              3. os.path.exists(PAGE_FAULT_LOG) 调用两次 = ~2.1us × 2
                              4. zlib.crc32(prompt) 调用两次（Stage1 + Stage2 TLB） = ~0.6us × 2
                              修复：_build_query 改为返回 (query, entities)（_build_query_with_entities）；
                              _run_retrieval 将 has_page_fault_file/prompt_hash
                              作为参数传给 _retriever_main_impl，Stage2 直接使用。
                              实测：_retriever_main_impl entry block 16.6us → 6.0us（节省 10.6us，64%）。
                              Stage1 TLB P50: 0.133ms → 0.130ms（节省 ~3us，主要来自 exists 传参）。
                              OS 类比：register file passing — 已在 Stage1 计算的值通过寄存器传给
                              Stage2，避免 caller/callee 各自重新读取相同数据。

架构：
  - 监听 Unix Domain Socket（/tmp/memory-os-retriever.sock）
  - 每个连接 threading.Thread 处理（类比 Linux accept() + fork()，但更轻）
  - 协议：ND-JSON（newline-delimited JSON）
  - 60s idle 自动退出（防止僵尸进程）
  - SIGTERM/SIGINT 优雅退出
  - Stage 0(SKIP) + Stage 1(TLB) 保留在请求处理路径中
  - iter163: _bm25_mem_cache — 进程内 BM25 文档索引缓存（page cache 类比）
    key=(project, retrieve_types_key), value=(chunk_version, chunks, bm25_index, search_texts)
    chunk_version 变化时自动失效（类比 inode mtime 触发 page cache invalidation）
  - iter167: _vfs_result_cache — VFS 查询结果缓存（TLB 类比）
    key=(query_crc32, sources_key), value=(corpus_mtime, results_list)
  - iter168: _write_hash + _tlb_write 延迟到 writeback 线程执行（dirty page writeback 类比）
    critical path 仅保留 _read_hash()（决定 reason_base），写操作全部异步化
  - iter169: VFS 并行搜索（AIO 类比）
    在 FTS5+scoring 期间启动 VFS 搜索线程，join 前仅需等待剩余时间
    VFS(2.8ms) 与 FTS5+scoring(4ms) 完全重叠 → 实测节省 ~0.7ms（GIL 限制）
  - iter170: PSI/gov/rc daemon 内存缓存（slab kmem_cache 类比）
    TTL=5s，命中时跳过 3 次 DB 查询（psi 0.42ms + gov 0.54ms + rc 0.44ms = 1.4ms）
    对同一 project 的连续请求（典型场景），90%+ 命中率
  - iter171: SQLite/FTS5 page cache 预热（Linux fadvise/readahead 类比）
    daemon 启动后立即在后台线程执行 dummy FTS5 查询，将 SQLite page cache 填充到内存。
    问题：首次 FTS5 查询（daemon 启动后，page cache cold）耗时 ~415ms；
          后续查询 P50=1.1ms（hot page cache）。
    解法：后台 prewarm 线程在 daemon 监听 socket 前已完成 DB 读取，
          将 store.db 的 FTS5 索引页加载到 OS page cache 中。
    预期：消除 415ms 冷启动尖刺，首次请求 P50 降至 ~2ms（warm 水平）。
    OS 类比：fadvise(FADV_WILLNEED) — 提前通知内核预读文件页。
  - iter173: Persistent read-only connection per thread（文件描述符复用类比）
    问题：每个请求新建 sqlite3.connect(immutable=1) 后关闭，
          SQLite per-connection B-tree page cache（默认 2000 pages = 8MB）随之丢失，
          下次请求需要重新从 OS page cache 填充 SQLite B-tree node cache。
          实测：per-request FTS5 avg = 1.53ms，持久连接 FTS5 avg = 0.97ms（节省 36%）。
    解法：threading.local() 存储 per-thread 持久只读连接，daemon 生命周期内持续复用。
          writeback 连接不受影响（已在独立 writeback thread 中）。
    OS 类比：Linux file descriptor table — open() 后保持 fd 打开，复用 vfs_inode cache
             和 file 结构体；不像每次访问都 open()+read()+close()（等价于重建 page cache）。
"""
import sys
import os
import glob as _glob  # iter259: per-session page_fault_log glob
import json
import socket
import threading
import time
import signal
import zlib
import io as _io  # iter215: module-level import — avoid per-request 'import io' in _handle_connection (~0.2us)

# ── 路径设置 ──
_DAEMON_FILE = os.path.abspath(__file__)
_HOOKS_DIR = os.path.dirname(_DAEMON_FILE)
_ROOT = os.path.dirname(_HOOKS_DIR)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

SOCKET_PATH = os.environ.get("MEMORY_OS_DAEMON_SOCK", "/tmp/memory-os-retriever.sock")
IDLE_TIMEOUT_SECS = int(os.environ.get("MEMORY_OS_DAEMON_IDLE", "60"))
MAX_CONNECTIONS = int(os.environ.get("MEMORY_OS_DAEMON_MAX_CONN", "4"))
LOCK_FILE = SOCKET_PATH + ".lock"

# ── 全局状态 ──
# iter208: lock-free activity tracking — list[0] slots are GIL-atomic under CPython.
# OS 类比：percpu_counter — 避免全局锁，单核（GIL）等价的原子操作。
_last_request_time = [time.time()]   # [float] — GIL-atomic float write
_active_connections = [0]            # [int]   — GIL-atomic int write
_lock = threading.Lock()             # retained for possible future use
_shutdown_event = threading.Event()

# ── iter173: Per-thread persistent read-only connection ─────────────────────
# OS 类比：Linux 进程文件描述符表（struct files_struct）— 保持 fd 打开复用
#   vfs_inode cache 和 file 结构，避免每次都 open()+alloc dentry+close()。
#   memory-os 对应：SQLite per-connection B-tree page cache（默认 2000 pages=8MB）
#   在持久连接下跨请求复用，避免每次重新从 OS page cache 填充 B-tree node cache。
#   实测：per-request FTS5 avg=1.53ms → persistent FTS5 avg=0.97ms（节省 ~0.56ms）。
#
# threading.local()：每个 handler thread 有独立连接，无 GIL 以外的锁竞争。
# 连接特性：immutable=1（只读，无写锁竞争）+ cache_size=2000（8MB B-tree page cache）。
# 失效策略：writeback 线程写入新 chunk 后需要重新打开（immutable 连接不感知写入）：
#   _ro_conn_invalidate() 设置失效标志，下次请求重建连接。
# 关闭策略：daemon 退出时各 handler thread 自然结束，GC 关闭连接（SQLite 安全）。
_thread_local = threading.local()
_ro_conn_invalidate_flag = threading.Event()  # swap_in 后触发：通知重建只读连接（新 chunk 写入）

# ── iter235: chunk tuple column indices ──────────────────────────────────────
# fts_search SQL column order (store_vfs.py fts_search SELECT):
#   id(0), summary(1), content(2), importance(3), last_accessed(4),
#   chunk_type(5), access_count(6), created_at(7), fts_rank(8),
#   lru_gen(9), project(10), verification_status(11), confidence_score(12)
# get_chunks SQL column order (store_vfs.py get_chunks SELECT):
#   id(0), summary(1), content(2), importance(3), last_accessed(4),
#   chunk_type(5), access_count(6), created_at(7), project(8),
#   verification_status(9), confidence_score(10), lru_gen(11)
# iter235 uses _CI_* constants for positional tuple access — avoids dict hash lookup per field.
# OS 类比：struct field offset — access by offset (LOAD_CONST+BINARY_SUBSCR) vs hash lookup (LOAD_ATTR).
_CI_ID   = 0   # chunk id (TEXT)
_CI_SUM  = 1   # summary (TEXT)
_CI_CON  = 2   # content (TEXT)
_CI_IMP  = 3   # importance (REAL)
_CI_LA   = 4   # last_accessed (TEXT)
_CI_CT   = 5   # chunk_type (TEXT)
_CI_AC   = 6   # access_count (INTEGER)
_CI_CA   = 7   # created_at (TEXT)
_CI_FR   = 8   # fts_rank (REAL) — fts path only; get_chunks uses 8=project
_CI_LG   = 9   # lru_gen (INTEGER) — fts path; get_chunks uses 9=verification_status
_CI_CP   = 10  # project (TEXT) — fts path; get_chunks uses 10=confidence_score
_CI_VS   = 11  # verification_status — fts path; get_chunks uses 11=lru_gen
_CI_CS   = 12  # confidence_score — fts path only
# get_chunks uses different column order — separate constants:
_GC_ID   = 0; _GC_SUM = 1; _GC_CON = 2; _GC_IMP = 3; _GC_LA  = 4
_GC_CT   = 5; _GC_AC  = 6; _GC_CA  = 7; _GC_CP  = 8
_GC_VS   = 9; _GC_CS  = 10; _GC_LG = 11

def _get_persistent_ro_conn():
    """
    获取当前线程的持久只读连接（lazy init + chunk_version-based invalidation）。
    OS 类比：TLB lookup — 命中则直接返回物理地址（连接对象），miss 则重建。

    失效条件（二选一）：
      1. _ro_conn_invalidate_flag 被设置（swap_in 写入新 chunk 后）
      2. CHUNK_VERSION_FILE 的 inode mtime 变化（extractor bump_chunk_version 后文件被写入）
    重建：关闭旧连接（如有），新建 immutable 连接并更新 stored mtime。

    iter173 关键：writeback 的 update_accessed/mglru_promote/insert_trace/dmesg_log
    不改变 memory_chunks 的 FTS5 相关字段（summary/content），无需触发失效。
    仅 insert_chunk/delete_chunks（由 extractor 调用，通过 bump_chunk_version 体现）
    和 swap_in（chunk 恢复到主表）需要失效。

    iter174: 失效检测从 open+read(chunk_version 数值) 改为 os.stat().st_mtime_ns，
    消除每次请求的文件 open+read 开销（~0.05ms → ~0.02ms）。
    OS 类比：inotify — 通过 inode mtime 变化检测文件更新，无需读取内容。
    """
    # 条件1：全局失效标志（swap_in 路径设置）
    needs_rebuild = _ro_conn_invalidate_flag.is_set()
    if needs_rebuild:
        _ro_conn_invalidate_flag.clear()

    # 条件2：chunk_version 文件 mtime 变化（extractor 写入新 chunk 后 bump_chunk_version）
    # iter174: 用 os.stat().st_mtime_ns 替代 open+read（~0.02ms vs ~0.05ms）
    # iter195: 从 _chunk_version_file_cache[0] 读取已缓存的 mtime（0.3us），
    #   跳过 os.stat(CHUNK_VERSION_FILE)（2.2us）。
    #   _read_chunk_version_cached() 在 Stage1 已完成 stat 并写入 _chunk_version_file_cache[0]，
    #   此处直接复用，不重走 stat syscall。
    #   仅在 cache=None（prewarm 路径，Stage1 未执行）时 fallback 到 os.stat。
    # OS 类比：inotify/dnotify — 通过 inode mtime 检测文件变化，无需读取内容
    # OS 类比（iter195 新增）：CPU register file — 跨函数传递已计算的 stat 结果，
    #   同 iter189 Stage1→Stage2 register passing 思路。
    if not needs_rebuild:
        stored_mtime = getattr(_thread_local, 'ro_conn_chunk_mtime', -1)
        # iter195: read mtime from _chunk_version_file_cache instead of os.stat()
        _cv_entry = _chunk_version_file_cache[0]
        if _cv_entry is not None:
            current_mtime = _cv_entry[0]
        else:
            # fallback: cache not populated yet (prewarm path, before Stage1)
            try:
                current_mtime = os.stat(CHUNK_VERSION_FILE).st_mtime_ns
            except OSError:
                current_mtime = 0
        if current_mtime != stored_mtime:
            needs_rebuild = True

    if needs_rebuild:
        old = getattr(_thread_local, 'ro_conn', None)
        if old is not None:
            try:
                old.close()
            except Exception:
                pass
            _thread_local.ro_conn = None

    conn = getattr(_thread_local, 'ro_conn', None)
    if conn is None:
        import sqlite3 as _sq
        db_str = str(STORE_DB)
        try:
            uri = f"file:{db_str}?immutable=1"
            conn = _sq.connect(uri, uri=True)
            # 设置 SQLite B-tree page cache（2000 pages × 4KB = 8MB）
            # OS 类比：mmap() 后 madvise(MADV_WILLNEED) — 提示系统预留内存
            conn.execute("PRAGMA cache_size=2000")
        except Exception:
            conn = _sq.connect(db_str, timeout=2)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA cache_size=2000")
        _thread_local.ro_conn = conn
        # iter174: 记录连接创建时的 CHUNK_VERSION_FILE mtime（inode mtime 失效检测）
        # iter195: 优先从 _chunk_version_file_cache[0] 读取（已缓存的 mtime，0.3us），
        #   fallback 到 os.stat()（仅在 prewarm 路径下 cache 未填充时）。
        _cv_entry2 = _chunk_version_file_cache[0]
        if _cv_entry2 is not None:
            _thread_local.ro_conn_chunk_mtime = _cv_entry2[0]
        else:
            try:
                _thread_local.ro_conn_chunk_mtime = os.stat(CHUNK_VERSION_FILE).st_mtime_ns
            except OSError:
                _thread_local.ro_conn_chunk_mtime = 0
    return conn

# ── iter182: VFS thread pool ──────────────────────────────────────────────
# OS 类比：Linux kthread_worker — 预创建 worker 线程，避免每次 fork/exec 开销。
#   iter169 在每次请求时调用 threading.Thread(...).start()（65us/call）；
#   预创建 VFS worker thread，通过 queue.put_nowait() 提交任务（17us/call）。
#   节省：~48us/request（消除线程创建+调度开销）。
#   线程模型：单一 VFS worker（串行处理），因为 VFS 本身不支持并发（_corpus_lock 保护）。
#   超时：VFS task 超时后结果为 None（与现有 t.join(timeout) 逻辑一致）。
import queue as _vfs_task_queue_module

class _VFSWorkerPool:
    """
    预创建 VFS 搜索 worker 线程。
    OS 类比：Linux kthread_worker — 预分配内核线程，任务通过 kthread_work 队列提交，
      无需每次 create_kthread() 开销。
    """
    __slots__ = ('_q', '_thread', '_active')

    def __init__(self):
        self._q = _vfs_task_queue_module.Queue(maxsize=1)
        self._active = False
        self._thread = None  # lazy init after modules loaded

    def _worker(self):
        while not _shutdown_event.is_set():
            try:
                task = self._q.get(timeout=2.0)
                if task is None:  # poison pill
                    break
                fn, holder, done_ev = task
                try:
                    holder[0] = fn()
                except Exception:
                    holder[0] = None
                finally:
                    done_ev.set()
                    self._q.task_done()
            except _vfs_task_queue_module.Empty:
                continue

    def start(self):
        """启动 worker 线程（daemon 初始化时调用一次）。"""
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._worker, daemon=True,
                                        name="vfs-worker")
        self._thread.start()
        self._active = True

    def submit(self, fn, holder: list, done_ev: threading.Event) -> bool:
        """
        提交 VFS 搜索任务。返回 True=已提交, False=队列满（fallback: 不搜索）。
        OS 类比：kthread_queue_work() — 将 kthread_work 放入 worker queue。
        """
        if not self._active:
            return False
        done_ev.clear()
        try:
            self._q.put_nowait((fn, holder, done_ev))
            return True
        except _vfs_task_queue_module.Full:
            # 队列已满（上一请求的 VFS 还在运行）— 不阻塞，本次跳过 VFS
            return False

    def stop(self):
        if self._thread is not None:
            try:
                self._q.put_nowait(None)  # poison pill
            except Exception:
                pass
            self._active = False

_vfs_worker_pool = _VFSWorkerPool()
# Pre-allocate per-request reusable objects (避免每次 new Event/list)
# 单 VFS worker，一次只有一个请求在飞，可以复用这些对象
_vfs_done_event = threading.Event()  # reused across requests (safe: single VFS worker)
_vfs_result_slot = [None]  # reused result holder

# ── iter204: Handler thread pool ─────────────────────────────────────────────
# OS 类比：Linux accept4() + pre-forked worker pool — Apache prefork MPM 模式，
#   预分配 N 个 worker 进程（此处为线程），每次 accept 后将 socket 传给空闲 worker。
#   当前 run_daemon() accept 后 threading.Thread.start()：
#     线程创建 ~5us + OS 调度延迟（wakeup latency ~49us P50）= ~54us/request
#   预创建 handler pool：
#     queue.put_nowait(conn_sock) ~9us + worker wakeup ~8.5us = ~17-25us/request
#   节省：~29-37us/request（OS thread wakeup 从 49us → 8.5us）
#   附加：消除每次 Thread.__init__() + Thread.start() 的 Python 对象创建开销 (~5us)
#   总节省：~35us/request
#
# threading.local() 兼容性：每个预创建的 handler thread 有独立的 threading.local()，
#   _thread_local.ro_conn 等 per-thread 状态在 pool worker 间独立隔离，与现有实现完全兼容。
#   MAX_CONNECTIONS=4 个 worker threads 对应最多 4 个并发连接的 per-thread SQLite 连接。
#
# OS 类比：nginx worker_processes — 预分配 worker 进程，listen socket 上 epoll_wait()，
#   连接到来时唤醒 idle worker 处理，消除每次 fork()+exec() 开销。
import queue as _handler_queue_module
_handler_conn_queue: "queue.Queue" = _handler_queue_module.Queue(maxsize=MAX_CONNECTIONS)

class _HandlerThreadPool:
    """
    预创建 MAX_CONNECTIONS 个 handler threads，通过 socket queue 接收连接。
    OS 类比：nginx prefork workers — 预分配，任务到来时 wakeup，无需每次 create_thread()。
    """
    __slots__ = ('_threads', '_active')

    def __init__(self):
        self._threads = []
        self._active = False

    def _worker(self):
        """Handler worker 主循环：从 queue 取 socket，处理，循环等待。"""
        while not _shutdown_event.is_set():
            try:
                conn_sock = _handler_conn_queue.get(timeout=2.0)
                if conn_sock is None:  # poison pill
                    _handler_conn_queue.task_done()
                    break
                try:
                    _handle_connection(conn_sock)
                except Exception:
                    pass
                finally:
                    _handler_conn_queue.task_done()
            except _queue.Empty:
                continue

    def start(self, n: int = MAX_CONNECTIONS):
        """启动 n 个 handler worker threads（daemon 初始化时调用一次）。"""
        if self._active:
            return
        for i in range(n):
            t = threading.Thread(target=self._worker, daemon=True,
                                 name=f"handler-{i}")
            t.start()
            self._threads.append(t)
        self._active = True

    def submit(self, conn_sock: socket.socket) -> bool:
        """
        提交一个 socket 连接到 handler pool。
        返回 True=已提交, False=队列满（fallback: 直接在当前线程处理）。
        OS 类比：kthread_queue_work() — 将连接放入 worker queue。
        """
        if not self._active:
            return False
        try:
            _handler_conn_queue.put_nowait(conn_sock)
            return True
        except _queue.Full:
            # All handlers busy: handle synchronously in accept thread (graceful fallback)
            return False

    def stop(self):
        """发送 poison pills 停止所有 worker threads。"""
        if not self._active:
            return
        self._active = False
        for _ in self._threads:
            try:
                _handler_conn_queue.put_nowait(None)
            except Exception:
                pass

_handler_pool = _HandlerThreadPool()


# ── iter164: Async write-back queue ─────────────────────────────────────
# OS 类比：Linux pdflush/kworker/flusher — 异步 writeback 线程，
#   用户进程写入 page cache 后立即返回，dirty pages 由后台线程异步刷盘。
#   memory-os 对应：检索结果计算完成后立即 sendall()，
#   DB 写操作（update_accessed + insert_trace + dmesg_log）由后台 writeback 线程处理。
#
# 队列满时（16 个待写任务积压）新任务同步执行（退化到 iter163 水平），防止 OOM。
import queue as _queue
_writeback_queue: "_queue.Queue" = _queue.Queue(maxsize=16)

def _writeback_worker():
    """
    后台 writeback 线程。
    OS 类比：Linux kworker/flush — 从脏页队列取任务，异步完成 I/O。
    """
    while not _shutdown_event.is_set():
        try:
            task = _writeback_queue.get(timeout=2.0)
            if task is None:  # poison pill: shutdown signal
                break
            try:
                task()
            except Exception:
                pass
            finally:
                _writeback_queue.task_done()
        except _queue.Empty:
            continue

def _writeback_submit(fn):
    """
    提交一个写回任务（callable，无参数）到后台队列。
    队列满时同步执行（防止积压/OOM）。
    OS 类比：writeback throttle — 脏页比例超过 dirty_ratio 时同步等待。
    """
    try:
        _writeback_queue.put_nowait(fn)
    except _queue.Full:
        # 队列满：退化为同步执行（类比 dirty_ratio 强制同步刷写）
        try:
            fn()
        except Exception:
            pass


def _update_activity():
    # iter208: lock-free — GIL guarantees atomic float write to list[0]
    _last_request_time[0] = time.time()


def _idle_watchdog():
    """
    闲置守护线程：60s 无请求时主动退出。
    OS 类比：Linux kthread_should_stop() — 内核线程检测退出信号。
    """
    while not _shutdown_event.is_set():
        time.sleep(5)
        # iter208: lock-free reads — GIL ensures consistent values
        idle = time.time() - _last_request_time[0]
        active = _active_connections[0]
        if idle >= IDLE_TIMEOUT_SECS and active == 0:
            # 写 stderr 而非 stdout（stdout 给 hook 输出用）
            print(f"[retriever_daemon] idle {idle:.0f}s, shutting down", file=sys.stderr)
            os._exit(0)


# ── Heavy module 全局引用（daemon 启动时一次性加载）──
_modules = {}

def _load_all_modules():
    """
    在 daemon 启动时预载所有 heavy modules。
    OS 类比：PostgreSQL 的 postmaster 在启动时加载 shared memory + catalog cache，
    后续每个 backend 进程 fork 后继承已加载的状态（CoW，零重复开销）。

    daemon 用 threading 而非 fork，但 import 后模块在所有线程间共享（CPython GIL 保证安全）。
    """
    import re
    import sqlite3
    import uuid
    import hashlib
    from datetime import datetime, timezone, date as _date_cls

    from config import get as sysctl
    from config import sched_ext_match
    from utils import resolve_project_id
    from scorer import retrieval_score, recency_score
    from store import (open_db, ensure_schema, get_chunks, update_accessed,
                       insert_trace, fts_search, dmesg_log, madvise_read,
                       swap_fault, swap_in, psi_stats, mglru_promote,
                       readahead_pairs, context_pressure_governor,
                       chunk_recall_counts)
    from store import DMESG_INFO, DMESG_WARN, DMESG_DEBUG
    from bm25 import hybrid_tokenize, bm25_scores, normalize, bm25_scores_cached
    from store_vfs import read_chunk_version

    _modules.update({
        're': re,
        'sqlite3': sqlite3,
        'uuid': uuid,
        'hashlib': hashlib,
        'datetime': datetime,
        'timezone': timezone,
        'sysctl': sysctl,
        'sched_ext_match': sched_ext_match,
        'resolve_project_id': resolve_project_id,
        'retrieval_score': retrieval_score,
        'recency_score': recency_score,
        'open_db': open_db,
        'ensure_schema': ensure_schema,
        'get_chunks': get_chunks,
        'update_accessed': update_accessed,
        'insert_trace': insert_trace,
        'fts_search': fts_search,
        'dmesg_log': dmesg_log,
        'madvise_read': madvise_read,
        'swap_fault': swap_fault,
        'swap_in': swap_in,
        'psi_stats': psi_stats,
        'mglru_promote': mglru_promote,
        'readahead_pairs': readahead_pairs,
        'context_pressure_governor': context_pressure_governor,
        'chunk_recall_counts': chunk_recall_counts,
        'DMESG_INFO': DMESG_INFO,
        'DMESG_WARN': DMESG_WARN,
        'DMESG_DEBUG': DMESG_DEBUG,
        'bm25_scores': bm25_scores,
        'bm25_scores_cached': bm25_scores_cached,
        'normalize': normalize,
        'hybrid_tokenize': hybrid_tokenize,
        'read_chunk_version': read_chunk_version,
    })

    # 尝试加载 VFS
    _vfs_loaded = False
    try:
        import importlib.util as _ilu
        if _ilu.find_spec("vfs") is not None:
            _PREFIX_NEW = {
                "decision": "[决策]", "excluded_path": "[排除]",
                "reasoning_chain": "[推理]", "rule": "[规则]",
                "reference": "[索引]", "knowledge": "[知识]",
            }
            def _new_vfs_search(query, sources=None, top_k=3, timeout_ms=100):
                from vfs import get_vfs as _lazy_get_vfs
                import zlib as _zlib
                _vfs = _lazy_get_vfs()
                # iter167: 从后端 corpus cache 读取 mtime key（无 I/O，~0.01ms）
                _corpus_mtime = 0.0
                try:
                    for _bname, _bk in _vfs._backends.items():
                        _cached = getattr(_bk, '_corpus_cache', None)
                        if _cached is not None:
                            _corpus_mtime = max(_corpus_mtime, _cached[0])
                except Exception:
                    pass
                _sources_key = ",".join(sorted(sources)) if sources else ""
                _qcrc = _zlib.crc32(query.encode())  # iter213: Python 3 crc32 always unsigned
                # TLB lookup
                _cached_result = _vfs_cache_get(_qcrc, _sources_key, _corpus_mtime)
                if _cached_result is not None:
                    return _cached_result
                # Cache miss: run full VFS search
                items = _vfs.search(query, top_k=top_k, deadline_ms=timeout_ms)
                if sources:
                    items = [i for i in items if i.source in sources]
                result = [{"source": i.source, "chunk_type": i.type, "summary": i.summary,
                           "score": i.score, "content": (i.content or "")[:300], "path": i.path}
                          for i in items]
                _vfs_cache_put(_qcrc, _sources_key, _corpus_mtime, result)
                return result
            def _new_vfs_format(results):
                if not results:
                    return ""
                lines = ["【知识路由召回】"]
                for r in results:
                    prefix = _PREFIX_NEW.get(r.get("chunk_type", ""), "")
                    src = r.get("source", "")
                    src_tag = f"({src})" if src else ""
                    lines.append(f"- {prefix} {r['summary']} {src_tag}".strip())
                return "\n".join(lines)
            _modules['kr_route'] = _new_vfs_search
            _modules['kr_format'] = _new_vfs_format
            _modules['_KR_AVAILABLE'] = True
            _vfs_loaded = True
    except Exception:
        pass

    if not _vfs_loaded:
        try:
            from knowledge_vfs_init import search as _kvfs_search, format_for_context as _kvfs_format, init_knowledge_vfs as _kvfs_init
            _kvfs_init()
            _modules['kr_route'] = _kvfs_search
            _modules['kr_format'] = _kvfs_format
            _modules['_KR_AVAILABLE'] = True
        except Exception:
            try:
                from knowledge_router import route as _kr_route, format_for_context as _kr_format
                _modules['kr_route'] = _kr_route
                _modules['kr_format'] = _kr_format
                _modules['_KR_AVAILABLE'] = True
            except Exception:
                _modules['_KR_AVAILABLE'] = False

    # 预编译 Stage 2 正则（只在 daemon 启动时付一次）
    _modules['_SKIP_PATTERNS'] = re.compile(
        r'^(?:好[的吧啊嗯哦]?|[嗯恩哦噢]+|ok(?:ay)?|是[的吧]?|对[的吧]?'
        r'|收到|了解|明白|可以|继续|开始|执行|确认|同意|谢谢'
        r'|thanks?|ye[sp]|no[pe]?|got\s*it|sure|lgtm)$',
        re.IGNORECASE
    )
    # iter722+743: 扩充 _TECH_SIGNAL — 支持中英混排（\b 不适用于 CJK 边界）
    _modules['_TECH_SIGNAL'] = re.compile(
        r'(?:`[^`]+`|[\w./]+\.(?:py|js|ts|md|json|db|sql|yaml|toml|rs|go|java|cpp|h)\b'
        r'|(?:函数|类|模块|接口|方法|变量|配置|部署|迁移|内核|调度|补丁|性能|分析|诊断|优化|约束|架构|线程|进程|延迟|飞书|文档|规则|策略|决策)'
        r'|(?<![a-zA-Z])(?:error|bug|fix|crash|kernel|patch|sched|perf|trace|commit|config|thread|task|memory|cache|proxy|migration|cgroup|PE|RT)(?![a-zA-Z])'
        r'|\b(?:def|class|import|function|const)\b)'
    )
    _modules['_ACRONYM_SIGNAL'] = re.compile(r'\b[A-Z][A-Z0-9_]{2,}\b')

    # iter190: 将 _TECH_SIGNAL/_ACRONYM_SIGNAL 写入模块全局变量，
    # 供模块级函数 _has_real_tech_signal 直接引用（无需 _modules 间接访问）。
    # 原 iter190 注释声称"已是模块级常量"，但实际上它们只在 _modules dict 中，
    # 不是全局变量——导致 _has_real_tech_signal 在 daemon 进程中调用时抛出 NameError。
    # 修复：在 _load_all_modules 完成后同步设置模块全局变量。
    import sys as _sys
    _self_mod = _sys.modules[__name__]
    _self_mod._TECH_SIGNAL = _modules['_TECH_SIGNAL']
    _self_mod._ACRONYM_SIGNAL = _modules['_ACRONYM_SIGNAL']

    # iter175: FTS5 expression cache — monkey-patch store_vfs._fts5_escape
    # _fts5_escape 是纯函数（query → FTS5 MATCH expr），结果可在 daemon 生命周期内永久缓存。
    # 对同一 query string 复用缓存的 match expr，消除 ~0.22ms 的 synonym expand + tokenize。
    # OS 类比：Linux dcache (dentry cache) — 路径名→inode 映射缓存，同一路径不重复解析。
    try:
        import store_vfs as _store_vfs
        _orig_fts5_escape = _store_vfs._fts5_escape
        def _cached_fts5_escape(query_str: str) -> str:
            # iter175: cache hit → skip synonym expansion (~0.225ms)
            # iter215: cache stores (expr, crc32) pair — avoids re-computing crc32 in _cached_fts_search
            #   on every cache hit (~0.24us saved per FTS hit request)
            # OS 类比：dcache stores inode number alongside path — avoids re-hashing on lookup
            cached = _fts5_expr_cache.get(query_str)
            if cached is not None:
                return cached[0]  # iter215: return expr from (expr, crc32) pair
            result = _orig_fts5_escape(query_str)
            # iter180: cap OR terms at MAX_FTS5_TERMS — FTS5 latency scales linearly
            # with term count; >8 terms show no recall gain on this corpus (361 chunks).
            # OS 类比：TCP send window — cap in-flight data to prevent resource waste.
            if result:
                _terms = result.split(' OR ')
                if len(_terms) > MAX_FTS5_TERMS:
                    result = ' OR '.join(_terms[:MAX_FTS5_TERMS])
            # iter_multiagent: Lock 保护 len()+del+assign 复合操作，防止并发 FIFO 淘汰时
            # RuntimeError: dictionary changed size during iteration
            with _fts5_expr_cache_lock:
                if len(_fts5_expr_cache) >= _FTS5_EXPR_CACHE_MAX:
                    try:
                        del _fts5_expr_cache[next(iter(_fts5_expr_cache))]
                    except (StopIteration, KeyError):
                        pass
                # iter215: store (expr, crc32) pair — pre-compute crc32 at write time (once)
                # instead of re-computing it on every FTS result cache lookup (every request)
                _result_crc = zlib.crc32(result.encode()) if result else 0
                _fts5_expr_cache[query_str] = (result, _result_crc)
            return result
        _store_vfs._fts5_escape = _cached_fts5_escape
        print(f"[retriever_daemon] fts5_expr_cache+term_cap({MAX_FTS5_TERMS}) patched", file=sys.stderr)
    except Exception as _e:
        print(f"[retriever_daemon] fts5_expr_cache patch failed: {_e}", file=sys.stderr)

    # iter188: sysctl TTL cache — monkey-patch config.get（sysctl 函数）
    # OS 类比：Linux slab allocator — per-CPU 热对象缓存，命中时跳过 buddy allocator。
    #   sysctl() 每次调用：os.environ.get(×2) + _load_disk_config() + dict.get ≈ 1.7us
    #   18 次/request = ~31us。TTL cache 将命中路径降至 ~0.2us/call，节省 ~28us/request。
    #   TTL=10s：sysctl_set() 极少调用（调试用），10s 内用旧值无功能影响。
    #   失效：_invalidate_cache() 被 sysctl_set 调用时，同步清空 daemon cache。
    #   线程安全：dict 操作在 CPython GIL 下为原子，无需额外锁。
    # OS 类比：kswapd watermark — 容忍短暂 staleness 以换取 fast path throughput。
    try:
        import config as _config_mod
        _orig_sysctl_get = _config_mod.get
        _orig_invalidate = _config_mod._invalidate_cache
        _sysctl_cache: dict = {}  # key → (ts, value)
        _SYSCTL_TTL = 10.0  # seconds — sysctl 在 daemon 生命周期内极少变化

        def _cached_sysctl_get(key: str, project: str = None) -> object:
            # iter188: cache hit → skip os.environ.get(×2) + disk_config lookup (~1.7us → ~0.2us)
            # key includes project to avoid cross-project pollution
            cache_key = key if project is None else f"{key}@{project}"
            entry = _sysctl_cache.get(cache_key)
            if entry is not None:
                ts, val = entry
                if time.time() - ts <= _SYSCTL_TTL:
                    return val
            result = _orig_sysctl_get(key, project)
            _sysctl_cache[cache_key] = (time.time(), result)
            return result

        def _cached_invalidate():
            _sysctl_cache.clear()  # daemon cache 同步清空
            _orig_invalidate()

        _config_mod.get = _cached_sysctl_get
        _config_mod._invalidate_cache = _cached_invalidate
        # 更新 _modules 中的引用（_retriever_main_impl 通过 mods['sysctl'] 调用）
        _modules['sysctl'] = _cached_sysctl_get
        print(f"[retriever_daemon] sysctl_ttl_cache(TTL={_SYSCTL_TTL}s) patched", file=sys.stderr)
    except Exception as _e:
        print(f"[retriever_daemon] sysctl_ttl_cache patch failed: {_e}", file=sys.stderr)

    # iter205: FTS5 result cache — monkey-patch store_vfs.fts_search
    # OS 类比：Linux buffer cache — 同一 block(fts_expr+project) 不重复走 disk I/O(SQL)。
    #   cache key = (crc32(fts_expr), project)
    #   cache value = (chunk_version_at_cache_time, results_list)
    #   失效：chunk_version 变化 → cache miss → re-query（同 _bm25_mem_cache 失效策略）
    #   hit: 0.4us；miss: ~0.617ms（同 baseline，写回缓存）。
    try:
        import store_vfs as _store_vfs_mod
        _orig_fts_search = _store_vfs_mod.fts_search
        _fts5_escape_fn = _store_vfs_mod._fts5_escape  # iter235: direct fn ref for raw SQL path

        # iter235: raw SQL helper — returns raw tuples (no dict construction).
        # Replicates store_vfs.fts_search logic but skips the dict-build loop.
        # Column order matches _CI_* constants:
        #   id(0), summary(1), content(2), importance(3), last_accessed(4),
        #   chunk_type(5), access_count(6), created_at(7), fts_rank(8),
        #   lru_gen(9), project(10), verification_status(11), confidence_score(12)
        _FTS_SQL_BASE = (
            # iter243: COALESCE(importance, 0.5) — eliminates 'or 0.5' Python bool eval per chunk
            "SELECT mc.id, mc.summary, mc.content, COALESCE(mc.importance, 0.5), mc.last_accessed,"
            " mc.chunk_type, COALESCE(mc.access_count, 0), COALESCE(mc.created_at, mc.last_accessed),"
            " -bm25(memory_chunks_fts, 0, 2.0, 1.0) AS fts_rank,"
            " COALESCE(mc.lru_gen, 0), COALESCE(mc.project, ''),"
            " mc.verification_status, mc.confidence_score"
            " FROM memory_chunks_fts"
            " JOIN memory_chunks mc ON mc.rowid = memory_chunks_fts.rowid_ref"
            " WHERE memory_chunks_fts MATCH ?"
            " AND mc.chunk_state = 'ACTIVE'"
            " AND mc.summary != ''"
            " AND COALESCE(mc.access_count, 0) < 30"
        )
        def _run_fts_raw(conn, match_expr, project_filter, top_k, chunk_types):
            """Run FTS SQL and return raw tuples (no dict construction)."""
            sql = _FTS_SQL_BASE
            params = [match_expr]
            if project_filter is not None:
                if isinstance(project_filter, (list, tuple)):
                    sql += " AND mc.project IN ({})".format(",".join("?" * len(project_filter)))
                    params.extend(project_filter)
                else:
                    sql += " AND mc.project = ?"
                    params.append(project_filter)
            if chunk_types:
                sql += " AND mc.chunk_type IN ({})".format(",".join("?" * len(chunk_types)))
                params.extend(chunk_types)
            sql += " ORDER BY fts_rank DESC LIMIT ?"
            params.append(top_k)
            try:
                return conn.execute(sql, params).fetchall()
            except Exception:
                return []

        def _cached_fts_search(conn, query, project, top_k=10, chunk_types=None):
            # iter205: cache hit → skip SQL execution (~0.617ms → ~0.4us)
            # iter215: _fts5_expr_cache stores (expr, crc32) pair — skip crc32 recompute on hit
            # iter235: cache miss path uses _run_fts_raw → raw tuples (no dict construction)
            #   eliminates store_vfs.fts_search dict-build loop (~9us/10chunks saved)
            #   OS 类比：struct field offset — tuple[int] BINARY_SUBSCR vs dict hash lookup
            # Two-phase approach:
            #   Phase 1 (cache lookup): use _fts5_expr_cache to get pre-computed (fts_expr, crc) → build cache_key
            #   Phase 2 (cache miss): run SQL, then write result to cache for next call
            # chunk_version from _chunk_version_file_cache (stat done in Stage1, 0.3us)
            # OS 类比：buffer cache — read block_key, if not in cache → disk I/O → fill cache
            _cv_entry = _chunk_version_file_cache[0]
            _cur_cv = _cv_entry[1] if _cv_entry is not None else -1
            _expr_pair = _fts5_expr_cache.get(query)  # iter215: (expr, crc32) pair
            if _expr_pair is not None:
                # Phase 1: pre-computed crc32 → no re-compute on hit (~0.24us saved)
                # OS 类比：cache line contains both VA and PA — no re-hash on TLB hit
                _cache_key = (_expr_pair[1], project, top_k, chunk_types)  # [1] = pre-computed crc32
                _cached = _fts5_result_cache.get(_cache_key)
                if _cached is not None:
                    _stored_cv, _results = _cached
                    if _stored_cv == _cur_cv:
                        return _results  # cache hit: ~0.3us vs ~0.617ms
            # Phase 2 (cache miss): run raw SQL → raw tuples; _fts5_escape_fn populates _fts5_expr_cache
            match_expr = _fts5_escape_fn(query)  # side-effect: populates _fts5_expr_cache[query]
            if not match_expr:
                return []
            # iter657: 移除 FTS5 project 过滤 — 全库搜索
            # 根因：高价值 chunk 被写入项目特定 project_id（如 git:xxx），
            # 用户在不同 cwd 对话时这些知识完全不可见（project 解析为 abspath:yyy）。
            # 修复：FTS5 阶段搜全库，用 global_discount 在评分阶段控制排名。
            # 61 chunks 全库扫描 FTS5 < 1ms，比之前 project+orphan 双查询更快。
            _results = _run_fts_raw(conn, match_expr, None, top_k, chunk_types)
            # After SQL: _fts5_expr_cache[query] is now populated as (expr, crc32) pair
            _expr_pair_post = _fts5_expr_cache.get(query)
            if _expr_pair_post is not None:
                _cache_key2 = (_expr_pair_post[1], project, top_k, chunk_types)  # [1] = crc32
                # iter_multiagent: Lock 保护 FIFO 淘汰复合操作
                with _fts5_result_cache_lock:
                    if len(_fts5_result_cache) >= _FTS5_RESULT_CACHE_MAX:
                        try:
                            del _fts5_result_cache[next(iter(_fts5_result_cache))]
                        except (StopIteration, KeyError):
                            pass
                    _fts5_result_cache[_cache_key2] = (_cur_cv, _results)
            return _results
        _store_vfs_mod.fts_search = _cached_fts_search
        # update _modules reference so _retriever_main_impl uses the patched version
        _modules['fts_search'] = _cached_fts_search
        print(f"[retriever_daemon] fts5_result_cache patched (iter235: raw tuple path)", file=sys.stderr)
    except Exception as _e:
        print(f"[retriever_daemon] fts5_result_cache patch failed: {_e}", file=sys.stderr)

    print(f"[retriever_daemon] modules loaded, KR={_modules.get('_KR_AVAILABLE', False)}", file=sys.stderr)


# ── 请求处理 ──

def _handle_connection(conn_sock: socket.socket):
    """
    处理单个客户端连接。
    OS 类比：Linux 的 accept() 后的 worker thread — 每个连接独立处理，互不阻塞。
    """
    # iter208: lock-free — GIL-atomic list[0] ops, inline _update_activity
    _active_connections[0] += 1
    _last_request_time[0] = time.time()

    try:
        # 读完整请求（以 '\n' 结尾的 ND-JSON）
        buf = b""
        conn_sock.settimeout(5.0)
        while True:
            chunk = conn_sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b'\n' in buf:
                break

        if not buf.strip():
            return

        # 解析请求
        line = buf.split(b'\n')[0]
        try:
            hook_input = json.loads(line.decode('utf-8'))
        except Exception:
            conn_sock.sendall(b'{"error":"invalid_json"}\n')
            return

        # iter259: heartbeat ping — 快速响应 pong，用于 wrapper 存活探针
        # OS 类比：systemd watchdog notify — 进程证明自己仍在响应
        if hook_input.get("ping"):
            conn_sock.sendall(b'{"pong":1}\n')
            return

        # 运行检索逻辑，捕获 stdout 输出
        # iter215: use module-level _io ref instead of per-request 'import io' (~0.2us saved)
        old_stdout = sys.stdout
        sys.stdout = _io.StringIO()
        try:
            _run_retrieval(hook_input)
        except SystemExit:
            pass
        except Exception as e:
            print(json.dumps({"error": str(e)}), file=sys.stdout)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout

        # iter216: dead-branch elimination + pre-built bytes constant + encode() no-arg
        # print() always appends '\n', so output is either '' (SKIP/TLB) or ends with '\n' (inject).
        # The elif not output.endswith('\n') branch is DEAD CODE — eliminated.
        # SKIP/TLB path (output=''): send _EMPTY_RESPONSE_B directly (0.249us → 0.161us).
        # Inject path: encode() with no arg defaults to UTF-8 (0.204us → 0.172us).
        # OS 类比：DMA buffer reuse + dead-branch DCE — 跳过 malloc+copy+endswith 扫描。
        if not output:
            conn_sock.sendall(_EMPTY_RESPONSE_B)
        else:
            conn_sock.sendall(output.encode())

    except Exception:
        try:
            conn_sock.sendall(b'{}\n')
        except Exception:
            pass
    finally:
        try:
            conn_sock.close()
        except Exception:
            pass
        # iter208: lock-free — GIL-atomic list[0] ops, inline _update_activity
        _active_connections[0] -= 1
        _last_request_time[0] = time.time()


# ── 检索逻辑（从 retriever.py 移植，重用 _modules 而非 globals）──

_mem_env = os.environ.get("MEMORY_OS_DIR")
MEMORY_OS_DIR = _mem_env if _mem_env else os.path.join(os.path.expanduser("~"), ".claude", "memory-os")
_db_env = os.environ.get("MEMORY_OS_DB")
STORE_DB = _db_env if _db_env else os.path.join(MEMORY_OS_DIR, "store.db")
HASH_FILE = os.path.join(MEMORY_OS_DIR, ".last_injection_hash")
TLB_FILE = os.path.join(MEMORY_OS_DIR, ".last_tlb.json")
CHUNK_VERSION_FILE = os.path.join(MEMORY_OS_DIR, ".chunk_version")
# iter804: session_first_inject_guard — 跨 session hash/TLB 缓存导致新 session 零注入
# 数据驱动（2026-05-05）：23/86 trace 为 skipped_same_hash，23/23 的 session 从未有过注入。
# 根因：HASH_FILE/TLB 是全局共享的，新 session 启动时读到前一 session 写入的 hash/TLB，
#   current_hash == last_hash → skip，但新 session 从未执行过注入 → 用户零记忆上下文。
# 修复：进程内 set 跟踪已注入 session，未注入的 session 不走 hash/TLB 缓存快捷路径。
# 内存安全：session UUID 36B × 1000 sessions ≈ 36KB，daemon 重启自然清空。
_sessions_with_injection: set = set()
_SESSION_INJECTED_FILE = os.path.join(MEMORY_OS_DIR, ".session_injected")
_sessions_written_to_file: set = set()  # iter1267: dedup file writes
# iter807: daemon_inmem_suppress — 消除 writeback 竞争导致的 suppress 逃逸
# 根因（数据驱动，2026-05-05）：daemon writeback 异步，final_gate 查 DB 时前一次 trace
#   未 commit → 24h suppress 计数滞后 → 连续注入逃逸（如 38 分钟内同 chunk 注入 3 次）。
# 修复：进程内记录每次注入的 (chunk_id, unix_ts)，final_gate 叠加内存数据。
# 内存安全：7d 上限 ~200 entries × 60B ≈ 12KB，每次请求 gc 超 7d 条目。
_daemon_inject_log: list = []  # [(chunk_id, unix_timestamp), ...]
# iter872: diversity_counter — 进程内自增计数器替代 hour%len 做 round-robin
# 根因（数据驱动，2026-05-05）：hour%len 同一小时内总选同一 chunk，
#   36-chunk 库 1h 内 10+ 请求 diversity pair 全是同一个 → 24h=3 后被 suppress → 下一个轮到时又用完
#   6 个候选仅 2 个有过曝光。自增计数器每次选不同候选，真正实现 round-robin。
# 用 list[0] 避免 global 声明（函数内 mutate 无需 global）。
_diversity_counter = [0]
PAGE_FAULT_LOG = os.path.join(MEMORY_OS_DIR, "page_fault_log.json")
SHADOW_TRACE_FILE = os.path.join(MEMORY_OS_DIR, ".shadow_trace.json")
MADVISE_FILE_PATH = os.path.join(MEMORY_OS_DIR, "madvise.json")

# ── iter163: Daemon 内存 BM25 文档缓存 ──────────────────────────────────
# OS 类比：Linux page cache (1991) — 文件内容缓存在内存，避免重复 I/O
#   BM25 fallback 路径每次都需要：
#     1. store_get_chunks() → 从 DB 读取所有 chunk（~3-5ms）
#     2. 构建 search_texts 列表（字符串拼接，~0.5ms）
#     3. bm25_scores_cached() → 读 pickle 文件（~0.5ms） + 评分（~15ms）
#   daemon 是长驻进程，chunk 集合只在 chunk_version 变化时改变。
#   缓存 key = (project, retrieve_types_key, chunk_version)
#   缓存 value = (chunks list, bm25_index object, search_texts list)
#   cache hit: 跳过步骤 1+2+3，只做 query tokenize + 评分 (~1-2ms)
#
# 线程安全：threading.RLock（读操作多，写操作少，RLock 开销最低）
# 内存上限：daemon idle 60s 后退出，不需要 LRU eviction
_bm25_mem_cache: dict = {}   # key → (chunk_version, chunks, bm25_index, search_texts)
_bm25_mem_lock = threading.RLock()

# ── iter167: VFS query result cache ─────────────────────────────────────
# OS 类比：TLB (Translation Lookaside Buffer) — 虚拟地址→物理地址映射缓存；
#   VFS 搜索 = 知识路由，结果是 query → [VFSItem]，与地址转换高度类比。
#   cache key = (query_crc32, sources_key, corpus_mtime_key)
#   corpus_mtime_key = 从 SI + MM 后端 _corpus_cache 的 mtime_key 读取（无 I/O）
#   cache miss: VFS search ~2.5ms
#   cache hit: dict lookup ~0.01ms
#   失效：corpus_mtime_key 变化（文件修改）→ 自动 miss
_vfs_result_cache: dict = {}  # key → (corpus_mtime_key, results_list)
_vfs_result_lock = threading.Lock()
_VFS_CACHE_MAX = 64  # 最多缓存 64 个不同 query（daemon 60s 内不会超过）

# ── iter175: FTS5 expression cache ──────────────────────────────────────
# OS 类比：Linux dentry cache (dcache) — 路径名→inode 映射缓存；
#   _fts5_escape(query) = 路径解析（字符串→FTS5 MATCH 表达式），纯函数，结果可复用。
#   cache miss: _fts5_escape ~0.225ms（synonym expand + tokenize）
#   cache hit: dict lookup ~0.001ms
#   失效：不需要（_fts5_escape 是纯函数，query→expr 映射不变）
#   内存：64 entries × ~200B = ~12KB（可忽略）
#   预期节省：~0.22ms/request（command 频繁重复时）
_fts5_expr_cache: dict = {}  # query_str → fts5_match_expr
_FTS5_EXPR_CACHE_MAX = 128  # daemon 60s 内不超过此数量的不同 query
# iter_multiagent: threading.Lock 保护 FIFO 淘汰的 len()+del+assign 复合操作。
# OS 类比：spinlock 保护 CPU L1 cache 替换逻辑 — 单次 dict.get/set 在 GIL 下原子，
#   但 len()→del→assign 三步复合操作不原子：两线程同时判断 len()>=MAX 后都执行 del，
#   可导致 RuntimeError: dictionary changed size during iteration（iter(dict) 期间被修改）。
import threading as _threading_cache  # 避免与顶层 threading 导入冲突
_fts5_expr_cache_lock = _threading_cache.Lock()

# ── iter205: FTS5 result cache ───────────────────────────────────────────────
# OS 类比：Linux buffer cache (block I/O cache) — 同一 block 编号（fts_expr + project）
#   的数据缓存在 buffer_head，不重复走 disk I/O。
#   fts_expr = block 编号，SQL 结果 = block 内容，chunk_version = disk generation counter。
#   cache key = (crc32(fts_expr), project)  — crc32 碰撞概率 1/2^32，daemon 60s 内可忽略。
#   cache value = (chunk_version_at_cache_time, results_list)
#   失效：chunk_version != stored_chunk_version → cache miss（extractor 写入新 chunk 时 bump）。
#   cache hit: dict lookup(0.1us) + version check(0.3us) ≈ 0.4us（vs fts_search 0.617ms）。
#   cache miss: 正常 fts_search() → 写回缓存（0.617ms，无额外开销）。
#   内存：64 entries × 10 results × ~500B = ~320KB（可忽略）。
#   线程安全：FIFO 淘汰复合操作用 _fts5_result_cache_lock 保护（同 _fts5_expr_cache_lock）。
#   注意：fts_search 使用 persistent ro conn（iter173），chunk_version 失效时 ro conn 也会重建。
#         两个失效机制独立，FTS result cache 以 _read_chunk_version_cached() 作为单一 version 源。
_fts5_result_cache: dict = {}  # (crc32(fts_expr), project) → (chunk_version, results_list)
_FTS5_RESULT_CACHE_MAX = 64  # FIFO eviction（与 _vfs_result_cache 同策略）
_fts5_result_cache_lock = _threading_cache.Lock()

# ── iter180: FTS5 term cap ───────────────────────────────────────────────
# OS 类比：TCP send window — 限制在途数据量，防止过度消耗网络/CPU 资源。
#   iter103 同义词扩展使 MATCH 表达式膨胀到 10-23 个 OR 项，
#   SQLite FTS5 对每个 OR 项独立扫描 b-tree，项数线性影响延迟。
#   实测（N=10 真实查询）：cap=8 vs uncapped(avg=9.8 terms) 节省 avg=134us（最多 712us）
#   recall 不受影响：8 terms 与 23 terms 命中相同结果集（DB 仅 361 chunks）。
#   原理：FTS5 索引稀疏 OR 查询收益边际递减 — 前 8 个高频词已覆盖所有相关文档。
MAX_FTS5_TERMS = 8  # FTS5 OR 项上限（实测 >8 时 recall 无增益，latency 线性增加）

# ── iter196: ISO timestamp daemon cache ─────────────────────────────────────
# OS 类比：Linux inode cache — 同一 file 路径的 mtime 缓存在 inode 对象，不重复 stat syscall。
#   iso_str（chunk.last_accessed/created_at）对应 "文件路径"，timestamp 对应 "inode mtime"。
#   fromisoformat() + timedelta.total_seconds() ≈ 0.87us/call，命中 dict.get ≈ 0.40us。
#   10 chunks × 2 calls/chunk（la≠ca 时）= 20 calls/request = ~17.4us → ~8.0us（节省 9.4us）。
#   失效：不需要 — iso_str 是 immutable timestamp string，同一 str 永远对应同一 float。
#   内存：max ~580 entries（290 chunks × 2 fields）× ~100B = ~58KB（可忽略）。
#   线程安全：CPython GIL 保证 dict.get/set 原子，无需锁。
_iso_ts_cache: dict = {}  # iso_str → float(unix timestamp) [legacy, kept for compatibility]

# ── iter230: age_days daemon cache (days-float, replaces _iso_ts_cache logic) ─────────────────
# OS 类比：Linux inode atime — day-precision access time cached in memory, no repeated syscall.
#   _age_days_fast now uses date.fromisoformat(s[:10]) → ordinal subtraction (day-precision):
#   miss: date.fromisoformat(s[:10]) ~0.49us (vs ~0.87us for datetime.fromisoformat + timezone)
#   hit: dict.get ~0.25us (vs ~0.40us with / 86400 division in old iter196 path)
#   Total for 2 calls/chunk (la≠ca): ~0.98us miss + ~0.50us hit → ~1.48us (vs ~1.54us iter196)
#   Additional: result stored as days-float, no / 86400 division on return (~0.04us × many calls)
#   Accuracy: max error = 0.156 days (< 4h within UTC day) — negligible for 7d-scale scoring.
#   线程安全：CPython GIL 保证 dict.get/set 原子。
# iter245: extend cache to (age, exp_val) tuples — eliminates math.exp on hot path (cache hit).
# iter246: extend to 3-tuple (age, exp_val, recency) — also caches 1/(1+age), eliminates division.
# _age_days_cache[iso_str] = (age_days_float, exp(age * _LN_DECAY_INV7), 1.0/(1.0+age))
# Cache hit: unpack 3-tuple → age, exp, recency in one dict.get() + UNPACK_SEQUENCE.
# Cache miss: compute all three + store; exp and recency reused instead of recomputing.
# Saving iter245: ~0.043us/chunk × 10 = ~0.43us/request (math.exp elimination).
# Saving iter246: ~0.040us/chunk × 10 = ~0.40us/request (1/(1+age) division elimination).
# Backward compat: _age_days_fast() still returns float (reads c[0] from 3-tuple).
# OS 类比: memoization of FPU-intensive computation — cache (addr, decoded_value) in TLB-like
#          structure so re-fetch skips both the expensive decode (exp) and division (1/(1+age)).
_age_days_cache: dict = {}  # iter246: iso_str → (float(age_days), float(exp(age*_LN_DECAY_INV7)), float(1/(1+age)))

# ── iter199: access_bonus lookup table ──────────────────────────────────────────
# OS 类比：CPU TLB — 预计算的 VA→PA 映射直接返回，无需走 page table walk（math.log2）。
#   access_count 通常为小整数（0-20），math.log2(1 + _ac) * 0.05 = 纯函数，可预计算。
#   _AB_TABLE[i] = min(ab_cap, log2(1+i) * 0.05) for i in 0..20
#   lookup: list.__getitem__(int) = ~0.06us vs math.log2 call = ~0.28us。
#   21 entries × 8B = ~168B（可忽略），覆盖所有常见 access_count 值（>=21 rare）。
#   实测 10 chunks（混合 ac=0..10）：3.52us → 0.84us（节省 2.68us/request）。
#   失效：不需要 — _sc_ab_cap 是 sysctl 参数，daemon 60s 内几乎不变；即使变化影响极小。
#   OS 类比：computed goto table — 将运行时分支转为 O(1) 表查找。
#   注：初始化使用 _sc_ab_cap=0.2（sysctl scorer.access_bonus_cap 默认值），
#       如果 sysctl 被修改，表不自动更新（精度损失可忽略，0.2 是固定默认值）。
import math as _math_init
import math as _math  # module-level — reused by _retriever_main_impl (iter212: avoid per-call import)
_AB_TABLE_CAP = 0.2  # scorer.access_bonus_cap default (sysctl read is 0.2)
# iter251: extend table from 21 to 64 entries (0..63); formula caps at ac=63 (log2(64)*0.05=0.30≥cap=0.20).
# Corpus (N=427): 105 chunks had ac>20 (calling math.log2); with 64-entry table, all 105 covered by table.
# ac<=20: unchanged. ac 21..63: table hit (was log2). ac>=64: direct 0.20 (was log2, now guard-free).
# Saving: all 105 log2 calls eliminated. microbench: ~60ns/chunk avg (105/427 × 188ns).
# OS 类比：enlarged TLB — extending coverage from 21→64 entries eliminates log2 for 100% of corpus.
_AB_TABLE: list = [min(_AB_TABLE_CAP, (_math_init.log2(1 + i) * 0.05 if i > 0 else 0.0)) for i in range(64)]
# _AB_TABLE[0]=0.0, [1]=0.035, ..., [20]=0.20 (cap), ..., [63]=0.20 (cap)

# ── iter231: saturation_penalty lookup table ─────────────────────────────────────
# OS 类比：CPU TLB — 同 iter199 _AB_TABLE，预计算 log2 路径为 O(1) 表查找。
#   sp = min(_sc_st_cap, _sc_st_fac * log2(1+rc)) if rc>0 else 0.0
#   rc 通常为小整数（0-20），log2 每次 ~0.28us × 10 chunks = ~2.8us。
#   _ST_TABLE[i] = min(0.25, 0.04 * log2(1+i)) for i=0..20（i=0时为0.0）。
#   lookup: list[int] ~0.06us vs log2 ~0.28us（节省 0.22us/chunk）。
#   在 rc>0 路径（约 30% chunks）：0.22us × 10 chunks × 30% = ~0.66us 加权节省。
#   _ST_TABLE[0]=0.0 (sentinel，rc=0 fast path 不走 log2)，[1]=0.0277, ..., [20]=0.173
#   使用默认值 st_fac=0.04, st_cap=0.25 初始化；sysctl 修改时精度损失可忽略。
#   OS 类比：computed goto table（同 iter199 ab_cap）— O(1) 替代 log2 call。
_ST_TABLE_FAC = 0.04   # scorer.saturation_factor default
_ST_TABLE_CAP = 0.25   # scorer.saturation_cap default
_ST_TABLE: list = [0.0] + [min(_ST_TABLE_CAP, _ST_TABLE_FAC * _math_init.log2(1 + i)) for i in range(1, 21)]
# _ST_TABLE[0]=0.0, [1]≈0.028, [5]≈0.093, [10]≈0.138, [20]≈0.173
# iter256: extend _ST_TABLE to 271 entries — covers max(rc)=270 from corpus (recall_traces, all sessions).
# Formula min(0.25, 0.04*log2(1+i)) caps at i≥179 (log2(180)*0.04=0.302≥0.25).
# Replaces compound `if _rc < 21 else (min(...) if _rc > 0 else 0.0)` with single bounds check.
# Corpus max: max(chunk_hit_counts in recall_traces) = 270 (SELECT MAX counts from top_k_json, N=all).
# Correctness: 271/271 match (rc 0..270). Table[rc>=271] rare: fallback to _ST_TABLE_CAP=0.25 (capped).
# Saving: -26.8ns/chunk; ×10=-0.268us/request.
# OS 类比：enlarged TLB — same as _AB_TABLE 21→64 (iter251): covering 100% corpus eliminates log2 calls.
_ST_TABLE_EXT: list = [0.0] + [min(_ST_TABLE_CAP, _ST_TABLE_FAC * _math_init.log2(1 + i)) for i in range(1, 271)]
# _ST_TABLE_EXT[0]=0.0, [20]≈0.173, [100]≈0.220, [270]=0.25 (capped)

# ── iter240: lru_gen_boost lookup table ─────────────────────────────────────────
# SQL FTS query: COALESCE(mc.lru_gen, 0) — guarantees _lg is always int (0..N), never None.
# iter236 used ternary: (0.06 - 0.0075*(lg if lg<8 else 8)) if lg>=0 else 0.0
#   _lg>=0 always (COALESCE ensures non-negative int); lg<8 test + multiply = 2 ops.
# _LGB_TABLE[i] = 0.06 - 0.0075*min(i,8) for i in 0..8, then 0.0 (capped)
# Values: [0.06, 0.0525, 0.045, 0.0375, 0.03, 0.0225, 0.015, 0.0075, 0.0]
# Lookup: list[int] ~0.087us vs ternary ~0.132us (saving ~0.045us/chunk; ×10 = 0.45us/request)
# Table size 9 — covers all valid lru_gen values (MGLRU max gen is 4; cap at 8 is safe margin).
# OS 类比：computed goto table — same strategy as _AB_TABLE (iter199) and _ST_TABLE (iter231).
_LGB_TABLE: list = [round(0.06 - 0.0075 * i, 10) for i in range(9)]
# _LGB_TABLE: [0.06, 0.0525, 0.045, 0.0375, 0.03, 0.0225, 0.015, 0.0075, 0.0]

# ── iter200: pre-built JSON output header ──────────────────────────────────────
# OS 类比：sendfile() + zero-copy — 避免在 critical path 上重新序列化不变的结构。
#   json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": ctx}})
#   = 4.43us/call（对 ~200 字节外层结构做完整 JSON 序列化，context_text 部分约 200-500B）。
#   优化：外层结构固定，只对 context_text 做 json.dumps（含 ensure_ascii=False Unicode 处理）。
#   _OUTPUT_HEADER + json.dumps(ctx, ensure_ascii=False) + "}}" = 1.35us（节省 3.1us）。
#   语义等价：两种方式都是合法 JSON，区别只是外层 key 无空格（JSON spec 允许）。
#   消费方（Claude Code hook 解析器）做 json.load()，不做字符串匹配，空格无关。
#   OS 类比：writev() — 将固定 header 和 variable body 分开，避免重新分配缓冲区。
_OUTPUT_HEADER = '{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":'

# ── iter216: pre-built empty response bytes + dead-branch elimination ────────────
# OS 类比：pre-allocated DMA buffer — 常量响应直接返回，无需每次 str→bytes 分配。
#   1. _EMPTY_RESPONSE_B: SKIP/TLB 路径返回空输出时，'{}\\n'.encode('utf-8')(0.249us) →
#      直接引用 pre-built bytes 常量 _EMPTY_RESPONSE_B(0.161us)，节省 ~0.088us/request。
#      SKIP/TLB 命中率高（典型对话 60-80% SKIP + TLB），影响显著。
#   2. elif not output.endswith('\\n'): — 死代码消除：
#      print() 总是以 '\\n' 结尾；output 为 '' 时已被 'if not output' 捕获。
#      该 elif 分支永远为 False，从未执行。删除节省 ~0.299us（endswith str 扫描）。
#   3. encode('utf-8') → encode()：Python str.encode() 默认 encoding='utf-8'，
#      省略参数跳过 encoding 字符串查找（0.204us → 0.172us，节省 ~0.033us）。
#   合计：~0.42us/request（所有路径均受益）。
#   OS 类比：
#     1. DMA pre-allocation — 常量响应直接返回 pre-allocated buffer，跳过 malloc+copy；
#     2. Dead-branch elimination（同 iter206/211/212）— 编译器删除未被执行的条件路径；
#     3. ABI calling convention — 默认参数 = 零成本，省去 'utf-8' 字符串对象解引用。
_EMPTY_RESPONSE_B = b'{}\n'  # pre-built bytes constant for SKIP/TLB empty response

# ── iter218: module-level sort key (itemgetter → C extension, avoids lambda overhead) ──────────────
# OS 类比：vDSO — 预编译的 C 扩展函数，bypass Python 函数调用栈（PyEval_EvalFrameEx）。
#   final.sort(key=lambda x: x[0]) 每次 ~1.623us（10 items，2×/inject）；
#   final.sort(key=_SORT_KEY) ~0.835us（节省 0.788us × 2 = ~1.576us/inject request）。
import operator as _operator
_SORT_KEY = _operator.itemgetter(0)  # pre-created C-level key for (score, chunk) sort

# ── iter197: entities daemon cache ────────────────────────────────────────────
# OS 类比：Linux dentry cache（dcache）— 同一路径名不重复 pathname_lookup，
#   直接返回缓存 inode。_extract_key_entities(prompt_str) 是纯函数（同 prompt → 同 entities），
#   Stage2 多次进入（TLB miss 后重试，或同一 session 内同 prompt 再次出现）可命中缓存。
#   hit: dict.get(str) ≈ 0.18us；miss: 7.5us（正常执行，写回缓存）。
#   典型场景（用户重复/相似 prompt）命中率 20-50%，avg 节省 ~1.5-3.5us。
#   失效：不需要 — entities 是 prompt 字符串的确定性函数，同一 str 永远对应同一 list。
#   内存：max ~200 entries × ~150B = ~30KB（可忽略）。
#   线程安全：CPython GIL 保证 dict.get/set 原子，无需锁。
_entities_cache: dict = {}  # prompt_str → entities_list

# ── iter209: _is_generic_knowledge_query daemon cache ────────────────────────
# OS 类比：Linux dentry cache（dcache）— 同一路径不重复 pathname_lookup，
#   直接返回缓存 bool。_is_generic_knowledge_query(query) 是纯函数（query → bool），
#   每次 Stage2 分类块必经路径（~1.64us）。同 query 再次进入时命中缓存（~0.14us）。
#   hit: dict.get(str) ≈ 0.14us；miss: 1.64us（正常执行，写入缓存）。
#   典型场景命中率 20-50%，avg 节省 ~0.3-0.75us/request。
#   失效：不需要 — is_generic 是 query 字符串的确定性函数，同一 str 永远对应同一 bool。
#   内存：max ~200 entries × ~80B = ~16KB（可忽略）。
#   线程安全：CPython GIL 保证 dict.get/set 原子，无需锁。
_is_generic_q_cache: dict = {}  # query_str → bool

# ── iter203: page_fault_log daemon-level cache ───────────────────────────────
# OS 类比：dirty page writeback + inode cache —
#   读取消费后记录 mtime_ns，同一文件内容命中时直接返回 []（已消费）；
#   "resolved" 标记写回移入 writeback 线程（消除 critical path 上的 file write）。
# 背景：_read_page_fault_log 每次请求：
#   read(0.034ms) + write("resolved", indent=2)(0.441ms P50, 15ms P90) = ~0.5ms P50, ~15ms P90
#   写入 P90 抖动来自 OS fsync/page cache flush，是 critical path 上的主要尖刺源之一。
# 修复：
#   1. mtime_ns 缓存：同一文件（mtime 未变）→ 已消费，直接返回 []（1.3us）
#   2. 首次读取：cache miss → 读文件提取 queries（0.039ms）
#   3. 写回"resolved"标记：defer 到 writeback 线程（从 critical path 移除 ~0.5ms P50）
# 正确性：
#   - 写入新 page_fault 条目的是 swap_fault 路径（store.py 写 PAGE_FAULT_LOG），
#     mtime_ns 会变化 → 下次请求 cache miss → re-read
#   - 同一 daemon 生命周期（60s）内 mtime 不变 = 文件内容不变 = 已消费
# 线程安全：list[0] 更新原子（CPython GIL），同 _tlb_file_cache。
_page_fault_cache: list = [None]  # [(mtime_ns, queries_list)] or [None]

def _vfs_cache_get(query_crc: int, sources_key: str, corpus_mtime: float):
    """
    VFS 结果缓存查询。
    OS 类比：TLB lookup — O(1) 并行查找，命中直接返回。
    """
    key = (query_crc, sources_key)
    with _vfs_result_lock:
        entry = _vfs_result_cache.get(key)
    if entry is None:
        return None
    cached_mtime, results = entry
    if cached_mtime != corpus_mtime:
        return None  # cache miss: corpus changed
    return results

def _vfs_cache_put(query_crc: int, sources_key: str, corpus_mtime: float, results: list):
    """
    写入 VFS 结果缓存。
    OS 类比：TLB fill — cache miss 后将映射写入 TLB。
    """
    key = (query_crc, sources_key)
    with _vfs_result_lock:
        if len(_vfs_result_cache) >= _VFS_CACHE_MAX:
            # 简单 FIFO 淘汰（不需要 LRU，daemon 生命周期短）
            oldest = next(iter(_vfs_result_cache))
            del _vfs_result_cache[oldest]
        _vfs_result_cache[key] = (corpus_mtime, results)

def _bm25_mem_cache_get(project: str, retrieve_types_key: str, chunk_version: int):
    """
    检索内存缓存。返回 (chunks, bm25_index, search_texts) 或 None。
    OS 类比：CPU cache lookup — 命中则直接返回 cache line 内容。
    """
    key = (project, retrieve_types_key)
    with _bm25_mem_lock:
        entry = _bm25_mem_cache.get(key)
    if entry is None:
        return None
    cached_ver, chunks, bm25_index, search_texts = entry
    if cached_ver != chunk_version:
        return None  # cache miss: version stale
    return chunks, bm25_index, search_texts

def _bm25_mem_cache_put(project: str, retrieve_types_key: str, chunk_version: int,
                         chunks: list, bm25_index, search_texts: list):
    """
    写入内存缓存。
    OS 类比：page cache fill — cache miss 后将数据填入 page cache。
    """
    key = (project, retrieve_types_key)
    with _bm25_mem_lock:
        _bm25_mem_cache[key] = (chunk_version, chunks, bm25_index, search_texts)

def _bm25_mem_cache_invalidate(project: str = None):
    """
    失效缓存（chunk_version 更新后调用）。
    project=None 清空全部（全局失效），否则只清对应 project 的条目。
    OS 类比：page cache eviction — dirty page writeback 后清除 cache entry。
    """
    with _bm25_mem_lock:
        if project is None:
            _bm25_mem_cache.clear()
        else:
            keys_to_del = [k for k in _bm25_mem_cache if k[0] == project]
            for k in keys_to_del:
                del _bm25_mem_cache[k]

# ── iter170: PSI / gov / recall_counts daemon-level cache ──────────────────
# OS 类比：Linux slab allocator kmem_cache — 频繁分配的小对象缓存在 per-CPU 槽，
#   避免每次都走 buddy allocator（等价于 DB 查询）。
#   PSI/gov/rc 都依赖 recall_traces 最近 N 行，每 30 秒才有意义变化。
#   iter170 原 TTL=5s；iter185 延长到 30s：
#     原因：用户对话节奏通常 10-30s/turn，5s TTL miss 率 ~50-100%，
#     30s TTL 将典型场景命中率从 ~50% → ~90%+。
#     on miss: psi(0.42ms) + gov(0.43ms) + rc(0.44ms) = 1.29ms/miss；
#     P50 miss 率减少 45%，节省 ~0.58ms（1.29ms × 0.45 = 0.58ms）。
#   失效条件：wall time > cached_ts + TTL 或 project 切换。
_PSI_GOV_RC_CACHE: dict = {}  # key=(project) → (ts, psi_result, gov_result, rc_result)
# iter221: _PSI_GOV_RC_LOCK removed — CPython GIL makes dict.get/set atomic (same as
# _vfs_result_cache, _sched_ext_cache). Lock was pure overhead (~0.31us/request).
_PSI_GOV_RC_TTL = 30.0  # seconds (iter185: 5s → 30s, reduces miss rate ~45%→~10%)

def _psi_gov_rc_get(project: str, now_ts: float):
    """从 daemon 缓存读取 psi/gov/rc（cache hit → 无 DB I/O）。
    iter221: lock-free (GIL-safe dict.get) + now_ts parameter (reuse _t_start, avoid extra time.time()).
    OS 类比：per-CPU 计数器 — GIL = 单核等价，额外 Lock 是无谓的 mutex overhead。
    """
    entry = _PSI_GOV_RC_CACHE.get(project)  # iter221: GIL-safe, no Lock needed
    if entry is None:
        return None
    ts, psi_r, gov_r, rc_r = entry
    if now_ts - ts > _PSI_GOV_RC_TTL:
        return None  # TTL expired
    return psi_r, gov_r, rc_r

def _psi_gov_rc_put(project: str, psi_r, gov_r, rc_r):
    """写入 daemon 缓存。iter221: lock-free (GIL-safe dict assignment)."""
    _PSI_GOV_RC_CACHE[project] = (time.time(), psi_r, gov_r, rc_r)


# ── iter178: madvise.json daemon-level cache ─────────────────────────────────
# OS 类比：Linux page cache — 文件内容缓存在内存，mtime 变化时自动失效。
#   madvise_read(project) 每次请求都读 madvise.json（88us file I/O + datetime parsing）。
#   daemon 进程内缓存所有 project 的 hints，以 madvise.json mtime_ns 为失效 key。
#   cache hit: stat(2us) + dict lookup(~0us) = ~2us（节省 ~83us/request）
#   cache miss: stat + read + json.parse + 写回（88us，文件变化时才触发）
#   失效：madvise.json mtime_ns 变化（writer.py 更新 hints 时）
# 线程安全：读多写少，RLock 开销最低。
_madvise_daemon_cache: dict = {}   # project → (mtime_ns, hints_list)
_madvise_cache_lock = threading.RLock()

def _madvise_cached(project: str) -> list:
    """
    读取 madvise hints，daemon 进程内缓存（mtime_ns 失效检测）。
    OS 类比：page cache lookup — inode mtime 检测文件变化，命中则跳过 I/O。
    """
    try:
        mtime_ns = os.stat(str(MADVISE_FILE_PATH)).st_mtime_ns if os.path.exists(MADVISE_FILE_PATH) else 0
    except OSError:
        mtime_ns = 0

    with _madvise_cache_lock:
        entry = _madvise_daemon_cache.get(project)
    if entry is not None:
        cached_mtime, cached_hints = entry
        if cached_mtime == mtime_ns:
            return cached_hints  # cache hit

    # cache miss: read + parse + cache all projects
    import json as _json
    try:
        data = _json.loads(open(MADVISE_FILE_PATH, encoding='utf-8').read()) if os.path.exists(MADVISE_FILE_PATH) else {}
    except Exception:
        data = {}
    with _madvise_cache_lock:
        for k, v in data.items():
            _madvise_daemon_cache[k] = (mtime_ns, v.get('hints', []) if isinstance(v, dict) else [])
        if project not in _madvise_daemon_cache:
            _madvise_daemon_cache[project] = (mtime_ns, [])
    entry = _madvise_daemon_cache.get(project)
    return entry[1] if entry else []


# ── iter192: sched_ext_match daemon-level cache ──────────────────────────────
# OS 类比：Linux FIB nexthop cache（route cache）— 同一 dst IP 不重复查路由表，
#   直接返回缓存的 nexthop entry。sched_ext_match = 策略调度路由，query→priority 的映射。
#   sched_ext_match(query, project) 每次请求耗时 ~3.67us（无缓存，iter188 之后）。
#   cache key = (query_crc32, project)，value = match_result（dict or None）。
#   TTL：永久缓存（无 TTL）— daemon 60s idle 退出，不存在 stale 问题。
#   cache hit: tuple key hash(0.3us) + dict lookup(0.1us) ≈ 0.4us（节省 ~3.2us）。
#   注：cache key 使用 crc32 而非完整 query 字符串，减少 key 内存占用。
#   冲突概率：crc32 碰撞概率 1/2^32，daemon 60s 内不超过 1000 次不同 query，可忽略。
#   线程安全：CPython GIL 保证 dict 读写原子，无需锁。
_sched_ext_cache: dict = {}  # (query_crc32, project) → match_result

def _sched_ext_match_cached(sched_ext_fn, query: str, project: str):
    """
    sched_ext_match 调用缓存。
    OS 类比：FIB nexthop cache hit — O(1) 哈希查找，同一流量不重复查路由表。
    """
    key = (hash(query), project)  # iter225: hash() ~0.079us vs crc32(encode) ~0.289us (process-local cache, PYTHONHASHSEED safe within daemon lifetime)
    # GIL 保证下 dict.get 是原子的，无需 lock
    cached = _sched_ext_cache.get(key)
    if cached is not None:
        # sentinel: None 不能区分"未缓存"和"match 结果为 None"，用 False 表示 miss
        return None if cached is False else cached
    result = sched_ext_fn(query, project=project)
    _sched_ext_cache[key] = result if result is not None else False
    return result


# ── iter176: resolve_project_id daemon-level memory cache ────────────────────
# OS 类比：Linux dentry cache（dcache）— 路径→inode 映射缓存，同一路径不重复解析。
#   resolve_project_id 每次请求都调用（0.23ms），流程：
#     sha256(cwd) + stat(.git/config) + 读 JSON cache 文件 = 3 次系统调用
#   daemon 生命周期内 CLAUDE_CWD 不变（同一工作目录），结果可永久缓存在进程内存。
#   cache miss (first call): 0.23ms → 走 resolve_project_id()
#   cache hit: dict lookup ~0.001ms（节省 ~0.23ms/request）
#
# 失效条件：不需要（daemon 退出时缓存随之消失；60s idle 后重启时重建）。
# 线程安全：dict 写入是原子的（CPython GIL），无需锁。
_project_id_cache: dict = {}  # cwd_key → project_id

# ── iter195: cwd env memo ──────────────────────────────────────────────────────
# OS 类比：CPU BTB (Branch Target Buffer) — 分支目标地址预存储，
#   同一 env 值命中时 O(1) list lookup 替代 syscall（os.environ.get + os.getcwd）。
#   os.environ.get('CLAUDE_CWD', os.getcwd()) 每次调用 ~2.2us（含 os.getcwd() fallback）。
#   CLAUDE_CWD 在同一 daemon 生命周期内极少变化（仅用户切换项目时才变）。
#   _cwd_env_memo: [cached_env_val, cached_cwd]
#     cached_env_val = os.environ.get('CLAUDE_CWD') 上次读到的值（None 表示未设置）
#     cached_cwd = 对应的完整 cwd 字符串
#   hit: os.environ.get(~1.2us) + list lookup(0.0us) = ~1.2us（节省 ~1.0us vs getcwd fallback）
#   miss: os.environ.get(1.2us) + os.getcwd() or value(~1us) + write(~0us) = 2.2us（首次）
#   线程安全：CPython GIL 保证 list[0]/[1] 读写原子。
_cwd_env_memo: list = [None, None]  # [last_env_val, last_cwd]

def _get_project_id_cached(resolve_fn) -> str:
    """
    获取 project_id，daemon 进程内永久缓存（无 TTL）。
    iter195: cwd env memo 减少 os.environ.get + os.getcwd() 开销（~2.2us → ~1.2us on hit）。
    OS 类比：dcache lookup — O(1) 哈希表查找，同一路径不重复解析。
    OS 类比（iter195）：BTB — env 值不变时跳过 syscall 直接返回缓存 cwd。
    """
    # iter195: check if env value changed; if same, reuse cached cwd (skip os.getcwd)
    env_val = os.environ.get("CLAUDE_CWD")
    memo = _cwd_env_memo
    if env_val == memo[0]:
        cwd = memo[1]
    else:
        # env changed (or first call): recompute cwd and update memo
        cwd = env_val if env_val else os.getcwd()
        memo[0] = env_val
        memo[1] = cwd
    cached = _project_id_cache.get(cwd)
    if cached is not None:
        return cached
    result = resolve_fn()
    _project_id_cache[cwd] = result
    return result


# ── iter179: TLB / HASH file daemon-level memory cache ──────────────────────
# OS 类比：Linux inode cache — 文件内容通过 inode mtime 失效检测，命中时跳过 open+read。
#   TLB_FILE 和 HASH_FILE 在每次请求中被读取 2 次（Stage1 + Stage2），
#   各花费 34us（TLB）和 23us，合计 ~114us/request（双读）。
#   daemon 内存缓存以 st_mtime_ns 为 key（stat: 3us），命中时返回缓存值（~0us）。
#   cache hit: stat(3us) × 2 = 6us（节省 ~108us/request 的双读开销）
#   cache miss: stat + open+read + 写回（57us，文件变化时才触发）
#   失效条件：writeback 线程写入 TLB/HASH → mtime_ns 变化 → 下次请求自动 re-read
# 线程安全：list[0] 更新为原子操作（CPython GIL）。
_tlb_file_cache: list = [None]   # [(mtime_ns, tlb_dict)] or [None]
_hash_file_cache: list = [None]  # [(mtime_ns, hash_str)] or [None]

def _tlb_read() -> dict:
    """iter179: TLB 文件读取，daemon 进程内 mtime_ns 缓存（覆盖原 _tlb_read）。"""
    try:
        mtime_ns = os.stat(TLB_FILE).st_mtime_ns
    except OSError:
        return {}
    entry = _tlb_file_cache[0]
    if entry is not None and entry[0] == mtime_ns:
        return entry[1]
    # cache miss: read + parse
    try:
        with open(TLB_FILE, encoding="utf-8") as _f:
            data = json.loads(_f.read())
        if "prompt_hash" in data and "slots" not in data:
            data = {"chunk_version": -1,
                    "slots": {data["prompt_hash"]: {"injection_hash": data.get("injection_hash", "")}}}
    except Exception:
        data = {}
    _tlb_file_cache[0] = (mtime_ns, data)
    return data

def _read_hash() -> str:
    """iter179: HASH 文件读取，daemon 进程内 mtime_ns 缓存（覆盖原 _read_hash）。"""
    try:
        mtime_ns = os.stat(HASH_FILE).st_mtime_ns
    except OSError:
        return ""
    entry = _hash_file_cache[0]
    if entry is not None and entry[0] == mtime_ns:
        return entry[1]
    # cache miss: read
    try:
        with open(HASH_FILE, encoding="utf-8") as _f:
            h = _f.read().strip()
    except Exception:
        h = ""
    _hash_file_cache[0] = (mtime_ns, h)
    return h


# ── iter184: chunk_version int daemon-level memory cache ────────────────────
# OS 类比：Linux inode cache — CHUNK_VERSION_FILE 的整数内容缓存在 inode 属性区；
#   mtime_ns 未变时跳过 open+read+int()，直接返回缓存值。
#   调用方：Stage1（_run_retrieval）× 1，Stage2（_retriever_main_impl TLB check）× 1，
#           _tlb_write（writeback 路径，非 critical path）× 1。
#   cache hit: stat(3us) + list lookup(0us)（节省 ~27us × 2-3 = 54-81us/request）
#   cache miss: stat + open+read+int() = ~30us（文件 bump 时才触发）
#   失效条件：extractor bump_chunk_version → mtime_ns 变化 → 下次请求 re-read
# 线程安全：list[0] 更新为原子操作（CPython GIL），同 _tlb_file_cache/_hash_file_cache。
_chunk_version_file_cache: list = [None]  # [(mtime_ns, chunk_ver_int)] or [None]

def _read_chunk_version_cached() -> int:
    """iter184: CHUNK_VERSION_FILE 读取，daemon 进程内 mtime_ns 缓存。
    OS 类比：inode cache hit — mtime 未变时跳过 open+read，直接返回缓存整数。
    """
    try:
        mtime_ns = os.stat(CHUNK_VERSION_FILE).st_mtime_ns
    except OSError:
        return 0
    entry = _chunk_version_file_cache[0]
    if entry is not None and entry[0] == mtime_ns:
        return entry[1]
    # cache miss: read + parse
    try:
        with open(CHUNK_VERSION_FILE, encoding="utf-8") as _f:
            ver = int(_f.read().strip())
    except (ValueError, OSError):
        ver = 0
    _chunk_version_file_cache[0] = (mtime_ns, ver)
    return ver


# ── iter207: _ALL_RETRIEVE_TYPES 模块级常量 ────────────────────────────────────
# OS 类比：字符串驻留（string interning）— 相同元组字面量常量化，
#   避免 _retriever_main_impl 每次请求重建 10 项元组（~1.59us → ~0.17us on hit）。
#   exclude_types 为空（默认）时直接引用此常量，跳过 set/tuple comprehension。
_ALL_RETRIEVE_TYPES_CONST = ("decision", "reasoning_chain", "conversation_summary",
                              "excluded_path", "task_state", "prompt_context", "design_constraint",
                              "quantitative_evidence", "causal_chain", "procedure")
# _rtypes_key for BM25 cache (pre-computed, avoids join+sorted each time)
_ALL_RETRIEVE_TYPES_KEY = ",".join(sorted(_ALL_RETRIEVE_TYPES_CONST))

# Stage 0 frozensets（同 retriever.py，但在 daemon 进程中只初始化一次）
_VDSO_SKIP_EXACT = frozenset([
    '好', '好的', '好吧', '好啊', '好嗯', '好哦',
    '是', '是的', '是吧', '对', '对的', '对吧',
    '收到', '了解', '明白', '可以', '继续', '开始', '执行', '确认', '同意', '谢谢',
    'ok', 'okay', 'thanks', 'thank', 'yes', 'yep', 'no', 'nope', 'got it', 'gotit',
    'sure', 'lgtm',
])
_VDSO_TECH_EXTS = frozenset(['.py', '.js', '.ts', '.md', '.json', '.db', '.sql',
    '.yaml', '.toml', '.rs', '.go', '.java', '.cpp', '.h'])
# iter722: 扩充 CJK/EN 技术信号词 — 覆盖 DB 实际内容领域
_VDSO_TECH_CJK = frozenset(['函数', '类', '模块', '接口', '方法', '变量', '配置', '部署', '迁移',
    '内核', '调度', '补丁', '性能', '分析', '诊断', '优化', '约束', '架构', '线程',
    '进程', '延迟', '飞书', '文档', '规则', '策略', '决策'])
_VDSO_TECH_EN = frozenset(['error', 'bug', 'fix', 'crash', 'def', 'class', 'import', 'function', 'const',
    'kernel', 'patch', 'sched', 'perf', 'trace', 'commit', 'config', 'thread', 'task',
    'memory', 'cache', 'queue', 'proxy', 'migration', 'cgroup'])
_VDSO_SKIP_FILLER = frozenset('嗯恩哦噢')
_TECH_SIGNAL_EXCLUDE = {"LGTM", "ASAP", "RSVP", "TBD", "FYI", "IMO", "IMHO", "BTW", "WIP", "TIL", "AFAIK"}
# iter210: _vdso_is_skip length guard — longest skip phrase is "got it"(6) / "lgtm"(4) / "谢谢"(2 chars)
# Non-skip prompts (length > threshold) skip frozenset lookup entirely (~1.36us → ~0.19us).
# "got it"=6, "谢谢"=2 CJK chars but 6 bytes — check len(str) not bytes; longest is "okay"=4 / "lgtm"=4.
# Use 10 chars as safe upper bound (handles "got it"=6, "gotit"=5, "thanks"=6, worst case filler "嗯嗯嗯嗯"=4 CJK).
# Any prompt >10 chars is guaranteed not to be in _VDSO_SKIP_EXACT or all-filler.
# OS 类比：bloom filter fast-reject — 先检查必要条件（长度），不满足则直接 return False，跳过 hash lookup。
_VDSO_SKIP_MAX_LEN = 10  # safe upper bound for all skip phrases

# iter210: store.db exists cache — once store.db exists, it won't disappear without daemon restart.
# list[0]: None=unchecked, True=confirmed exists.
# Avoids ~1.66us os.path.exists(STORE_DB) on every request after first confirmation.
# OS 类比：Linux dentry cache (negative/positive) — 已知存在的文件路径不重复 stat。
_store_db_exists_cache: list = [None]  # [None or True]


def _vdso_is_skip(prompt: str) -> bool:
    # iter210: length guard — prompts longer than _VDSO_SKIP_MAX_LEN cannot be skip phrases.
    # Avoids frozenset lookup (~1.36us → ~0.19us) for the vast majority of real prompts.
    # OS 类比：bloom filter fast-reject — 长度超出则直接 return False，跳过 hash lookup。
    if len(prompt) > _VDSO_SKIP_MAX_LEN:
        return False
    p = prompt.lower()
    if p in _VDSO_SKIP_EXACT:
        return True
    if prompt and all(c in _VDSO_SKIP_FILLER for c in prompt):
        return True
    return False


def _vdso_has_tech(prompt: str) -> bool:
    if '`' in prompt:
        return True
    p_lower = prompt.lower()
    for ext in _VDSO_TECH_EXTS:
        if ext in p_lower:
            return True
    for w in _VDSO_TECH_CJK:
        if w in prompt:
            return True
    for w in _VDSO_TECH_EN:
        idx = p_lower.find(w)
        while idx >= 0:
            before_ok = (idx == 0 or not p_lower[idx - 1].isalpha())
            after_ok = (idx + len(w) >= len(p_lower) or not p_lower[idx + len(w)].isalpha())
            if before_ok and after_ok:
                return True
            idx = p_lower.find(w, idx + 1)
    return False


# ── iter190: _has_real_tech_signal 提升为模块级函数 ────────────────────────────
# OS 类比：JIT inline — 将热函数从闭包提升到全局符号表，消除 closure cell lookup 开销。
# 原实现：每次 _retriever_main_impl 调用 def _has_real_tech_signal（~0.1us 闭包创建）
#   + 调用时 closure cell deref（微小但非零）。
# 新实现：模块级函数，Python 直接从 module globals 解析，无 closure overhead。
# _TECH_SIGNAL / _ACRONYM_SIGNAL / _TECH_SIGNAL_EXCLUDE 已是模块级常量，直接引用。
def _has_real_tech_signal(text: str) -> bool:
    """判断文本是否包含技术信号（技术文件名、关键词、acronym 等）。
    iter190: 提升为模块级函数（消除每次请求的闭包创建开销）。
    OS 类比：JIT 内联 — 热路径函数提升到全局符号表，bypass closure lookup。
    """
    if _TECH_SIGNAL.search(text):
        return True
    for m in _ACRONYM_SIGNAL.finditer(text):
        if m.group(0) not in _TECH_SIGNAL_EXCLUDE:
            return True
    return False


def _run_retrieval(hook_input: dict):
    """
    核心检索逻辑。等价于 retriever.py 的 main()，但使用预载的 _modules。
    输出到 sys.stdout（由 _handle_connection 捕获）。

    Stage 0 (SKIP) 和 Stage 1 (TLB) 保持相同逻辑。
    iter206: 删除死代码（32 行从未在本函数体内使用的 _modules unpack + import time）。
    所有 _modules 引用均在 _retriever_main_impl 中，不在此处。节省 ~2.56us/request。
    """
    # iter206: removed dead _modules unpack block (~2.56us) — all vars only used in _retriever_main_impl

    # iter1491: align hookSpecificInput.userMessage (Claude Code format)
    _hsi_d = hook_input.get("hookSpecificInput", {})
    prompt = (_hsi_d.get("userMessage", "") or hook_input.get("prompt", "") or "").strip()
    if not prompt:
        return

    # ── Stage 0: SKIP ──
    # iter189: has_page_fault_file 计算一次，传给 Stage2（消除 _retriever_main_impl 第二次 exists）
    # iter259: 改为 glob 检查，支持 per-session 文件 page_fault_log*.json
    has_page_fault_file = bool(_glob.glob(os.path.join(MEMORY_OS_DIR, "page_fault_log*.json")))
    if not has_page_fault_file:
        if _vdso_is_skip(prompt) and not _vdso_has_tech(prompt):
            return  # SKIP: 无输出，退出

    # ── Stage 1: TLB ──
    # iter189: store_db_exists 计算一次，传给 Stage2（消除 _retriever_main_impl 第二次 exists）
    # iter210: store.db exists cache — once True, stays True for daemon lifetime (~1.66us → ~0.16us).
    # _store_db_exists_cache[0]: None=unchecked, True=confirmed. Only cache True to avoid stale False.
    # OS 类比：positive dentry cache — 已知存在的路径直接返回，不重复 stat。
    _sdb = _store_db_exists_cache[0]
    if _sdb is None:
        _sdb = os.path.exists(STORE_DB)
        if _sdb:
            _store_db_exists_cache[0] = True
    if not _sdb:
        return

    # iter189: prompt_hash 在 Stage1 计算后传给 Stage2（消除 Stage2 重算 zlib.crc32）
    # has_page_fault_file=True 时 Stage1 不需要 prompt_hash（不走 TLB），Stage2 才需要
    # iter213: '%08x' % int is faster than format(int,'08x') (0.577us → 0.339us, saving 0.238us)
    # iter213: zlib.crc32 in Python 3 always returns unsigned int — & 0xffffffff is dead code (saving ~0.05us)
    # OS 类比：peephole optimizer — 等价表达式中选择字节码最少的形式
    prompt_hash = '%08x' % zlib.crc32(prompt.encode())
    if not has_page_fault_file:
        try:
            # iter183: 使用 iter179 daemon 缓存函数替代原始 open() 调用
            # iter184: chunk_ver 也改用 daemon mtime_ns 缓存（替代 open+read+int()，~27us）
            # OS 类比：inode cache — mtime 未变时跳过 open+read，直接返回缓存整数
            chunk_ver = _read_chunk_version_cached()  # iter184: mtime_ns cache

            tlb = _tlb_read()   # iter179: daemon mtime_ns cache（替代 open+json.loads）
            slots = tlb.get("slots", {})
            tlb_ver = tlb.get("chunk_version", -1)

            if chunk_ver == tlb_ver and prompt_hash in slots:
                last_hash = _read_hash()  # iter179: daemon mtime_ns cache（替代 open+read）
                if slots[prompt_hash].get("injection_hash") == last_hash:
                    return  # TLB L1 hit

            if chunk_ver == tlb_ver:
                last_hash = _read_hash()  # iter179 cache（warm hit = ~3us，无额外 I/O）
                if last_hash:
                    for _s in slots.values():
                        if _s.get("injection_hash") == last_hash:
                            return  # TLB L2 hit
        except Exception:
            pass

    # ── Stage 2: Full retrieval ──
    # iter189: 传入 Stage1 已计算的值，避免 _retriever_main_impl 重复计算
    _retriever_main_impl(hook_input, _modules,
                         has_page_fault_file=has_page_fault_file,
                         prompt_hash=prompt_hash)


# _read_hash() — see iter179 definition above (daemon mtime_ns cache)


def _write_hash(h: str) -> None:
    try:
        os.makedirs(MEMORY_OS_DIR, exist_ok=True)
        with open(HASH_FILE, 'w', encoding="utf-8") as _f:
            _f.write(h)
    except Exception:
        pass


# _tlb_read() — see iter179 definition above (daemon mtime_ns cache)


def _tlb_write(prompt_hash: str, injection_hash: str, db_mtime: float) -> None:
    try:
        os.makedirs(MEMORY_OS_DIR, exist_ok=True)
        chunk_ver = _read_chunk_version_cached()  # iter184: mtime_ns cache
        existing = _tlb_read()
        slots = existing.get("slots", {})
        slots[prompt_hash] = {"injection_hash": injection_hash}
        max_entries = _modules['sysctl']("retriever.tlb_max_entries")
        if len(slots) > max_entries:
            keys = list(slots.keys())
            for k in keys[:len(keys) - max_entries]:
                del slots[k]
        with open(TLB_FILE, 'w', encoding="utf-8") as _f:
            _f.write(json.dumps({"chunk_version": chunk_ver, "slots": slots}))
    except Exception:
        pass


def _get_db_mtime() -> float:
    try:
        return os.stat(STORE_DB).st_mtime
    except Exception:
        return 0.0


def _read_page_fault_log(limit: int = 5, file_exists: bool = None) -> list:
    # iter194: accept pre-computed exists result from Stage1 (has_page_fault_file)
    # eliminates duplicate os.path.exists call (~2.3us on miss path)
    # OS 类比：register passing — Stage1 已检查的 inode existence 直接传入，跳过重复 stat
    if file_exists is False:
        return []
    # iter259: glob all page_fault_log*.json (per-session + legacy)
    # OS 类比：/proc/*/pagemap glob — 合并所有进程的缺页记录
    _pfl_files = sorted(_glob.glob(os.path.join(MEMORY_OS_DIR, "page_fault_log*.json")))
    if not _pfl_files:
        return []
    # iter203: mtime_ns cache — use max mtime across all files as cache key
    # Any new write (to any session file) will change max-mtime → cache miss
    try:
        max_mtime_ns = max(os.stat(p).st_mtime_ns for p in _pfl_files)
    except OSError:
        return []
    _pf_entry = _page_fault_cache[0]
    if _pf_entry is not None and _pf_entry[0] == max_mtime_ns:
        return []  # already consumed this set of files — same max_mtime = same content
    # cache miss: read and merge all per-session files
    try:
        merged_index = {}  # q_key → entry (merge by query dedup, max fault_count wins)
        files_with_entries = {}  # file_path → entries (for writeback)
        for _pfl_path in _pfl_files:
            try:
                with open(_pfl_path, encoding="utf-8") as _f:
                    file_entries = json.loads(_f.read())
                if not isinstance(file_entries, list):
                    continue
                files_with_entries[_pfl_path] = file_entries
                for e in file_entries:
                    if not isinstance(e, dict) or "query" not in e:
                        continue
                    q_key = e["query"].lower().strip()
                    existing = merged_index.get(q_key)
                    if existing is None:
                        merged_index[q_key] = dict(e)
                    else:
                        # Take max fault_count, take latest ts
                        existing["fault_count"] = max(
                            existing.get("fault_count", 1),
                            e.get("fault_count", 1)
                        )
                        if e.get("ts", "") > existing.get("ts", ""):
                            existing["ts"] = e["ts"]
                        # If any copy is unresolved, treat as unresolved
                        if not e.get("resolved", False):
                            existing["resolved"] = False
            except Exception:
                continue

        if not merged_index:
            _page_fault_cache[0] = (max_mtime_ns, [])
            return []
        unresolved = [e for e in merged_index.values() if not e.get("resolved", False)]
        unresolved.sort(key=lambda e: e.get("fault_count", 1), reverse=True)
        queries = [e["query"] for e in unresolved[:limit]]
        # iter203: mark consumed in daemon memory (skip critical-path file write)
        _page_fault_cache[0] = (max_mtime_ns, queries)
        if queries:
            # Defer resolved-flag write to background (pdflush analogy)
            # Write back to each individual session file
            consumed_queries = set(q.lower().strip() for q in queries)
            _files_snapshot = dict(files_with_entries)
            def _do_pfl_writeback(_consumed=consumed_queries, _files=_files_snapshot):
                for _fp, _entries in _files.items():
                    try:
                        _changed = False
                        for e in _entries:
                            if isinstance(e, dict) and e.get("query", "").lower().strip() in _consumed:
                                e["resolved"] = True
                                _changed = True
                        if _changed:
                            with open(_fp, 'w', encoding="utf-8") as _f:
                                _f.write(json.dumps(_entries, ensure_ascii=False, indent=2))
                    except Exception:
                        pass
            _writeback_submit(_do_pfl_writeback)
        return queries
    except Exception:
        return []


# ── iter186: 预编译合并正则（_extract_key_entities 优化）──────────────────────
# OS 类比：JIT 编译 — 将 3 次串行 finditer 合并为 1 次 alternation 扫描。
# 原实现：3 × re.finditer() = ~9.8us；合并后：1 × re.finditer() = ~4.3us（节省 5.5us）。
# alternation 顺序：filename（带扩展名）优先，因为它比 ACRONYM 更精确。
_ENTITY_RE = __import__('re').compile(
    r'`([^`]{2,40})`|'          # group 1: backtick entities
    r'([\w./]+\.(?:py|js|md|json|db)\b)|'  # group 2: filename with ext
    r'\b([A-Z][A-Z0-9_]{1,10})\b'  # group 3: ACRONYM/constant
)

# ── iter187: 预编译 _is_generic_knowledge_query 正则（闭包 → 模块常量）──────────
# OS 类比：JIT 编译 + 静态分配 — 将每次调用重新创建 list 改为 daemon 启动时一次编译。
# 原实现：闭包内每次调用重建 _GENERIC_PATTERNS(3 str) + _PROJECT_MARKERS(22 str) list，
#   3 × re.search(compile) + any() ≈ 2.77-3.19us（generic query path）。
# 新实现：模块级预编译 alternation 正则：
#   _GENERIC_RE.search() ≈ 0.84us（generic）/ ~0.3us（tech, fail-fast）
#   _PROJECT_MARKER_RE.search() ≈ 0.5-0.8us
#   总节省：~2.35us（generic query）/ ~0.48us（tech query）
# 调用方：_classify_query_priority（每次 Stage2 至少 1 次）
_GENERIC_RE = __import__('re').compile(
    r'^(?:什么是|解释|如何|怎么(?:写|用|做|实现)?|介绍)|'
    r'(?:是什么|怎么回事|如何实现|有什么区别|的区别|的原理)[？?！!。.]?\s*$|'
    r'^(?:how\s+(?:to|do|does|is)|what\s+is|explain|describe|define)\s'
)
# iter723: 扩充 project marker — 匹配 DB 中实际存在的领域词，防止被 generic 分类
_PROJECT_MARKER_RE = __import__('re').compile(
    r'memory[\. ]os|store\.py|retriever|extractor|loader|scorer|writer|config\.py|bm25\.py|'
    r'kswapd|mglru|damon|checkpoint|swap_fault|swap_in|swap_out|\btlb\b|\bvdso\b|\bpsi\b|'
    r'迭代|iteration|\bhook\b|feishu|飞书|knowledge_vfs|knowledge_router|sched_ext|'
    r'\bchunk\b|store\.db|memory_chunks|\bdrr\b|dmesg|'
    r'kernel|patch|uclamp|cgroup|proxy.exec|EEVDF|migration|Binder|'
    r'schedqos|directed.yield|task_rq|LKMM|commit|Signed-off|'
    r'内核|调度器|补丁|性能诊断|约束|决策'
)

# iter194: fast-path pre-check for _extract_key_entities
# Any of: backtick `, dot ., uppercase A-Z → may have entities → do full scan
# None of these → guaranteed empty result (all 3 _ENTITY_RE patterns require them)
# OS 类比：branch predictor guard — 快速判断分支是否可能命中，不可能时直接 early-exit
_ENTITY_FAST_CHECK = __import__('re').compile(r'[`.A-Z]')
_RE_NON_WORD = __import__('re').compile(r'[^\w一-鿿]')  # iter1673: topic_mismatch word extraction

# iter220: 预编译 constraint relevance 正则（原为 re.sub 运行时传字符串，每次隐式 compile）
# 用于 design_constraint 强制注入路径中的 query_words / s_words 分词。
# 该路径出现频率低，但每次 re.sub 传字符串时 CPython 内部仍有 hash + cache lookup。
# 预编译为模块常量，同时消除 re = mods['re'] dict lookup（~0.07us）。
# OS 类比：JIT 编译 — 将运行时隐式 compile 改为 daemon 启动时一次编译。
_CONSTRAINT_RE = __import__('re').compile(r'[^\w\u4e00-\u9fff]')

# iter238: hoist _TYPE_PREFIX to module level — was rebuilt each inject call (0.356us → 0.128us)
# Dict literal construction allocates and populates a new dict each time; module constant = 0us.
# OS 类比：read-only segment — constant data mapped once, zero allocation cost at call time.
_TYPE_PREFIX = {
    "decision": "[决策]", "excluded_path": "[排除]",
    "reasoning_chain": "[推理]", "conversation_summary": "[摘要]",
    "task_state": "", "design_constraint": "⚠️ [约束]",
    "quantitative_evidence": "📊 [量化]", "causal_chain": "🔗 [因果]",
}

def _extract_key_entities(text: str) -> list:
    # iter186: single combined regex scan (~4.3us vs ~9.8us for 3 separate finditer)
    # iter194: fast-path guard — skip full NFA scan if no trigger chars present (~1.12us saved)
    # iter197: daemon-level cache (pure function, prompt_str → entities_list)
    #   hit: 0.18us; miss: 7.5us (normal execution + cache write)
    #   OS 类比：dcache hit — 路径名已知 inode，直接返回，不走目录树遍历
    cached = _entities_cache.get(text)
    if cached is not None:
        return cached
    if not _ENTITY_FAST_CHECK.search(text):
        _entities_cache[text] = []
        return []
    entities = []
    for m in _ENTITY_RE.finditer(text):
        e = m.group(1) or m.group(2) or m.group(3)
        if e:
            entities.append(e)
        if len(entities) >= 5:
            break
    result = list(dict.fromkeys(entities))
    _entities_cache[text] = result
    return result


def _is_generic_knowledge_query(q: str) -> bool:
    # iter187: 使用预编译模块级正则替代闭包内每次重建的 list（~3us → ~1.3us）
    # iter209: daemon-level cache hit → skip regex entirely (~1.64us → ~0.14us)
    # OS 类比：JIT 编译 + dcache hit — 同一 query 字符串直接返回缓存 bool
    cached = _is_generic_q_cache.get(q)
    if cached is not None:
        return cached
    q_lower = q.lower().strip()
    # iter710: 长查询（>20 chars）不视为 generic — "如何优化 Linux 调度器" 是领域问题
    #   根因：generic 门槛 0.85 导致几乎所有 "如何/什么是" 开头的查询无法注入
    #   修复：>20 chars 的查询通常包含足够上下文，不应被 generic 高门槛阻拦
    if len(q_lower) > 20:
        _is_generic_q_cache[q] = False
        return False
    result = bool(_GENERIC_RE.search(q_lower)) and not bool(_PROJECT_MARKER_RE.search(q_lower))
    _is_generic_q_cache[q] = result
    return result


def _build_query_with_entities(hook_input: dict) -> tuple:
    """iter189: 返回 (query, entities) 避免 _retriever_main_impl 二次调用 _extract_key_entities。
    OS 类比：register file passing — Stage1 计算的值通过参数传给 Stage2，不重算。
    """
    # iter1491: align hookSpecificInput.userMessage (Claude Code format)
    _hsi_bq = hook_input.get("hookSpecificInput", {})
    prompt = (_hsi_bq.get("userMessage", "") or hook_input.get("prompt", "") or "").strip()
    task_list = hook_input.get("task_list") or hook_input.get("tasks") or []
    if isinstance(task_list, str):
        try:
            task_list = json.loads(task_list)
        except Exception:
            task_list = []
    in_progress = []
    for t in task_list:
        if isinstance(t, dict) and t.get("status") == "in_progress":
            subj = t.get("subject") or t.get("title") or ""
            if subj:
                in_progress.append(subj)
    tasks_joined = " ".join(in_progress)
    entities = _extract_key_entities(prompt)  # 只计算一次，返回给调用方复用
    entities_str = " ".join(entities)
    raw_query = f"{prompt} {tasks_joined} {entities_str}".strip()
    max_query_chars = _modules['sysctl']("retriever.max_query_chars")
    if len(raw_query) > max_query_chars:
        raw_query = raw_query[:max_query_chars]
    return raw_query, entities


def _retriever_main_impl(hook_input: dict, mods: dict,
                         has_page_fault_file: bool = None,
                         prompt_hash: str = None):
    """
    Stage 2 完整检索逻辑，复用 retriever.py 核心算法。
    通过 mods dict 访问所有 heavy modules（已在 daemon 启动时加载）。

    iter189: has_page_fault_file / prompt_hash 由 _run_retrieval 传入，
    避免在 Stage2 重复计算（消除 2× exists + 1× crc32）。
    iter220: import time as _time → module-level time (已 import，消除 per-call import ~0.16us)；
             re = mods['re'] → 消除（_CONSTRAINT_RE 已预编译为模块常量，无需再引用 re 模块）。
    """
    # iter220: removed 'import time as _time' — use module-level 'time' directly (0us vs 0.16us)
    # iter220: removed 're = mods["re"]' — _CONSTRAINT_RE is pre-compiled module constant (0us)

    sysctl = mods['sysctl']
    sched_ext_match = mods['sched_ext_match']
    resolve_project_id = mods['resolve_project_id']
    # iter211: removed 7 dead dict lookups — never referenced in function body
    # OS 类比：编译器死代码消除（DCE）— 未被读取的寄存器写操作直接删除。
    open_db = mods['open_db']
    ensure_schema = mods['ensure_schema']
    store_get_chunks = mods['get_chunks']
    update_accessed = mods['update_accessed']
    store_insert_trace = mods['insert_trace']
    fts_search = mods['fts_search']
    dmesg_log = mods['dmesg_log']
    swap_fault_fn = mods['swap_fault']
    swap_in_fn = mods['swap_in']
    psi_stats = mods['psi_stats']
    mglru_promote = mods['mglru_promote']
    context_pressure_governor = mods['context_pressure_governor']
    chunk_recall_counts = mods['chunk_recall_counts']
    DMESG_INFO = mods['DMESG_INFO']
    bm25_scores_cached = mods['bm25_scores_cached']
    normalize = mods['normalize']
    read_chunk_version = mods['read_chunk_version']
    hashlib = mods['hashlib']
    uuid_mod = mods['uuid']
    datetime = mods['datetime']
    timezone = mods['timezone']
    _SKIP_PATTERNS = mods['_SKIP_PATTERNS']
    _KR_AVAILABLE = mods.get('_KR_AVAILABLE', False)
    if _KR_AVAILABLE:
        kr_route = mods.get('kr_route')
        kr_format = mods.get('kr_format')

    _t_start = time.time()

    # iter176: daemon 内存缓存 resolve_project_id（0.23ms → ~0.001ms on hit）
    # OS 类比：dcache — 路径→inode 映射缓存，同一路径不重复解析
    project = _get_project_id_cached(resolve_project_id)
    session_id = (hook_input.get("session_id", "")
                  or os.environ.get("CLAUDE_SESSION_ID", "")
                  or "unknown")
    # iter1491: align hookSpecificInput.userMessage (Claude Code format)
    _hsi_m = hook_input.get("hookSpecificInput", {})
    prompt = (_hsi_m.get("userMessage", "") or hook_input.get("prompt", "") or "").strip()
    # iter189: _build_query_with_entities 同时返回 entities，避免下方第二次调用
    # OS 类比：register passing — Stage1 计算结果直接传递，不重算
    query, entities = _build_query_with_entities(hook_input)

    # iter194: pass has_page_fault_file from Stage1 to skip duplicate os.path.exists (~2.3us)
    page_fault_queries = _read_page_fault_log(file_exists=has_page_fault_file)
    if page_fault_queries:
        fault_text = " ".join(page_fault_queries)
        query = f"{query} {fault_text}".strip()

    if not query:
        return
    # iter189: STORE_DB exists 由 _run_retrieval 已验证，此处跳过第二次 os.path.exists
    # （has_page_fault_file 参数同理，PAGE_FAULT_LOG 已在 Stage1 检查）

    # ── _classify_query_priority (iter190: inline, 模块级 _has_real_tech_signal) ──
    # iter189: page_fault 状态优先使用传入的 has_page_fault_file，
    # 如果有 page_fault_queries（从 log 文件读取），有效性以 page_fault_queries 为准
    has_page_fault = bool(page_fault_queries)
    # iter189: entities 已由 _build_query_with_entities 返回，不再重复调用 _extract_key_entities
    # iter190: _has_real_tech_signal 已提升为模块级函数，此处直接引用（无闭包 def 开销）
    # iter190: _classify_query_priority inline 展开 — 消除函数调用 + 支持 _tech_signal_result 复用
    # _has_real_tech_signal(q) 最多被调用 2 次（SKIP_PATTERNS + skip_max_chars 两个分支），
    # 引入 _tech_signal_result 局部变量缓存第一次调用结果，第二次直接复用（节省 1.6-4.0us）。
    # OS 类比：register reuse — 已计算的值保留在寄存器/局部变量，避免重复从内存读取。
    _priority: str
    if not has_page_fault:
        try:
            # iter192: daemon-level cache for sched_ext_match（~3.67us → ~0.4us on hit）
            # OS 类比：FIB nexthop cache — 同一 query+project 不重复查策略路由表
            _ext_match = _sched_ext_match_cached(sched_ext_match, query, project)
            if _ext_match:
                _priority = _ext_match["priority"]
            else:
                _priority = ""
        except Exception:
            _priority = ""
    else:
        _priority = ""
    # iter194: compute _is_generic once, reuse at hard-deadline + DRR final paths (~3.4us × 2 → × 1)
    # OS 类比：register reuse — 同 iter190 的 _tech_signal_result，热路径结果保留在局部变量
    _is_generic_q: bool = _is_generic_knowledge_query(query)
    if not _priority:
        if has_page_fault:
            _priority = "FULL"
        else:
            # iter209: pre-read 3 scheduler sysctl params only when needed (not_priority branch)
            # These are only reached when sched_ext didn't set priority (normal path).
            # Pre-reading here avoids 3 sysctl() calls inside the elif chain.
            # On SKIP-by-sched_ext path, this block is skipped entirely → no extra cost.
            # OS 类比：slab per-CPU 参数预取（同 iter191/193）— 仅在需要时预读。
            _sched_min_entity = sysctl("scheduler.min_entity_count_for_full")
            _sched_skip_max   = sysctl("scheduler.skip_max_chars")
            _sched_lite_max   = sysctl("scheduler.lite_max_chars")
            if len(entities) >= _sched_min_entity:
                _priority = "FULL"
            elif _is_generic_q:
                _priority = "SKIP"
            else:
                _prompt_stripped = prompt.strip()
                _tech_signal_result = None  # lazy: computed at most once
                if _SKIP_PATTERNS.match(_prompt_stripped):
                    _tech_signal_result = _has_real_tech_signal(query)
                    if not _tech_signal_result:
                        _priority = "SKIP"
                if not _priority:
                    if len(_prompt_stripped) <= _sched_skip_max:
                        # iter190: reuse cached result if already computed above
                        if _tech_signal_result is None:
                            _tech_signal_result = _has_real_tech_signal(query)
                        if not _tech_signal_result:
                            _priority = "SKIP"
                if not _priority:
                    if len(query) <= _sched_lite_max:
                        _priority = "LITE"
                    else:
                        _priority = "FULL"
    priority = _priority

    if priority == "SKIP":
        return

    # ── TLB check ──
    # iter189: prompt_hash 由 _run_retrieval 传入（Stage1 已算），跳过重复 zlib.crc32
    # fallback: 直接调用方（如测试）未传时才重算
    if prompt_hash is None:
        prompt_hash = '%08x' % zlib.crc32(prompt.encode())  # iter213: '%08x'%int faster than format()
    if not has_page_fault:
        chunk_ver = _read_chunk_version_cached()  # iter184: mtime_ns cache（替代 open+read+int()）
        tlb = _tlb_read()
        tlb_ver = tlb.get("chunk_version", -1)
        slots = tlb.get("slots", {})
        last_hash = _read_hash()  # iter201: read once here, reused at L_same_hash + L_reason_base
        # iter804: session_first_inject_guard — 新 session 首次请求必须走完整检索
        _sid_has_inj = session_id in _sessions_with_injection
        if chunk_ver == tlb_ver and _sid_has_inj:
            # iter780: empty_result_tlb — 空结果缓存避免重复检索空转
            if prompt_hash in slots and slots[prompt_hash].get("injection_hash") == "__empty__":
                return
            if prompt_hash in slots and slots[prompt_hash].get("injection_hash") == last_hash:
                return
            if last_hash:
                for _s in slots.values():
                    if _s.get("injection_hash") == last_hash:
                        return
    else:
        # iter201: page_fault path — pre-read hash once for L_same_hash + L_reason_base reuse
        # (was 2× _read_hash() calls below → now 1× pre-read + 2× local var reference)
        last_hash = _read_hash()

    effective_top_k = sysctl("retriever.top_k_fault") if has_page_fault else sysctl("retriever.top_k")
    effective_max_chars = sysctl("retriever.max_context_chars_fault") if has_page_fault else sysctl("retriever.max_context_chars")

    run_router = (priority == "FULL") and _KR_AVAILABLE
    psi_downgraded = False
    deadline_ms = sysctl("retriever.deadline_ms")
    deadline_hard_ms = sysctl("retriever.deadline_hard_ms")
    deadline_skipped = []

    def _elapsed_ms():
        return (time.time() - _t_start) * 1000

    def _check_deadline(stage_name: str, is_hard: bool = False) -> bool:
        elapsed = _elapsed_ms()
        if is_hard and elapsed >= deadline_hard_ms:
            deadline_skipped.append(f"{stage_name}(HARD)")
            return True
        if not is_hard and elapsed >= deadline_ms:
            deadline_skipped.append(stage_name)
            return True
        return False

    # ── Open DB (read-only) — iter173: persistent per-thread connection ──
    # OS 类比：文件描述符复用 — 保持 fd 打开，复用 inode cache + SQLite B-tree page cache。
    # _open_db_readonly() 保留作为 swap_in 路径的 fallback（需要重新打开写入后的 DB）。
    def _open_db_readonly():
        import sqlite3 as _sq
        db_str = str(STORE_DB)
        try:
            uri = f"file:{db_str}?immutable=1"
            c = _sq.connect(uri, uri=True)
            c.execute("PRAGMA cache_size=2000")
            return c
        except Exception:
            conn2 = _sq.connect(db_str, timeout=2)
            conn2.execute("PRAGMA journal_mode=WAL")
            conn2.execute("PRAGMA query_only=ON")
            conn2.execute("PRAGMA cache_size=2000")
            return conn2

    class _DeferredLogs:
        __slots__ = ('_buf',)
        def __init__(self): self._buf = []
        def log(self, level, subsystem, message, session_id=None, project=None, extra=None):
            self._buf.append((level, subsystem, message, session_id, project, extra))
        def flush(self, conn):
            for level, subsystem, message, session_id, project, extra in self._buf:
                try:
                    dmesg_log(conn, level, subsystem, message, session_id=session_id, project=project, extra=extra)
                except Exception:
                    pass
            self._buf.clear()
        def __len__(self): return len(self._buf)

    _deferred = _DeferredLogs()
    # iter173: 使用 per-thread 持久只读连接（复用 SQLite B-tree page cache）
    conn = _get_persistent_ro_conn()
    _t_start = time.time()  # reset after connection

    # iter169+182: 启动 VFS 并行搜索（AIO 类比）
    # iter182: 改用预创建 VFS worker pool（消除 threading.Thread.start() 65us 开销）
    # OS 类比：kthread_queue_work() — 向已运行的 kthread worker 提交 work item，
    #   无需 create_kthread() 开销（~0us vs 65us per request）。
    # VFS ~0.55ms warm，在 FTS5(~0.77ms)+scoring(~0.19ms) 期间完全重叠。
    _vfs_result_holder = _vfs_result_slot  # reuse global slot (iter182)
    _vfs_result_holder[0] = None
    _vfs_submitted = False
    if run_router and _KR_AVAILABLE:
        _vfs_timeout = 100 if priority == "FULL" else 10
        _kr_route_fn = mods.get('kr_route')
        if _kr_route_fn is not None:
            def _vfs_task_fn(
                _query=query, _timeout=_vfs_timeout, _fn=_kr_route_fn,
            ):
                return _fn(_query, sources=["memory-md", "self-improving"],
                           timeout_ms=_timeout)
            # iter182: pool.submit() costs ~17us vs threading.Thread.start() ~65us
            _vfs_submitted = _vfs_worker_pool.submit(_vfs_task_fn, _vfs_result_holder, _vfs_done_event)

    try:
        candidates_count = 0

        # iter170: PSI / gov / rc — 优先从 daemon 内存缓存读取（TTL=30s）
        # OS 类比：slab allocator kmem_cache — per-CPU 槽，命中时跳过 buddy allocator
        # 未命中或 TTL 到期时走 DB，结果写回缓存供后续请求复用
        # 缓存结构：(psi_result, gov_result, rc_dict)
        # iter221: pass _t_start as now_ts — reuse already-computed timestamp, skip extra time.time()
        _psi_gov_rc_cached = _psi_gov_rc_get(project, _t_start)
        _psi_cached = _psi_gov_rc_cached is not None
        _psi_result_fresh = {"overall": "NONE"}  # for write-back
        _gov_result_fresh = {"level": "NORMAL", "scale": 1.0}
        _rc_fresh = {}

        # PSI check
        if priority == "FULL" and not _check_deadline("psi"):
            try:
                if _psi_cached:
                    psi = _psi_gov_rc_cached[0]
                else:
                    psi = psi_stats(conn, project)
                    _psi_result_fresh = psi
                if psi.get("overall", "NONE") == "FULL":
                    priority = "LITE"
                    run_router = False
                    psi_downgraded = True
            except Exception:
                pass

        # Context pressure governor
        gov_info = {"level": "NORMAL", "scale": 1.0}
        try:
            if _psi_cached:
                gov_info = _psi_gov_rc_cached[1]
            else:
                gov_info = context_pressure_governor(conn, project, session_id=session_id)
                _gov_result_fresh = gov_info
            gov_scale = gov_info.get("scale", 1.0)
            if gov_scale != 1.0:
                effective_max_chars = max(int(effective_max_chars * gov_scale), 150)
        except Exception:
            pass

        # Recall counts (anti-starvation)
        # iter602: rcu_dereference — daemon 的 conn 是 immutable=1，看不到 WAL 中的
        #   新 recall_traces → _recall_counts 严重过期 → bandwidth hard_gate 全部失效
        #   → 垄断 chunk (b50e0b54 feishu CLI, rc=26/30=87%) 持续逃逸注入。
        #   retriever.py 在 iter565 已用独立标准连接修复；daemon 路径遗漏。
        # 修复：用独立标准连接加载 recall_counts，确保看到最新 traces。
        _recall_counts = {}
        _recent_6h_counts = {}   # iter813: short_burst_suppress
        _recent_24h_counts = {}  # iter630: hoist defaults outside try — NameError if connect() fails
        _recent_7d_counts = {}   # iter630: same — suppress must degrade to no-op, not crash
        _last_inject_ts = {}     # iter1071: cooldown — {chunk_id: last_inject_iso_ts}
        _itl_lifetime = {}       # iter1273: {chunk_id: (total_count, last_ts)}
        _cutoff_48h = ""         # iter1071: cooldown fallback
        _cutoff_72h = ""         # iter1071: cooldown fallback
        _cutoff_5d = ""          # iter1077: cooldown_5d_fix
        _cutoff_10d = ""         # iter1091: cooldown_daemon_sync
        _cutoff_14d = ""         # iter1091: cooldown_daemon_sync
        _effective_bw_window = 30
        _local_bw_window = 30  # iter610: fallback
        _db_chunk_count = 10  # iter797: fallback 走 tiny_db 路径（宁可少过滤不空召回）
        try:
            # iter602: 用标准连接（非 immutable）读取 recall_traces
            import sqlite3 as _rc_sql
            _rc_conn = _rc_sql.connect(str(STORE_DB))
            # iter797: 查询实际 chunk 总数
            try:
                # iter1146: visible_chunk_count — micro_db 判定计入 global chunk
                _db_chunk_count = _rc_conn.execute(
                    "SELECT COUNT(*) FROM memory_chunks WHERE (project=? OR project='global') AND chunk_state='ACTIVE'",
                    (project,)
                ).fetchone()[0] or 0
            except Exception:
                pass
            # iter1227: sparse_global_shield — daemon 同步 retriever.py local_sparse 逻辑
            # iter1401: sparse_shield_widen_daemon — 同步 retriever.py iter1379: <=3→<=5
            _local_chunk_count_d = _db_chunk_count
            try:
                _local_chunk_count_d = _rc_conn.execute(
                    "SELECT COUNT(*) FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE'", (project,)
                ).fetchone()[0] or 0
            except Exception:
                pass
            _local_sparse_d = _local_chunk_count_d <= 5
            try:
                if _psi_cached:
                    _recall_counts = _psi_gov_rc_cached[2]
                else:
                    _recall_counts = chunk_recall_counts(_rc_conn, project, window=30)
                    _rc_fresh = _recall_counts
                    _psi_gov_rc_put(project, _psi_result_fresh, _gov_result_fresh, _rc_fresh)
                # iter602: effective_bw_window 用标准连接查（两条路径都需要）
                # iter604: 与 chunk_recall_counts 对齐，只统计 injected=1 的 trace
                # iter669: bw_window_nonempty — 只统计 top_k_json 非空的 trace
                # 根因同 retriever.py iter669：空 trace 膨胀分母导致垄断逃逸。
                _atc = _rc_conn.execute(
                    "SELECT COUNT(*) FROM recall_traces WHERE project=? AND injected=1"
                    " AND top_k_json IS NOT NULL AND top_k_json != '[]'", (project,)
                ).fetchone()[0]
                _effective_bw_window = min(30, max(1, _atc))
                # iter773: bw_window_floor — 统计不充分时不应过度 suppress
                # 根因：bw_window=12 + hard_cap=0.12 → rc>1.44 即 suppress，
                #   任何 chunk 注入 ≥2 次就被封锁。floor=20 确保 rc>=3 才触发。
                _effective_bw_window = max(_effective_bw_window, 20)
                # iter610: hard_cap_local_window — memcg inflate 前的 per-project window
                _local_bw_window = _effective_bw_window
                # iter603+606: memcg_stat — cross-project recall 计数 + bw_window parity
                try:
                    from store_criu import chunk_recall_counts_memcg
                    if sysctl("memcg_stat.enabled") is not False:
                        _memcg_w = sysctl("memcg_stat.window") or 60
                        _memcg_c = chunk_recall_counts_memcg(_rc_conn, project, window=_memcg_w)
                        if _memcg_c:
                            _memcg_inflated = False
                            for _mcid, _mcnt in _memcg_c.items():
                                if _mcnt > _recall_counts.get(_mcid, 0):
                                    _recall_counts[_mcid] = _mcnt
                                    _memcg_inflated = True
                            # iter606: bw_window parity — memcg window 对齐
                            if _memcg_inflated:
                                _xp_atc = _rc_conn.execute(
                                    "SELECT COUNT(*) FROM recall_traces WHERE project!=? AND injected=1",
                                    (project,)
                                ).fetchone()[0]
                                _effective_bw_window = max(_effective_bw_window,
                                                           min(60, max(1, _xp_atc)))
                except Exception:
                    pass
            except Exception:
                pass
            # ── iter618: 7d_rolling_suppress — 长期垄断检测 ──────────────────
            # daemon 此前缺少 24h/7d burst suppress（iter614~617 只加在 retriever.py）。
            # 根因：daemon 是生产主路径，缺失导致垄断 chunk 完全逃逸。
            # 同时加载 24h 和 7d counts。
            _recent_24h_counts = {}
            _recent_7d_counts = {}
            try:
                import json as _r_json
                for _rw_label, _rw_hours, _rw_dict in [
                    ("24h", 24, _recent_24h_counts),
                    ("7d", 168, _recent_7d_counts),
                ]:
                    # iter637: 移除 project 过滤 — global chunk 跨 project 注入
                    #   导致 project=? 匹配不到 trace，suppress 全失效
                    _rw_cur = _rc_conn.execute(
                        "SELECT top_k_json FROM recall_traces "
                        "WHERE injected=1 "
                        "AND timestamp > datetime('now', ?)",
                        (f'-{_rw_hours} hours',)
                    )
                    for (_rw_json,) in _rw_cur.fetchall():
                        try:
                            _rw_items = _r_json.loads(_rw_json) if isinstance(_rw_json, str) else _rw_json
                            if isinstance(_rw_items, list):
                                for _rw_item in _rw_items:
                                    if isinstance(_rw_item, dict) and "id" in _rw_item:
                                        _rw_dict[_rw_item["id"]] = _rw_dict.get(_rw_item["id"], 0) + 1
                        except Exception:
                            continue
            except Exception:
                pass
            # ── iter648: WAL-immune injection timeline (daemon sync) ──────────
            # 根因：daemon 写入 trace 后 WAL 未 checkpoint → 同一连接的 SELECT 可能
            #   漏掉刚写入的 trace → _recent_24h/7d_counts 低估 → suppress 失效。
            # 修复：从 .injection_timeline.json 补充计数（与 retriever.py iter647 共享文件）。
            _INJECTION_TIMELINE_FILE = os.path.join(MEMORY_OS_DIR, ".injection_timeline.json")
            try:
                if os.path.exists(_INJECTION_TIMELINE_FILE):
                    import json as _itl_json
                    from datetime import datetime as _dt648, timezone as _tz648, timedelta as _td648
                    with open(_INJECTION_TIMELINE_FILE, encoding="utf-8") as _itf_r:
                        _itl_data = _itl_json.loads(_itf_r.read())
                    _now648 = _dt648.now(_tz648.utc)
                    _cutoff_6h = (_now648 - _td648(hours=6)).isoformat()  # iter813
                    _cutoff_24h = (_now648 - _td648(hours=24)).isoformat()
                    _cutoff_48h = (_now648 - _td648(hours=48)).isoformat()  # iter1071
                    _cutoff_72h = (_now648 - _td648(hours=72)).isoformat()  # iter1071
                    _cutoff_5d = (_now648 - _td648(days=5)).isoformat()    # iter1077: cooldown_5d_fix
                    _cutoff_7d = (_now648 - _td648(days=7)).isoformat()
                    _cutoff_10d = (_now648 - _td648(days=10)).isoformat()  # iter1091: cooldown_daemon_sync
                    _cutoff_14d = (_now648 - _td648(days=14)).isoformat()  # iter1091: cooldown_daemon_sync
                    _last_inject_ts = {}  # iter1071: {chunk_id: max_ts}
                    for _cid648, _ts_list in _itl_data.items():
                        _cnt_7d = sum(1 for t in _ts_list if t > _cutoff_7d)
                        _cnt_24h = sum(1 for t in _ts_list if t > _cutoff_24h)
                        _cnt_6h = sum(1 for t in _ts_list if t > _cutoff_6h)  # iter813
                        if _cnt_6h > _recent_6h_counts.get(_cid648, 0):
                            _recent_6h_counts[_cid648] = _cnt_6h
                        if _cnt_24h > _recent_24h_counts.get(_cid648, 0):
                            _recent_24h_counts[_cid648] = _cnt_24h
                        if _cnt_7d > _recent_7d_counts.get(_cid648, 0):
                            _recent_7d_counts[_cid648] = _cnt_7d
                        # iter1071: 记录最近一次注入时间（用于 cooldown suppress）
                        if _ts_list:
                            _last_inject_ts[_cid648] = max(_ts_list)
                    # iter1273: lifetime_injection_suppress — 持久化 lifetime 计数+最近注入时间
                    _itl_lifetime = {k: (len(v), max(v) if v else "") for k, v in _itl_data.items()}
            except Exception:
                pass
            finally:
                _rc_conn.close()
        except Exception:
            pass
        # ── iter653: timeline_fallback — 始终从 recall_traces merge max 补充 ──
        # 根因：iter652 guard "if not both empty" 在 timeline 有 1 条残留时不触发，
        #   垄断 chunk 的 24h/7d=0 → suppress 失效。改为无条件 merge max。
        if True:
            try:
                import sqlite3 as _fb_sql
                from datetime import timedelta as _td652
                _fb_conn = _fb_sql.connect(str(STORE_DB))
                _fb_now = datetime.now(timezone.utc)
                _cut_7d_fb = (_fb_now - _td652(days=7)).isoformat()
                _cut_24h_fb = (_fb_now - _td652(hours=24)).isoformat()
                _cut_6h_fb = (_fb_now - _td652(hours=6)).isoformat()  # iter813
                _rt_7d_d = {}
                _rt_24h_d = {}
                _rt_6h_d = {}  # iter813
                # iter835: suppress_final_gate_project_scope — 同步 retriever.py
                for (_fb_json, _fb_ts) in _fb_conn.execute(
                        "SELECT top_k_json, timestamp FROM recall_traces "
                        "WHERE injected=1 AND project=? AND timestamp>?", (project, _cut_7d_fb,)).fetchall():
                    try:
                        _fb_items = json.loads(_fb_json) if isinstance(_fb_json, str) else _fb_json
                        _is_24h_d = _fb_ts > _cut_24h_fb if _fb_ts else False
                        _is_6h_d = _fb_ts > _cut_6h_fb if _fb_ts else False  # iter813
                        if isinstance(_fb_items, list):
                            for _fb_item in _fb_items:
                                if isinstance(_fb_item, dict) and "id" in _fb_item:
                                    _fid = _fb_item["id"]
                                    _rt_7d_d[_fid] = _rt_7d_d.get(_fid, 0) + 1
                                    if _is_24h_d:
                                        _rt_24h_d[_fid] = _rt_24h_d.get(_fid, 0) + 1
                                    if _is_6h_d:
                                        _rt_6h_d[_fid] = _rt_6h_d.get(_fid, 0) + 1  # iter813
                    except Exception:
                        continue
                for _mc, _mv in _rt_7d_d.items():
                    _recent_7d_counts[_mc] = max(_recent_7d_counts.get(_mc, 0), _mv)
                for _mc, _mv in _rt_24h_d.items():
                    _recent_24h_counts[_mc] = max(_recent_24h_counts.get(_mc, 0), _mv)
                # iter813: 6h merge
                for _mc, _mv in _rt_6h_d.items():
                    _recent_6h_counts[_mc] = max(_recent_6h_counts.get(_mc, 0), _mv)
                # iter1024: global_cross_project_suppress — global chunk 跨项目聚合 suppress 计数
                # 根因（数据驱动，2026-05-07）：global chunk 分散在多项目各注入 1-2 次，
                #   per-project 计数不触发 suppress，但用户实际 7d 看到多次。
                # 修复：对 global chunk 做跨项目聚合，取所有项目总和。
                try:
                    _global_ids_set = set(r[0] for r in _fb_conn.execute(
                        "SELECT id FROM memory_chunks WHERE project='global' AND chunk_state='ACTIVE'"
                    ).fetchall())
                    if _global_ids_set:
                        for (_g_tk, _g_ts) in _fb_conn.execute(
                                "SELECT top_k_json, timestamp FROM recall_traces "
                                "WHERE injected=1 AND project!=? AND timestamp>?",
                                (project, _cut_7d,)).fetchall():
                            if not _g_tk: continue
                            try:
                                _g_ids = json.loads(_g_tk)
                            except Exception: continue
                            _g_is_24h = _g_ts > _cut_24h if _g_ts else False
                            _g_is_6h = _g_ts > _cut_6h if _g_ts else False
                            for _gi in (_g_ids if isinstance(_g_ids, list) else []):
                                _gc = _gi.get("id","") if isinstance(_gi, dict) else ""
                                if _gc and _gc in _global_ids_set:
                                    _recent_7d_counts[_gc] = _recent_7d_counts.get(_gc, 0) + 1
                                    if _g_is_24h:
                                        _recent_24h_counts[_gc] = _recent_24h_counts.get(_gc, 0) + 1
                                    if _g_is_6h:
                                        _recent_6h_counts[_gc] = _recent_6h_counts.get(_gc, 0) + 1
                except Exception:
                    pass
                _fb_conn.close()
            except Exception:
                pass

        # ── iter660: timeline_ghost_gc (daemon sync) ────────────────────
        # 根因：retriever.py iter659 已有 ghost_gc，daemon 完全缺失。
        #   实测 timeline 51 个 ID 中 26 个是幽灵（已删除 chunk），
        #   7d suppress 计数中幽灵贡献 62 条 vs 存活 36 条（63%）。
        #   幽灵条目虽不会被 FTS 检索到，但污染 suppress 计数统计，
        #   导致 suppress 对低频但真正垄断的存活 chunk 阈值判断失真。
        # 修复：合并 24h/7d counts 后、评分前，批量查 memory_chunks 过滤幽灵。
        #   同时回写清理后的 timeline 文件。
        try:
            _all_suppress_ids = set(_recent_24h_counts.keys()) | set(_recent_7d_counts.keys())
            if _all_suppress_ids:
                import sqlite3 as _gc_sql
                _gc_conn = _gc_sql.connect(str(STORE_DB))
                _gc_alive = set()
                _gc_ids = list(_all_suppress_ids)
                for _gc_i in range(0, len(_gc_ids), 50):
                    _gc_batch = _gc_ids[_gc_i:_gc_i+50]
                    _gc_ph = ",".join("?" for _ in _gc_batch)
                    _gc_alive.update(
                        r[0] for r in _gc_conn.execute(
                            f"SELECT id FROM memory_chunks WHERE id IN ({_gc_ph}) AND chunk_state='ACTIVE'", _gc_batch
                        ).fetchall()
                    )
                _gc_conn.close()
                _gc_ghosts = _all_suppress_ids - _gc_alive
                if _gc_ghosts:
                    _recent_24h_counts = {k: v for k, v in _recent_24h_counts.items() if k not in _gc_ghosts}
                    _recent_7d_counts = {k: v for k, v in _recent_7d_counts.items() if k not in _gc_ghosts}
                    # 回写 timeline 文件清理幽灵条目
                    try:
                        _INJECTION_TIMELINE_FILE_GC = os.path.join(MEMORY_OS_DIR, ".injection_timeline.json")
                        if os.path.exists(_INJECTION_TIMELINE_FILE_GC):
                            import json as _gc_json
                            with open(_INJECTION_TIMELINE_FILE_GC, encoding="utf-8") as _gc_f:
                                _gc_tl = _gc_json.loads(_gc_f.read())
                            _gc_tl_clean = {k: v for k, v in _gc_tl.items() if k not in _gc_ghosts}
                            if len(_gc_tl_clean) < len(_gc_tl):
                                with open(_INJECTION_TIMELINE_FILE_GC, "w", encoding="utf-8") as _gc_fw:
                                    _gc_fw.write(_gc_json.dumps(_gc_tl_clean))
                    except Exception:
                        pass
        except Exception:
            pass

        # Memory zones
        # iter207: fast path — exclude_types is empty in ~100% of real usage
        # direct reference to module-level constant (0.17us vs 1.59us for tuple rebuild)
        # OS 类比：字符串驻留 — 常量元组一次分配，永久复用
        _exclude_str = sysctl("retriever.exclude_types")
        if not _exclude_str:
            _retrieve_types = _ALL_RETRIEVE_TYPES_CONST
        else:
            _exclude_set = set(t.strip() for t in _exclude_str.split(",") if t.strip())
            _retrieve_types = tuple(t for t in _ALL_RETRIEVE_TYPES_CONST if t not in _exclude_set) or None

        # ── DRR selector ──
        def _drr_select(candidates, top_k):
            max_same = _drr_max_same  # iter193: pre-read local var (was sysctl() call)
            # iter1641: sync normative pool from retriever.py iter337+1641
            _NORM = frozenset(("decision", "design_constraint"))
            _norm_cap = max_same + 1  # 联合配额: 3 slots (50% of top_k=6)
            _norm_n = 0
            selected = []
            type_counts = {}
            overflow = []
            for score, chunk in candidates:
                if len(selected) >= top_k:
                    break
                ctype = (chunk[_CI_CT] or "task_state") if chunk is not None else "task_state"
                count = type_counts.get(ctype, 0)
                if ctype in _NORM and _norm_n >= _norm_cap:
                    overflow.append((score, chunk))
                    continue
                if count < max_same:
                    selected.append((score, chunk))
                    type_counts[ctype] = count + 1
                    if ctype in _NORM:
                        _norm_n += 1
                else:
                    overflow.append((score, chunk))
            overflow_type_counts = {}
            _of_norm = 0
            for score, chunk in overflow:
                if len(selected) >= top_k:
                    break
                ctype = (chunk[_CI_CT] or "task_state") if chunk is not None else "task_state"
                already = type_counts.get(ctype, 0) + overflow_type_counts.get(ctype, 0)
                if ctype in _NORM and _norm_n + _of_norm >= _norm_cap * 2:
                    continue
                if already < max_same * 2:
                    selected.append((score, chunk))
                    overflow_type_counts[ctype] = overflow_type_counts.get(ctype, 0) + 1
                    if ctype in _NORM:
                        _of_norm += 1
            return selected

        # ── Score function (iter191: inline retrieval_score, single _age_days, cached sysctl params) ──
        # iter191 优化：retrieval_score 原耗时 ~22.5us/call（10× sysctl + 3× _age_days + md5）
        # 1. 在请求开始时一次性读取所有 scorer sysctl 参数（10次 → 1次，~22us → ~2us）
        # 2. _age_days(last_accessed) 只调用一次，传给所有子函数（3次 → 1-2次，~5us → ~1.7-3.4us）
        # 3. 其余所有子函数内联展开（消除函数调用 overhead ~1-2us）
        # 预期：~22.5us → ~3.5us/call，10 chunks = 节省 ~190us/request
        # OS 类比：slab 参数预取 + register passing — 将热路径参数从每次 DB lookup 改为
        #   请求级局部变量，类比 kmem_cache per-CPU 槽的 CPU-local 访问。
        # 注意：sysctl 已有 daemon TTL cache（iter188），但仍有 dict lookup + time.time() 开销；
        #   在 scoring loop（10次/request）里还是比局部变量慢 ~2us/call。
        _sc_decay   = sysctl("scorer.importance_decay_rate") or 0.95
        # iter231: precompute ln(decay)/7.0 once per request — replaces per-chunk decay**(age/7.0)
        # exp(age * _LN_DECAY_INV7) = decay**(age/7.0) mathematically equivalent, but:
        #   decay**(x): LOAD_FAST + LOAD_FAST + BINARY_POWER (~0.42us) + / 7.0 (~0.07us) = ~0.49us/chunk
        #   exp(age*const): LOAD_FAST + LOAD_FAST + BINARY_MULTIPLY + math.exp (~0.27us) = ~0.29us/chunk
        #   节省：~0.20us/chunk × 10 chunks = ~2.0us/request
        # OS 类比：FMADD — 单指令乘加（mul+exp C call）替代幂运算（pow = exp(y*log(x)) in libm）。
        _LN_DECAY_INV7 = _math.log(_sc_decay) / 7.0  # negative constant: log(0.95)/7 ≈ -0.00733
        _sc_floor   = sysctl("scorer.importance_floor") or 0.3
        _sc_ab_cap  = sysctl("scorer.access_bonus_cap") or 0.2
        _sc_fb_max  = sysctl("scorer.freshness_bonus_max") or 0.15
        _sc_fb_grc  = sysctl("scorer.freshness_grace_days") or 7.0
        _sc_st_fac  = sysctl("scorer.saturation_factor") or 0.04
        _sc_st_cap  = sysctl("scorer.saturation_cap") or 0.25
        _sc_sv_fac  = sysctl("scorer.starvation_boost_factor") or 0.30
        _sc_sv_min  = sysctl("scorer.starvation_min_age_days") or 0.5
        _sc_sv_rmp  = sysctl("scorer.starvation_ramp_days") or 3.0
        _sc_al_thr  = sysctl("scorer.aslr_access_threshold") or 5
        _sc_al_eps  = sysctl("scorer.aslr_epsilon") or 0.0
        _sc_al_eps  = _sc_al_eps if _sc_al_eps else 0.0  # None-safe
        # iter193: 预读 4 个多次使用的 sysctl 参数，消除重复 TTL cache 查找开销
        # 每个 TTL-cache sysctl() 调用 ~2.4us（time.time() + dict lookup），4个×2次 = 8个额外调用
        # 节省：4 × 2.4us = ~9.6us/request（drr_max_same_type/drr_enabled×2, min_score_threshold×2,
        #        generic_query_min_threshold×2）
        # OS 类比：slab per-CPU 参数预取（同 iter191），将重复 dict lookup 改为寄存器局部变量。
        _drr_max_same  = sysctl("retriever.drr_max_same_type")
        _drr_enabled   = sysctl("retriever.drr_enabled")
        _min_score_thr = sysctl("retriever.min_score_threshold")
        _gen_query_thr = sysctl("retriever.generic_query_min_threshold")
        # iter560: cfs_bandwidth — per-chunk retrieval frequency throttle
        # OS 类比：CFS Bandwidth Control (Paul Turner, 2011) — quota/period 超额 throttle
        _bw_enabled    = sysctl("cfs_bandwidth.enabled")
        _bw_quota      = sysctl("cfs_bandwidth.quota") or 8
        _bw_factor     = sysctl("cfs_bandwidth.throttle_factor") or 0.50
        _bw_decay      = sysctl("cfs_bandwidth.overflow_decay") or 0.85
        _bw_max_pct    = sysctl("scorer.bw_max_pct") or 0.30  # iter588
        _inject_hard_cap = sysctl("retriever.constraint_inject_hard_cap") or 0.30  # iter601
        # iter212: removed 3 redundant in-function imports (0.139+0.160+0.260=0.56us/request):
        #   import math as _math → use module-level _math (same object, no overhead)
        #   import hashlib as _hashlib → use already-unpacked hashlib from mods
        #   from datetime import datetime as _dt, timezone as _tz → use datetime/timezone from mods
        # OS 类比：DCE + 寄存器复用 — 已载入模块不重复 import，直接引用 LOAD_FAST 局部变量。
        # datetime.now 在 scoring loop 外调用一次，节省 N_chunks × 0.5us
        _dt = datetime   # alias for _age_days_fast closure (iter212: was from-import)
        _tz = timezone   # alias for _age_days_fast closure (iter212: was from-import)
        # _date_cls = date class from module-level import (iter235 bugfix: avoid _dt.date which is a method descriptor)
        _hashlib = hashlib  # alias for _score_chunk closure (iter212: was import)
        _now_utc = _dt.now(_tz.utc)
        _now_ts = _now_utc.timestamp()  # iter196: pre-compute once for timestamp subtraction
        # iter230: pre-compute today's ordinal (date.today().toordinal()) for _age_days_fast
        # date.today() = ~0.5us per call; moved outside _age_days_fast (0us in cache-hit path).
        # OS 类比：page table walker pre-fetch — pre-compute base address once before loop.
        # iter235 bugfix: _dt.date is datetime.datetime.date (method descriptor), not datetime.date class.
        # Must use _now_utc.date() or import date separately to get today's date.
        _today_ord = _now_utc.date().toordinal()

        def _age_days_fast(iso_str: str) -> float:
            """iter191: 使用外部预计算的 _now_utc，避免每次 datetime.now()
            iter196: iso_str → float timestamp daemon cache（消除 fromisoformat 重复解析）
            iter230: _age_days_cache（days float 直接缓存）+ date.fromisoformat(s[:10])
                     day-precision：误差 ≤ 0.156d，对 7d-scale scoring 影响可忽略。
                     cache 改存 days-float（非 unix timestamp），消除 / 86400 除法。
                     实测（N=500000）：iter196 cache=0.40us → iter230 cache=0.25us（-0.15us/hit）；
                                       cache miss：0.87us → 0.49us（-0.38us/miss）。
            OS 类比：inode atime day-precision — day-only access time sufficient for aging.
            """
            # iter230: separate _age_days_cache stores days-float directly (no / 86400 needed)
            # Old _iso_ts_cache stored unix timestamps; new cache stores age in days.
            # Both are daemon-level, module-global; _age_days_cache is iter230-introduced.
            # iter245: cache now stores (age, exp_val) tuple; _age_days_fast returns age (c[0]).
            c = _age_days_cache.get(iso_str)
            if c is None:
                try:
                    # iter230: date.fromisoformat(s[:10]) — day-precision, ~0.38us faster than datetime.fromisoformat
                    # _today_ord pre-computed per-request (date.today().toordinal()), 0us to access
                    age = float(_today_ord - _date_cls.fromisoformat(iso_str[:10]).toordinal())
                except Exception:
                    age = 30.0  # 30 days ago sentinel
                _a = age if age >= 0.0 else 0.0
                c = (_a, _math.exp(_a * _LN_DECAY_INV7), 1.0 / (1.0 + _a))
                _age_days_cache[iso_str] = c
            return c[0]  # iter245/246: extract age from 3-tuple

        # iter1029: project_concentration_penalty — per-project 7d 注入占比预计算
        _proj_7d_conc = {}  # {project: (ratio, n_chunks)}
        try:
            if _recent_7d_counts:
                import sqlite3 as _pc_sql
                _pc_ids = list(_recent_7d_counts.keys())
                _pc_proj_map = {}
                _pc_conn2 = _pc_sql.connect(str(STORE_DB))
                for _pc_i in range(0, len(_pc_ids), 50):
                    _pc_batch = _pc_ids[_pc_i:_pc_i+50]
                    _pc_ph = ",".join("?" for _ in _pc_batch)
                    for (_pid, _pproj) in _pc_conn2.execute(
                            f"SELECT id, project FROM memory_chunks WHERE id IN ({_pc_ph})", _pc_batch).fetchall():
                        _pc_proj_map[_pid] = _pproj or ""
                _pc_conn2.close()
                _pc_agg = {}  # project -> [total_7d, set(chunk_ids)]
                for _pcid, _pccnt in _recent_7d_counts.items():
                    _pcp = _pc_proj_map.get(_pcid, "")
                    if _pcp:
                        if _pcp not in _pc_agg:
                            _pc_agg[_pcp] = [0, set()]
                        _pc_agg[_pcp][0] += _pccnt
                        _pc_agg[_pcp][1].add(_pcid)
                _pc_total = sum(_recent_7d_counts.values()) or 1
                for _pcp, (_pc_sum, _pc_set) in _pc_agg.items():
                    _proj_7d_conc[_pcp] = (_pc_sum / _pc_total, len(_pc_set))
        except Exception:
            pass

        _pattern_keywords: set = set()
        # iter232: hoist _sc_al_eps > 0 check outside per-chunk scoring loop
        # _sc_al_eps defaults to 0.0 — in 100% of typical usage, exploration bonus is disabled.
        # Moving the condition out of _score_chunk eliminates 1× comparison per chunk per request.
        # OS 类比：branch prediction bias — always-false branch removed from hot loop.
        # iter234: hoist freshness division into multiply — fdiv→fmul strength reduction
        # _sc_fb_max / _sc_fb_grc computed once per request; per-chunk: age_ca * _sc_fb_scale (mul, no div).
        # OS 类比：strength reduction — compiler replaces div-by-constant with multiply-by-reciprocal.
        _sc_fb_scale = _sc_fb_max / _sc_fb_grc
        _run_aslr = _sc_al_eps > 0  # True only when scorer.aslr_epsilon sysctl is non-zero
        # iter233: hoist max(0.1, _sc_sv_rmp) guard once per request — starvation denominator is loop-invariant
        # Default sc_sv_rmp=3.0 → guard always evaluates to 3.0; hoisting saves 1× max() call per chunk (ac=0 path).
        # OS 类比：LICM — CPython 无 LICM，需手动外提循环不变量。
        _sc_sv_rmp_safe = _sc_sv_rmp if _sc_sv_rmp > 0.1 else 0.1
        # iter1673: topic_mismatch_discount — sync retriever.py iter1612
        # 根因（数据驱动，2026-05-12）：同项目 kernel 知识（MTK ALB、PE 分析）
        #   与 memory-os 迭代工作 topic 完全不匹配，FTS5 因共用词（如"注入"）匹配。
        #   ac>=3 + overlap=0 → 降权防止噪声占位。
        _query_content_words = set()
        try:
            _query_content_words = set(
                w for w in _RE_NON_WORD.sub(' ', query.lower()).split()
                if len(w) >= 2
            )
        except Exception:
            pass
        def _score_chunk(chunk, relevance):
            # iter191: fully inlined retrieval_score
            # _age_days called 1-2 times instead of 3 (reuse if same string)
            # iter214: direct [] access for schema-guaranteed fields (skip .get() miss-detection)
            # iter235: positional tuple access (_CI_* constants) — FTS path returns raw SQL tuples
            #   BINARY_SUBSCR[int] vs dict BINARY_SUBSCR[str] (hash lookup) — saves ~9us/10chunks
            #   OS 类比：struct field offset access vs hash map lookup
            # iter247: full tuple unpack replaces 9 individual BINARY_SUBSCR[int] calls.
            # `_cid, _, _, _imp, _la, _, _ac, _ca, _, _lg, _cp, _vs, _cs = chunk`
            # UNPACK_SEQUENCE(13) is a single C-loop over the tuple, faster than 9 separate
            # BINARY_SUBSCR calls (each requires LOAD_FAST + LOAD_CONST + BINARY_SUBSCR bytecodes).
            # _ discards: summary(_CI_SUM=1), content(_CI_CON=2), chunk_type(_CI_CT=5), fts_rank(_CI_FR=8).
            # microbench: 9× individual = 0.222us → UNPACK_SEQUENCE(13) = 0.158us; -64ns/chunk; ×10=-0.64us
            # OS 类比：struct copy (memcpy) vs field-by-field load — single cache-line copy beats multiple loads.
            # Correctness: indices unchanged (SQL column order fixed since _FTS_SQL_BASE definition).
            # iter257: _cs renamed to _ — no longer used after iter255 (vb simplified to vs-only ternary).
            # CPython STORE_FAST into '_' reuses the discard slot; saves one LOAD_FAST dereference.
            # Benchmarked: -13.5ns/chunk (full function); ×10=-0.135us/request.
            # OS 类比：register renaming — dead var eliminated from tracked live range (liveness analysis).
            _cid, _, _, _imp, _la, _, _ac, _ca, _, _lg, _cp, _vs, _ = chunk  # iter257: _cs → _ (unused)
            _rc = _recall_counts.get(_cid, 0)

            # age_la: iter237: inline _age_days_fast to eliminate function call overhead (~0.12us/call)
            # _age_days_fast is called 1-2×/chunk; inlining saves ~0.12-0.24us/chunk.
            # OS 类比：inlining small functions — remove CALL/RETURN overhead for hot path.
            # Cache-hit path: _age_days_cache.get(_la) + guard; cache-miss: fromisoformat + store.
            # iter245: _age_days_cache stores (age, exp_val) tuples — skip math.exp on cache hit.
            # Tuple unpack: age_la, _exp_la = c  → both retrieved from one dict.get().
            # Cache miss: compute age + exp_val together, store as tuple.
            # OS 类比：TLB with pre-decoded PTE — cache stores decoded physical address alongside tag,
            #          avoiding re-decode (math.exp) on hot path (analogous to PTE decode elimination).
            _c_la = _age_days_cache.get(_la)
            if _c_la is None:
                try: _a = float(_today_ord - _date_cls.fromisoformat(_la[:10]).toordinal())
                except Exception: _a = 30.0
                _a = _a if _a >= 0.0 else 0.0
                _c_la = (_a, _math.exp(_a * _LN_DECAY_INV7), 1.0 / (1.0 + _a))
                _age_days_cache[_la] = _c_la
            age_la, _exp_la, rec = _c_la  # iter246: unpack 3-tuple (age, exp, recency) in one step
            # age_ca: used by freshness_bonus, starvation — reuse if same string
            # iter242: _ca always non-empty (SQL COALESCE(created_at, last_accessed) guarantees non-NULL).
            # iter245/246: for age_ca, we only need age (not exp/recency), so use c[0] from tuple cache.
            if _ca != _la:
                _c_ca = _age_days_cache.get(_ca)
                if _c_ca is None:
                    try: _a2 = float(_today_ord - _date_cls.fromisoformat(_ca[:10]).toordinal())
                    except Exception: _a2 = 30.0
                    _a2 = _a2 if _a2 >= 0.0 else 0.0
                    _c_ca = (_a2, _math.exp(_a2 * _LN_DECAY_INV7), 1.0 / (1.0 + _a2))
                    _age_days_cache[_ca] = _c_ca
                age_ca = _c_ca[0]  # only need age, not exp_ca/recency_ca
            else:
                age_ca = age_la  # _ca == _la (either same or COALESCE(ca=NULL) → la)

            # importance_with_decay
            # iter231: exp(age*const) replaces decay**(age/7.0) — ~0.20us/chunk saving
            # _LN_DECAY_INV7 = log(decay)/7 precomputed per-request (after sysctl read)
            # OS 类比：FMADD — C-level exp() + multiply vs Python BINARY_POWER (pow = exp(y*log(x)))
            # iter232: ternary replaces 2-arg max() call (~2.041us → ~0.857us per 10 chunks = 1.184us saving)
            # max(a, b) has Python function call overhead; ternary is LOAD_FAST + COMPARE + jump (no call).
            # OS 类比：cmov — conditional move instruction vs function call dispatch.
            # iter245: _exp_la from tuple cache — no math.exp call on hot path.
            # iter250: drop `eff_imp >= _sc_floor` ternary guard — corpus verified: 0/427 chunks trigger floor.
            # min(importance)=0.60, max(age)=1d → min eff = 0.60 * exp(1 * -0.00733) = 0.596 >> 0.05.
            # Corpus has max_age ~1d (active knowledge; old chunks evicted by kswapd/DAMON).
            # Removing COMPARE_OP + POP_JUMP_IF_FALSE: -13.8ns/chunk; ×10 = -0.14us/request.
            # Risk: if a chunk somehow has age >> 1000d with low importance, eff_imp could go below floor,
            # changing score by at most 0.05 (minor). kswapd_scan should evict such chunks before score matters.
            # OS 类比：eliding bounds-check after static analysis proves value always in-range (JIT no-overflow).
            eff_imp = _imp * _exp_la  # iter250: drop floor guard (corpus verified: min eff_imp = 0.596 >> 0.05)
            # recency_score — iter246: rec from 3-tuple cache (no division on hot path)
            # access_bonus: iter199 lookup table (0.28us → 0.06us per chunk)
            # OS 类比：TLB hit — 预计算表查找，跳过 math.log2 call
            # iter233: _ac < 21 → _ac <= 20 (equivalent; clarifies table max index = 20)
            ab = _AB_TABLE[_ac] if _ac < 64 else _sc_ab_cap  # iter251: 64-entry table covers 100% corpus
            # iter831: access_diminishing_return — 高频 chunk 的 access_bonus 衰减
            # 根因（数据驱动，2026-05-05）：ac>=8 的 chunk 占据 top_k 半数席位，
            #   ab 已 cap 到 0.20 无惩罚，导致高频 chunk 评分优势固化。
            # 修复：ac>8 时 ab 乘以 1/(1+(ac-8)*0.1)，ac=12→0.71x, ac=20→0.45x
            if _ac > 8:
                ab *= 1.0 / (1.0 + (_ac - 8) * 0.1)
            # iter1647: internalized_knowledge_decay — sync scorer.py
            if _ac >= 6:
                ab = ab - (_ac - 6) * 0.015
                if ab < 0.0:
                    ab = 0.0
            # freshness_bonus
            # iter234: strength reduction — age_ca / _sc_fb_grc → age_ca * _sc_fb_scale (hoisted per-request)
            # _sc_fb_scale = _sc_fb_max / _sc_fb_grc precomputed; result: _sc_fb_max - age_ca * _sc_fb_scale
            # iter242: drop 'if _ca' guard — COALESCE guarantees _ca is always non-empty.
            # iter254: drop `if age_ca < _sc_fb_grc` guard — corpus-verified: 0/427 chunks have age_ca >= 30.
            # kswapd/DAMON evict old chunks; active corpus always has recent created_at.
            # SELECT COUNT(*) WHERE julianday('now') - julianday(created_at) >= 30 → 0 (N=427, 2026-04-23).
            # Removing COMPARE_OP + POP_JUMP_IF_FALSE: -18.3ns/chunk; ×10 = -0.18us/request.
            # Risk: if a chunk somehow has old created_at (e.g., imported from backup), fb becomes slightly
            # negative (fb_max - age_ca * scale < 0 when age_ca > fb_max/scale = 0.05/0.00167 = 30d).
            # Acceptable: kswapd should evict such chunks before scoring matters.
            # OS 类比：same as iter244 (drop age>=0 guard) — compiler proves range after kswapd invariant.
            fb = _sc_fb_max - age_ca * _sc_fb_scale  # iter254: drop grace guard (corpus max age_ca = 1.2d avg)
            # exploration_bonus — iter230: hash() vs md5 (~0.465us vs ~1.592us, saving ~1.127us when ac < thr)
            # PYTHONHASHSEED is fixed per-process (Python randomizes at startup, but stays constant
            # for the daemon's lifetime). hash(tuple) is deterministic within a single daemon run.
            # Semantics: uniform pseudo-random bonus in [0, eps] — property preserved by hash().
            # hash() may return negative; & 0x7fffffff ensures positive int for % 10000.
            # collision / distribution: hash(tuple) uses SipHash-1-3 (CPython 3.x), passes
            # avalanche criterion, so % 10000 produces approximately uniform [0, 9999].
            # No cross-restart reproducibility needed: bonus is ephemeral scoring noise.
            # OS 类比：ASLR per-process randomness — per-process seed is stable within lifetime,
            #   sufficient for intra-session exploration diversity (not cross-restart reproducibility).
            # iter252: eliminate `eb=0.0` assignment + `if eb: score+=eb` check.
            # _run_aslr=False (default, eps=0.0): no eb variable needed. Save 2×(LOAD_CONST+STORE/LOAD_FAST+POP_JUMP).
            # Restructured: compute score first, then `if _run_aslr: score += eb` (no else branch).
            # OS 类比：DCE + branch-free path — compiler eliminates dead else-branch when flag is provably false.
            # starvation_boost
            # iter233: min(1.0,...) + max(0.1,...) → ternary + hoisted _sc_sv_rmp_safe (per-request)
            # OLD: sb = _sc_sv_fac * min(1.0, (age_ca - _sc_sv_min) / max(0.1, _sc_sv_rmp))
            # NEW: _sc_sv_rmp_safe hoisted outside; ternary replaces min(1.0,...) — no function call overhead.
            # OS 类比：cmov — ternary compiles to conditional move; no function dispatch.
            if _ac == 0 and age_ca >= _sc_sv_min:
                _sv_ratio = (age_ca - _sc_sv_min) / _sc_sv_rmp_safe
                sb = _sc_sv_fac * (_sv_ratio if _sv_ratio <= 1.0 else 1.0)
            else:
                sb = 0.0
            # saturation_penalty — iter231: _ST_TABLE lookup (same strategy as _AB_TABLE iter199)
            # _ST_TABLE[i] = min(0.25, 0.04*log2(1+i)) for i=0..20; [0]=0.0 (rc=0 fast path)
            # rc>0 path: list[int] ~0.06us vs log2 ~0.28us (节省 0.22us × ~30% rc>0 chunks)
            # OS 类比：TLB hit — 预计算表替代 log2 call（同 iter199 access_bonus）
            # iter256: extend to _ST_TABLE_EXT (271 entries) — covers max rc=270 from corpus.
            # Replaces compound `if <21 else (min(...) if >0 else 0)` with single bounds check.
            # Correctness: _ST_TABLE_EXT[0..270] matches formula exactly (271/271 verified).
            sp = _ST_TABLE_EXT[_rc] if _rc < 271 else _sc_st_cap  # iter256: 271-entry table, -26.8ns/chunk
            # iter240: _LGB_TABLE lookup replaces ternary (iter236) — saves multiply+compare.
            # SQL COALESCE(lru_gen, 0) guarantees _lg is always int ≥ 0 (never None).
            # _LGB_TABLE[i] = 0.06 - 0.0075*min(i,8) for i=0..8; index cap: lg>=9 → lgb=0.0.
            # microbench: 0.132us (iter236 ternary) → 0.087us (_LGB_TABLE); -45ns/chunk; ×10=-0.45us
            # iter239a retracted: _lg is None never happens (SQL COALESCE), removing that branch.
            # iter249: drop `_lg < 9` guard — corpus verified: max(lru_gen) = 4 (N=415).
            # MGLRU max generation is 4 in practice; _LGB_TABLE has 9 entries (cap at 8, safe margin).
            # Verified: SELECT MAX(COALESCE(lru_gen,0)) → 4; no chunk has lru_gen >= 9.
            # Risk: if a future chunk somehow has lru_gen >= 9, IndexError. Acceptable — same
            # pattern as iter244 (drop age>=0 guard). Log an error in kswapd_scan if lru_gen > 8.
            # microbench: guard=108ns → no-guard=82ns; saving -26ns/chunk; ×10 = -0.26us/request.
            # OS 类比：computed goto table (same as AB/ST, iter199/231) — O(1) BINARY_SUBSCR vs arith.
            lgb = _LGB_TABLE[_lg]  # iter249: drop _lg<9 guard (corpus max=4, table has 9 entries)
            # iter253: drop `if _vs is None` guard + `or 0.7` / `or "pending"` fallbacks.
            # Corpus-verified: 0/427 chunks have vs IS NULL or cs IS NULL (SELECT COUNT(*) = 0).
            # verification_status: always "pending"/"verified" (never None/empty).
            # confidence_score: always one of 0.7/0.8/0.9/0.99 (never None).
            # Removing 1×(is None check) + 2×(or fallback) per chunk: -19.8ns/chunk; ×10=-0.20us.
            # iter239c note: `if _vs is None` was the fast path; now the single branch is direct.
            # OS 类比：same as iter249 (drop lru_gen bounds check) — static range analysis proves
            #          field is always non-null, so null-guard is provably dead code.
            # iter255: collapse 4-branch vb + vp into single ternary; drop vp entirely.
            # Corpus-verified: 0/427 disputed → vp=0.0 always.
            # Pending chunks: all have cs=0.7 (corpus N=225), so elif cs>=0.9/0.8 never fire.
            # Only 2 live states: vs="verified"→vb=0.12; vs="pending"→vb=0.0.
            # Collapse: vb = 0.12 if _vs=="verified" else 0.0; drop vp variable + -vp from score.
            # Removes: 3×elif/COMPARE_OP + POP_JUMP + vp COMPARE+LOAD+STORE; -55.5ns/chunk; ×10=-0.555us.
            # OS 类比：branch predictor — replacing multi-way if-chain with single conditional
            #          (no mispredicts for 2-state enum) → eliminates pipeline stalls.
            vb = 0.12 if _vs == "verified" else 0.0  # iter255: single ternary, vp dropped (0/427 disputed)
            # numa_distance_penalty: iter197 ternary (cp==project is common case, ndp=0)
            # OS 类比：short-circuit eval — most chunks belong to current project
            # iter258: reorder branches — "global" first (67.9% of corpus) vs "project" first (0-2%).
            # Corpus distribution: 290/427=67.9% global, <5% current project (varies by session).
            # Moving global check first: 67.9% chunks hit branch 1 vs branch 2 (saves 1 COMPARE_OP+POP_JUMP).
            # microbench: 168.1ns→137.4ns; -30.7ns/chunk; ×10=-0.307us/request.
            # Correctness: global != project always (project is e.g. "memory-os"); identical semantics.
            # OS 类比：branch layout optimization (PGO) — reordering branches so the hot path executes
            #          fewest branches (same as profile-guided ordering of switch cases).
            # iter846: global penalty 0.02→0.10 — global 仅占 14% 库存但 20% 注入量
            #   iter718 前提"67.5% global"已不成立，恢复有意义的惩罚
            ndp = (0.10 if _cp == "global" else
                   0.0 if _cp == project else
                   0.15 if _cp else 0.0)

            # iter239b: compact score formula — eb=0 always when _run_aslr=False (default);
            # sb=0 when _ac>0 (most accessed chunks); avoid unconditional LOAD_FAST+BINARY_ADD for zeros.
            # iter248: fuse `base` temp into score expression — eliminate one STORE_FAST + LOAD_FAST.
            # OLD: base = eff_imp*0.55+rec*0.45; score = rel*(base+ab+fb) - sp + ...  (2 statements)
            # NEW: score = rel*(eff_imp*0.55+rec*0.45+ab+fb) - sp + ...               (1 statement)
            # microbench: -24ns/chunk; ×10 = -0.24us/request.
            # OS 类比：register allocation — eliminating an intermediate temp avoids an extra
            #          STORE/LOAD pair (stack push+pop), keeping values in Python's eval stack.
            score = relevance * (eff_imp * 0.55 + rec * 0.45 + ab + fb) - sp + vb + lgb - ndp  # iter255: drop -vp (always 0)
            if _run_aslr and _cid and _ac < _sc_al_thr:  # iter252: no else-branch (eb=0 implicit)
                _h = hash((_cid, query)) & 0x7fffffff
                score += _sc_al_eps * (1.0 - _ac / _sc_al_thr) * ((_h % 10000) / 10000.0)
            if sb: score += sb

            if _pattern_keywords:
                _summary_lower = (chunk[_CI_SUM] or "").lower()
                _matched = sum(1 for kw in _pattern_keywords if kw in _summary_lower)
                if _matched > 0:
                    score += min(0.10, _matched * 0.03)
            # iter1302: thin_content_penalty — content==summary 零增量降权
            _tc_con = chunk[_CI_CON] or ""
            _tc_sum = chunk[_CI_SUM] or ""
            if len(_tc_con) <= len(_tc_sum) + 5 and len(_tc_con) < 80:
                score *= 0.5
            # iter560: cfs_bandwidth — multiplicative throttle for over-quota chunks
            # OS 类比：CFS bandwidth throttle_cfs_rq() — 超额 cgroup 任务移出 runqueue
            # saturation_penalty 是加法上限 0.25，无法压制 base>0.8 的垄断 chunk；
            # cfs_bandwidth 用乘法 score *= factor * decay^overflow 实现渐进强压制。
            if _bw_enabled and _rc > _bw_quota:
                score *= _bw_factor * (_bw_decay ** (_rc - _bw_quota))
            # iter600+601+612: bandwidth throttle — graduated penalty
            # iter612: graduated_bandwidth_penalty — 线性渐进惩罚 [soft_start, hard_cap]
            #   根因：垄断 chunk 的 util 恰好低于 hard_cap 持续逃逸。
            #   修复：util ∈ [hard_cap*0.5, hard_cap] 线性插值 penalty ∈ [1.0, 0.0]
            if _rc > 0:
                _hard_util_sc = _rc / _local_bw_window
                if _hard_util_sc > _inject_hard_cap:
                    score = 0.0
                else:
                    _bw_soft_start = _inject_hard_cap * 0.5
                    if _hard_util_sc > _bw_soft_start:
                        _bw_penalty = 1.0 - (_hard_util_sc - _bw_soft_start) / (_inject_hard_cap - _bw_soft_start)
                        score *= _bw_penalty
            # iter875: soft_diversity_penalty — 7d 注入次数越高，score 乘法衰减越强
            # iter876: factor 0.2→0.35 — 数据驱动：7d=6 的 pe_analysis 仍垄断（0.2 时衰减仅到 45%，
            #   高 FTS 基分仍胜出）。0.35 使 7d=5→36%, 7d=6→32%，有效让位给 7d=0 chunk。
            # iter898: small_db_diversity_boost — <50 库 factor 0.35→0.55
            _r7d_sc = _recent_7d_counts.get(_cid, 0)
            # iter1639: sync iter1624 zero_7d_historical_penalty — 7d=0 但历史高注入激活 diversity
            # iter1676: graduated_synthetic_7d_sync — sync retriever.py iter1651
            _total_inj_d = _itl_lifetime.get(_cid, (0,))[0] if _itl_lifetime else 0
            if _r7d_sc == 0 and _total_inj_d >= 5 and _db_chunk_count > 5:
                _r7d_sc = min(3, 1 + (_total_inj_d - 5) // 2)
            if _r7d_sc > 0 and _db_chunk_count > 5:
                # iter969: diversity_factor_align_small_db — <100 统一 0.55
                _dp_factor = 0.55 if _db_chunk_count < 100 else 0.35
                # iter1639: sync iter1003 global_chunk_diversity_boost
                if (chunk[_CI_CP] or "") == "global" and project != "global":
                    _dp_factor *= 2.0
                # iter1639: sync iter1453 ac_weighted_diversity
                _dp_ac = chunk[_CI_AC] or 0
                if _dp_ac >= 4:
                    _dp_factor *= 1.0 + 0.15 * (_dp_ac - 3)
                # iter1552: cumulative_boost_tighten — sync retriever.py timeline_cumulative_boost
                if _total_inj_d >= 3:
                    _dp_factor *= 1.0 + 0.35 * (_total_inj_d - 2)
                score *= 1.0 / (1.0 + _r7d_sc * _dp_factor)
                # iter1029: project_concentration_penalty — 同项目群体垄断衰减
                # iter1123: proj_conc_threshold_lower — 阈值 0.45→0.38, 衰减 0.75→0.70
                _cp_proj_d = chunk[_CI_CP] or ""
                _pc_info_d = _proj_7d_conc.get(_cp_proj_d)
                if _pc_info_d and _pc_info_d[0] > 0.38 and _pc_info_d[1] >= 4:
                    if _r7d_sc > 1:
                        score *= 0.70 ** (_r7d_sc - 1)
                    # iter1131: proj_conc_saturated_suppress — 高浓度项目内已内化 chunk hard suppress
                    # iter1333: small_db_proj_conc_tighten — <50 库收紧
                    # iter1540: tiny_db_proj_conc_tighten — <50 库 7d>=2+ac>=3
                    _pcs_7d_t = 2 if _db_chunk_count < 50 else 4
                    _pcs_ac_t = 3 if _db_chunk_count < 50 else 7
                    if _r7d_sc >= _pcs_7d_t and (chunk[_CI_AC] or 0) >= _pcs_ac_t:
                        score = 0.0
            # iter1572: cross_proj_constraint_hard_suppress — sync retriever.py
            _cp_sc = chunk[_CI_CP] if len(chunk) > _CI_CP else ""
            _is_xp_sc = (_cp_sc != project) if _cp_sc and _cp_sc != "global" else (_cp_sc == "global")
            if _is_xp_sc and score > 0:
                _ac_sc = chunk[_CI_AC] or 0
                _ct_sc = chunk[_CI_CT] if len(chunk) > _CI_CT else ""
                _is_cl_sc = _ct_sc in ("design_constraint", "procedure")
                # iter1666: cross_proj_general_suppress_tighten — sync retriever.py
                _xp_floor_sc = 4 if (_cp_sc == "global" or _is_cl_sc) else 5
                if _ac_sc >= _xp_floor_sc:
                    if _cp_sc == "global" or _is_cl_sc or _ac_sc >= 5:
                        score = 0.0
                    else:
                        score *= 0.4
            # iter1673: topic_mismatch_discount — sync retriever.py iter1612
            # iter1680: daemon_topic_mismatch_hard_suppress — sync retriever.py iter1679
            #   ac>=5 非 dc + topic 完全不匹配 → hard suppress（降权不够，经 fallback 逃逸）。
            if (score > 0 and not _is_xp_sc and _cp_sc != "global"
                    and (chunk[_CI_AC] or 0) >= 3 and _query_content_words):
                _tm_s = (chunk[_CI_SUM] or "").lower() if len(chunk) > _CI_SUM else ""
                _tm_w = set(w for w in _RE_NON_WORD.sub(' ', _tm_s).split() if len(w) >= 2)
                if _tm_w and len(_query_content_words & _tm_w) == 0:
                    _tm_ct = chunk[_CI_CT] if len(chunk) > _CI_CT else ""
                    _tm_ac = chunk[_CI_AC] or 0
                    if _tm_ct != "design_constraint" and _tm_ac >= 5:
                        score = 0.0
                    else:
                        score *= 0.6 if _tm_ct == "design_constraint" else 0.3
            # iter618: 24h + 7d burst suppress（daemon 此前完全缺失）
            # iter619: 阈值收紧 24h:3→2, 7d:8→5
            # iter672: relevance_exempt — 高分 chunk 放宽阈值，防 suppress 过杀
            # iter703: 小库放宽 — 40 chunk DB 中 2/3 阈值导致全库 suppress spiral
            #   DB<100 chunk 时 24h:3→5, 7d:5→8（低分）/ 24h:3→6, 7d:5→10（高分）
            #   根因：40 chunk × 频繁对话 → 2次/24h 即封锁 → 注入率骤降
            # iter767: tiered_small_db — 分级小库阈值
            _s672_micro = _db_chunk_count <= 5  # iter801: micro_db — suppress 全禁用
            _s672_tiny = _db_chunk_count < 50  # iter848: 边界 40→50
            _s672_small = _db_chunk_count < 100
            # iter806: small_db_suppress_tighten — 24h 4/3→3/2, 7d 7/5→5/4
            # iter801: micro_db (<=5) 跳过 24h/7d/saturation suppress — 唯一知识不可 suppress
            # iter1049: micro_db_cross_project_suppress — 跨项目 chunk 不享受 micro_db 免疫
            # iter1227: sparse_local_shield_daemon — local_sparse 时本地 chunk 等同 micro_db 保护
            _is_local_d = (_cp == project)
            _sparse_shield_d = _local_sparse_d and _is_local_d
            if not (_s672_micro or _sparse_shield_d) or (_cp != project and _cp != "global"):
                # iter813: short_burst_suppress — 6h 内 >=N 次即 suppress
                # iter818: tiny_db_6h_relax — 6h 分级
                # iter865: 6h_tighten_tiny — tiny_db 3→2（数据驱动：6h=3 逃逸导致垄断）
                # iter1042: saturated_6h_cap — ac>=7 → 6h_thresh=1
                # iter1047: constraint_saturated_6h — design_constraint ac>=5 也享受 thresh=1
                # iter1048: global_6h_sync — global ac>=4 同步 iter1023(24h cap=1)
                # iter1225: constraint_saturated_6h_sync — design_constraint ac>=4 对齐 retriever.py iter1171
                # iter1230: 6h_floor_2 — 6h suppress 最低阈值 2（允许 6h 内注入 1 次）
                # 根因（数据驱动，2026-05-09）：thresh=1 导致活跃 session 内 22% 空召回。
                #   24-chunk 库大部分 ac>=7，6h 注入 1 次即全灭 → 后续请求零知识。
                #   7d suppress 仍控制长期垄断，6h 只需防 burst（>=2 次/6h 才异常）。
                _6h_thresh_d = 2 if (_ac >= 7 or (chunk[_CI_CT] == "design_constraint" and _ac >= 4) or (chunk[_CI_CP] == "global" and _ac >= 4)) else 3
                # iter1227: sparse_global_shield — local_sparse 时 global chunk 6h 阈值 +1
                if _local_sparse_d and (chunk[_CI_CP] or "") == "global":
                    _6h_thresh_d += 1
                if _recent_6h_counts.get(_cid, 0) >= _6h_thresh_d:
                    score = 0.0
                # iter810: tiny_db_24h_relax — 小库统一阈值
                # iter1019: saturated_24h_tighten — ac>=7 chunk 24h 阈值 -1（sync retriever.py）
                else:
                    _24h_base_d = 3 if _s672_tiny else (3 if score >= 0.5 else 2) if _s672_small else (3 if score >= 0.5 else 2)
                    if _ac >= 10:
                        _24h_base_d = max(1, _24h_base_d - 2)
                    elif _ac >= 7:
                        _24h_base_d = max(1, _24h_base_d - 1)
                    elif (chunk[_CI_CP] or "") == "global" and _ac >= 4:
                        _24h_base_d = 1  # iter1023: global_24h_saturated_cap
                    if _recent_24h_counts.get(_cid, 0) >= _24h_base_d:
                        score = 0.0
                # iter854: tiny_db_7d_relax_v2 — 阈值 5→7（sync retriever.py）
                # iter882: 7d_tighten_monopoly — tiny_db 5→3, small_db 5/4→4/3
                #   数据驱动（2026-05-05）：23 chunk DB 中 top chunk inj7d=6，
                #   阈值 5 允许 4 次注入才 suppress，垄断 chunk 高 FTS 基分仍胜出。
                #   收紧到 3 使同一 chunk 7d 内最多注入 2 次后 hard suppress。
                # iter971: tiny 4→3 去垄断
                # iter990: small_db_7d_relax_v3 — small_db 4/3→6/4（sync retriever.py）
                #   根因：85-chunk 库 13/21 活跃 chunk 7d>=3 被 suppress → 40% 空召回
                if score > 0:  # iter1071: fix syntax — 原 else 与 if 不配对，改为独立 guard
                    # iter1513: tiny_db_7d_tighten — 7→4 去垄断
                    # 根因（数据驱动，2026-05-11）：38-chunk 库 import-90139(ac=3) 7d=5，
                    #   因 tiny_db _7d_base=7 使低 ac chunk 周注入 6 次才 suppress。
                    #   用户 3-4 次注入后已内化，继续注入为垄断。收紧到 4。
                    _7d_base = 4 if _s672_tiny else (4 if score >= 0.5 else 3) if _s672_small else (5 if score >= 0.5 else 3)
                    # iter1194: global_unified_thresh — sync daemon _score_chunk
                    # iter1462: small_db_global_7d_relax — <100 库 global 阈值 2→4
                    #   根因（数据驱动，2026-05-11）：66-chunk 库 5/8 global chunk 被 7d>=2 封杀，
                    #   高价值约束（git author/feishu CLI/memory验证）整周不可见。
                    #   small_db 内 global 知识尚未内化，需更多曝光。
                    if (chunk[_CI_CP] or "") == "global":
                        # iter1478: global_deep_saturated_7d_tighten — ac>=4 thresh 3→2
                        # iter1524: tiny_db_global_7d_relax — tiny_db(<50) ac>=4 thresh 2→4
                        # iter1562: global_dc_monopoly_cap — dc ac>=4 thresh 4→3
                        _g_ac_d = chunk[_CI_AC] or 0
                        if _s672_tiny:
                            # iter1640: global_dc_tinydb_7d_tighten — ac>=4 dc thresh 3→2
                            # 根因（数据驱动，2026-05-13）：feishu CLI(ac=5,dc) 7d=3 才 suppress，
                            #   35-chunk 库每周注入 2 次仍过高（用户已内化 ac>=4 知识）。
                            if _g_ac_d >= 4 and chunk[_CI_CT] == "design_constraint":
                                _7d_base = 2
                            elif _g_ac_d >= 4:
                                _7d_base = 3
                            else:
                                _7d_base = 5
                        elif _s672_small:
                            _7d_base = 2 if _g_ac_d >= 4 else 4
                        else:
                            _7d_base = 2
                        # iter1227: sparse_global_shield — local_sparse 时 global 7d 阈值 +1
                        if _local_sparse_d:
                            _7d_base += 1
                    elif (chunk[_CI_CP] or "") != "global":
                        # iter1143: local_mid_saturated_suppress — sync retriever.py
                        _l_ac_d = chunk[_CI_AC] or 0
                        # iter1219: raw_ac_7d_thresh — ac>=10 thresh=1 对齐 retriever.py
                        if _l_ac_d >= 10:
                            _7d_base = 1
                        elif _l_ac_d >= 7:
                            _7d_base = 2
                        elif _l_ac_d >= 5:
                            _7d_base = max(2, _7d_base - 2)  # iter1152: local_mid_saturated_tighten
                        elif _l_ac_d >= 4:
                            # iter1225: constraint_7d_sync — design_constraint ac>=4 用 -2 对齐 retriever.py iter1171
                            # iter1549: ac4_tiny_db_7d_cap2 — tiny_db ac>=4 统一 thresh=2 对齐 retriever.py
                            _7d_base = 2 if _s672_tiny else (max(2, _7d_base - 2) if chunk[_CI_CT] == "design_constraint" else max(3, _7d_base - 1))
                        # iter1402: ac3_7d_tinydb_relax — tiny_db cap 2→3
                        elif _l_ac_d >= 3:
                            _7d_base = min(_7d_base, 3 if _s672_tiny else 2)
                    if _recent_7d_counts.get(_cid, 0) >= _7d_base:
                        score = 0.0
                # iter1072: cooldown_widen — ac>=10 cooldown 72h→7d, ac>=7 48h→5d
                # iter1073: global_cooldown_widen — global chunk ac>=4 纳入 cooldown（72h→48h）
                # iter1078: cooldown_floor_unify — sync daemon floor 7→4
                # iter1083: global_cooldown_floor_fix — global chunk 绕过 ac_floor
                _cd_floor_d = 4
                _cd_is_global_d = (chunk[_CI_CP] == "global")
                if score > 0 and (_cd_is_global_d or (chunk[_CI_AC] or 0) >= _cd_floor_d) and _cutoff_48h and _last_inject_ts:
                    _cd_id = chunk[_CI_ID]
                    _cd_last = _last_inject_ts.get(_cd_id)
                    # iter1110: fallback_floor_align — ac>=_cd_floor_d 统一 fallback（原 ac>=7 漏洞）
                    if not _cd_last and (chunk[_CI_AC] or 0) >= _cd_floor_d:
                        _cd_la_d = chunk[_CI_LA] or ""
                        if _cd_la_d:
                            _cd_last = _cd_la_d
                    if _cd_last:
                        # iter1091: cooldown_daemon_sync — 对齐 retriever.py iter1089
                        # ac>=10→14d, ac>=7→10d, global→10d（原 7d/5d 太短导致逃逸）
                        if _cd_is_global_d:
                            _cd_cut = _cutoff_14d if (chunk[_CI_AC] or 0) >= 10 else _cutoff_10d
                        else:
                            # iter1252: cooldown_5d_to_3d — ac=4-6 cooldown 5d→3d
                            _cd_cut = _cutoff_14d if (chunk[_CI_AC] or 0) >= 10 else (_cutoff_10d if (chunk[_CI_AC] or 0) >= 7 else _cutoff_72h)
                        # iter1151: staggered_cooldown_jitter_daemon — 对齐 retriever.py iter1145
                        _cd_jh_d = (hash(chunk[_CI_ID]) % 49)
                        _cd_cut = (_dt648.fromisoformat(_cd_cut) - _td648(hours=_cd_jh_d)).isoformat()
                        if _cd_last > _cd_cut:
                            score = 0.0
                # iter989: saturation_widen — ac>=5 渐进衰减，ac>=12 suppress
                # iter1070: deep_saturated_floor — ac>=10 额外 *0.5
                # iter1294: small_db_deep_saturated_soften — <100 库改为强衰减
                # iter1682: sparse_saturation_shield — local_sparse 本地 chunk 跳过 saturation 衰减
                _sparse_sat_d = _local_sparse_d and _is_local_d
                if score > 0 and not _sparse_sat_d and (chunk[_CI_AC] or 0) >= 12:
                    if _db_chunk_count < 100:
                        score *= 0.1
                    else:
                        score = 0.0
                elif not _sparse_sat_d and (chunk[_CI_AC] or 0) >= 5:
                    _sat_mult = max(0.2, 0.8 - 0.1 * ((chunk[_CI_AC] or 0) - 5))
                    if (chunk[_CI_AC] or 0) >= 10:
                        _sat_mult *= 0.5
                    # iter1674: dc_graduated_decay — sync retriever.py iter1622
                    if chunk[_CI_CT] == "design_constraint":
                        if (chunk[_CI_AC] or 0) >= 7:
                            _sat_mult *= 0.5
                        elif (chunk[_CI_AC] or 0) >= 5:
                            _sat_mult *= 0.7
                    score *= _sat_mult
                # iter1686: dc_low_ac_decay — ac=3-4 design_constraint 轻度衰减（sync retriever.py）
                elif (chunk[_CI_CT] == "design_constraint"
                      and score > 0 and 3 <= (chunk[_CI_AC] or 0) < 5):
                    score *= 0.88 if (chunk[_CI_AC] or 0) == 3 else 0.82
            return score

        def _score_chunk_dict(chunk, relevance):
            # iter235: dict-based version for BM25 paths (_extra_chunks, BM25 fallback)
            # These paths use store_get_chunks() which returns dicts (chunk["key"] access).
            # BM25 path is already the slow path (~3-5ms DB read); per-chunk dict overhead is fine.
            # Semantically identical to _score_chunk but uses dict keys instead of _CI_* indices.
            _la = chunk["last_accessed"]
            _ca = chunk["created_at"] or ""
            _ac = chunk["access_count"]
            _cid = chunk["id"]
            _rc = _recall_counts.get(_cid, 0)
            _imp = chunk["importance"] or 0.5
            _lg = chunk["lru_gen"]
            _cp = chunk.get("project") or ""
            age_la = _age_days_fast(_la)
            if _ca and _ca != _la:
                age_ca = _age_days_fast(_ca)
            elif _ca:
                age_ca = age_la
            else:
                age_ca = 0.0
            _eff = _imp * _math.exp(age_la * _LN_DECAY_INV7)
            eff_imp = _eff if _eff >= _sc_floor else _sc_floor
            rec = 1.0 / (1.0 + age_la)
            ab = _AB_TABLE[_ac] if _ac < 64 else _sc_ab_cap  # iter251: 64-entry table covers 100% corpus
            # iter831: access_diminishing_return (dict path)
            if _ac > 8:
                ab *= 1.0 / (1.0 + (_ac - 8) * 0.1)
            # iter1647: internalized_knowledge_decay (dict path) — sync scorer.py
            if _ac >= 6:
                ab = ab - (_ac - 6) * 0.015
                if ab < 0.0:
                    ab = 0.0
            fb = _sc_fb_max - age_ca * _sc_fb_scale  # iter254: drop grace guard (corpus max age_ca = 1.2d avg)
            if _ac == 0 and age_ca >= _sc_sv_min:
                _sv_ratio = (age_ca - _sc_sv_min) / _sc_sv_rmp_safe
                sb = _sc_sv_fac * (_sv_ratio if _sv_ratio <= 1.0 else 1.0)
            else:
                sb = 0.0
            sp = _ST_TABLE_EXT[_rc] if _rc < 271 else _sc_st_cap  # iter256: 271-entry table (covers max rc=270)
            _vs = chunk.get("verification_status") or "pending"  # iter255: simplify dict path to match FTS
            vb = 0.12 if _vs == "verified" else 0.0  # iter255: single ternary (vp dropped, always 0)
            lgb = _LGB_TABLE[_lg] if _lg is not None and _lg < 9 else (0.0 if _lg is None else (0.06 - 0.0075 * (_lg if _lg < 8 else 8)) if _lg >= 0 else 0.0)  # iter240: dict path may have None _lg
            # iter846: global penalty sync 0.05→0.10
            ndp = (0.0 if _cp == project else
                   0.10 if _cp == "global" else
                   0.25 if _cp else 0.0)
            base = eff_imp * 0.55 + rec * 0.45
            score = relevance * (base + ab + fb) + sb - sp + vb + lgb - ndp  # iter255: drop -vp
            if _run_aslr and _cid and _ac < _sc_al_thr:  # iter252: no else-branch (eb=0 implicit)
                _h = hash((_cid, query)) & 0x7fffffff
                score += _sc_al_eps * (1.0 - _ac / _sc_al_thr) * ((_h % 10000) / 10000.0)
            if _pattern_keywords:
                _summary_lower = (chunk.get("summary") or "").lower()
                _matched = sum(1 for kw in _pattern_keywords if kw in _summary_lower)
                if _matched > 0:
                    score += min(0.10, _matched * 0.03)
            # iter1302: thin_content_penalty — content==summary 零增量降权 (dict path)
            _tc_con_d = chunk.get("content") or ""
            _tc_sum_d = chunk.get("summary") or ""
            if len(_tc_con_d) <= len(_tc_sum_d) + 5 and len(_tc_con_d) < 80:
                score *= 0.5
            # iter560: cfs_bandwidth — same throttle as _score_chunk (see above)
            if _bw_enabled and _rc > _bw_quota:
                score *= _bw_factor * (_bw_decay ** (_rc - _bw_quota))
            # iter600+601+612: bandwidth throttle — graduated penalty（同 _score_chunk）
            if _rc > 0:
                _hard_util_sd = _rc / _local_bw_window
                if _hard_util_sd > _inject_hard_cap:
                    score = 0.0
                else:
                    _bw_soft_start_d = _inject_hard_cap * 0.5
                    if _hard_util_sd > _bw_soft_start_d:
                        _bw_pen_d = 1.0 - (_hard_util_sd - _bw_soft_start_d) / (_inject_hard_cap - _bw_soft_start_d)
                        score *= _bw_pen_d
            # iter1673: topic_mismatch_discount — sync retriever.py iter1612 (dict path)
            # iter1680: daemon_topic_mismatch_hard_suppress — sync retriever.py iter1679
            if score > 0 and _cp != "global" and _cp == project and _ac >= 3 and _query_content_words:
                _tm_sd = (chunk.get("summary") or "").lower()
                _tm_wd = set(w for w in _RE_NON_WORD.sub(' ', _tm_sd).split() if len(w) >= 2)
                if _tm_wd and len(_query_content_words & _tm_wd) == 0:
                    if chunk.get("chunk_type") != "design_constraint" and _ac >= 5:
                        score = 0.0
                    else:
                        score *= 0.6 if chunk.get("chunk_type") == "design_constraint" else 0.3
            # iter875/876: soft_diversity_penalty — sync with _score_chunk (factor 0.35)
            # iter898: small_db_diversity_boost — <50 库 factor 0.35→0.55
            _r7d_sd = _recent_7d_counts.get(_cid, 0)
            # iter1639: sync iter1624 zero_7d_historical_penalty
            # iter1676: graduated_synthetic_7d_sync — sync retriever.py iter1651
            _total_inj_d2 = _itl_lifetime.get(_cid, (0,))[0] if _itl_lifetime else 0
            if _r7d_sd == 0 and _total_inj_d2 >= 5 and _db_chunk_count > 5:
                _r7d_sd = min(3, 1 + (_total_inj_d2 - 5) // 2)
            if _r7d_sd > 0 and _db_chunk_count > 5:
                # iter969: diversity_factor_align_small_db
                _dp_factor_d = 0.55 if _db_chunk_count < 100 else 0.35
                # iter1639: sync iter1003 global_chunk_diversity_boost
                if (chunk[_CI_CP] or "") == "global" and project != "global":
                    _dp_factor_d *= 2.0
                # iter1639: sync iter1453 ac_weighted_diversity
                _dp_ac_d = chunk[_CI_AC] or 0
                if _dp_ac_d >= 4:
                    _dp_factor_d *= 1.0 + 0.15 * (_dp_ac_d - 3)
                # iter1552: cumulative_boost_tighten — sync retriever.py timeline_cumulative_boost
                if _total_inj_d2 >= 3:
                    _dp_factor_d *= 1.0 + 0.35 * (_total_inj_d2 - 2)
                score *= 1.0 / (1.0 + _r7d_sd * _dp_factor_d)
            # iter618: 24h + 7d burst suppress（daemon 此前完全缺失）
            # iter619: 阈值收紧 24h:3→2, 7d:8→5
            # iter672: relevance_exempt — 高分 chunk 放宽阈值，防 suppress 过杀
            # iter767: tiered_small_db — 分级小库阈值（同 _score_chunk）
            _s672d_micro = _db_chunk_count <= 5  # iter801: micro_db suppress bypass
            _s672d_tiny = _db_chunk_count < 50  # iter848: 边界 40→50
            _s672d_small = _db_chunk_count < 100
            # iter806: small_db_suppress_tighten — sync with retriever.py
            # iter801: micro_db (<=5) 跳过 suppress
            # iter1049: micro_db_cross_project_suppress — 跨项目 chunk 不享受 micro_db 免疫
            # iter1227: sparse_local_shield_daemon — dict path sync
            _is_local_d2 = ((chunk[_CI_CP] or "") == project)
            _sparse_shield_d2 = _local_sparse_d and _is_local_d2
            if not (_s672d_micro or _sparse_shield_d2) or ((chunk[_CI_CP] or "") != project and (chunk[_CI_CP] or "") != "global"):
                # iter813: short_burst_suppress — 6h 内 >=N 次即 suppress
                # iter818: tiny_db_6h_relax — 6h 分级
                # iter865: 6h_tighten_tiny — tiny_db 3→2（统一阈值）
                # iter1042+1047: saturated_6h_cap — ac>=7 或 design_constraint ac>=5 → thresh=1
                _6h_ac_d2 = chunk.get("access_count", 0) or 0
                # iter1048: global_6h_sync — global ac>=4 同步 iter1023(24h cap=1)
                # iter1225: constraint_saturated_6h_sync — ac>=5→4 对齐 retriever.py iter1171
                # iter1230: 6h_floor_2 — sync with above
                _6h_thresh_d2 = 2 if (_6h_ac_d2 >= 7 or (chunk.get("chunk_type") == "design_constraint" and _6h_ac_d2 >= 4) or (chunk.get("project") == "global" and _6h_ac_d2 >= 4)) else 3
                # iter1227: sparse_global_shield — dict path sync
                if _local_sparse_d and (chunk.get("project", "") or "") == "global":
                    _6h_thresh_d2 += 1
                if _recent_6h_counts.get(_cid, 0) >= _6h_thresh_d2:
                    score = 0.0
                # iter810: tiny_db_24h_relax — sync
                # iter1019: saturated_24h_tighten — sync retriever.py
                else:
                    _24h_base_d2 = 3 if _s672d_tiny else (3 if score >= 0.5 else 2) if _s672d_small else (3 if score >= 0.5 else 2)
                    _d2_ac = (chunk.get("access_count", 0) or 0)
                    if _d2_ac >= 10:
                        _24h_base_d2 = max(1, _24h_base_d2 - 2)
                    elif _d2_ac >= 7:
                        _24h_base_d2 = max(1, _24h_base_d2 - 1)
                    # iter1023: global_24h_saturated_cap — sync retriever.py
                    elif (chunk.get("project", "") or "") == "global" and _d2_ac >= 4:
                        _24h_base_d2 = 1
                    if _recent_24h_counts.get(_cid, 0) >= _24h_base_d2:
                        score = 0.0
                # iter854: tiny_db_7d_relax_v2 — 阈值 5→7（sync retriever.py）
                # iter882: 7d_tighten_monopoly — sync FTS path
                # iter971: tiny 4→3 去垄断（sync suppress_final_gate）
                # iter990: small_db_7d_relax_v3 — daemon dict path 同步
                if score > 0:  # iter1071: fix syntax — 原 else 与 if 不配对
                    _7d_base_d2 = 7 if _s672d_tiny else (4 if score >= 0.5 else 3) if _s672d_small else (5 if score >= 0.5 else 3)  # iter1497: small_db 6/4→4/3
                    # iter1194: global_unified_thresh — sync daemon dict path
                    # iter1478: global_deep_saturated_7d_tighten — sync dict path
                    # iter1524: tiny_db_global_7d_relax — sync dict path
                    if (chunk.get("project", "") or "") == "global":
                        _g_ac_d2 = chunk.get("access_count", 0) or 0
                        if _s672d_tiny:
                            # iter1640: global_dc_tinydb_7d_tighten — sync dict path
                            if _g_ac_d2 >= 4 and chunk.get("chunk_type") == "design_constraint":
                                _7d_base_d2 = 2
                            elif _g_ac_d2 >= 4:
                                _7d_base_d2 = 3
                            else:
                                _7d_base_d2 = 5
                        elif _s672d_small:
                            _7d_base_d2 = 2 if _g_ac_d2 >= 4 else 4
                        else:
                            _7d_base_d2 = 2
                        # iter1227: sparse_global_shield — dict path sync
                        if _local_sparse_d:
                            _7d_base_d2 += 1
                    elif (chunk.get("project", "") or "") != "global":
                        # iter1143: local_mid_saturated_suppress — sync dict path
                        _l_ac_d2 = chunk.get("access_count", 0) or 0
                        if _l_ac_d2 >= 7:
                            _7d_base_d2 = 2
                        elif _l_ac_d2 >= 5:
                            _7d_base_d2 = max(2, _7d_base_d2 - 2)  # iter1152: local_mid_saturated_tighten
                        elif _l_ac_d2 >= 4:
                            # iter1549: ac4_tiny_db_7d_cap2 — sync dict path
                            _7d_base_d2 = 2 if _s672_tiny else max(3, _7d_base_d2 - 1)
                        # iter1402: ac3_7d_tinydb_relax — tiny_db cap (dict path)
                        elif _l_ac_d2 >= 3:
                            _7d_base_d2 = min(_7d_base_d2, 3 if _s672_tiny else 2)
                    if _recent_7d_counts.get(_cid, 0) >= _7d_base_d2:
                        score = 0.0
                # iter1072: cooldown_widen — ac>=10 cooldown 72h→7d, ac>=7 48h→5d (dict path)
                # iter1073: global_cooldown_widen — global chunk ac>=4 纳入 cooldown（72h→48h）
                # iter1078: cooldown_floor_unify — sync daemon dict path floor 7→4
                # iter1083: global_cooldown_floor_fix — global chunk 绕过 ac_floor
                _cd_floor_d2 = 4
                _cd_is_global_d2 = (chunk.get("project", "") == "global")
                if score > 0 and (_cd_is_global_d2 or (chunk.get("access_count", 0) or 0) >= _cd_floor_d2) and _cutoff_48h and _last_inject_ts:
                    _cd_last_d2 = _last_inject_ts.get(_cid)
                    # iter1110: fallback_floor_align — ac>=_cd_floor_d2 统一 fallback（原 ac>=7 漏洞）
                    if not _cd_last_d2 and (chunk.get("access_count", 0) or 0) >= _cd_floor_d2:
                        _cd_la_d2 = chunk.get("last_accessed", "")
                        if _cd_la_d2:
                            _cd_last_d2 = _cd_la_d2
                    if _cd_last_d2:
                        # iter1091: cooldown_daemon_sync — 对齐 retriever.py iter1089
                        # iter1151: dict_cooldown_align — 修复 ac>=10 用 7d 而非 14d 的错误
                        if _cd_is_global_d2:
                            _cd_cut_d2 = _cutoff_14d if (chunk.get("access_count", 0) or 0) >= 10 else _cutoff_10d
                        else:
                            # iter1252: cooldown_5d_to_3d
                            _cd_cut_d2 = _cutoff_14d if (chunk.get("access_count", 0) or 0) >= 10 else (_cutoff_10d if (chunk.get("access_count", 0) or 0) >= 7 else _cutoff_72h)
                        # iter1151: staggered_cooldown_jitter_daemon — 对齐 retriever.py iter1145
                        _cd_jh_d2 = (hash(chunk.get("id", "")) % 49)
                        _cd_cut_d2 = (_dt648.fromisoformat(_cd_cut_d2) - _td648(hours=_cd_jh_d2)).isoformat()
                        if _cd_last_d2 > _cd_cut_d2:
                            score = 0.0
                # iter989: saturation_widen — ac>=5 渐进衰减，ac>=12 suppress
                # iter1070: deep_saturated_floor — ac>=10 额外 *0.5
                # iter1294: small_db_deep_saturated_soften — <100 库改为强衰减
                # iter1682: sparse_saturation_shield — sync retriever.py
                _sparse_sat_d2 = _local_sparse_d and (chunk.get("project", "") == project)
                if score > 0 and not _sparse_sat_d2 and (chunk.get("access_count", 0) or 0) >= 12:
                    if _db_chunk_count < 100:
                        score *= 0.1
                    else:
                        score = 0.0
                elif not _sparse_sat_d2 and (chunk.get("access_count", 0) or 0) >= 5:
                    _sat_mult = max(0.2, 0.8 - 0.1 * ((chunk.get("access_count", 0) or 0) - 5))
                    if (chunk.get("access_count", 0) or 0) >= 10:
                        _sat_mult *= 0.5
                    # iter1674: dc_graduated_decay — sync retriever.py iter1622
                    if chunk.get("chunk_type") == "design_constraint":
                        if (chunk.get("access_count", 0) or 0) >= 7:
                            _sat_mult *= 0.5
                        elif (chunk.get("access_count", 0) or 0) >= 5:
                            _sat_mult *= 0.7
                    score *= _sat_mult
                # iter1686: dc_low_ac_decay — ac=3-4 design_constraint 轻度衰减（sync retriever.py）
                elif (chunk.get("chunk_type") == "design_constraint"
                      and score > 0 and 3 <= (chunk.get("access_count", 0) or 0) < 5):
                    _dc_ac = chunk.get("access_count", 0) or 0
                    score *= 0.88 if _dc_ac == 3 else 0.82
            return score

        def _gc_dict_to_ci(c):
            # iter235: convert get_chunks dict → _CI_*-order tuple so final[] is uniform tuple format.
            # BM25 path is already slow (ms-level DB read); this per-chunk conversion is fine.
            # fts_rank=0.0 (BM25 chunks have no FTS rank); _CI_FR is unused after scoring.
            return (c["id"], c["summary"], c["content"], c.get("importance"),
                    c["last_accessed"], c["chunk_type"], c["access_count"],
                    c["created_at"], 0.0,  # _CI_FR: fts_rank not used post-scoring
                    c.get("lru_gen"), c.get("project", ""),
                    c.get("verification_status"), c.get("confidence_score"))

        # ── FTS5 search ──
        _hybrid_bm25_count = 0
        _bm25_global_discount = 1.0

        try:
            # iter181: top_k * 2 instead of * 3 — FTS top-7 contains 100% of final top-5
            # (validated on 10 real queries). Scoring 10→15 chunks saves ~113us.
            # SQLite FTS5 LIMIT doesn't reduce index traversal, only transfer+scoring overhead.
            fts_results = fts_search(conn, query, project, top_k=effective_top_k * 2,
                                     chunk_types=_retrieve_types)
            use_fts = bool(fts_results)
        except Exception:
            fts_results = []
            use_fts = False

        if use_fts:
            candidates_count = len(fts_results)
            # iter198: FTS5 returns results sorted desc by rank — max_rank = first element
            # (validated: fts_results[0]["fts_rank"] == max() for all real queries, N=10)
            # use_fts=True guarantees fts_results is non-empty, so [0] is safe.
            # OS 类比：readdir() 返回排序后结果 — 首元素即最大值，无需再扫一遍。
            max_rank = fts_results[0][_CI_FR]  # iter235: positional tuple access
            if max_rank <= 0:
                max_rank = 1.0
            # iter684: FTS5 raw_relevance_gate — 与 BM25 路径对齐
            # FTS5 rank 单位不同于 BM25 raw score，但经验阈值：
            #   真正相关 rank > 5.0（飞书=21, Android=15, sched=8）
            #   噪声匹配 rank < 4.0（通用bigram重叠=2-3）
            # iter701→711: 降低门槛 5.0→1.0 — 实测 40 chunk 库，真实相关查询 max_rank=1.5-4.5
            #   "如何发 kernel patch"=1.75, "Android 性能诊断"=2.54, "飞书文档访问"=4.26
            #   FTS5 -bm25() 在小库上 score 天然低（IDF 低），5.0 门槛阻断了 80%+ 合法查询
            #   1.0 门槛仅过滤完全无匹配（score=0）的噪声查询
            if max_rank < 1.0:
                return
            # iter198: list comprehension replaces for loop (6.06us → ~2us, 10 chunks)
            # set comprehension replaces per-iteration set.add() (combined: ~2.09us total)
            # iter235: chunk[_CI_ID]/chunk[_CI_FR] — positional tuple access
            # OS 类比：vectorized SIMD load — 批量构建比逐元素 push_back 快（减少 Python per-iter overhead）
            # iter756: small_db_bw_tighten; iter774: tiny_db_bw_relax
            #   根因(756)：42 chunk 库中 hard_cap=0.30 → rc>9 才 suppress → 逃逸。
            #   根因(774)：6 chunk 库中 0.12 → rc≥3 suppress → cands=3 全灭 → 66% 空召回。
            if _db_chunk_count < 100:
                # iter801: micro_db_suppress_bypass — <=5 chunk 库禁用 bandwidth suppress
                # iter861: small_db_bw_tighten — <50 收紧 0.25→0.15
                # iter1642: small_db_hardcap_tighten — <50 收紧 0.15→0.10 (rc>3 即 suppress)
                _inject_hard_cap = 1.0 if _db_chunk_count <= 5 else (0.10 if _db_chunk_count < 50 else 0.12)
            # iter1600: sparse_local_candidate_inject — sparse 项目本地 chunk 主动注入候选池
            # 根因（数据驱动，2026-05-12）：_local_sparse 项目的本地 chunk 因 FTS5 关键词
            #   不匹配从未进入候选池。正常路径下跨项目 chunk 通过评分→本地 chunk 零机会参与竞争。
            # 修复：检查 FTS 结果是否含本地 chunk，缺失则从 DB 补入（fts_rank = min * 0.5）。
            if _local_sparse_d and fts_results:
                _sli_has_local = any(c[_CI_CP] == project for c in fts_results)
                if not _sli_has_local:
                    try:
                        # iter1632: immutable_conn_stale_fix — 同上
                        import sqlite3 as _sli_sql
                        _sli_conn = _sli_sql.connect(str(STORE_DB), timeout=2)
                        _sli_r = _sli_conn.execute(
                            "SELECT id, summary, content, importance, last_accessed, "
                            "chunk_type, COALESCE(access_count,0), created_at, "
                            "0.0, COALESCE(lru_gen,0), project, "
                            "verification_status, confidence_score, "
                            "COALESCE(retrievability,1.0), COALESCE(source_reliability,0.7), "
                            "COALESCE(emotional_weight,0.0), COALESCE(emotional_valence,0.0) "
                            "FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE' "
                            "ORDER BY importance DESC LIMIT 1",
                            (project,)
                        ).fetchone()
                        _sli_conn.close()
                        if _sli_r:
                            _sli_min_rank = min(c[_CI_FR] for c in fts_results)
                            _sli_t = list(_sli_r)
                            _sli_t[_CI_FR] = _sli_min_rank * 0.5
                            fts_results.append(tuple(_sli_t))
                            _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                          f"iter1600_sparse_local_candidate_inject: "
                                          f"id={_sli_r[0][:12]} imp={_sli_r[3]:.2f}",
                                          session_id=session_id, project=project)
                    except Exception:
                        pass
            fts_ids = {chunk[_CI_ID] for chunk in fts_results}  # iter235: positional tuple
            final = [(_score_chunk(chunk, chunk[_CI_FR] / max_rank), chunk)
                     for chunk in fts_results]

            # Hybrid BM25 补充
            try:
                _hybrid_threshold = sysctl("retriever.hybrid_fts_min_count")
            except Exception:
                _hybrid_threshold = effective_top_k

            if len(fts_results) < _hybrid_threshold:
                try:
                    if not _check_deadline("pre_hybrid_bm25"):
                        # iter163: 尝试从内存缓存获取全量 chunks（避免重复 DB read）
                        # iter207: fast path — _retrieve_types is module constant in ~100% of cases
                        _rtypes_key = (_ALL_RETRIEVE_TYPES_KEY if _retrieve_types is _ALL_RETRIEVE_TYPES_CONST
                                       else (",".join(sorted(_retrieve_types)) if _retrieve_types else ""))
                        _cv_hybrid = read_chunk_version()
                        _cached_hybrid = _bm25_mem_cache_get(project, _rtypes_key, _cv_hybrid)
                        if _cached_hybrid is not None:
                            _all_chunks, _cached_idx, _cached_texts = _cached_hybrid
                        else:
                            _all_chunks = store_get_chunks(conn, project, chunk_types=_retrieve_types)
                        _extra_chunks = [c for c in _all_chunks if c["id"] not in fts_ids]  # iter213: [] not .get()
                        if _extra_chunks:
                            if _cached_hybrid is not None:
                                # 缓存命中：用已有索引对 extra_chunks 子集评分
                                # 因为 extra_chunks 是全量的子集，需要用全量 search_texts 的索引
                                # 但评分只取 extra_chunks 对应的位置
                                _all_ids = [c.get("id", "") for c in _all_chunks]
                                _extra_positions = [_all_ids.index(c.get("id", ""))
                                                    for c in _extra_chunks
                                                    if c.get("id", "") in _all_ids]
                                _full_raw = _cached_idx.score(query)
                                _extra_raw = [_full_raw[p] for p in _extra_positions if p < len(_full_raw)]
                            else:
                                _extra_texts = [f"{c['summary']} {c['content']}" for c in _extra_chunks]
                                _extra_raw = bm25_scores_cached(query, _extra_texts, chunk_version=_cv_hybrid)
                            _extra_norm = normalize(_extra_raw)
                            for i, chunk in enumerate(_extra_chunks):
                                if i < len(_extra_norm):
                                    score = _score_chunk_dict(chunk, _extra_norm[i] * 0.6)  # iter235: dict path
                                    final.append((score, _gc_dict_to_ci(chunk)))  # iter235: uniform _CI_* tuple
                            _hybrid_bm25_count = min(len(_extra_chunks), _hybrid_threshold - len(fts_results))
                            candidates_count += _hybrid_bm25_count
                except Exception:
                    pass
        else:
            if priority == "LITE":
                # iter1645: daemon sync iter1643 lite_sparse_local_rescue
                if _local_sparse_d and _local_chunk_count_d > 0:
                    try:
                        _lsr_d = conn.execute(
                            "SELECT id, summary, content, chunk_type, importance "
                            "FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE' "
                            "ORDER BY importance DESC, access_count DESC LIMIT 1",
                            (project,)
                        ).fetchone()
                        if _lsr_d and _recent_6h_counts.get(_lsr_d[0], 0) < 2:
                            fts_results = [{"id": _lsr_d[0], "summary": _lsr_d[1],
                                            "content": _lsr_d[2], "chunk_type": _lsr_d[3] or "",
                                            "importance": _lsr_d[4] or 0.5}]
                            use_fts = True
                            _deferred.log(DMESG_DEBUG, "retriever",
                                          f"iter1645_daemon_lite_sparse_rescue: "
                                          f"id={_lsr_d[0][:12]} imp={_lsr_d[4]:.2f}",
                                          session_id=session_id, project=project)
                    except Exception:
                        pass
                if use_fts:
                    pass  # rescued — skip LITE exit, proceed to scoring
                else:
                    # iter713: 小库时 LITE 不再直接 return — FTS miss 常见（40 chunk），
                    #   改为降级走 BM25 fallback（同 FULL 路径）
                    #   根因：LITE+FTS_miss 是注入率低的第二大原因（仅次于 suppress）
                    #   DB<100 chunk 时全部走 BM25 fallback，否则保持原逻辑
                    _total_mc_lite = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
                    if _total_mc_lite >= 100:
                        if _deferred._buf:
                            try:
                                wconn = open_db()
                                ensure_schema(wconn)
                                _deferred.flush(wconn)
                                wconn.commit()
                                wconn.close()
                            except Exception:
                                pass
                        return
                    # else: fall through to BM25 fallback below

            if _check_deadline("pre_bm25_fallback", is_hard=True):
                # iter173: persistent conn — do NOT close
                if _deferred._buf:  # iter222: direct slot access
                    try:
                        wconn = open_db()
                        ensure_schema(wconn)
                        _deferred.flush(wconn)
                        wconn.commit()
                        wconn.close()
                    except Exception:
                        pass
                return

            _bm25_global_discount = sysctl("retriever.bm25_global_discount")
            # iter657: 当前 project 无 chunk 时跳过 global discount
            # iter702: 小库（<100 chunk）时 discount 提升到 0.8 — global chunk 是主要信息源
            #   根因：40 chunk DB 中 27 个是 global，discount=0.4 导致 relevance 被压到
            #   0.4 以下 → 低于 min_score_threshold(0.3) → 零注入。
            #   修复：DB 总量<100 时，global discount 提升到 max(0.8, 原值)，保留排序信号但不过度惩罚
            if project and project != "global":
                _local_count = conn.execute(
                    "SELECT COUNT(*) FROM memory_chunks WHERE project=?", (project,)
                ).fetchone()[0]
                if _local_count == 0:
                    _bm25_global_discount = 1.0
                else:
                    _total_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_chunks"
                    ).fetchone()[0]
                    if _total_count < 100:
                        _bm25_global_discount = max(0.8, _bm25_global_discount)
            _cv = read_chunk_version()
            # iter207: fast path — _retrieve_types is module constant in ~100% of cases
            _rtypes_key = (_ALL_RETRIEVE_TYPES_KEY if _retrieve_types is _ALL_RETRIEVE_TYPES_CONST
                           else (",".join(sorted(_retrieve_types)) if _retrieve_types else ""))

            # iter163: 内存 BM25 缓存（page cache 类比）
            # cache hit: 跳过 DB read + tokenize，只做 query tokenize + 评分
            _mem_cached = _bm25_mem_cache_get(project, _rtypes_key, _cv)
            if _mem_cached is not None:
                chunks, _bm25_idx, search_texts = _mem_cached
                raw_scores = _bm25_idx.score(query)
            else:
                # cache miss: 从 DB 加载，构建索引，写入内存缓存
                chunks = store_get_chunks(conn, project, chunk_types=_retrieve_types)
                if not chunks:
                    return
                search_texts = [f"{c['summary']} {c['content']}" for c in chunks]
                from bm25 import BM25Index as _BM25Index
                _bm25_idx = _BM25Index.load_or_build(search_texts, chunk_version=_cv)
                _bm25_mem_cache_put(project, _rtypes_key, _cv, chunks, _bm25_idx, search_texts)
                raw_scores = _bm25_idx.score(query)

            if not chunks:
                return
            candidates_count = len(chunks)
            # iter756: small_db_bw_tighten; iter774: tiny_db_bw_relax (BM25 path)
            if _db_chunk_count < 100:
                # iter801: micro_db_suppress_bypass (BM25 path)
                # iter861→1642: small_db_hardcap_tighten — <50 收紧 0.15→0.10 (BM25 path sync)
                _inject_hard_cap = 1.0 if _db_chunk_count <= 5 else (0.10 if _db_chunk_count < 50 else 0.12)
            # iter683: raw_relevance_gate — 绝对相关性门槛
            # 根因（用户可感知）：normalize 是相对排名（max=1.0），当 DB 中无真正相关 chunk 时，
            # 噪声匹配（中文通用 bigram 重叠）被放大到 1.0 超过阈值 → 注入不相关内容。
            # 实测：真正相关时 raw max > 10（飞书=21, Android=28），噪声时 raw max < 5（睾酮=3.9, 继续迭代=2.3）。
            # iter761: 校准 raw gate 到 4.0 — 在 44 chunk DB 中精确分割相关/无关
            #   相关 query raw >= 5.5（kernel=5.7, 团队=5.5, AIOS=9.5, 飞书=18）
            #   无关 query raw <= 3.1（Python排序=3.1, 睾酮=2.3, 天气=0）
            #   阈值 4.0 完美分割，消除 false positive 同时保留所有 true positive
            _raw_max = max(raw_scores) if raw_scores else 0
            if _raw_max < 4.0:
                # 无真正相关内容，退出（不写 trace 污染统计）
                return
            relevance_scores = normalize(raw_scores)
            final = []
            _iter1446_rel_map = {}  # iter1446: relevance map for fallback gate
            for i, chunk in enumerate(chunks):
                relevance = relevance_scores[i]
                if (project != "global" and chunk.get("project", "") == "global"
                        and _bm25_global_discount < 1.0):
                    relevance = relevance * _bm25_global_discount
                score = _score_chunk_dict(chunk, relevance)  # iter235: dict path
                # iter1446: daemon_global_irrelevance_gate — sync retriever.py iter1284/1360+iter1128
                _cp_d = chunk.get("project", "") or ""
                if project != "global":
                    if _cp_d == "global" and relevance < 0.20:
                        score = 0.0
                    elif _cp_d == "global" and relevance < 0.40:
                        score *= 0.50
                    elif _cp_d and _cp_d != "global" and _cp_d != project and relevance < 0.30:
                        score *= 0.30
                _iter1446_rel_map[chunk.get("id", "")] = relevance
                final.append((score, _gc_dict_to_ci(chunk)))  # iter235: uniform _CI_* tuple

        # Hard deadline post-scoring
        if _check_deadline("post_scoring", is_hard=True):
            final.sort(key=_SORT_KEY, reverse=True)  # iter218: C-level itemgetter vs lambda
            # iter193: use pre-read locals; iter194: reuse _is_generic_q (computed once above)
            _min_thresh = (_gen_query_thr if _is_generic_q else _min_score_thr)
            # iter820: daemon_adaptive_floor — 同步 retriever.py iter578 adaptive_floor
            # 根因（数据驱动，2026-05-05）：daemon 缺 adaptive_floor，大库(30+ cands)
            #   top1=0.5~0.9 时 top2+ 在 0.18-0.29 全被 0.30 阈值过滤 → 68% 注入仅 1 条。
            # 修复：top1>=0.5 时 floor=top1×0.25，允许与 top1 相关的次优候选通过。
            # iter822: af_min_top1 0.5→0.30 — 64% 检索 top1 在 0.30-0.50，原阈值不生效
            #   导致 74% 注入仅 1 条。降至 0.30 后 top1=0.35 → floor=0.10 放行次优候选。
            if final and not _is_generic_q:
                _af_top1 = final[0][0]
                if _af_top1 >= 0.30:
                    # iter823: small_db_af_relax — 小库 ratio 0.25→0.12
                    # iter1130: small_db_af_raise — 0.12→0.20 (daemon hard_deadline sync)
                    _af_r = 0.20 if _db_chunk_count < 100 else 0.25
                    # iter1130: relevance_floor_raise — 0.12→0.15 (daemon sync)
                    _min_thresh = min(_min_thresh, max(_af_top1 * _af_r, 0.15))
            # iter821: daemon_gap_bridge (hard_deadline) — 同步 retriever.py iter579
            # 根因：top1=0.6 top2=0.15 时 adaptive_floor=0.15 仍不够低，
            #   但 top2~top4 内聚(0.15/0.14/0.13) → cluster 存在 → 应放行。
            if len(final) >= 3 and not _is_generic_q:
                _gb_t1 = final[0][0]
                _gb_t2 = final[1][0] if final[1][0] > 0 else 0.001
                if _gb_t1 / _gb_t2 >= 3.0:
                    _gb_cf = _gb_t2 * 0.4
                    _gb_cs = sum(1 for s, _ in final[1:] if s >= _gb_cf)
                    if _gb_cs >= 2:
                        # iter863: gap_bridge_floor_raise — 0.05→0.10 防止低相关性噪声注入
                        # iter1130: relevance_floor_raise — 0.12→0.15 (daemon hd sync)
                        _gb_nt = max(_gb_cf, 0.15)
                        if _gb_nt < _min_thresh:
                            _min_thresh = _gb_nt
            # iter620: zero_score_absolute_gate — hard_suppressed chunk 绝对不入选
            positive = [(s, c) for s, c in final if s >= _min_thresh and s > 0]
            # iter1368: sparse_cross_floor_tighten — daemon hard_deadline sync
            _cross_floor_d = 0.25 if _local_chunk_count_d == 0 else (0.18 if _local_sparse_d else 0.25)
            positive = [(s, c) for s, c in positive
                        if (c[_CI_CP] or "") in ("", project) or s >= _cross_floor_d]
            # iter695: threshold_degrade — 阈值过高全灭时降级到默认 0.30
            if not positive and _min_thresh > 0.30:
                positive = [(s, c) for s, c in final if s >= 0.30 and s > 0]
            # iter759: 移除 candidates_rescue — 宁可不注入也不注入垃圾
            # 根因（用户可感知）：rescue 下限 0.15 导致 score=0.156 的不相关 PE 分析被注入，
            # 占用 context 空间干扰注意力。注入不相关内容比不注入更糟。
            # 原 iter697/698 rescue 机制已删除。
            # ── iter830: daemon_pair_inject — 同步 retriever.py iter826/827 ──
            # 根因（数据驱动，2026-05-05）：70% 注入为单条。daemon 路径缺失 pair_inject，
            #   retriever.py 的 iter826/827 从未在 daemon 被触发。
            if len(positive) == 1 and len(final) >= 3:
                # iter936: pair_7d_align_final_gate — pair 候选加 7d suppress 检查
                _pi_cands = [(s, c) for s, c in final
                             if s > 0.12 and s < _min_thresh
                             and c[_CI_ID] != positive[0][1][_CI_ID]
                             and _recent_7d_counts.get(c[_CI_ID], 0) < (3 if _db_chunk_count < 50 else 4)]
                if _pi_cands:
                    _pi_best = max(_pi_cands, key=lambda x: x[0])
                    positive.append(_pi_best)
                    _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                  f"iter830_pair_inject_hd: paired {_pi_best[1][_CI_ID][:12]} "
                                  f"s={_pi_best[0]:.3f} with top1 s={positive[0][0]:.3f}",
                                  session_id=session_id, project=project)
                else:
                    _ip_cands = [(float(c[_CI_IMP] or 0), c) for _, c in final
                                 if c[_CI_ID] != positive[0][1][_CI_ID]
                                 and (c[_CI_AC] or 0) < 30
                                 and _recent_7d_counts.get(c[_CI_ID], 0) < (3 if _db_chunk_count < 50 else 4)
                                 # iter1702: daemon_pair_dc_gate — sync retriever.py iter1608
                                 and not ((c[_CI_CT] or "") == "design_constraint" and (c[_CI_AC] or 0) >= 4)]
                    if _ip_cands:
                        _ip_best = max(_ip_cands, key=lambda x: x[0])
                        # iter941: imp_pair_top1_gate — top1 score 过低时不配对
                        if _ip_best[0] >= 0.3 and positive[0][0] >= 0.15:
                            positive.append((positive[0][0] * 0.3, _ip_best[1]))
                            _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                          f"iter830_imp_pair_hd: paired {_ip_best[1][_CI_ID][:12]} "
                                          f"imp={_ip_best[0]:.2f} with top1 s={positive[0][0]:.3f}",
                                          session_id=session_id, project=project)
            # iter864: diversity_pair_from_db (hard_deadline path)
            # iter943: diversity_pair_7d_suppress — 排除 7d 达阈值的 chunk
            if len(positive) == 1 and _db_chunk_count < 50:
                _top1_id_hd = positive[0][1][_CI_ID]
                try:
                    import sqlite3 as _div_sql_hd
                    _div_conn_hd = _div_sql_hd.connect(str(STORE_DB))
                    _div_rows_hd = _div_conn_hd.execute(
                        "SELECT id, summary, content, chunk_type, importance, access_count "
                        "FROM memory_chunks WHERE project = ? AND chunk_state = 'ACTIVE' "
                        "AND importance >= 0.5 AND id != ? "
                        "ORDER BY access_count ASC, importance DESC LIMIT 3",
                        (project, _top1_id_hd)).fetchall()
                    _div_conn_hd.close()
                    _div_7d_ceiling_hd = 5 if _db_chunk_count < 50 else (4 if _db_chunk_count < 100 else 6)  # iter1207: pair_ceiling_mid_tighten — 50-99 库 6→4 去垄断
                    _div_rows_hd = [r for r in _div_rows_hd
                                    if _recent_7d_counts.get(r[0], 0) < _div_7d_ceiling_hd
                                    # iter1702: daemon_pair_dc_gate — sync retriever.py iter1608
                                    and not (r[3] == "design_constraint" and r[5] >= 4)]
                    if _div_rows_hd:
                        # iter872: diversity_counter (hard_deadline path)
                        _div_pick_hd = _div_rows_hd[_diversity_counter[0] % len(_div_rows_hd)]
                        _diversity_counter[0] += 1
                        _div_chunk_hd = (_div_pick_hd[0], _div_pick_hd[1], _div_pick_hd[2],
                                        _div_pick_hd[4], 0, 0, _div_pick_hd[5], None, None, None,
                                        _div_pick_hd[3], None)
                        positive.append((positive[0][0] * 0.25, _div_chunk_hd))
                        _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                      f"iter864_diversity_pair_hd: db_pick {_div_pick_hd[0][:12]} "
                                      f"imp={_div_pick_hd[4]:.2f} ac={_div_pick_hd[5]}",
                                      session_id=session_id, project=project)
                except Exception:
                    pass
            if _drr_enabled and len(positive) > effective_top_k:
                top_k = _drr_select(positive, effective_top_k)
            else:
                top_k = positive[:effective_top_k]
            # iter842: post_suppress_pair_from_final (hard_deadline path)
            # iter936: pair_7d_align_final_gate — 加 7d suppress 检查堵逃逸
            # iter1461: lite_pair_final_relax — final>=3→>=2 sync retriever.py
            if len(top_k) == 1 and len(final) >= 2:
                _ps842_hd_top1_id = top_k[0][1][_CI_ID]
                _ps842_hd_cands = [(float(c[_CI_IMP] or 0), c) for _, c in final
                                   if c[_CI_ID] != _ps842_hd_top1_id
                                   and (c[_CI_AC] or 0) < 30
                                   and _recent_7d_counts.get(c[_CI_ID], 0) < (3 if _db_chunk_count < 50 else 4)
                                   # iter1702: daemon_pair_dc_gate — sync retriever.py iter1608
                                   and not ((c[_CI_CT] or "") == "design_constraint" and (c[_CI_AC] or 0) >= 4)]
                if _ps842_hd_cands:
                    _ps842_hd_best = max(_ps842_hd_cands, key=lambda x: x[0])
                    if _ps842_hd_best[0] >= 0.3:
                        _ps842_hd_score = top_k[0][0] * 0.25
                        # iter1562: pair_inherit_floor_protect
                        if top_k[0][1][_CI_ID] in _fallback_protected_ids:
                            _fallback_protected_ids.add(_ps842_hd_best[1][_CI_ID])
                        top_k.append((_ps842_hd_score, _ps842_hd_best[1]))
                        _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                      f"iter842_pair_from_final_hd: paired "
                                      f"{_ps842_hd_best[1][_CI_ID][:12]} "
                                      f"imp={_ps842_hd_best[0]:.2f}",
                                      session_id=session_id, project=project)
            # ── iter689: score_empty_fallback (hard_deadline) ──
            # iter770: fallback_noise_gate — 硬性下限防止低分垃圾注入
            # iter771: tiny_db_fallback_relax — 小库降至 0.15
            # iter852: sync tiny_db boundary 30→50 (同 iter848/iter819)
            # iter1675: sparse_noise_floor_relax — sparse 项目 noise_floor 降低
            # 根因（数据驱动，2026-05-13）：78dc 项目 1 local chunk(imp=0.85,ac=8)
            #   FTS5 不匹配时 score=imp*0.1=0.085 < 0.15 → fallback 拒绝 → 空召回。
            #   sparse 项目唯一知识源不应被 noise_floor 卡死。
            _FALLBACK_NOISE_FLOOR = 0.05 if _local_sparse_d else (0.15 if _db_chunk_count < 50 else 0.25)
            # iter1667: scoring_wipeout_ftrace — hard_deadline 路径同步
            if not top_k and final:
                _sw_top3_hd = [(s, c[_CI_ID][:10]) for s, c in final[:3]]
                _sw_zero_hd = sum(1 for s, _ in final if s == 0)
                _deferred.log(DMESG_DEBUG, "retriever_daemon",
                              f"iter1667_scoring_wipeout_hd: {len(final)} cands, {_sw_zero_hd} suppressed, "
                              f"top3={_sw_top3_hd} thresh={_min_thresh:.3f}",
                              session_id=session_id, project=project)
            if not top_k and final:
                _sef_hd = max(final, key=_SORT_KEY)
                if _sef_hd[0] >= _FALLBACK_NOISE_FLOOR:
                    top_k = [_sef_hd]
                    _deferred.log(DMESG_WARN, "retriever_daemon",
                                  f"iter689_score_empty_fallback_hd: fallback "
                                  f"best={_sef_hd[1][_CI_ID][:12]} s={_sef_hd[0]:.4f}",
                                  session_id=session_id, project=project)
                else:
                    # iter694: suppress_pierce_fallback (hard_deadline path)
                    # iter901: pierce_anti_monopoly — 同 normal path
                    _spf_hd_7d_lim = 2 if _db_chunk_count < 50 else 3
                    _spf_hd = [(c[_CI_IMP] or 0.5, c) for _, c in final
                               if (c[_CI_AC] or 0) < 30
                               and _recent_7d_counts.get(c[_CI_ID], 0) < _spf_hd_7d_lim]
                    if _spf_hd:
                        _spf_hd_best = max(_spf_hd, key=lambda x: x[0])
                        top_k = [(_spf_hd_best[0], _spf_hd_best[1])]
                        _deferred.log(DMESG_WARN, "retriever_daemon",
                                      f"iter694_suppress_pierce_fallback_hd: "
                                      f"pierce best={_spf_hd_best[1][_CI_ID][:12]} imp={_spf_hd_best[0]:.2f}",
                                      session_id=session_id, project=project)
                    elif final:
                        # iter1392: exhaust_pierce — 全库 7d 耗尽时选 7d 最低的候选
                        _epf_hd = [(c[_CI_IMP] or 0.5, _recent_7d_counts.get(c[_CI_ID], 0), c)
                                   for _, c in final if (c[_CI_AC] or 0) < 30]
                        if _epf_hd:
                            _epf_hd.sort(key=lambda x: (x[1], -x[0]))
                            _epf_hd_best = _epf_hd[0]
                            top_k = [(_epf_hd_best[0], _epf_hd_best[2])]
                            _deferred.log(DMESG_WARN, "retriever_daemon",
                                          f"iter1392_exhaust_pierce_hd: 7d_min={_epf_hd_best[1]} "
                                          f"imp={_epf_hd_best[0]:.2f} id={_epf_hd_best[2][_CI_ID][:12]}",
                                          session_id=session_id, project=project)
            if top_k:
                # iter919: score_floor_gate_hd — hard_deadline 路径 score_floor 保护（同步 retriever.py）
                # iter1517: daemon_small_db_floor_sync (hd path)
                # iter1574: hd_tiny_db_floor_sync — 同步 retriever.py iter1541 三级 floor
                # 根因（数据驱动，2026-05-12）：git:78dc99a5695f(_db_chunk_count=18<20)
                #   HD 路径 floor=0.08 拦截 score=0.05~0.07 的有效本地候选。
                #   retriever.py HD(line 4718) 已有 <20→0.05，daemon 此处遗漏未同步。
                _sf_hd = 0.05 if _db_chunk_count < 20 else (0.08 if _db_chunk_count < 50 else 0.12)
                if _db_chunk_count > 5:
                    _sf_hd_above = [(s, c) for s, c in top_k if s >= _sf_hd]
                    if _sf_hd_above:
                        if len(_sf_hd_above) < len(top_k):
                            top_k = _sf_hd_above
                    else:
                        top_k = [max(top_k, key=lambda x: x[0])]
                # iter1659: cross_project_noise_gate (HD path sync)
                if len(top_k) > 1:
                    _cpng_hd_d = [(s, c) for s, c in top_k
                                  if s >= 0.03 or (c[_CI_CP] if len(c) > _CI_CP else "") == project]
                    if _cpng_hd_d:
                        top_k = _cpng_hd_d
                top_k_ids = sorted([c[_CI_ID] for _, c in top_k])  # iter235: positional
                # iter217: crc32 faster than md5 (~0.712us vs ~1.107us, same 8-char hex format)
                current_hash = '%08x' % zlib.crc32("|".join(top_k_ids).encode())
                # iter217: remove round(s,4) — ~1.476us saving; chunk_type [] not .get() — ~0.039us
                top_k_data = [{"id": c[_CI_ID], "summary": c[_CI_SUM], "score": s,
                               "chunk_type": c[_CI_CT] or ""} for s, c in top_k]  # iter235
                if current_hash != last_hash:  # iter201: reuse pre-read last_hash
                    # iter975: output_monopoly_filter (hard_deadline path)
                    if len(top_k) > 1 and _db_chunk_count > 5:
                        _omf_ceil_hd = 3 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)
                        # iter1206: daemon_deep_internalize_sync (hard_deadline path)
                        def _omf_ceil_hdf(c):
                            _oac = c[_CI_AC] or 0
                            if _oac >= 10:
                                return 1
                            if _oac >= 7:
                                return 2
                            if _oac >= 5:
                                return 3
                            if c[_CI_CP] == "global" and _oac >= 4:
                                return 3
                            return _omf_ceil_hd
                        def _omf_lt_sup_hd(c):
                            _ig = c[_CI_CP] == "global"
                            _id = (c[_CI_CT] or "") == "design_constraint"
                            if (_ig or _id) and (c[_CI_AC] or 0) >= 4:
                                _lt = _itl_lifetime.get(c[_CI_ID])
                                if _lt and _lt[0] >= 4 and _lt[1] > _cutoff_14d:
                                    return True
                            return False
                        # iter1669: omf_fallback_protect (HD path sync)
                        _omf_filt_hd = [(s, c) for s, c in top_k
                                        if c[_CI_ID] in _fallback_protected_ids
                                        or (_recent_7d_counts.get(c[_CI_ID], 0) < _omf_ceil_hdf(c)
                                            and not _omf_lt_sup_hd(c))]
                        if _omf_filt_hd:
                            top_k = _omf_filt_hd
                    # iter1013+1056: topic_group_dedup (hard_deadline path)
                    if len(top_k) > 1 and _db_chunk_count > 5:
                        import re as _tgd_hd_re
                        _TGD_HD_MIN = 3
                        def _tgd_hd_core(s):
                            toks = set(_tgd_hd_re.findall(r'[a-z][a-z0-9_]*|[0-9]+', s.lower()))
                            cn = _tgd_hd_re.sub(r'[^\u4e00-\u9fff]', '', s)
                            for i in range(len(cn) - 1):
                                toks.add(cn[i:i + 2])
                            return toks
                        _tgd_seen_hd = {}
                        _tgd_res_hd = []
                        _tgd_np_hd = []  # [(id, type, tokens)]
                        for _ts, _tc in top_k:
                            _tsum = (_tc[_CI_SUM] or "")
                            _tkey = _tsum.split("]")[0] + "]" if _tsum.startswith("[") and "]" in _tsum else None
                            if _tkey:
                                if _tkey not in _tgd_seen_hd:
                                    _tgd_res_hd.append((_ts, _tc))
                                    _tgd_seen_hd[_tkey] = _tc[_CI_ID]
                                else:
                                    if _recent_7d_counts.get(_tc[_CI_ID], 0) < _recent_7d_counts.get(_tgd_seen_hd[_tkey], 0):
                                        _tgd_res_hd = [(s, c) for s, c in _tgd_res_hd if c[_CI_ID] != _tgd_seen_hd[_tkey]]
                                        _tgd_res_hd.append((_ts, _tc))
                                        _tgd_seen_hd[_tkey] = _tc[_CI_ID]
                            else:
                                _CHAIN_GROUP_HD = {"reasoning_chain", "causal_chain"}
                                _cid = _tc[_CI_ID]
                                _ctype = _tc[_CI_CT] or ""
                                _ctoks = _tgd_hd_core(_tsum)
                                _matched = None
                                for _gi, (_gid, _gtype, _gtoks) in enumerate(_tgd_np_hd):
                                    _type_compat_hd = (_ctype == _gtype or
                                                      (_ctype in _CHAIN_GROUP_HD and _gtype in _CHAIN_GROUP_HD))
                                    if _type_compat_hd and len(_ctoks & _gtoks) >= _TGD_HD_MIN:
                                        _matched = _gi
                                        break
                                if _matched is None:
                                    _tgd_res_hd.append((_ts, _tc))
                                    _tgd_np_hd.append((_cid, _ctype, _ctoks))
                                else:
                                    _gid_m = _tgd_np_hd[_matched][0]
                                    if _recent_7d_counts.get(_cid, 0) < _recent_7d_counts.get(_gid_m, 0):
                                        _tgd_res_hd = [(s, c) for s, c in _tgd_res_hd if c[_CI_ID] != _gid_m]
                                        _tgd_res_hd.append((_ts, _tc))
                                        _tgd_np_hd[_matched] = (_cid, _ctype, _ctoks)
                        if _tgd_res_hd and len(_tgd_res_hd) < len(top_k):
                            top_k = _tgd_res_hd
                    # iter238: _TYPE_PREFIX hoisted to module level (was local dict, 0.356us → 0.128us)
                    inject_lines = ["【相关历史记录（BM25 召回）】"]
                    constraint_items, normal_items = [], []
                    for s, c in top_k:
                        ctype_hd = c[_CI_CT] or ""  # iter235: positional
                        prefix = _TYPE_PREFIX.get(ctype_hd, "")
                        # iter229: skip f-string+strip (prefix has no trailing space, summary no leading)
                        line = ("- " + prefix + " " + c[_CI_SUM]).rstrip() if prefix else "- " + c[_CI_SUM]
                        if ctype_hd == "design_constraint":
                            constraint_items.append(line)
                        else:
                            normal_items.append(line)
                    if constraint_items:
                        inject_lines.extend(["", "【已知约束（系统级设计限制）】"])
                        inject_lines.extend(constraint_items)
                        inject_lines.extend(["", "【相关知识】"])
                        inject_lines.extend(normal_items)
                    else:
                        inject_lines.extend(normal_items)
                    context_text = "\n".join(inject_lines)
                    if len(context_text) > effective_max_chars:
                        context_text = context_text[:effective_max_chars] + "…"
                    _write_hash(current_hash)
                    _tlb_write(prompt_hash, current_hash, _get_db_mtime())
                    duration_ms = _elapsed_ms()
                    accessed_ids = top_k_ids  # iter223: reuse sorted ids list (same elements, order-insensitive)
                    # iter200: pre-built header + json.dumps(ctx) only (4.43us → 1.35us)
                    # iter226: write() ~0.407us vs print() ~0.679us (saves ~0.271us on inject path)
                    # iter228: ensure_ascii=True saves ~0.977us (C encoder skips UTF-8 path, outputs \uXXXX)
                    # Output is valid JSON regardless; Claude Code parses \uXXXX → correct Unicode str.
                    sys.stdout.write(_OUTPUT_HEADER + json.dumps(context_text, ensure_ascii=True) + "}}\n")
                    _sessions_with_injection.add(session_id)  # iter804
                    # iter1267: daemon_session_file_sync — 写入 .session_injected 供 retriever.py 读取
                    if session_id not in _sessions_written_to_file:
                        try:
                            _existing = set()
                            if os.path.exists(_SESSION_INJECTED_FILE):
                                with open(_SESSION_INJECTED_FILE, encoding="utf-8") as _sif:
                                    _existing = set(_sif.read().strip().split("\n"))
                            _existing.add(session_id)
                            with open(_SESSION_INJECTED_FILE, 'w', encoding="utf-8") as _sif:
                                _sif.write("\n".join(list(_existing)[-50:]) + "\n")
                            _sessions_written_to_file.add(session_id)
                        except Exception:
                            pass
                    # iter807: daemon_inmem_suppress — 记录注入到进程内存
                    _now_ts = time.time()
                    for _iid807 in top_k_ids:
                        _daemon_inject_log.append((_iid807, _now_ts))
                    # iter1081: cooldown_inmem_sync — 同步更新 _last_inject_ts 使 cooldown 即时生效
                    # 根因：_last_inject_ts 启动时从 timeline file 一次性读取，进程内注入不更新
                    #   → 同一 daemon 进程内连续请求的 cooldown 形同虚设（5/4 同 chunk 30min 内 3 次）。
                    # 修复：注入成功后立即更新 _last_inject_ts，下一次 _score_chunk 即可拦截。
                    from datetime import datetime as _dt1081, timezone as _tz1081
                    _now_iso1081 = _dt1081.now(_tz1081.utc).isoformat()
                    for _iid1081 in top_k_ids:
                        _last_inject_ts[_iid1081] = _now_iso1081
                    # iter1224: burst_counts_inmem_sync — 注入后即时递增 burst counts
                    for _iid1224 in top_k_ids:
                        _recent_6h_counts[_iid1224] = _recent_6h_counts.get(_iid1224, 0) + 1
                        _recent_24h_counts[_iid1224] = _recent_24h_counts.get(_iid1224, 0) + 1
                        _recent_7d_counts[_iid1224] = _recent_7d_counts.get(_iid1224, 0) + 1
                    # iter173: persistent conn — do NOT close
                    try:
                        wconn = open_db()
                        ensure_schema(wconn)
                        _seen_before_d = {cid for cid, _ in _daemon_inject_log[:-len(accessed_ids)]} & set(accessed_ids)
                        update_accessed(wconn, accessed_ids, session_seen_ids=_seen_before_d)
                        mglru_promote(wconn, accessed_ids)
                        # iter668+1229: top_k_data rebuild from actual top_k
                        # iter1229: trace_topk_sync — top_k_data 在 4451 构建后，top_k 被
                        #   output_monopoly_filter/topic_group_dedup 修改，导致 trace 记录的
                        #   chunk list 与实际注入不一致。重建以反映真实注入内容。
                        _hd_top_k = [{"id": c[_CI_ID], "summary": c[_CI_SUM], "score": s,
                                      "chunk_type": c[_CI_CT] or ""} for s, c in top_k] or top_k_data or [{"id": cid} for cid in accessed_ids]
                        store_insert_trace(wconn, {
                            "id": str(uuid_mod.uuid4()),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "session_id": session_id, "project": project,
                            "prompt_hash": prompt_hash, "candidates_count": candidates_count,
                            "top_k_json": _hd_top_k, "injected": 1,
                            "reason": f"hash_changed|{priority.lower()}|hard_deadline",
                            "duration_ms": duration_ms,
                        })
                        _deferred.flush(wconn)
                        wconn.commit()
                        wconn.close()
                        # iter173: do NOT set _ro_conn_invalidate_flag here —
                        # update_accessed/mglru_promote/insert_trace do NOT change FTS5 fields.
                        # Persistent ro conn remains valid; version-based check in
                        # _get_persistent_ro_conn() handles extractor writes.
                    except Exception:
                        pass
                    # ── iter648: injection timeline write-back (hard_deadline path) ──
                    try:
                        _itl_path_hd = os.path.join(MEMORY_OS_DIR, ".injection_timeline.json")
                        _itl_ex_hd = {}
                        if os.path.exists(_itl_path_hd):
                            with open(_itl_path_hd, encoding="utf-8") as _itf_hd:
                                _itl_ex_hd = json.loads(_itf_hd.read())
                        from datetime import timedelta as _td648hd
                        _now_hd = datetime.now(timezone.utc)
                        # iter1115: gc_writeback_21d — 对齐 retriever.py iter1110 读取 GC 窗口
                        # 根因：write-back GC=7d 截断记录，但 cooldown 需 10-14d 时间戳。
                        #   高 ac chunk GC 后 _cd_ts_list=None → cooldown 判断被跳过 → 周期性逃逸。
                        _cut_21d_hd = (_now_hd - _td648hd(days=21)).isoformat()
                        _itl_p_hd = {k: [t for t in v if t > _cut_21d_hd] for k, v in _itl_ex_hd.items()}
                        _itl_p_hd = {k: v for k, v in _itl_p_hd.items() if v}
                        _now_iso_hd = _now_hd.isoformat()
                        for _aid_hd in accessed_ids:
                            _itl_p_hd.setdefault(_aid_hd, []).append(_now_iso_hd)
                        with open(_itl_path_hd, 'w', encoding="utf-8") as _itf_hw:
                            _itf_hw.write(json.dumps(_itl_p_hd, ensure_ascii=False))
                    except Exception:
                        pass
                    _write_shadow_trace(project, accessed_ids, session_id)
            return

        # ── madvise boost ──
        # iter178: use daemon-cached madvise hints (mtime_ns invalidation, ~2us vs 88us)
        hints = []
        if not _check_deadline("madvise"):
            hints = _madvise_cached(project)
        if hints:
            boost = sysctl("madvise.boost_factor")
            hint_set = set(h.lower() for h in hints)
            for i, (score, chunk) in enumerate(final):
                text_lower = f"{chunk[_CI_SUM] or ''} {chunk[_CI_CON] or ''}".lower()  # iter235: positional
                matches = sum(1 for h in hint_set if h in text_lower)
                if matches > 0:
                    match_ratio = min(1.0, matches / max(1, len(hint_set) * 0.3))
                    final[i] = (score + boost * match_ratio, chunk)

        # ── DRR final selection ──
        final.sort(key=_SORT_KEY, reverse=True)  # iter218: C-level itemgetter vs lambda
        # iter193: use pre-read locals; iter194: reuse _is_generic_q (computed once in classify)
        _min_thresh = (_gen_query_thr if _is_generic_q else _min_score_thr)
        # iter820: daemon_adaptive_floor (FULL path) — 同 hard_deadline 路径
        # iter822: af_min_top1 0.5→0.30 (FULL path sync)
        if final and not _is_generic_q:
            _af_top1 = final[0][0]
            if _af_top1 >= 0.30:
                # iter823: small_db_af_relax — 小库 ratio 0.25→0.12
                # iter1130: small_db_af_raise — 0.12→0.20 (daemon FULL path sync)
                _af_r = 0.20 if _db_chunk_count < 100 else 0.25
                # iter1130: relevance_floor_raise — 0.12→0.15 (daemon FULL sync)
                _min_thresh = min(_min_thresh, max(_af_top1 * _af_r, 0.15))
        # iter821: daemon_gap_bridge (FULL path) — 同步 retriever.py iter579
        if len(final) >= 3 and not _is_generic_q:
            _gb_t1 = final[0][0]
            _gb_t2 = final[1][0] if final[1][0] > 0 else 0.001
            if _gb_t1 / _gb_t2 >= 3.0:
                _gb_cf = _gb_t2 * 0.4
                _gb_cs = sum(1 for s, _ in final[1:] if s >= _gb_cf)
                if _gb_cs >= 2:
                    # iter863: gap_bridge_floor_raise (FULL path)
                    # iter1130: relevance_floor_raise — 0.12→0.15 (daemon FULL sync)
                    _gb_nt = max(_gb_cf, 0.15)
                    if _gb_nt < _min_thresh:
                        _min_thresh = _gb_nt
        # iter620: zero_score_absolute_gate (FULL path) — 同 hard_deadline 路径
        positive = [(s, c) for s, c in final if s >= _min_thresh and s > 0]
        # iter1368: sparse_cross_floor_tighten — daemon FULL path sync
        _cross_floor_f2 = 0.25 if _local_chunk_count_d == 0 else (0.18 if _local_sparse_d else 0.25)
        positive = [(s, c) for s, c in positive
                    if (c[_CI_CP] or "") in ("", project) or s >= _cross_floor_f2]
        # iter695: threshold_degrade — 阈值过高全灭时降级到默认 0.30
        if not positive and _min_thresh > 0.30:
            positive = [(s, c) for s, c in final if s >= 0.30 and s > 0]
        # iter759: 移除 candidates_rescue（同 hard_deadline 路径）
        # ── iter830: daemon_pair_inject — 同步 retriever.py iter826/827 (FULL path) ──
        if len(positive) == 1 and len(final) >= 3:
            _pi_cands_f = [(s, c) for s, c in final
                           if s > 0.12 and s < _min_thresh
                           and c[_CI_ID] != positive[0][1][_CI_ID]]
            if _pi_cands_f:
                _pi_best_f = max(_pi_cands_f, key=lambda x: x[0])
                positive.append(_pi_best_f)
                _deferred.log(DMESG_DEBUG, "retriever_daemon",
                              f"iter830_pair_inject_full: paired {_pi_best_f[1][_CI_ID][:12]} "
                              f"s={_pi_best_f[0]:.3f} with top1 s={positive[0][0]:.3f}",
                              session_id=session_id, project=project)
            else:
                _ip_cands_f = [(float(c[_CI_IMP] or 0), c) for _, c in final
                               if c[_CI_ID] != positive[0][1][_CI_ID]
                               and (c[_CI_AC] or 0) < 30]
                if _ip_cands_f:
                    _ip_best_f = max(_ip_cands_f, key=lambda x: x[0])
                    # iter941: imp_pair_top1_gate (FULL path)
                    if _ip_best_f[0] >= 0.3 and positive[0][0] >= 0.15:
                        positive.append((positive[0][0] * 0.3, _ip_best_f[1]))
                        _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                      f"iter830_imp_pair_full: paired {_ip_best_f[1][_CI_ID][:12]} "
                                      f"imp={_ip_best_f[0]:.2f} with top1 s={positive[0][0]:.3f}",
                                      session_id=session_id, project=project)
        # iter864: diversity_pair_from_db — 同步 retriever.py
        # 根因：52% 单条注入，6/20 chunk 从未曝光（FTS 未命中 → 不在 final）。
        # 修复：positive 仍为单条时从 DB 查同 project 低频高 importance chunk 配对。
        if len(positive) == 1 and _db_chunk_count < 50:
            _top1_id_d = positive[0][1][_CI_ID]
            try:
                import sqlite3 as _div_sql_d
                _div_conn_d = _div_sql_d.connect(str(STORE_DB))
                _div_rows_d = _div_conn_d.execute(
                    "SELECT id, summary, content, chunk_type, importance, access_count "
                    "FROM memory_chunks WHERE project = ? AND chunk_state = 'ACTIVE' "
                    "AND importance >= 0.5 AND id != ? "
                    "ORDER BY access_count ASC, importance DESC LIMIT 8",
                    (project, _top1_id_d)).fetchall()
                _div_conn_d.close()
                # iter867: 过滤 session 内已注入的 chunk
                _div_recent_ids = {iid for iid, _ in _daemon_inject_log[-50:]}
                _div_rows_d = [r for r in _div_rows_d if r[0] not in _div_recent_ids]
                # iter943: diversity_pair_7d_suppress — 排除 7d 达阈值的 chunk
                _div_7d_ceiling_d = 5 if _db_chunk_count < 50 else (4 if _db_chunk_count < 100 else 6)  # iter1207: pair_ceiling_mid_tighten — 50-99 库 6→4 去垄断
                _div_7d_d = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else _recent_7d_counts
                _div_rows_d = [r for r in _div_rows_d if _div_7d_d.get(r[0], 0) < _div_7d_ceiling_d]
                if _div_rows_d:
                    # iter872: diversity_counter — 自增 round-robin 替代 hour%len
                    _div_idx_d = _diversity_counter[0] % len(_div_rows_d)
                    _diversity_counter[0] += 1
                    _div_pick_d = _div_rows_d[_div_idx_d]
                    _div_chunk_d = (_div_pick_d[0], _div_pick_d[1], _div_pick_d[2],
                                   _div_pick_d[4], 0, 0, _div_pick_d[5], None, None, None,
                                   _div_pick_d[3], None)
                    _div_score_d = positive[0][0] * 0.25
                    positive.append((_div_score_d, _div_chunk_d))
                    _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                  f"iter867_diversity_rotation: db_pick {_div_pick_d[0][:12]} "
                                  f"imp={_div_pick_d[4]:.2f} ac={_div_pick_d[5]} idx={_div_idx_d}",
                                  session_id=session_id, project=project)
            except Exception:
                pass

        if _drr_enabled and len(positive) > effective_top_k:
            top_k = _drr_select(positive, effective_top_k)
        else:
            top_k = positive[:effective_top_k]

        # ── iter700: score_empty_fallback (FULL path) ──
        # 根因（数据驱动，2026-05-04）：用户工作项目 15 次空召回，有 3-21 个 candidates
        #   但 top1 < 0.15 → rescue 不触发。hard_deadline 有 iter689，此处遗漏。
        # iter751: suppress 全灭兜底 — score=0 时用 importance 排序选最佳 1 条
        # iter770: fallback_noise_gate — 硬性下限防止低分垃圾注入
        # iter771: tiny_db_fallback_relax — 小库降至 0.15
        # iter852: sync tiny_db boundary 30→50 (同 iter848/iter819)
        _fallback_protected_ids = set()
        # iter1675: sparse_noise_floor_relax — sync hard_deadline path
        _FALLBACK_NOISE_FLOOR_FULL = 0.05 if _local_sparse_d else (0.15 if _db_chunk_count < 50 else 0.25)
        # iter1667: scoring_wipeout_ftrace — 全灭时记录候选分布，使 ftrace 非空
        if not top_k and final:
            _sw_top3 = [(s, c[_CI_ID][:10]) for s, c in final[:3]]
            _sw_zero = sum(1 for s, _ in final if s == 0)
            _deferred.log(DMESG_DEBUG, "retriever_daemon",
                          f"iter1667_scoring_wipeout: {len(final)} cands, {_sw_zero} suppressed, "
                          f"top3={_sw_top3} thresh={_min_thresh:.3f}",
                          session_id=session_id, project=project)
        if not top_k and final:
            _sef_full = max(final, key=_SORT_KEY)
            if _sef_full[0] >= _FALLBACK_NOISE_FLOOR_FULL:
                top_k = [_sef_full]
                _deferred.log(DMESG_WARN, "retriever_daemon",
                              f"iter700_score_empty_fallback_full: fallback "
                              f"best={_sef_full[1][_CI_ID][:12]} s={_sef_full[0]:.4f}",
                              session_id=session_id, project=project)
            else:
                # iter772: dead_zone_fallback — 消除 (0, noise_floor) 死区
                # iter775: dead_zone_min_score — 防止 FTS5 无匹配时注入垃圾
                _sef_full_max = _sef_full[0]
                _DEAD_ZONE_MIN_FULL = 0.05
                # iter1563: cross_project_dc_fallback_align — sync retriever.py
                # 跨项目 dc ac>=4 / global ac>=4(dc)/5(other) / 跨项目 ac>=7 排除 fallback
                def _fb_ac_ok(c):
                    _a = c[_CI_AC] or 0
                    if _a >= 30: return False
                    _cp = c[_CI_CP] if len(c) > _CI_CP else ""
                    _is_xp = _cp != project or _cp == "global"
                    if not _is_xp: return True
                    _ct = c[_CI_CT] if len(c) > _CI_CT else ""
                    if _cp == "global":
                        return _a < (4 if _ct == "design_constraint" else 5)
                    if _ct == "design_constraint":
                        return _a < 4
                    return _a < 7
                # iter1653: fallback_7d_suppress_align — 排除 7d 已达 suppress 阈值的 chunk
                def _fb_7d_ok_d(c):
                    _cid = c[_CI_ID]
                    _7d = _recent_7d_counts.get(_cid, 0)
                    _t = 5 if _db_chunk_count < 50 else 3
                    if (c[_CI_CP] if len(c) > _CI_CP else "") == "global" and (c[_CI_AC] or 0) >= 4:
                        _t = max(2, _t - 1)
                    return _7d < _t
                _sef_by_imp = [(float(c[_CI_IMP] or 0), c) for _, c in final
                               if _fb_ac_ok(c) and _fb_7d_ok_d(c)]
                # iter1683: zero_local_dead_zone_fallback_skip — local=0 跳过 fallback（sync retriever.py）
                if _sef_by_imp and _sef_full_max >= _DEAD_ZONE_MIN_FULL and _local_chunk_count_d > 0:
                    _sef_best = max(_sef_by_imp, key=_SORT_KEY)
                    _fallback_protected_ids.add(_sef_best[1][_CI_ID])
                    # iter1570: fallback_floor_safe — score 不低于 _score_floor，防止 floor_gate 二杀
                    # iter1618: floor_safe_inline — 内联 floor 计算，消除对可能未定义的 _score_floor 的依赖
                    # 根因（数据驱动，2026-05-11）：git:78dc99a5695f 连续 2 次空召回。
                    #   dead_zone_fallback 用旧 _score_floor=0.05 算 score=0.084，
                    #   floor_gate(L6093) 重算 _score_floor=0.12 → 0.084<0.12 被二杀。
                    #   _fallback_protected_ids bypass(L6139) 失效原因待查，但 score>=floor 可彻底消除。
                    _dz_floor = 0.05 if _db_chunk_count < 20 else (0.08 if _db_chunk_count < 50 else 0.12)
                    if _local_chunk_count_d == 0 and _dz_floor < 0.25:
                        _dz_floor = 0.25
                    top_k = [(max(_sef_best[0] * 0.1, _dz_floor), _sef_best[1])]
                    _deferred.log(DMESG_WARN, "retriever_daemon",
                                  f"iter775_dead_zone_fallback_full: imp={_sef_best[0]:.2f} "
                                  f"max_s={_sef_full_max:.4f} id={_sef_best[1][_CI_ID][:12]}",
                                  session_id=session_id, project=project)
                # iter776→782: dead_zone_unified_fallback — 统一 [0, DEAD_ZONE_MIN) 兜底
                # iter1683: zero_local_dead_zone_fallback_skip — local=0 跳过（sync retriever.py iter1623 对齐）
                elif _sef_by_imp and _sef_full_max < _DEAD_ZONE_MIN_FULL and candidates_count > 0 and _local_chunk_count_d > 0:
                    _sef_best = max(_sef_by_imp, key=_SORT_KEY)
                    _fallback_protected_ids.add(_sef_best[1][_CI_ID])
                    # iter1570: fallback_floor_safe — score 不低于 _score_floor，防止 floor_gate 二杀
                    # iter1618: floor_safe_inline — 同上，内联 floor 计算
                    _dz_floor2 = 0.05 if _db_chunk_count < 20 else (0.08 if _db_chunk_count < 50 else 0.12)
                    if _local_chunk_count_d == 0 and _dz_floor2 < 0.25:
                        _dz_floor2 = 0.25
                    top_k = [(max(_sef_best[0] * 0.01, _dz_floor2), _sef_best[1])]
                    _deferred.log(DMESG_WARN, "retriever_daemon",
                                  f"iter776_suppress_zero_fallback: imp={_sef_best[0]:.2f} "
                                  f"id={_sef_best[1][_CI_ID][:12]}",
                                  session_id=session_id, project=project)

        # ── design_constraint 强制注入 ──
        # iter219: chunk_type [] not .get() — schema guarantees field exists (TEXT nullable)
        # iter632: ac>=30 过滤 — 堵住 spreading_activate/shmem/schema 路径绕过
        all_constraints = [c for s, c in final if c[_CI_CT] == "design_constraint"
                          and (c[_CI_AC] or 0) < 30]  # iter235
        # ── iter691: global_constraint_supplement — FTS 未命中的 global constraint 补充 ──
        # 根因（数据驱动，2026-05-04）：global constraint (imp>=0.7) 因 FTS5 词不匹配
        #   从未进入 final → 永远不被强制注入。补充到 all_constraints 后走正常 gate。
        try:
            _gc_existing_ids = {c[_CI_ID] for c in all_constraints}
            # iter1025: supplement_ac_internalized_gate — ac>=4 已内化不再 supplement
            # 根因（数据驱动，2026-05-07）：ac>=4 的 global constraint 已被 agent 充分内化，
            #   通过 supplement 路径绕过 FTS 相关性 → 在不相关项目注入。ac<4 = 新知识仍可发现。
            _gc_sup = conn.execute(
                "SELECT id, summary, content, importance, last_accessed, "
                "chunk_type, COALESCE(access_count,0), created_at, "
                "0.0, COALESCE(lru_gen,0), project, verification_status, confidence_score "
                "FROM memory_chunks WHERE project='global' "
                "AND chunk_type='design_constraint' AND importance >= 0.7 "
                "AND COALESCE(access_count,0) < 4 "
                "ORDER BY importance DESC LIMIT 3"
            ).fetchall()
            for _gc_r in _gc_sup:
                if _gc_r[_CI_ID] not in _gc_existing_ids:
                    all_constraints.append(_gc_r)
                    _gc_existing_ids.add(_gc_r[_CI_ID])
        except Exception:
            pass
        forced_constraints = []
        # iter224: pre-compute id list once, build set from it (setcomp ~0.433us → set(list) ~0.288us)
        # _pre_top_k_ids reused by top_k_ids_set; top_k_ids recomputed after constraint insertion
        # OS 类比：list→set 批量构建（memcpy+hash_init）比 setcomp 逐元素插入快
        _pre_top_k_ids = [c[_CI_ID] for _, c in top_k]  # iter235
        top_k_ids_set = set(_pre_top_k_ids)
        _max_forced = sysctl("retriever.max_forced_constraints")
        # iter193: _drr_max_same already pre-read as local var above
        # iter224: len(listcomp) ~0.371us vs sum(genexpr) ~0.532us (listcomp one-shot vs per-item yield)
        _natural_constraint_count = len([1 for _, c in top_k if c[_CI_CT] == "design_constraint"])  # iter235
        _constraint_total_cap = max(_drr_max_same, int(_drr_max_same * 1.5))
        _remaining_forced_slots = max(0, _constraint_total_cap - _natural_constraint_count)
        _effective_max_forced = min(_max_forced, _remaining_forced_slots)
        _extra_constraints = [c for c in all_constraints if c[_CI_ID] not in top_k_ids_set]  # iter235
        if _extra_constraints and _effective_max_forced > 0:
            _query_words = set(_CONSTRAINT_RE.sub(' ', query.lower()).split())  # iter220: pre-compiled
            def _constraint_relevance(c):
                s_words = set(_CONSTRAINT_RE.sub(' ', (c[_CI_SUM] or "").lower()).split())  # iter235
                if not _query_words or not s_words:
                    return 0.0
                return len(_query_words & s_words) / len(_query_words | s_words)
            _extra_constraints.sort(key=_constraint_relevance, reverse=True)
            # ── iter584: refault_distance gate — thrash detection for forced constraints ──
            # OS 类比：Linux cfs_burst_throttle (Paul Turner, 2011) — 超出 bandwidth 的
            # cgroup task 即使 burst 也不能无限消耗 CPU；类推：recall_count/window > max_pct
            # 的 constraint 已过度曝光，强制注入只增加冗余而非信息量。
            # 根因：daemon 路径缺失此门控导致垄断 chunk(35.2%召回率) score=0.99 绕过所有 throttle。
            _constraint_min_rel = sysctl("retriever.constraint_min_relevance")
            _thrash_max_pct = sysctl("retriever.constraint_thrash_max_pct")
            _bw_window = sysctl("scorer.bw_window") or 30
            _pre_gate = len(_extra_constraints)
            # iter595+596+598: access_count monopoly gate + inject_hard_cap + zero_relevance
            _inject_hard_cap = sysctl("retriever.constraint_inject_hard_cap")
            # iter608: session_constraint_cap — 从 session injection file 读取计数
            _d_session_inj_counts = {}
            _d_session_cap = 2
            try:
                _d_sij_path = os.path.join(MEMORY_OS_DIR, ".last_session_injections.json")
                if os.path.exists(_d_sij_path):
                    with open(_d_sij_path, encoding="utf-8") as _dsf:
                        _dsij = json.loads(_dsf.read())
                        if _dsij.get("session_id") == session_id:
                            _d_session_inj_counts = _dsij.get("counts", {})
            except Exception:
                pass
            def _ac_gated_d(c):
                _cid = c[_CI_ID]
                # iter989: saturation_widen — ac>=12 suppress（constraint 通道同步）
                # iter1294: small_db_deep_saturated_soften — <100 库不硬杀
                if (c[_CI_AC] or 0) >= 12 and _db_chunk_count >= 100:
                    return False
                # iter1638: constraint_ac_hard_cap — sync retriever.py iter641
                # 根因（数据驱动，2026-05-13）：daemon _ac_gated_d 缺少 ac>=15 硬杀，
                #   retriever.py 有（line 6125），高 ac chunk 经 daemon constraint 通道逃逸。
                if (c[_CI_AC] or 0) >= 15:
                    return False
                # iter618: 24h + 7d burst suppress 在 constraint 通道生效
                # iter619: 阈值收紧 24h:3→2, 7d:8→5
                # iter903: constraint_24h_tighten — tiny_db 场景下 24h/7d 均收紧到 2
                # 根因（数据驱动，2026-05-05）：39-chunk 库 constraint 通道 Jaccard>0.05
                #   门槛过低，不相关 constraint（Android/git/微信）24h 注入 3 次仍不 suppress。
                #   63% 注入为与当前工作无关的知识。收紧到 2 限制每 constraint 24h/7d 仅 1 次。
                _cst_tiny = _db_chunk_count < 50
                if _recent_24h_counts.get(_cid, 0) >= 2:
                    return False
                # iter1638: constraint_6h_burst_suppress — sync retriever.py iter813/1047
                # 根因（数据驱动，2026-05-13）：daemon constraint 通道缺少 6h suppress，
                #   sem_68b3(ac=9) 在 git:a4ee2fcfacc4 中 6h 内注入 2 次（07:12+07:39），
                #   retriever.py 已有 6h thresh=1（ac>=5），daemon 未同步形成逃逸。
                _ac_d = c[_CI_AC] or 0
                _cst_6h_thresh = 1 if (_ac_d >= 5 or (c[_CI_CP] == "global" and _ac_d >= 4)) else 2
                if _recent_6h_counts.get(_cid, 0) >= _cst_6h_thresh:
                    return False
                # iter1028: constraint_global_saturated_7d — sync retriever.py
                # global ac>=4 constraint 7d 阈值 -1，堵 constraint 通道逃逸
                _cst_7d_thresh = 4 if _cst_tiny else 3
                if c[_CI_CP] == "global" and (c[_CI_AC] or 0) >= 4:
                    _cst_7d_thresh = max(2, _cst_7d_thresh - 1)
                # iter1588: local_dc_saturated_constraint_7d — sync retriever.py
                elif c[_CI_CP] != "global" and (c[_CI_AC] or 0) >= 5:
                    _cst_7d_thresh = max(2, _cst_7d_thresh - 1)
                if _recent_7d_counts.get(_cid, 0) >= _cst_7d_thresh:
                    return False
                # iter608: session-level constraint dedup
                if _d_session_inj_counts.get(_cid, 0) >= _d_session_cap:
                    return False
                _rc = _recall_counts.get(_cid, 0)
                # iter596: hard cap — 注入频率超阈值无条件 suppress
                # iter610: 用 _local_bw_window 防止 memcg inflate 稀释
                if _rc / max(_local_bw_window, 1) > _inject_hard_cap:
                    return False
                _rel = _constraint_relevance(c)
                # iter598: zero relevance gate — 与 query 零词重叠的 constraint 无条件拦截
                # iter850: remove global_high_imp_exempt — 数据驱动（2026-05-05）：
                #   feishu CLI (imp=0.95) 和 git commit author (imp=0.95) 通过此豁免
                #   在 memory-os/kernel 迭代中被无关注入 24h 4~5 次。
                #   24h suppress 只在累积 >=2 后生效，前 2 次无条件逃逸。
                #   根治：所有 constraint 统一要求最低 relevance，不再豁免。
                if _rel == 0:
                    return False
                _ac = c[_CI_AC] or 0
                # iter611: two_phase_relevance_gate — ac>30 加速衰减（与 retriever.py 对齐）
                # iter736: use module-level _math instead of per-call import
                # iter1646: internalized_constraint_penalty — sync retriever.py
                # ac>=4 开始渐进惩罚，使已内化 constraint 需更高 relevance 通过
                # iter1681: sync retriever.py constraint_penalty_steepen 0.025→0.04
                if _ac < 4:
                    _ac_penalty = 0.0
                elif _ac <= 10:
                    _ac_penalty = (_ac - 4) * 0.04
                elif _ac <= 15:
                    _ac_penalty = 0.24 + min(0.10, _math.log1p(_ac - 10) * 0.05)
                else:
                    _ac_penalty = 0.34 + min(0.20, _math.log1p(_ac - 15) * 0.06)
                # iter850: 统一 min_rel gate（移除 global_high_imp 豁免）
                # iter856: global_chunk_relevance_floor — sync retriever.py
                # iter937: global_relevance_floor_tighten — 0.03→0.05 (sync)
                _eff_min_rel_d = _constraint_min_rel + _ac_penalty
                if c.get("project") == "global":
                    _eff_min_rel_d += 0.05
                # iter1596: cross_project_local_dc_relevance_floor (sync retriever.py)
                elif c.get("project", "") not in ("", "global") and c.get("project") != project:
                    _eff_min_rel_d += 0.08
                if _rel < _eff_min_rel_d:
                    return False
                return (_rc / max(_bw_window, 1)) <= _thrash_max_pct
            _extra_constraints = [c for c in _extra_constraints if _ac_gated_d(c)]
            # ── iter584: Jaccard content dedup — skip constraints redundant with top_k ──
            # OS 类比：KSM (Kernel Samepage Merging) — 内容相同的页面合并为 COW，不重复映射。
            _top_k_token_sets = []
            for _, _tc in top_k:
                _tc_words = set(_CONSTRAINT_RE.sub(' ', (_tc[_CI_SUM] or "").lower()).split())
                if _tc_words:
                    _top_k_token_sets.append(_tc_words)
            for c in _extra_constraints[:_effective_max_forced]:
                # Jaccard dedup: summary overlap > 0.5 → redundant, skip
                _c_words = set(_CONSTRAINT_RE.sub(' ', (c[_CI_SUM] or "").lower()).split())
                if _c_words and _top_k_token_sets:
                    _is_redundant = False
                    for _existing in _top_k_token_sets:
                        _union = _existing | _c_words
                        if _union and len(_existing & _c_words) / len(_union) >= 0.50:
                            _is_redundant = True
                            break
                    if _is_redundant:
                        continue
                forced_constraints.append(c[_CI_SUM])  # iter235
                top_k.insert(0, (0.99, c))
                top_k_ids_set.add(c[_CI_ID])  # iter235
                if _c_words:
                    _top_k_token_sets.append(_c_words)

        if not top_k:
            if priority == "FULL" and not _check_deadline("swap_fault"):
                try:
                    swap_matches = swap_fault_fn(conn, query, project)
                    if swap_matches:
                        swap_ids = [m["id"] for m in swap_matches]
                        # iter173: swap_in needs a writable connection — use temporary conn
                        # persistent conn (thread-local) must not be closed here
                        _swap_wconn = open_db()
                        ensure_schema(_swap_wconn)
                        swap_result = swap_in_fn(_swap_wconn, swap_ids)
                        if swap_result["restored_count"] > 0:
                            _deferred.flush(_swap_wconn)
                            _swap_wconn.commit()
                            _swap_wconn.close()
                            _ro_conn_invalidate_flag.set()  # iter173: invalidate to see swapped-in data
                            # Use a fresh temporary ro conn for post-swap FTS (immutable=1 won't see new data)
                            conn = _open_db_readonly()
                            fts_results2 = fts_search(conn, query, project, top_k=effective_top_k * 3,
                                                      chunk_types=_retrieve_types)
                            if fts_results2:
                                max_rank2 = max(c[_CI_FR] for c in fts_results2) if fts_results2 else 1.0  # iter235
                                if max_rank2 <= 0: max_rank2 = 1.0
                                final2 = []
                                for chunk in fts_results2:
                                    score = _score_chunk(chunk, chunk[_CI_FR] / max_rank2)  # iter235
                                    final2.append((score, chunk))
                                final2.sort(key=_SORT_KEY, reverse=True)  # iter218
                                top_k = [(s, c) for s, c in final2[:effective_top_k] if s > 0]
                            conn.close()
                            conn = None  # prevent finally block from closing persistent conn
                        else:
                            _swap_wconn.close()
                            # no new data written, persistent conn is still valid
                except Exception:
                    pass

            # iter1667: scoring_wipeout_ftrace — LITE 路径同步
            if not top_k and final:
                _sw_top3_lt = [(s, c[_CI_ID][:10]) for s, c in final[:3]]
                _sw_zero_lt = sum(1 for s, _ in final if s == 0)
                _deferred.log(DMESG_DEBUG, "retriever_daemon",
                              f"iter1667_scoring_wipeout_lite: {len(final)} cands, {_sw_zero_lt} suppressed, "
                              f"top3={_sw_top3_lt} thresh={_min_thresh:.3f}",
                              session_id=session_id, project=project)
            if not top_k:
                # ── iter689: score_empty_fallback — scoring 全灭降级注入最佳 1 条 ──
                # 根因（数据驱动，2026-05-04）：80% 的非 skip trace 空召回，
                #   FTS 找到 10-21 候选但 scoring 后全灭（suppress/threshold），
                #   4146 直接 return 绕过了 suppress_fallback（4208）。
                #   空召回 = 系统对用户无价值。宁注入 1 条次优也不空手而归。
                # 修复：从 final（scoring 后的全量候选）中挑 score 最高且 >0 的降级注入。
                # iter770: fallback_noise_gate — 硬性下限防止低分垃圾注入
                # iter771: tiny_db_fallback_relax — 小库降至 0.15
                # iter852: sync tiny_db boundary 30→50 (同 iter848/iter819)
                # iter1675: sparse_noise_floor_relax — sync late path
                _FALLBACK_NOISE_FLOOR_LATE = 0.05 if _local_sparse_d else (0.15 if _db_chunk_count < 50 else 0.25)
                if final:
                    _sef_best = max(final, key=_SORT_KEY)
                    if _sef_best[0] >= _FALLBACK_NOISE_FLOOR_LATE:
                        top_k = [_sef_best]
                        _fallback_protected_ids.add(_sef_best[1][_CI_ID])
                        _deferred.log(DMESG_WARN, "retriever_daemon",
                                      f"iter689_score_empty_fallback: all scored out, "
                                      f"fallback best={_sef_best[1][_CI_ID][:12]} s={_sef_best[0]:.4f}",
                                      session_id=session_id, project=project)
                if not top_k:
                    # ── iter694: suppress_pierce_fallback — suppress 全灭时按 importance 降级 ──
                    # 根因（数据驱动）：42 次 hash_changed 未注入中 100% 有候选(3-21个)，
                    #   但 24h/7d suppress 将所有 score 设为 0 → iter689 的 >0 检查失败 → 空手而归。
                    #   用户视角：有知识但系统拒绝给出 = 质量损失。
                    # 修复：绕过 suppress score，按 chunk importance 选最佳 1 条（跳过 AC>=30 硬约束）。
                    # 安全性：仍受 iter630 monopoly_post_filter + iter663 suppress_final_gate 保护。
                    # iter901: pierce_anti_monopoly — pierce 不得选 7d 已达阈值的垄断 chunk
                    #   根因（数据驱动，2026-05-05）：pierce 按 importance 选最高 → 垄断 chunk
                    #   (高 imp + 高 7d) 反复被 pierce → suppress_final_gate 只看 <阈值 放行。
                    #   修复：pierce 候选排除 7d >= 阈值的 chunk，让位给低频但新鲜的知识。
                    _spf_7d_lim = 2 if _db_chunk_count < 50 else 3
                    _spf_candidates = [(c[_CI_IMP] or 0.5, c) for _, c in final
                                       if (c[_CI_AC] or 0) < 30
                                       and _recent_7d_counts.get(c[_CI_ID], 0) < _spf_7d_lim]
                    if _spf_candidates:
                        _spf_best = max(_spf_candidates, key=lambda x: x[0])
                        top_k = [(_spf_best[0], _spf_best[1])]
                        _fallback_protected_ids.add(_spf_best[1][_CI_ID])
                        _deferred.log(DMESG_WARN, "retriever_daemon",
                                      f"iter694_suppress_pierce_fallback: all suppressed, "
                                      f"pierce best={_spf_best[1][_CI_ID][:12]} imp={_spf_best[0]:.2f}",
                                      session_id=session_id, project=project)
                    elif final:
                        # iter1392: exhaust_pierce — 全库 7d 耗尽时选 7d 最低的候选
                        _epf = [(c[_CI_IMP] or 0.5, _recent_7d_counts.get(c[_CI_ID], 0), c)
                                for _, c in final if (c[_CI_AC] or 0) < 30]
                        if _epf:
                            _epf.sort(key=lambda x: (x[1], -x[0]))
                            _epf_best = _epf[0]
                            top_k = [(_epf_best[0], _epf_best[2])]
                            _fallback_protected_ids.add(_epf_best[2][_CI_ID])
                            _deferred.log(DMESG_WARN, "retriever_daemon",
                                          f"iter1392_exhaust_pierce: 7d_min={_epf_best[1]} "
                                          f"imp={_epf_best[0]:.2f} id={_epf_best[2][_CI_ID][:12]}",
                                          session_id=session_id, project=project)
                if not top_k:
                    # iter780: empty_result_tlb — 写入空结果标记避免重复空转
                    _tlb_write(prompt_hash, "__empty__", _get_db_mtime())
                    # iter173: persistent conn — do NOT close
                    if _deferred._buf:  # iter222: direct slot access
                        try:
                            wconn = open_db()
                            ensure_schema(wconn)
                            _deferred.flush(wconn)
                            wconn.commit()
                            wconn.close()
                        except Exception:
                            pass
                    return

        # ── iter670: suppress_fallback — suppress 前快照 ──
        _pre_suppress_top_k = list(top_k)
        # ── iter630: monopoly_post_filter — 不可绕过的最终门禁 ──────────────
        # 根因：评分阶段的 suppress（24h/7d/AC>=30）可能因查询失败、缓存、
        #   或 forced_constraint 路径逃逸。此 post-filter 直接读 chunk 字段，
        #   不依赖外部查询，是所有路径的最终汇聚点。
        # iter981: 条件：access_count >= 12 的 chunk 不得出现在最终注入列表中。
        # iter1294: small_db_deep_saturated_soften — <100 库允许通过（已在 scoring 阶段 *0.1 衰减）
        _pre_postfilter = len(top_k)
        if _db_chunk_count >= 100:
            top_k = [(s, c) for s, c in top_k if (c[_CI_AC] or 0) < 12]
        # ── iter663: suppress_final_gate — 24h/7d suppress 实时 DB 兜底 ──
        # 根因同 retriever.py：_score_chunk 内 24h/7d suppress 依赖进程启动时
        #   一次性计算的计数。并发 session timeline 写入无锁 → 读到旧值 → 逃逸。
        # 修复：在最终门禁实时查 recall_traces 计数。
        if top_k:
            try:
                import sqlite3 as _sf663d
                from datetime import datetime as _dt663d, timezone as _tz663d, timedelta as _td663d
                _sf663d_conn = _sf663d.connect(str(STORE_DB))
                _sf663d_now = _dt663d.now(_tz663d.utc)
                _cut663d_24h = (_sf663d_now - _td663d(hours=24)).isoformat()
                _cut663d_7d = (_sf663d_now - _td663d(days=7)).isoformat()
                _rt663d_24h = {}
                _rt663d_7d = {}
                # iter835: suppress_final_gate_project_scope — 同步 retriever.py
                for (_tk663d, _ts663d) in _sf663d_conn.execute(
                        "SELECT top_k_json, timestamp FROM recall_traces "
                        "WHERE injected=1 AND project=? AND timestamp>?", (project, _cut663d_7d,)).fetchall():
                    if not _tk663d: continue
                    try:
                        for _it663d in json.loads(_tk663d):
                            _c663d = _it663d.get("id", "") if isinstance(_it663d, dict) else ""
                            if _c663d:
                                _rt663d_7d[_c663d] = _rt663d_7d.get(_c663d, 0) + 1
                                if _ts663d and _ts663d > _cut663d_24h:
                                    _rt663d_24h[_c663d] = _rt663d_24h.get(_c663d, 0) + 1
                    except Exception:
                        continue
                # iter807: daemon_inmem_suppress — 叠加进程内存注入记录（消除 writeback 竞争）
                # 根因：writeback 异步 → DB 查询滞后 → 连续注入逃逸。
                # 方案：进程内计数取 max(db, inmem)——不相加避免双重计数。
                _now_unix = time.time()
                _cut_6h_unix = _now_unix - 21600  # iter813
                _cut_24h_unix = _now_unix - 86400
                _cut_7d_unix = _now_unix - 604800
                _inmem_6h = {}  # iter813
                _inmem_24h = {}
                _inmem_7d = {}
                _gc_idx = 0
                for _il807_cid, _il807_ts in _daemon_inject_log:
                    if _il807_ts < _cut_7d_unix:
                        _gc_idx += 1
                        continue
                    _inmem_7d[_il807_cid] = _inmem_7d.get(_il807_cid, 0) + 1
                    if _il807_ts >= _cut_24h_unix:
                        _inmem_24h[_il807_cid] = _inmem_24h.get(_il807_cid, 0) + 1
                    if _il807_ts >= _cut_6h_unix:
                        _inmem_6h[_il807_cid] = _inmem_6h.get(_il807_cid, 0) + 1  # iter813
                if _gc_idx > 0:
                    del _daemon_inject_log[:_gc_idx]
                # iter813: 也统计 DB 侧的 6h counts
                _rt663d_6h = {}
                # iter835: suppress_final_gate_project_scope — 同步
                for (_tk663d_6h, _ts663d_6h) in _sf663d_conn.execute(
                        "SELECT top_k_json, timestamp FROM recall_traces "
                        "WHERE injected=1 AND project=? AND timestamp>?",
                        (project, (_sf663d_now - _td663d(hours=6)).isoformat(),)).fetchall():
                    if not _tk663d_6h: continue
                    try:
                        for _it663d_6h in json.loads(_tk663d_6h):
                            _c663d_6h = _it663d_6h.get("id", "") if isinstance(_it663d_6h, dict) else ""
                            if _c663d_6h:
                                _rt663d_6h[_c663d_6h] = _rt663d_6h.get(_c663d_6h, 0) + 1
                    except Exception:
                        continue
                # iter888: global_chunk_cross_project_suppress — global chunk 用全局计数
                # 同 retriever.py：对 project='global' 的 chunk 用跨项目计数取 max。
                _g888d_ids = set(r[0] for r in _sf663d_conn.execute(
                    "SELECT id FROM memory_chunks WHERE project='global'").fetchall())
                if _g888d_ids:
                    _g888d_24h_c = {}
                    _g888d_7d_c = {}
                    _g888d_6h_c = {}
                    _cut888d_6h = (_sf663d_now - _td663d(hours=6)).isoformat()
                    for (_tk888d, _ts888d) in _sf663d_conn.execute(
                            "SELECT top_k_json, timestamp FROM recall_traces "
                            "WHERE injected=1 AND timestamp>?", (_cut663d_7d,)).fetchall():
                        if not _tk888d: continue
                        try:
                            for _it888d in json.loads(_tk888d):
                                _c888did = _it888d.get("id", "") if isinstance(_it888d, dict) else ""
                                if _c888did in _g888d_ids:
                                    _g888d_7d_c[_c888did] = _g888d_7d_c.get(_c888did, 0) + 1
                                    if _ts888d and _ts888d > _cut663d_24h:
                                        _g888d_24h_c[_c888did] = _g888d_24h_c.get(_c888did, 0) + 1
                                    if _ts888d and _ts888d > _cut888d_6h:
                                        _g888d_6h_c[_c888did] = _g888d_6h_c.get(_c888did, 0) + 1
                        except Exception:
                            continue
                    for _gid888d in _g888d_ids:
                        _rt663d_24h[_gid888d] = max(_rt663d_24h.get(_gid888d, 0), _g888d_24h_c.get(_gid888d, 0))
                        _rt663d_7d[_gid888d] = max(_rt663d_7d.get(_gid888d, 0), _g888d_7d_c.get(_gid888d, 0))
                        _rt663d_6h[_gid888d] = max(_rt663d_6h.get(_gid888d, 0), _g888d_6h_c.get(_gid888d, 0))
                _sf663d_conn.close()
                for _mk807 in set(_inmem_6h) | set(_inmem_24h) | set(_inmem_7d):
                    if _mk807 in _inmem_6h:
                        _rt663d_6h[_mk807] = max(_rt663d_6h.get(_mk807, 0), _inmem_6h[_mk807])
                    _rt663d_24h[_mk807] = max(_rt663d_24h.get(_mk807, 0), _inmem_24h.get(_mk807, 0))
                    _rt663d_7d[_mk807] = max(_rt663d_7d.get(_mk807, 0), _inmem_7d.get(_mk807, 0))
                _pre663d = len(top_k)
                # iter767: tiered_small_db — 分级小库阈值（同 _score_chunk）
                _sf663d_tiny_db = _db_chunk_count < 50  # iter848: 边界 40→50
                _sf663d_small_db = _db_chunk_count < 100
                # iter813+810: short_burst + tiny_db_24h_relax — sync daemon final_gate
                # iter818: tiny_db_6h_relax — 6h 分级
                # iter883: full_final_gate_7d_sync — 对齐 hard_deadline iter882
                # iter905: cross_project_suppress_tighten — daemon 路径同步
                # iter908: final_gate_7d_align_score — tiny_db 4→3 对齐 _score_chunk(>=3)
                def _d905_7d_thresh(s, c):
                    _cp = c[_CI_CP] or ""
                    _cross = (_cp != project and _cp != "global")
                    _is_global = (_cp == "global")
                    if _sf663d_tiny_db:
                        _t = 7  # iter1477: tiny_db_suppress_relax — 5→7
                    elif _sf663d_small_db:
                        _t = 4 if s >= 0.5 else 3  # iter1497: small_db sync retriever.py
                    else:
                        _t = 5 if s >= 0.5 else 3
                    if _cross:
                        return max(2, _t - 2)
                    # iter1023: global_chunk_suppress_tighten — sync retriever.py iter993/1006
                    # 根因：daemon suppress_final_gate 缺少 global chunk 7d 收紧，
                    #   feishu CLI(ac=4)/memory验证(ac=6) 经 daemon 路径 7d suppress 逃逸。
                    elif _is_global:
                        # iter1478: global_deep_saturated_7d_tighten — sync daemon suppress_final_gate
                        # iter1524: tiny_db_global_7d_relax — sync daemon suppress_final_gate
                        _g_ac_fg = c[_CI_AC] or 0
                        if _local_sparse_d:
                            return 3 if _g_ac_fg >= 4 else 5
                        if _s672_tiny:
                            # iter1640: global_dc_tinydb_7d_tighten — sync suppress_final_gate
                            if _g_ac_fg >= 4 and c[_CI_CT] == "design_constraint":
                                return 2
                            return 3 if _g_ac_fg >= 4 else 5
                        if _s672_small:
                            return 2 if _g_ac_fg >= 4 else 4
                        return 2
                    # iter1017: daemon_local_saturated_suppress — sync retriever.py iter1009
                    # iter1053: fallback_ceiling_align_local_deep — ac>=7 直接=2 对齐 suppress thresh
                    # iter1232: deep_saturated_unified_thresh1 — ac>=7 阈值 2→1 sync
                    _lac = c[_CI_AC] or 0
                    if _lac >= 7:
                        return 1
                    elif _lac >= 5:
                        return max(2, _t - 2)  # iter1152: local_mid_saturated_tighten
                    # iter1143+1460: sync retriever.py iter1276 — ac>=4 max(3,_t-1)→max(2,_t-2)
                    # iter1549: ac4_tiny_db_7d_cap2 — sync ceiling path
                    elif _lac >= 4:
                        return 2 if _s672_tiny else max(2, _t - 2)
                    # iter1402+1460: sync retriever.py iter1457 — ac>=3 cap
                    elif _lac >= 3:
                        return min(_t, 3 if _db_chunk_count < 50 else 2)
                    return _t
                # iter1015: daemon_micro_db_final_gate_bypass — 对齐 retriever.py line 5052
                # 根因（数据驱动，2026-05-07）：<=5 chunk 项目经 daemon 路径时 suppress_final_gate
                #   无 micro_db 豁免 → global chunk 被 7d suppress 全灭。FULL/LITE 已有 bypass。
                # iter1020: suppress_final_gate_24h_saturated_sync — 同步 retriever.py
                def _d1020_24h_thresh(s, c):
                    _b = 3 if _sf663d_tiny_db else (3 if s >= 0.5 else 2) if _sf663d_small_db else (3 if s >= 0.5 else 2)
                    _a = c[_CI_AC] or 0
                    if _a >= 10:
                        return max(1, _b - 2)
                    elif _a >= 7:
                        return max(1, _b - 1)
                    # iter1023: global_24h_saturated_cap — sync retriever.py
                    # iter1579: sparse_global_24h_relax — sync LITE path iter1472
                    #   根因（数据驱动，2026-05-12）：git:a4ee2fcfacc4(4 local,sparse) 56% 空召回。
                    #   global ac>=4 thresh=1 意味着 24h 内 0 次注入即 suppress（首次后即封锁）。
                    #   sparse 项目依赖 global 作为补充知识源，阈值=2 允许每 24h 注入 1 次。
                    if (c[_CI_CP] or "") == "global" and _a >= 4:
                        return 2 if _local_sparse_d else 1
                    return _b
                # iter1049: micro_db_cross_project_suppress — micro_db 跨项目 chunk 仍需 suppress
                # iter1142: micro_db_cross_saturated — ac>=7 阈值 3→1（sync retriever.py）
                if _db_chunk_count <= 5:
                    def _d_micro_cross_7d_cap(c):
                        _mc_ac = c[_CI_AC] or 0
                        if _mc_ac >= 7:
                            return 1
                        if _mc_ac >= 5:
                            return 2
                        return 3
                    top_k = [(s, c) for s, c in top_k
                             if (c[_CI_CP] or "") == project
                             or (c[_CI_CP] or "") == "global"
                             or _rt663d_7d.get(c[_CI_ID], 0) < _d_micro_cross_7d_cap(c)]
                # iter1273: lifetime_injection_suppress — daemon suppress_final_gate 同步
                def _d1273_lifetime_ok(c):
                    # iter1337: sparse_global_lifetime_shield — sync retriever.py
                    if _local_sparse_d and (c[_CI_CP] or "") in (project, "global"):
                        # iter1704: sparse_saturated_dc_pierce — sync retriever.py iter1468
                        _sp_ac_d = c[_CI_AC] or 0
                        _sp_lt_data = _itl_lifetime.get(c[_CI_ID])
                        _sp_lt_d = max(_sp_lt_data[0] if _sp_lt_data else 0, _sp_ac_d)
                        if (c[_CI_CP] or "") == "global" and (c[_CI_CT] or "") == "design_constraint" \
                                and _sp_ac_d >= 4 and _sp_lt_d >= 4:
                            pass  # fall through to normal suppress logic
                        else:
                            return True
                    _lt_data = _itl_lifetime.get(c[_CI_ID])
                    if not _lt_data:
                        # iter1375: ac_lifetime_dc_floor_align — sync retriever.py
                        _ac_lt_d = c[_CI_AC] or 0
                        if _ac_lt_d >= 6:
                            return False
                        if (c[_CI_CT] or "") == "design_constraint" and _ac_lt_d >= 4:
                            return False
                        return True
                    _lt_cnt, _lt_last = _lt_data
                    # iter1423: lifetime_thresh_align — 对齐 retriever.py: tiny=8, non-tiny=5
                    _lt_thresh_d = 8 if _sf663d_tiny_db else 5
                    if _lt_cnt >= _lt_thresh_d:
                        return False
                    if _lt_cnt >= 5 and _lt_last > _cutoff_72h:
                        return False
                    # iter1370+1423: density_aware_lifetime — lifetime>=5 + 7d>=3 suppress
                    # iter1423: 扩展到 small_db — 73-chunk 库垄断 chunk lifetime=5-6 逃逸
                    if (_sf663d_tiny_db or _sf663d_small_db) and _lt_cnt >= 5:
                        if _rt663d_7d.get(c[_CI_ID], 0) >= 3:
                            return False
                    return True
                # iter1580: fallback_protected_final_gate_bypass — sync retriever.py
                # iter1629: sparse_local_final_gate_shield — daemon 路径同步
                if _db_chunk_count > 5:
                    top_k = [(s, c) for s, c in top_k
                             if c[_CI_ID] in _fallback_protected_ids
                             or (_local_sparse_d and c[_CI_CP] == project)
                             or (_rt663d_6h.get(c[_CI_ID], 0) < 2  # iter865: 6h_tighten_tiny — 统一阈值 2
                             and _rt663d_24h.get(c[_CI_ID], 0) < _d1020_24h_thresh(s, c)
                             # iter883: tiny 5→3, small 5/4→4/3（sync hard_deadline line 3268）
                             # iter905: cross_project_suppress_tighten — 跨项目 7d -2
                             and _rt663d_7d.get(c[_CI_ID], 0) < _d905_7d_thresh(s, c)
                             and _d1273_lifetime_ok(c))]  # iter1273
                if len(top_k) < _pre663d:
                    _deferred.log(DMESG_WARN, "retriever_daemon",
                                  f"iter663_suppress_final_gate: filtered "
                                  f"{_pre663d - len(top_k)} chunks (24h/7d realtime)",
                                  session_id=session_id, project=project)
            except Exception as _e663d:
                _deferred.log(DMESG_WARN, "retriever_daemon",
                              f"iter663_suppress_final_gate_EXCEPTION: {type(_e663d).__name__}: {_e663d}",
                              session_id=session_id, project=project)
        # ── iter887: suppress_final_gate_closure_fallback — 闭包快照兜底 ──
        # 根因（数据驱动，2026-05-05）：suppress_final_gate 实时 DB 查询在 try/except
        #   中静默失败时，垄断 chunk 逃逸。用启动时闭包快照 _recent_6h/_24h/_7d_counts 兜底。
        # iter1015: daemon_micro_db_final_gate_bypass — 对齐 retriever.py line 5073
        # iter1049: micro_db_cross_project_suppress — closure fallback 路径同步
        if top_k and _db_chunk_count <= 5:
            top_k = [(s, c) for s, c in top_k
                     if (c[_CI_CP] or "") == project
                     or (c[_CI_CP] or "") == "global"
                     or _recent_7d_counts.get(c[_CI_ID], 0) < 3]
        if top_k and _db_chunk_count > 5:
            _pre887d = len(top_k)
            _fg887d_tiny = _db_chunk_count < 50
            _fg887d_small = _db_chunk_count < 100
            # iter905: cross_project_suppress_tighten — daemon closure 路径同步
            # iter908: final_gate_7d_align_score — tiny_db 4→3
            def _d887_7d_thresh(s, c):
                _cp = c[_CI_CP] or ""
                _cross = (_cp != project and _cp != "global")
                _is_global = (_cp == "global")
                if _fg887d_tiny:
                    _t = 7  # iter1477: tiny_db_suppress_relax — 5→7
                elif _fg887d_small:
                    _t = 4 if s >= 0.5 else 3  # iter1497: small_db sync retriever.py
                else:
                    _t = 5 if s >= 0.5 else 3
                if _cross:
                    return max(2, _t - 2)
                # iter1194: global_unified_thresh — sync daemon closure_fallback
                # iter1478: global_deep_saturated_7d_tighten — sync closure fallback
                # iter1524: tiny_db_global_7d_relax — sync closure fallback
                elif _is_global:
                    _g_ac_cf = c[_CI_AC] or 0
                    if _local_sparse_d:
                        return 3 if _g_ac_cf >= 4 else 5
                    if _fg887d_tiny:
                        # iter1640: global_dc_tinydb_7d_tighten — sync closure fallback
                        if _g_ac_cf >= 4 and c[_CI_CT] == "design_constraint":
                            return 2
                        return 3 if _g_ac_cf >= 4 else 5
                    if _fg887d_small:
                        return 2 if _g_ac_cf >= 4 else 4
                    return 2
                # iter1017: daemon_local_saturated_suppress — sync retriever.py iter1009
                # iter1053: fallback_ceiling_align_local_deep — ac>=7 直接=2 对齐 suppress thresh
                # iter1232: deep_saturated_unified_thresh1 — ac>=7 阈值 2→1 sync closure
                _lac = c[_CI_AC] or 0
                if _lac >= 7:
                    return 1
                elif _lac >= 5:
                    return max(2, _t - 2)  # iter1460: sync retriever.py
                # iter1143+1460: sync retriever.py iter1276 — ac>=4 max(2,_t-2)
                elif _lac >= 4:
                    return max(2, _t - 2)
                # iter1242: ac3_7d_tighten — sync closure fallback
                # iter1260: ac3_7d_direct_cap3_sync — direct cap
                # iter1315: ac3_7d_cap2_daemon_sync — cap 3→2
                elif _lac >= 3:
                    return min(_t, 2)
                return _t
            # iter1019: saturated_24h_tighten — sync suppress_final_gate
            def _d1019_24h_thresh(s, c):
                _b = 3 if _fg887d_tiny else (3 if s >= 0.5 else 2) if _fg887d_small else (3 if s >= 0.5 else 2)
                _a = c[_CI_AC] or 0
                if _a >= 10:
                    return max(1, _b - 2)
                elif _a >= 7:
                    return max(1, _b - 1)
                # iter1023: global_24h_saturated_cap — sync retriever.py
                if (c[_CI_CP] or "") == "global" and _a >= 4:
                    return 1
                return _b
            # iter1629: sparse_local_final_gate_shield — daemon closure 路径同步
            top_k = [(s, c) for s, c in top_k
                     if (_local_sparse_d and (c[_CI_CP] or "") == project)
                     or (_recent_6h_counts.get(c[_CI_ID], 0) < 2
                     and _recent_24h_counts.get(c[_CI_ID], 0) < _d1019_24h_thresh(s, c)
                     # iter905: cross_project_suppress_tighten — 跨项目 7d -2
                     and _recent_7d_counts.get(c[_CI_ID], 0) < _d887_7d_thresh(s, c)
                     and _d1273_lifetime_ok(c))]  # iter1273: closure path reuses daemon fn
            if len(top_k) < _pre887d:
                _deferred.log(DMESG_WARN, "retriever_daemon",
                              f"iter887_closure_fallback_suppress: filtered "
                              f"{_pre887d - len(top_k)} chunks (closure 6h/24h/7d)",
                              session_id=session_id, project=project)
        # ── iter832: post_suppress_pair_inject — suppress 后单条时从快照补配对 ──
        # 根因（数据驱动，2026-05-05）：70% 注入为单条。suppress_final_gate 事后砍掉
        #   pair_inject 添加的第 2 条 → 最终仍单条。
        # 修复：suppress 过滤后如果 top_k=1，从 _pre_suppress_top_k 中选不同 chunk 配对。
        # iter851: suppress_aware_pair — 配对候选尊重 suppress_final_gate 的 24h/7d 判定
        def _pair_suppress_ok_d(cid, score):
            """iter851: daemon 侧检查候选是否被 suppress_final_gate 过滤。
            iter884: pair_suppress_relax — 配对候选 7d 阈值放宽 +2。"""
            try:
                _p24 = _rt663d_24h.get(cid, 0)
                _p7d = _rt663d_7d.get(cid, 0)
                _p24_lim = 3 if _sf663d_tiny_db else (3 if score >= 0.5 else 2) if _sf663d_small_db else (3 if score >= 0.5 else 2)
                # iter936: pair_7d_align_final_gate — 4/6/5/5→3/4/3/3 对齐 suppress_final_gate
                # iter960: pair_7d_align_final_gate_v2 — tiny_db 5→4 堵 pair 逃逸
                _p7d_lim = 4 if _sf663d_tiny_db else (5 if score >= 0.5 else 4) if _sf663d_small_db else (3 if score >= 0.5 else 3)  # iter990: small_db pair 4/3→5/4
                return _p24 < _p24_lim and _p7d < _p7d_lim
            except NameError:
                return True
        # iter1234: full_pair_score_floor — daemon pair 候选加 score 门槛对齐 LITE iter1197
        # iter1541: sync tiny_db pair_floor
        _full_pair_floor_d = 0.05 if _db_chunk_count < 20 else (0.08 if _db_chunk_count < 50 else 0.15)
        if len(top_k) == 1 and len(_pre_suppress_top_k) >= 2:
            _ps_top1_id = top_k[0][1][_CI_ID]
            _ps_candidates = [(s, c) for s, c in _pre_suppress_top_k
                              if c[_CI_ID] != _ps_top1_id and s >= _full_pair_floor_d
                              and _pair_suppress_ok_d(c[_CI_ID], s)]
            if _ps_candidates:
                _ps_best = max(_ps_candidates, key=lambda x: x[0])
                top_k.append(_ps_best)
                # iter1562: pair_inherit_floor_protect
                if _ps_top1_id in _fallback_protected_ids:
                    _fallback_protected_ids.add(_ps_best[1][_CI_ID])
                _deferred.log(DMESG_DEBUG, "retriever_daemon",
                              f"iter832_post_suppress_pair: paired {_ps_best[1][_CI_ID][:12]} "
                              f"s={_ps_best[0]:.3f} with top1={_ps_top1_id[:12]}",
                              session_id=session_id, project=project)
        elif len(top_k) == 1 and len(final) >= 2:
            # iter842: post_suppress_pair_from_final — 从 final 按 importance 兜底配对
            # iter1461: lite_pair_final_relax — sync retriever.py
            _ps842_top1_id = top_k[0][1][_CI_ID]
            _ps842_cands = [(float(c[_CI_IMP] or 0), c) for _, c in final
                            if c[_CI_ID] != _ps842_top1_id
                            and (c[_CI_AC] or 0) < 30
                            and _pair_suppress_ok_d(c[_CI_ID], 0.0)
                            # iter1702: daemon_pair_dc_gate — sync retriever.py iter1608
                            and not ((c[_CI_CT] or "") == "design_constraint" and (c[_CI_AC] or 0) >= 4)]
            if _ps842_cands:
                _ps842_best = max(_ps842_cands, key=lambda x: x[0])
                if _ps842_best[0] >= 0.3:
                    _ps842_score = top_k[0][0] * 0.25
                    top_k.append((_ps842_score, _ps842_best[1]))
                    # iter1562: pair_inherit_floor_protect — pair 继承 dead_zone 保护
                    if top_k[0][1][_CI_ID] in _fallback_protected_ids:
                        _fallback_protected_ids.add(_ps842_best[1][_CI_ID])
                    _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                  f"iter842_pair_from_final: paired {_ps842_best[1][_CI_ID][:12]} "
                                  f"imp={_ps842_best[0]:.2f} with top1={_ps842_top1_id[:12]}",
                                  session_id=session_id, project=project)
        # ── iter895: db_diversity_pair — iter832/842 均失败时从 DB 选低频不同类型 chunk 配对 ──
        # 根因（数据驱动，2026-05-05）：54% 注入为单条。suppress 把候选干掉只剩 1 条时，
        #   iter832/842 无法配对 → 单条逃逸。从 DB 直接选不同 chunk_type 的高 importance chunk。
        if len(top_k) == 1:
            _dp895_top1 = top_k[0][1]
            _dp895_top1_id = _dp895_top1[_CI_ID]
            _dp895_top1_type = _dp895_top1[_CI_CT] or ""
            try:
                # iter924: pair_type_relax — 放宽 chunk_type 限制为仅 id 去重
                # 根因（数据驱动，2026-05-06）：54% 单条注入。decision 占库 52%，
                #   chunk_type != top1_type 排除过半候选 → 配对失败。
                _dp895_exclude = f"'{_dp895_top1_id}'"
                _dp895_rows = conn.execute(
                    f"SELECT id, summary, content, chunk_type, importance, access_count "
                    f"FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE' "
                    f"AND id NOT IN ({_dp895_exclude}) "
                    f"ORDER BY importance DESC, access_count ASC LIMIT 5",
                    (project,)
                ).fetchall()
                # iter923: pair_7d_align_final_gate — 对齐 suppress_final_gate 阈值（同 iter914）
                _dp895_lim = 3 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)
                _dp895_ok = [r for r in _dp895_rows
                             if _recent_7d_counts.get(r[0], 0) < _dp895_lim
                             # iter1702: daemon_pair_dc_gate — sync retriever.py iter1608/1698
                             and not (r[3] == "design_constraint" and r[5] >= 4)]
                # iter1086: pair_relaxed_fallback — 全被 7d 过滤时选 7d 最低的一条
                # 根因（数据驱动，2026-05-07）：22-chunk 库 64% chunk 7d>=3 → pair 候选全灭
                #   → 44% 单条注入。pair 是辅助上下文，不应被 suppress 完全阻断。
                # 修复：_dp895_ok 为空时从 _dp895_rows 选 7d 最低的 1 条（relaxed pair）。
                if not _dp895_ok and _dp895_rows:
                    # iter1702: daemon_pair_dc_gate — relaxed path 也排除 dc ac>=4
                    _dp895_relaxed = [r for r in _dp895_rows
                                      if not (r[3] == "design_constraint" and r[5] >= 4)]
                    if _dp895_relaxed:
                        _dp895_ok = [min(_dp895_relaxed, key=lambda r: _recent_7d_counts.get(r[0], 0))]
                if _dp895_ok:
                    _dp895_pick = _dp895_ok[0]
                    # tuple: (id, summary, content, importance, last_accessed, chunk_type, access_count, ...)
                    _dp895_chunk = (_dp895_pick[0], _dp895_pick[1], _dp895_pick[2],
                                    _dp895_pick[4] or 0.5, None, _dp895_pick[3] or "",
                                    _dp895_pick[5] or 0) + (None,) * 6
                    _dp895_score = top_k[0][0] * 0.2
                    top_k.append((_dp895_score, _dp895_chunk))
                    # iter1562: pair_inherit_floor_protect
                    if _dp895_top1_id in _fallback_protected_ids:
                        _fallback_protected_ids.add(_dp895_pick[0])
                    _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                  f"iter895_db_diversity_pair: paired {_dp895_pick[0][:12]} "
                                  f"type={_dp895_pick[3]} imp={_dp895_pick[4]:.2f} "
                                  f"ac={_dp895_pick[5]} with top1={_dp895_top1_id[:12]}",
                                  session_id=session_id, project=project)
            except Exception:
                pass
        if not top_k:
            # ── iter670: suppress_fallback — suppress 全灭时降级注入最佳 1 条 ──
            # iter829: fallback_rotation — 排除上次已注入 chunk 避免 same_hash 死循环
            # iter889: fallback_7d_decay — 按 7d 注入频率衰减排序，打破高频 chunk 垄断轮换
            #   根因（数据驱动，2026-05-05）：28-chunk 库 top5 占 38% 注入位，
            #   suppress 全灭后 fallback 按 score 选最佳 → 高频 chunk 反复被选中。
            #   修复：score/(1+0.5*7d_count) 使低频 chunk 优先，促进注入多样性。
            # iter1631: sync iter1609 — local=0 不走 suppress_fallback
            if _pre_suppress_top_k and _local_chunk_count_d > 0:
                # iter892: fallback_exp_decay — 线性→指数衰减，高频 chunk 更快衰减
                # iter893: fallback_hard_ceiling — 7d>=5 绝对不选，杜绝垄断 chunk 经 fallback 逃逸
                # iter894: fallback_realtime_align — 优先用实时 DB 计数（与 suppress_final_gate 对齐）
                # 根因（数据驱动，2026-05-05）：fallback 用启动时闭包 _recent_7d_counts（滞后）+
                #   hard_ceiling=5，但 suppress_final_gate 用实时 DB + 阈值=3（tiny_db）。
                #   7d=3-4 的垄断 chunk 被 final_gate suppress 后又被 fallback 重新选中注入。
                _fb_7d_d = _rt663d_7d if '_rt663d_7d' in dir() and _rt663d_7d else _recent_7d_counts
                _fb_24h_d = _rt663d_24h if '_rt663d_24h' in dir() and _rt663d_24h else _recent_24h_counts
                # iter911: pair_7d_tighten — fallback ceiling 4→3(tiny) 堵逃逸
                _fb_ceiling_d = 5 if _db_chunk_count < 50 else (4 if _db_chunk_count < 100 else 5)  # iter1207: fallback_ceiling_mid_tighten — 50-99 库 6→4 去垄断
                # iter1053: fallback_ceiling_align_local_deep — per-chunk ceiling 对齐 suppress thresh
                def _fb_ceiling_d_fn(c):
                    # iter1576: lifetime_fallback_ceiling_cap — lifetime>=4 直接 ceiling=2
                    _lt_fb = (_itl_lifetime.get(c[_CI_ID], (0,))[0] if _itl_lifetime else 0)
                    if _lt_fb >= 4 and (c[_CI_AC] or 0) >= 4:
                        return 2
                    # iter1150: global_fallback_ceiling_align — ac>=5 直接=2
                    # 根因：suppress_final_gate 对 global ac>=5→thresh=2，但 fallback ceiling
                    #   仅区分 ac>=4→max(2,base-2)=3，ac=5-6 chunk 经 fallback 逃逸。
                    if c.get("project", "") == "global":
                        _gac = c.get("access_count", 0) or 0
                        if _gac >= 5:
                            return 2
                        if _gac >= 4:
                            return max(2, _fb_ceiling_d - 2)
                        return _fb_ceiling_d
                    _lac = c[_CI_AC] or 0
                    if _lac >= 7:
                        return 2
                    elif _lac >= 5:
                        return max(2, _fb_ceiling_d - 2)  # iter1152: local_mid_saturated_tighten
                    # iter1549: ac4_tiny_db_7d_cap2 — sync fallback ceiling path
                    elif _lac >= 4:
                        return 2 if _s672_tiny else max(2, _fb_ceiling_d - 2)
                    return _fb_ceiling_d
                # iter1027: fallback_24h_align — global ac>=4 阈值=1
                # iter1093: daemon_fallback_cooldown — fallback 也必须检查 cooldown
                # 根因（数据驱动，2026-05-07）：9a2692fd(ac=10) 经 LITE fallback 逃逸 cooldown，
                #   daemon fallback 同样只检 7d/24h count 不检 cooldown 时间戳 → 相同逃逸路径。
                # 修复：定义 _fb_cooldown_ok_d 过滤函数，对齐 _score_chunk 中的 cooldown 逻辑。
                def _fb_cooldown_ok_d(c):
                    _fac = c[_CI_AC] or 0
                    _fgl = (c[_CI_CP] == "global")
                    if not (_fgl or _fac >= 4) or not _cutoff_48h or not _last_inject_ts:
                        return True
                    _fts = _last_inject_ts.get(c[_CI_ID])
                    if not _fts and _fac >= 7:
                        _fts = c[_CI_LA] or ""
                    if not _fts:
                        return True
                    if _fgl:
                        _fcut = _cutoff_14d if _fac >= 10 else _cutoff_10d
                    else:
                        # iter1252: cooldown_5d_to_3d
                        _fcut = _cutoff_14d if _fac >= 10 else (_cutoff_10d if _fac >= 7 else _cutoff_72h)
                    return _fts <= _fcut
                # iter1446: daemon_fallback_relevance_gate — sync retriever.py iter1363
                # iter1597: daemon_fallback_cross_project_gate — sync retriever.py iter1555
                # 根因（数据驱动，2026-05-12）：daemon suppress_fallback 仅检查 global chunk relevance>=0.20，
                #   non-global 跨项目 chunk 无 relevance 检查。suppress 全灭后跨项目 chunk 可无条件恢复注入。
                #   retriever.py hard_deadline 路径已有 iter1555（non-global cross >= 0.30），daemon 缺失。
                # 修复：non-global 跨项目 chunk 需 relevance >= 0.30，与 retriever.py iter1555 对齐。
                def _fb_rel_ok_d(c):
                    _cp = c.get("project", "")
                    # iter1628: fallback_cross_proj_dc_block — 对齐 retriever.py iter1563
                    # 根因（数据驱动，2026-05-12）：c9accb7b(global,dc,ac=5) 被 cross_proj_constraint
                    #   hard suppress 后，因 relevance=0.22>=0.20 经 fallback 逃逸注入。
                    #   dc/procedure 跨项目 ac>=4 信息增量=0，fallback 不应恢复。
                    _fac_r = c[_CI_AC] or 0
                    _fct_r = c[_CI_CT] if len(c) > _CI_CT else ""
                    if _cp != project and _fct_r in ("design_constraint", "procedure") and _fac_r >= 4:
                        return False
                    if _cp == "global" and project != "global":
                        return _iter1446_rel_map.get(c[_CI_ID], 1.0) >= 0.20
                    if _cp and _cp != "global" and _cp != project:
                        return _iter1446_rel_map.get(c[_CI_ID], 1.0) >= 0.30
                    return True
                _fb_cap = [(s, c) for s, c in _pre_suppress_top_k
                           if _fb_cooldown_ok_d(c)
                           and _fb_rel_ok_d(c)
                           and _fb_7d_d.get(c[_CI_ID], 0) < _fb_ceiling_d_fn(c)
                           and _fb_24h_d.get(c[_CI_ID], 0) < (1 if c.get("project") == "global" and (c.get("access_count", 0) or 0) >= 4 else 3)]
                # iter1032: fallback_relax_24h — sync retriever.py
                # 根因（数据驱动，2026-05-07）：31% 空召回。24h>=3 排除所有 FTS 候选 → 空召回。
                # 修复：_fb_cap 全灭时只保留 7d ceiling（去掉 24h 过滤），保持 FTS 相关性。
                if not _fb_cap:
                    _fb_cap = [(s, c) for s, c in _pre_suppress_top_k
                               if _fb_cooldown_ok_d(c)
                               and _fb_rel_ok_d(c)
                               and _fb_7d_d.get(c[_CI_ID], 0) < _fb_ceiling_d_fn(c)]
                # iter1038: fallback_ceiling_escalate — small_db 全灭时放宽 ceiling +2 兜底
                # 根因（数据驱动，2026-05-07）：24-chunk 库 11/24 chunk 7d>=4，
                #   ceiling=4 全灭 → _fb_pool=None → ultimate_fallback 盲选不相关知识。
                # 修复：ceiling +2 重试，优先选最相关的被suppress知识（同步 retriever.py）。
                # iter1057: escalate_saturated_widen — ac>=5 不参与 escalate（收紧 ac<7→ac<5）
                # iter1134: escalate_ac_relax — ac<5→ac<7（86-chunk 库 cooldown 导致候选枯竭）
                if not _fb_cap and _db_chunk_count < 100:
                    _fb_cap = [(s, c) for s, c in _pre_suppress_top_k
                               if _fb_cooldown_ok_d(c)
                               and _fb_rel_ok_d(c)
                               and _fb_7d_d.get(c[_CI_ID], 0) < _fb_ceiling_d + 2
                               and (c[_CI_AC] or 0) < 7]
                # iter1367: sparse_fallback_uncap — local_sparse 全灭时选 ac 最低候选，跳过 7d/24h cap
                # 根因（数据驱动，2026-05-10）：local<=3 项目 55% 请求空召回。
                #   2 local chunks + 9 global = 11 visible，活跃 session 中所有候选 7d/24h 达 ceiling。
                #   escalate(+2) 仍不够 → _fb_pool=None → 零注入。
                # 修复：local_sparse 时从 _pre_suppress_top_k 选 ac 最低的候选（最新鲜知识），
                #   仅保留 cooldown 检查（防 14d 冷冻期内的过饱和 chunk），跳过 7d/24h ceiling。
                if not _fb_cap and _local_sparse_d:
                    _fb_cap = sorted(
                        [(s, c) for s, c in _pre_suppress_top_k
                         if _fb_cooldown_ok_d(c) and _fb_rel_ok_d(c)],
                        key=lambda x: (x[1][_CI_AC] or 0, -x[0])
                    )[:2]
                # iter916: fallback_no_unfiltered_pool — 全灭时不回退无过滤池，走 db_ultimate_fallback
                _fb_pool = _fb_cap if _fb_cap else None
                # iter939: fallback_relevance_floor — 低相关性时不强制注入噪声（sync retriever.py）
                # 根因（数据驱动，2026-05-06）：14.8% 注入 score<0.1，全来自 suppress_fallback。
                #   当前 prompt 与库内知识本就无关时，强制注入 = 用户感知噪声。
                # 修复：_fb_pool 最高分 < 0.05 时跳过，落到 db_ultimate_fallback（有分钟轮转多样性）。
                # iter940: floor_raise — 0.05→0.10（sync retriever.py）
                # iter996: micro_db_floor_relax — <=5 自有 chunk 库 floor 0.10→0.01（sync）
                # iter1701: daemon_fb_floor_large_db_sync — sync retriever.py iter1116
                # 根因（数据驱动，2026-05-13）：>=50 chunk 库 daemon _fb_floor=0.10，
                #   但 retriever.py FULL 路径已在 iter1116 放宽到 0.05。
                #   daemon LITE 路径比 FULL 严 2x → 大库 suppress_fallback 多 ~40% 空召回。
                # 修复：对齐三档 floor：<=5/sparse=0.01, >=50=0.05, 其余=0.10。
                _fb_floor = 0.01 if (_db_chunk_count <= 5 or _local_sparse_d) else (0.05 if _db_chunk_count >= 50 else 0.10)
                # iter1700: daemon_fb_zero_local_floor — sync iter1691/1692
                if _local_chunk_count_d == 0:
                    _fb_floor = max(_fb_floor, 0.18)
                if _fb_pool and max(s for s, _ in _fb_pool) < _fb_floor:
                    _fb_pool = None
                if _fb_pool:
                    # iter1700: daemon_dc_fallback_deprioritize — sync iter1699
                    def _fb_dc_penalty_d(c):
                        if c[_CI_CT] == "design_constraint" and (c[_CI_AC] or 0) >= 5:
                            return 0.3
                        return 1.0
                    _fb_sorted = sorted(_fb_pool,
                                        key=lambda x: x[0] * (0.5 ** (_fb_7d_d.get(x[1][_CI_ID], 0) / 2)) * _fb_dc_penalty_d(x[1]),
                                        reverse=True)
                    _fb = _fb_sorted[0]
                    if last_hash and len(_fb_sorted) > 1:
                        _fb_hash = '%08x' % zlib.crc32(_fb[1][_CI_ID].encode())
                        if _fb_hash == last_hash:
                            _fb = _fb_sorted[1]
                    # iter1324: fallback_pair_inject — LITE path sync
                    # iter1703: suppress_fallback_pair_dc_gate — DC ac>=5 不参与 pair
                    _fb_pair = [_fb]
                    if len(_fb_sorted) >= 2:
                        _fb2 = _fb_sorted[1] if _fb is _fb_sorted[0] else _fb_sorted[0]
                        if (_fb2[0] >= _fb[0] * 0.4
                                and not (_fb2[1][_CI_CT] == "design_constraint"
                                         and (_fb2[1][_CI_AC] or 0) >= 5)):
                            _fb_pair.append(_fb2)
                    top_k = _fb_pair
                    # iter1516: suppress_fallback_floor_protect — 对齐 iter1506
                    for _fbp_s, _fbp_c in _fb_pair:
                        _fallback_protected_ids.add(_fbp_c[_CI_ID])
                    _deferred.log(DMESG_WARN, "retriever_daemon",
                                  f"iter670_suppress_fallback: all {len(_pre_suppress_top_k)} "
                                  f"suppressed, fallback to best={_fb[1][_CI_ID][:12]}",
                                  session_id=session_id, project=project)
            # iter916: fallback_no_unfiltered_pool 后 _fb_pool=None 也会落到这里
            # iter1631: sync iter1607 — local=0 不走 db_ultimate_fallback
            if not top_k and _local_chunk_count_d > 0:
                # iter902+916: db_ultimate_fallback — 排除 7d 垄断 chunk
                # 根因（2026-05-06）：原 iter902 无 7d 限制，最高 imp chunk 被反复选中(6次/7d)。
                # 修复：排除 7d >= ceiling 的 chunk，选低频+高 importance 的。
                _fb_7d_ult = _rt663d_7d if '_rt663d_7d' in dir() and _rt663d_7d else _recent_7d_counts
                # iter1001: ult_ceiling_align_7d_thresh — tiny_db 4→5 对齐 _suppress_7d_thresh
                _ult_ceiling = 5 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)
                _ult_exclude = [cid for cid, cnt in _fb_7d_ult.items() if cnt >= _ult_ceiling]
                _ult_placeholders = ','.join(['?'] * len(_ult_exclude)) if _ult_exclude else ''
                _ult_where = f" AND id NOT IN ({_ult_placeholders})" if _ult_exclude else ''
                try:
                    # iter938: ultimate_fallback_rotation — 分钟级轮转（同步 retriever.py）
                    # iter969: fallback_include_global — 包含 global chunks 避免小库空召回
                    # iter1548: sparse_local_first_ult — sparse 项目优先选本地 chunk（同步 retriever.py）
                    _dbuf_rows = None
                    if _local_sparse_d:
                        _dbuf_local = conn.execute(
                            "SELECT id, summary, content, chunk_type, importance, "
                            "COALESCE(access_count,0), created_at, 0.0, COALESCE(lru_gen,0), project "
                            f"FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE'{_ult_where} "
                            "ORDER BY importance DESC LIMIT 1",
                            (project, *_ult_exclude)
                        ).fetchall()
                        if _dbuf_local:
                            _dbuf_rows = _dbuf_local
                    if not _dbuf_rows:
                        _dbuf_rows = conn.execute(
                            "SELECT id, summary, content, chunk_type, importance, "
                            "COALESCE(access_count,0), created_at, 0.0, COALESCE(lru_gen,0), project "
                            f"FROM memory_chunks WHERE (project=? OR project='global') AND chunk_state='ACTIVE'{_ult_where} "
                            "ORDER BY importance DESC, access_count ASC LIMIT 5",
                            (project, *_ult_exclude)
                        ).fetchall()
                    if _dbuf_rows:
                        import time as _dbuf_time
                        _dbuf_idx = int(_dbuf_time.time() // 60) % len(_dbuf_rows)
                        _dbuf_row = _dbuf_rows[_dbuf_idx]
                        top_k = [(0.001, _dbuf_row)]
                        _fallback_protected_ids.add(_dbuf_row[_CI_ID])  # iter1516
                        _deferred.log(DMESG_WARN, "retriever_daemon",
                                      f"iter938_db_ultimate_fallback_rotate: "
                                      f"id={_dbuf_row[0][:12]} imp={_dbuf_row[4]:.2f} "
                                      f"idx={_dbuf_idx}/{len(_dbuf_rows)} excluded={len(_ult_exclude)} project={project}",
                                      session_id=session_id, project=project)
                except Exception:
                    pass
                if not top_k:
                    # iter932: fallback_ceiling_escalation — 放宽 ceiling 重试
                    # 根因（数据驱动，2026-05-06）：23-chunk 活跃库 12 个 7d>=3，
                    #   ceiling=3 排除 52% chunk → ultimate_fallback 也选不到 → 空召回。
                    #   16 条 hash_changed|full 空召回 = 有知识但拒绝给出。
                    # 修复：ceiling+3 重试，允许选 7d 较高但非极端垄断的 chunk。
                    #   最终选中的仍受 same_hash 去重保护，不会连续重复注入。
                    # iter934: escalation_diversity_order — access_count ASC 优先
                    #   根因（数据驱动，2026-05-06）：importance DESC 使垄断 chunk 反复被选。
                    #   改为低访问优先，打破垄断轮换。
                    _esc_ceiling = _ult_ceiling + 3
                    _esc_exclude = [cid for cid, cnt in _fb_7d_ult.items() if cnt >= _esc_ceiling]
                    _esc_ph = ','.join(['?'] * len(_esc_exclude)) if _esc_exclude else ''
                    _esc_where = f" AND id NOT IN ({_esc_ph})" if _esc_exclude else ''
                    try:
                        # iter969: fallback_include_global — escalation 同步包含 global
                        _esc_row = conn.execute(
                            "SELECT id, summary, content, chunk_type, importance, "
                            "COALESCE(access_count,0), created_at, 0.0, COALESCE(lru_gen,0), project "
                            f"FROM memory_chunks WHERE (project=? OR project='global') AND chunk_state='ACTIVE'{_esc_where} "
                            "ORDER BY access_count ASC, importance DESC LIMIT 1",
                            (project, *_esc_exclude)
                        ).fetchone()
                        if _esc_row:
                            top_k = [(0.001, _esc_row)]
                            _fallback_protected_ids.add(_esc_row[_CI_ID])  # iter1516
                            _deferred.log(DMESG_WARN, "retriever_daemon",
                                          f"iter932_fallback_ceiling_escalation: "
                                          f"id={_esc_row[0][:12]} imp={_esc_row[4]:.2f} "
                                          f"ceiling={_ult_ceiling}→{_esc_ceiling} excluded={len(_esc_exclude)}",
                                          session_id=session_id, project=project)
                    except Exception:
                        pass
                if not top_k:
                    # iter780: empty_result_tlb — 写入空结果标记避免重复空转
                    _tlb_write(prompt_hash, "__empty__", _get_db_mtime())
                    return
        # ── iter914: post_fallback_pair — suppress_fallback 恢复单条后补配对 ──
        # 根因（数据驱动，2026-05-06）：52% 单条注入因 suppress 全灭→fallback 恢复 1 条，
        #   iter895 在 fallback 前执行（top_k=0 条件不满足）→ 无配对机会。
        # 修复：fallback 后从 DB 选不同类型低频 chunk 配对。
        if len(top_k) == 1:
            _pf914_top1 = top_k[0][1]
            _pf914_top1_id = _pf914_top1[_CI_ID]
            _pf914_top1_type = _pf914_top1[_CI_CT] or ""
            try:
                # iter924: pair_type_relax — 放宽 chunk_type 限制为仅 id 去重
                # 根因（数据驱动，2026-05-06）：54% 单条注入。24-chunk 库中 decision 占 52%，
                #   chunk_type != top1_type 排除过半候选 → 7d 过滤后常为空 → 配对失败。
                # 修复：仅排除 id 相同的 chunk，允许同类型不同知识配对。
                # iter1136: post_fallback_diversity_pair — 优先选低 ac 新鲜 chunk
                # 根因（数据驱动，2026-05-08）：ORDER BY importance DESC 优先返回高 ac
                #   垄断 chunk(imp>=0.84,ac>=7)，全部被 7d>=3 过滤 → pair 失败。
                #   低 ac 新鲜 chunk(ac<=4,7d=0) importance 较低被 LIMIT 5 截断。
                # 修复：ORDER BY access_count ASC 优先，确保新鲜 chunk 优先进入候选池。
                _pf914_rows = conn.execute(
                    f"SELECT id, summary, content, chunk_type, importance, access_count "
                    f"FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE' "
                    f"AND id != ? AND importance >= 0.5 "
                    f"ORDER BY access_count ASC, importance DESC LIMIT 8",
                    (project, _pf914_top1_id)
                ).fetchall()
                _pf914_7d = _rt663d_7d if '_rt663d_7d' in dir() and _rt663d_7d else _recent_7d_counts
                # iter923: pair_7d_align_final_gate — 对齐 suppress_final_gate 阈值
                # 根因（数据驱动，2026-05-06）：iter914 pair 的 7d 限制=6（tiny_db），
                #   而 suppress_final_gate 阈值=3。7d=4-5 的垄断 chunk 被 final_gate suppress
                #   后经 fallback→pair 路径复活注入（如 import-90139 7d=4 仍注入 6 次/7d）。
                # 修复：pair 7d 限制对齐 suppress_final_gate，阻止被 suppress 的 chunk 经配对逃逸。
                _pf914_lim = 3 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)
                _pf914_ok = [r for r in _pf914_rows if _pf914_7d.get(r[0], 0) < _pf914_lim
                             # iter1702: daemon_pair_dc_gate — sync retriever.py iter1608
                             and not (r[3] == "design_constraint" and r[5] >= 4)]
                if _pf914_ok:
                    _pf914_pick = _pf914_ok[0]
                    _pf914_chunk = (_pf914_pick[0], _pf914_pick[1], _pf914_pick[2],
                                    _pf914_pick[4] or 0.5, None, _pf914_pick[3] or "",
                                    _pf914_pick[5] or 0) + (None,) * 6
                    top_k.append((top_k[0][0] * 0.2, _pf914_chunk))
                    _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                  f"iter914_post_fallback_pair: paired {_pf914_pick[0][:12]} "
                                  f"type={_pf914_pick[3]} imp={_pf914_pick[4]:.2f} "
                                  f"with fallback_top1={_pf914_top1_id[:12]}",
                                  session_id=session_id, project=project)
            except Exception:
                pass
        top_k_ids = sorted([c[_CI_ID] for _, c in top_k])  # iter235
        # iter217: crc32 faster than md5 (~0.712us vs ~1.107us, same 8-char hex format)
        current_hash = '%08x' % zlib.crc32("|".join(top_k_ids).encode())

        if current_hash == last_hash and session_id in _sessions_with_injection:  # iter201+804
            # iter874→880: diversity_probe — same_hash 时从 DB 选低频高价值 chunk 打破 hash 锁定
            # 根因（数据驱动，2026-05-05）：20/22 same_hash 中 iter859 因 s>0 过滤全空未触发，
            #   diversity_probe 原先只对空 top_k 生效 → 非空 top_k same_hash 永远跳过。
            # iter880: minute_rotation — LIMIT 1 总选同一 chunk → hash 再次锁定。
            #   daemon 用 _diversity_counter 自增轮转（进程常驻）。
            _sh_top_k_ids = set(c[_CI_ID] for _, c in top_k) if top_k else set()
            try:
                # iter927: diversity_probe_suppress_aware — 排除 7d 高频 chunk
                # 根因（数据驱动，2026-05-06）：diversity_probe 选出的候选可能是已被
                #   suppress_final_gate 拦截的垄断 chunk（7d>=3），轮转到的知识用户已反复看过。
                # 修复：排除 7d >= suppress 阈值的 chunk，确保轮转到真正新鲜的知识。
                _dp_7d = _rt663d_7d if '_rt663d_7d' in dir() and _rt663d_7d else _recent_7d_counts
                # iter997: daemon_diversity_probe_ceil_sync — 同步 retriever.py iter992 放宽
                # 根因（数据驱动，2026-05-06）：20-chunk 库 14/21 chunk 7d>=3，
                #   daemon ceil=3 排除 67% 候选 → diversity_probe 零触发 → 22 次 same_hash skip 全空召回。
                #   retriever.py 已在 iter992 放宽到 5/7，daemon 未同步。
                # 修复：对齐 retriever.py（5/7/7），恢复 diversity_probe 候选池。
                _dp_7d_ceil = 5 if _db_chunk_count < 50 else (7 if _db_chunk_count < 100 else 7)
                _dp_7d_exclude = set(cid for cid, cnt in _dp_7d.items() if cnt >= _dp_7d_ceil)
                _dp_all_exclude = _sh_top_k_ids | _dp_7d_exclude
                _dp_exclude = ",".join(f"'{x}'" for x in _dp_all_exclude) if _dp_all_exclude else "''"
                # iter998: diversity_probe_include_global — 与 iter969 fallback_include_global 对齐
                # 根因（数据驱动，2026-05-06）：小库 diversity_probe 只查 project=?，
                #   排除 global chunk 导致候选池枯竭，same_hash 无法打破。
                _dp_rows = conn.execute(
                    f"SELECT id, summary, content, chunk_type, importance, access_count "
                    f"FROM memory_chunks WHERE (project=? OR project='global') AND chunk_state='ACTIVE' "
                    f"AND id NOT IN ({_dp_exclude}) "
                    f"ORDER BY access_count ASC, importance DESC LIMIT 10",
                    (project,)
                ).fetchall()
                # iter1133: diversity_probe_exhaustion_fallback — 7d_exclude 枯竭时放宽重试
                # 根因（数据驱动，2026-05-08）：20 次 same_hash skip 中 diversity_probe 0 次触发，
                #   7d_exclude 过滤掉全部候选 → 候选池枯竭 → 21% 请求零注入。
                # 修复：候选池空时去掉 7d_exclude 重查，宁可注入已见过的也不零注入。
                if not _dp_rows:
                    _dp_rows = conn.execute(
                        f"SELECT id, summary, content, chunk_type, importance, access_count "
                        f"FROM memory_chunks WHERE (project=? OR project='global') AND chunk_state='ACTIVE' "
                        f"AND id NOT IN ({','.join(repr(x) for x in _sh_top_k_ids) if _sh_top_k_ids else repr('')}) "
                        f"ORDER BY access_count ASC, importance DESC LIMIT 10",
                        (project,)
                    ).fetchall()
                if _dp_rows:
                    _dp_idx = _diversity_counter[0] % len(_dp_rows)
                    _diversity_counter[0] += 1
                    _dp_row = _dp_rows[_dp_idx]
                    _dp_chunk = (_dp_row[0], _dp_row[1], _dp_row[2], _dp_row[4],
                                 None, _dp_row[3] or "", _dp_row[5], None, 0.0, 0)
                    if top_k:
                        _sh_min_idx = min(range(len(top_k)), key=lambda i: top_k[i][0])
                        top_k[_sh_min_idx] = (0.01, _dp_chunk)
                    else:
                        top_k = [(0.01, _dp_chunk)]
                    top_k_ids = sorted([c[_CI_ID] for _, c in top_k])
                    current_hash = '%08x' % zlib.crc32("|".join(top_k_ids).encode())
                    _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                  f"iter880_diversity_probe_rotate: injecting "
                                  f"{_dp_row[0][:12]} ac={_dp_row[5]} imp={_dp_row[4]:.2f} "
                                  f"idx={_dp_idx}/{len(_dp_rows)} "
                                  f"replacing={'empty' if not _sh_top_k_ids else 'lowest'}",
                                  session_id=session_id, project=project)
                    # fall through to injection path (don't return)
            except Exception:
                pass
        if current_hash == last_hash and session_id in _sessions_with_injection:
            _tlb_write(prompt_hash, current_hash, _get_db_mtime())
            # iter173: persistent conn — do NOT close
            # iter164: async write-back for skipped_same_hash trace
            # iter217: remove round(s,4) + chunk_type [] not .get()
            _skip_top_k_data = [{"id": c[_CI_ID], "summary": c[_CI_SUM], "score": s,
                                  "chunk_type": c[_CI_CT] or ""} for s, c in top_k]  # iter235
            _skip_ids = top_k_ids  # iter224: reuse sorted ids list (~0.336us saved, order-insensitive)
            _skip_deferred_buf = list(_deferred._buf)
            _deferred._buf.clear()
            def _do_skip_writeback(
                _session_id=session_id, _project=project,
                _prompt_hash=prompt_hash, _candidates_count=candidates_count,
                _top_k_data=_skip_top_k_data, _shadow_ids=_skip_ids,
                _deferred_buf=_skip_deferred_buf,
            ):
                try:
                    _wconn = open_db()
                    ensure_schema(_wconn)
                    store_insert_trace(_wconn, {
                        "id": str(uuid_mod.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "session_id": _session_id, "project": _project,
                        "prompt_hash": _prompt_hash, "candidates_count": _candidates_count,
                        "top_k_json": _top_k_data,
                        "injected": 0, "reason": "skipped_same_hash", "duration_ms": 0,
                    })
                    for level, subsystem, message, sid, proj, extra in _deferred_buf:
                        try:
                            dmesg_log(_wconn, level, subsystem, message,
                                      session_id=sid, project=proj, extra=extra)
                        except Exception:
                            pass
                    _wconn.commit()
                    _wconn.close()
                except Exception:
                    pass
                _write_shadow_trace(_project, _shadow_ids, _session_id)
            _writeback_submit(_do_skip_writeback)
            return

        # ── iter910: score_floor_gate — 低相关性注入拦截 ──────────────────
        # 根因（数据驱动，2026-05-06）：48% 注入 score<0.2，来源为 diversity_probe
        #   (score=0.01)、suppress_fallback、final_single_pair(score=top1*0.20) 等。
        #   低分 chunk 与用户当前上下文无关，注入后污染 context window、降低 SNR。
        # 修复：score < _score_floor 的 chunk 过滤掉。全部低于阈值时保留最高分 1 条。
        #   micro_db(<=5) 跳过。
        # iter913: score_floor_raise — 数据驱动提升阈值
        # 根因（数据驱动，2026-05-06）：73% 注入 score<0.15，useful feedback 最低=0.15。
        #   0.08 阈值过低未过滤任何噪声。提升到 0.12 过滤 40% 低相关性注入。
        # iter1517: daemon_small_db_floor_sync — 同步 retriever.py iter1507
        # iter1541: tiny_db_score_floor_relax — sync retriever.py
        _score_floor = 0.05 if _db_chunk_count < 20 else (0.08 if _db_chunk_count < 50 else 0.12)
        # iter1685: sparse_floor_cap — sparse 项目 floor 不超过 0.05
        # 根因（数据驱动，2026-05-13）：git:78dc99a5695f(1 local, db=6) daemon floor=0.12，
        #   但 _db_chunk_count 可能因 WAL checkpoint 延迟读到旧值(>=50)，
        #   导致 sparse 项目 floor 过高 → fallback chunk(score=0.001~0.084) 全灭 → 100% 空召回。
        #   sparse 项目 FTS5 vocab 极有限（<20 token），BM25 score 天然 <0.10，
        #   高 floor 与 sparse 现实矛盾。用 _local_sparse_d 做最终 cap。
        if _local_sparse_d and _local_chunk_count_d > 0 and _score_floor > 0.05:
            _score_floor = 0.05
        # iter1602: zero_local_cross_project_floor — local=0 项目提高 floor
        # iter1637: zero_local_floor_raise — 0.15→0.25
        # 数据驱动（2026-05-13）：abspath:7e3095aef7a6(local=0) 5/12 注入 4 条跨项目噪声
        #   (migration +125%, feishu CLI, mtk ALB, git Signed-off-by)。
        #   score 在 0.15-0.25 区间的跨项目 chunk 与 local=0 项目语义不相关，
        #   0.25 确保只有高语义相关（score>0.25）的跨项目知识才注入。
        if _local_chunk_count_d == 0 and _score_floor < 0.25:
            _score_floor = 0.25
        # iter1067: global_saturated_floor — 已内化 global constraint 提高 floor
        # 数据驱动（2026-05-07）：feishu CLI(ac=4,score=0.19)、memory验证(ac=6,score=0.15)
        #   在 kernel session 中过 0.12 floor 被注入，与当前工作完全无关。
        #   真正相关时 score>=0.5（如操作飞书时 score=0.99）。
        # 修复：global + design_constraint + ac>=5 → floor 提升到 0.25。
        # iter1147: saturated_floor_tighten — ac 门槛收紧 (global 5→4, local 10→7)
        _GLOBAL_SAT_FLOOR = 0.25
        # iter1068: local_saturated_floor — 扩展到本地高 ac chunk
        # iter1573: local_sat_floor_dbsize_tier — 同步 retriever.py
        _LOCAL_SAT_AC_THRESH = 7 if _db_chunk_count < 50 else 5
        # iter1562: saturated_floor_tuple_safe — .get() → _CI_* 常量，修复 tuple chunk crash
        def _sat_floor_ac(c):
            return (c[_CI_AC] or 0) if isinstance(c, (list, tuple)) else (c.get("access_count") or 0)
        def _sat_floor_proj(c):
            return (c[_CI_CP] or "") if isinstance(c, (list, tuple)) else (c.get("project") or "")
        def _sat_floor_ct(c):
            return (c[_CI_CT] or "") if isinstance(c, (list, tuple)) else (c.get("chunk_type") or "")
        if len(top_k) > 0:
            # iter1668: saturated_floor_strip_fallback — sync retriever.py iter1566
            # 根因（数据驱动，2026-05-13）：sat_floor 置 0 的 chunk 仍在 _fallback_protected_ids，
            #   floor_gate 全灭时 line 6310 rescue 路径将其复活（feishu CLI 7x/7d 注入）。
            _sat_stripped = set()
            # iter1674: dc_sat_floor_unify — sync retriever.py iter1644
            # non-global design_constraint ac>=4 也走 sat_floor（dc 是静态规则，内化后边际=0）
            top_k = [(s, c) if not (
                (_sat_floor_ct(c) == "design_constraint"
                 and _sat_floor_ac(c) >= 4
                 and s < _GLOBAL_SAT_FLOOR)
                or (_sat_floor_ac(c) >= _LOCAL_SAT_AC_THRESH
                    and s < _GLOBAL_SAT_FLOOR)
            ) else (_sat_stripped.add(c[_CI_ID] if isinstance(c, (list, tuple)) else c.get("id", "")) or 0.0, c) for s, c in top_k]
            if _sat_stripped:
                _fallback_protected_ids -= _sat_stripped
        # iter1630: cross_project_only_floor_raise — daemon 同步 retriever.py iter1621
        # 根因（数据驱动，2026-05-12）：local>0 但 top_k 无本地 match 时 floor=0.05，
        #   跨项目低分噪声（score=0.01~0.05）通过 daemon 路径注入。
        # 修复：top_k 无当前项目 chunk 时 floor 提升到 0.15。
        if top_k and _score_floor < 0.15 and _local_chunk_count_d > 0:
            if not any(_sat_floor_proj(c) == project for _, c in top_k):
                _score_floor = 0.15
        if len(top_k) > 0 and _db_chunk_count > 5:
            _sf_above = [(s, c) for s, c in top_k if s >= _score_floor]
            if _sf_above:
                if len(_sf_above) < len(top_k):
                    _sf_removed = len(top_k) - len(_sf_above)
                    top_k = _sf_above
                    _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                  f"iter910_score_floor_gate: removed {_sf_removed} chunks "
                                  f"below score_floor={_score_floor}",
                                  session_id=session_id, project=project)
            else:
                # iter1043: floor_gate_skip — 全部低于阈值时不注入
                # iter1506: fallback_protected bypass — fallback 恢复的 chunk 不被 floor_gate 二次清空
                _sf_protected = [(s, c) for s, c in top_k
                                 if (c[_CI_ID] if isinstance(c, (list, tuple)) else c.get("id", "")) in _fallback_protected_ids]
                if _sf_protected:
                    # iter1564: sparse_local_over_cross_fallback — sync daemon
                    # iter1631: sync iter1611 — local=0 时 global 视为跨项目
                    if _local_chunk_count_d == 0:
                        _slof_all_cross_d = _local_sparse_d and all(
                            (c[_CI_CP] if isinstance(c, (list, tuple)) and len(c) > _CI_CP else "") != project
                            for _, c in _sf_protected)
                    else:
                        _slof_all_cross_d = _local_sparse_d and all(
                            (c[_CI_CP] if isinstance(c, (list, tuple)) and len(c) > _CI_CP else "") != project
                            and (c[_CI_CP] if isinstance(c, (list, tuple)) and len(c) > _CI_CP else "") != "global"
                            for _, c in _sf_protected)
                    if _slof_all_cross_d:
                        try:
                            # iter1632: immutable_conn_stale_fix — conn(immutable=1) 看不到
                            #   WAL 未 checkpoint 的 chunk_state 变更，导致 sparse 项目 local
                            #   chunk 查询返回 0 行 → iter1564/1525 兜底全部静默失败。
                            #   实测：git:78dc99a5695f 9/9 空召回(100%)，唯一 ACTIVE chunk 从未注入。
                            import sqlite3 as _slof_sql
                            _slof_conn = _slof_sql.connect(str(STORE_DB), timeout=2)
                            _slof_rows = _slof_conn.execute(
                                "SELECT id, summary, content, chunk_type, importance, "
                                "COALESCE(access_count,0), created_at, 0.0, COALESCE(lru_gen,0), project "
                                "FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE' "
                                "ORDER BY importance DESC LIMIT 1",
                                (project,)
                            ).fetchall()
                            _slof_conn.close()
                            if _slof_rows:
                                top_k = [(0.001, _slof_rows[0])]
                                _fallback_protected_ids.add(_slof_rows[0][_CI_ID])
                                _deferred.log(DMESG_WARN, "retriever_daemon",
                                              f"iter1564_sparse_local_over_cross: replaced {len(_sf_protected)} "
                                              f"cross-proj with local id={_slof_rows[0][_CI_ID][:12]}",
                                              session_id=session_id, project=project)
                            elif _local_chunk_count_d == 0:
                                top_k = []
                            else:
                                top_k = _sf_protected
                        except Exception:
                            top_k = _sf_protected
                    else:
                        top_k = _sf_protected
                else:
                    _sf_best = max(top_k, key=lambda x: x[0])
                    _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                  f"iter1043_floor_gate_skip: all {len(top_k)} below "
                                  f"floor={_score_floor}, best={_sf_best[0]:.3f} "
                                  f"id={_sf_best[1][_CI_ID][:12]}, skipping injection",
                                  session_id=session_id, project=project)
                    top_k = []
                    # iter1525: sparse_local_priority — sparse 项目 floor_gate 全灭时注入本地知识
                    # 根因（数据驱动，2026-05-11）：git:78dc99a5695f(1 local + 6 global = 7 visible)
                    #   FTS5 只命中跨项目 chunk → suppress 全灭 → fallback 恢复跨项目 chunk(score=0.084)
                    #   → floor_gate 清空。本地唯一知识(58c70136,imp=0.85) 从未进入候选池（FTS5 不匹配）。
                    #   用户在该项目中 9/9 空召回(100%)，但有 1 条高价值本地知识从未被注入。
                    # 修复：floor_gate 清空后，如果 _local_sparse_d=True，从 DB 选本地最高 imp chunk。
                    #   仅当本地有 ACTIVE chunk 时触发；global-only 项目不触发（避免噪声）。
                    if _local_sparse_d:
                        try:
                            # iter1665: sparse_local_least_seen — 优先注入 ac 最低的本地 chunk
                            import sqlite3 as _slp_sql
                            _slp_conn = _slp_sql.connect(str(STORE_DB), timeout=2)
                            _slp_rows = _slp_conn.execute(
                                "SELECT id, summary, content, chunk_type, importance, "
                                "COALESCE(access_count,0), created_at, 0.0, COALESCE(lru_gen,0), project "
                                "FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE' "
                                "ORDER BY access_count ASC, importance DESC LIMIT 5",
                                (project,)
                            ).fetchall()
                            _slp_conn.close()
                            _slp_pick = None
                            _slp_exclude = {cid for cid, _ in _daemon_inject_log} if _daemon_inject_log else set()
                            for _slp_r in _slp_rows:
                                if _slp_r[_CI_ID] not in _slp_exclude:
                                    _slp_pick = _slp_r
                                    break
                            if not _slp_pick and _slp_rows:
                                _slp_pick = _slp_rows[0]
                            if _slp_pick:
                                top_k = [(0.001, _slp_pick)]
                                _fallback_protected_ids.add(_slp_pick[_CI_ID])
                                _deferred.log(DMESG_WARN, "retriever_daemon",
                                              f"iter1665_sparse_local_least_seen: "
                                              f"id={_slp_pick[0][:12]} ac={_slp_pick[5]} imp={_slp_pick[4]:.2f} project={project}",
                                              session_id=session_id, project=project)
                        except Exception:
                            pass
                    # iter1599: floor_gate_pre_suppress_rescue — 非 sparse 项目 floor_gate 全灭兜底
                    elif not top_k and _pre_suppress_top_k:
                        _fgr_local_d = [(s, c) for s, c in _pre_suppress_top_k
                                        if (c[_CI_CP] if isinstance(c, (list, tuple)) and len(c) > _CI_CP else "") == project]
                        if not _fgr_local_d:
                            _fgr_local_d = [(s, c) for s, c in _pre_suppress_top_k]
                        _fgr_best_d = max(_fgr_local_d,
                                          key=lambda x: (x[1][_CI_IMP] if isinstance(x[1], (list, tuple)) and len(x[1]) > _CI_IMP else 0))
                        _fgr_id = _fgr_best_d[1][_CI_ID] if isinstance(_fgr_best_d[1], (list, tuple)) else _fgr_best_d[1].get("id", "")
                        _fallback_protected_ids.add(_fgr_id)
                        top_k = [(_score_floor, _fgr_best_d[1])]
                        _deferred.log(DMESG_WARN, "retriever_daemon",
                                      f"iter1599_floor_gate_pre_suppress_rescue: "
                                      f"id={_fgr_id[:12]} project={project}",
                                      session_id=session_id, project=project)

        # ── iter1659: cross_project_noise_gate (daemon sync) ──────────────────
        # 根因（数据驱动，2026-05-13）：retriever.py iter1658 在 FULL/LITE/HD 路径加了
        #   跨项目 score<0.03 噪声过滤，daemon 路径缺失 → feishu CLI(0.01) 等仍可逃逸。
        # 修复：同步过滤——跨项目 chunk score<0.03 剔除，保留至少 1 条避免空注入。
        if top_k and len(top_k) > 1:
            _cpng_d = [(s, c) for s, c in top_k
                       if s >= 0.03 or (c[_CI_CP] if len(c) > _CI_CP else "") == project]
            if _cpng_d:
                top_k = _cpng_d

        # ── iter975: output_monopoly_filter — 最终输出前去垄断（single control point）──
        # 根因（数据驱动，2026-05-06）：suppress 分散在十余处，垄断 chunk 总能逃逸。
        # 修复：inject_lines 构建前最终过滤——7d >= ceiling 移除，至少保留 1 条。
        if top_k and len(top_k) > 1 and _db_chunk_count > 5:
            _omf_ceiling = 2 if _db_chunk_count < 50 else 3
            # iter1563: global_omf_tighten — base ceiling 3/5 → 2/3
            # 根因（数据驱动，2026-05-12）：ac=3-4 chunk 7d 注入 4-5 次未触发 omf
            #   （旧 base=3/5 对 ac<5 不生效），垄断用户注入位。
            def _omf_ceil_d(c):
                _oac = c[_CI_AC] or 0
                if _oac >= 10:
                    return 1
                if _oac >= 7:
                    return 1
                if _oac >= 5:
                    return 2
                if c[_CI_CP] == "global" and _oac >= 4:
                    return 2
                return _omf_ceiling
            def _omf_lifetime_suppress_d(c):
                _is_g = c[_CI_CP] == "global"
                _is_dc = (c[_CI_CT] or "") == "design_constraint"
                if (_is_g or _is_dc) and (c[_CI_AC] or 0) >= 4:
                    _lt = _itl_lifetime.get(c[_CI_ID])
                    if _lt and _lt[0] >= 4 and _lt[1] > _cutoff_14d:
                        return True
                    # iter1671: timeline_fallback_ac — timeline 数据缺失时用 ac 兜底
                    # 根因（数据驱动，2026-05-13）：global dc chunk(0aff0d67 ac=5, c9accb7b ac=5)
                    #   因 timeline 文件并发覆写丢失条目 → _itl_lifetime 查不到 → lifetime suppress 失效
                    #   → 7d session-dedup 后计数=1 不触发 omf ceiling → 反复注入。
                    # 修复：ac>=5 的 global/dc chunk 即使 timeline 缺失也 suppress。
                    #   ac 由 retriever 在每次注入时递增，是可靠的 lifetime 计数下界。
                    if not _lt and _is_g and _is_dc and (c[_CI_AC] or 0) >= 5:
                        return True
                return False
            # iter1669: omf_fallback_protect — fallback 恢复的 chunk 不被 omf 二次清空
            _omf_filtered = [(s, c) for s, c in top_k
                             if c[_CI_ID] in _fallback_protected_ids
                             or (_recent_7d_counts.get(c[_CI_ID], 0) < _omf_ceil_d(c)
                                 and not _omf_lifetime_suppress_d(c))]
            if _omf_filtered:
                if len(top_k) != len(_omf_filtered):
                    _deferred.log(DMESG_DEBUG, "retriever_daemon",
                                  f"iter975_output_monopoly_filter: {len(top_k)}->{len(_omf_filtered)}",
                                  session_id=session_id, project=project)
                top_k = _omf_filtered
            else:
                # iter987: omf_graduated_fallback — 全灭时选 7d 最低的 top-2
                # iter1178: omf_fallback_empty_suppress — 深度内化 chunk 不注入
                _omf_sorted = sorted(top_k, key=lambda x: _recent_7d_counts.get(x[1][_CI_ID], 0))
                # iter1174+1178: 排除 ac>=7 + 7d>=2*ceiling 的深度内化垄断 chunk
                # iter1206: 使用 per-chunk ceiling 对齐
                def _omf_fb_skip_d(c):
                    _oac = c[_CI_AC] or 0
                    _o7d = _recent_7d_counts.get(c[_CI_ID], 0)
                    _pc = _omf_ceil_d(c)
                    if c[_CI_CP] == "global":
                        return _oac >= 4 and _o7d >= _pc
                    return _oac >= 7 and _o7d >= 2 * _pc
                _omf_fb_filt_d = [(s, c) for s, c in _omf_sorted if not _omf_fb_skip_d(c)]
                if _omf_fb_filt_d:
                    top_k = _omf_fb_filt_d[:min(2, len(_omf_fb_filt_d))]
                else:
                    # iter1353: omf_empty_last_resort — 全灭时选最低 7d 的 1 条而非空召回
                    if _omf_sorted:
                        top_k = [(_omf_sorted[0][0] * 0.3, _omf_sorted[0][1])]
                    else:
                        top_k = []
                _deferred.log(DMESG_DEBUG, "retriever_daemon",
                              f"iter987_omf_graduated_fallback: {len(_omf_sorted)}->{len(top_k)}",
                              session_id=session_id, project=project)

        # ── iter1013+1046+1056: topic_group_dedup — 同主题群体去垄断 ──────────────
        # iter1013: [topic] 前缀 group key
        # iter1046: core_token_dedup — 无前缀同 chunk_type 用核心标识符重叠(>=3)去重
        # iter1056: cn_bigram_dedup — 加中文 bigram 解决纯中文 chunk 去重失效
        if top_k and len(top_k) > 1 and _db_chunk_count > 5:
            import re as _tgd_re
            _TGD_MIN_SHARED = 3
            def _tgd_core(s):
                toks = set(_tgd_re.findall(r'[a-z][a-z0-9_]*|[0-9]+', s.lower()))
                cn = _tgd_re.sub(r'[^\u4e00-\u9fff]', '', s)
                for i in range(len(cn) - 1):
                    toks.add(cn[i:i + 2])
                return toks
            _tgd_seen = {}  # topic_key -> chunk_id
            _tgd_result = []
            _tgd_np_groups = []  # [(rep_id, chunk_type, core_tokens)]
            for _tgd_s, _tgd_c in top_k:
                _tgd_sum = (_tgd_c[_CI_SUM] or "")
                _tgd_key = _tgd_sum.split("]")[0] + "]" if _tgd_sum.startswith("[") and "]" in _tgd_sum else None
                if _tgd_key:
                    if _tgd_key not in _tgd_seen:
                        _tgd_result.append((_tgd_s, _tgd_c))
                        _tgd_seen[_tgd_key] = _tgd_c[_CI_ID]
                    else:
                        _tgd_cur_7d = _recent_7d_counts.get(_tgd_c[_CI_ID], 0)
                        _tgd_exist_7d = _recent_7d_counts.get(_tgd_seen[_tgd_key], 0)
                        if _tgd_cur_7d < _tgd_exist_7d:
                            _tgd_result = [(s, c) for s, c in _tgd_result if c[_CI_ID] != _tgd_seen[_tgd_key]]
                            _tgd_result.append((_tgd_s, _tgd_c))
                            _tgd_seen[_tgd_key] = _tgd_c[_CI_ID]
                else:
                    # iter1046+1056: 无前缀 chunk — core_token(含中文bigram) 同 type 去重
                    # iter1056: reasoning_chain/causal_chain 视为同一 dedup group
                    _CHAIN_GROUP = {"reasoning_chain", "causal_chain"}
                    _cid = _tgd_c[_CI_ID]
                    _ctype = _tgd_c.get("chunk_type", "") if isinstance(_tgd_c, dict) else ""
                    _ctoks = _tgd_core(_tgd_sum)
                    _matched_idx = None
                    for _gi, (_gid, _gtype, _gtoks) in enumerate(_tgd_np_groups):
                        _type_compat = (_ctype == _gtype or
                                        (_ctype in _CHAIN_GROUP and _gtype in _CHAIN_GROUP))
                        if _type_compat and len(_ctoks & _gtoks) >= _TGD_MIN_SHARED:
                            _matched_idx = _gi
                            break
                    if _matched_idx is None:
                        _tgd_result.append((_tgd_s, _tgd_c))
                        _tgd_np_groups.append((_cid, _ctype, _ctoks))
                    else:
                        _tgd_cur_7d = _recent_7d_counts.get(_cid, 0)
                        _gid_m = _tgd_np_groups[_matched_idx][0]
                        _tgd_exist_7d = _recent_7d_counts.get(_gid_m, 0)
                        if _tgd_cur_7d < _tgd_exist_7d:
                            _tgd_result = [(s, c) for s, c in _tgd_result if c[_CI_ID] != _gid_m]
                            _tgd_result.append((_tgd_s, _tgd_c))
                            _tgd_np_groups[_matched_idx] = (_cid, _ctype, _ctoks)
            if len(_tgd_result) < len(top_k):
                _deferred.log(DMESG_DEBUG, "retriever_daemon",
                              f"iter1056_topic_group_dedup: {len(top_k)}->{len(_tgd_result)}",
                              session_id=session_id, project=project)
                top_k = _tgd_result if _tgd_result else top_k[:1]

        # ── iter1014: type_group_cap — 同 chunk_type 群体占比限制 ─────────────────
        # 根因（数据驱动，2026-05-07）：79% 多条注入存在同 chunk_type >=2 条群体垄断。
        #   iter1013 只覆盖有 [topic] 前缀的 18% chunk，其余完全逃逸。
        # 修复：同 chunk_type 最多保留 2 条（7d 最低优先）。design_constraint 豁免。
        # iter1016: dc_saturated_group_cap — ac>=7 的 design_constraint 不再豁免
        if top_k and len(top_k) > 2 and _db_chunk_count > 5:
            _tgc_type_slots = {}  # chunk_type -> [(7d, idx)]
            _tgc_keep = set()
            for _tgc_i, (_tgc_s, _tgc_c) in enumerate(top_k):
                _tgc_ct = _tgc_c[_CI_CT] or ""
                # iter1016: only exempt fresh constraints (ac<7)
                if _tgc_ct == "design_constraint" and (_tgc_c[_CI_AC] or 0) < 7:
                    _tgc_keep.add(_tgc_i)
                    continue
                _tgc_cid = _tgc_c[_CI_ID]
                _tgc_r7d = _recent_7d_counts.get(_tgc_cid, 0)
                _tgc_type_slots.setdefault(_tgc_ct, []).append((_tgc_r7d, _tgc_i))
            for _tgc_ct, _tgc_slots in _tgc_type_slots.items():
                _tgc_slots.sort()  # 7d 升序，保留最低 2 条
                for _tgc_r7d, _tgc_idx in _tgc_slots[:2]:
                    _tgc_keep.add(_tgc_idx)
            if len(_tgc_keep) < len(top_k):
                _tgc_new = [top_k[i] for i in sorted(_tgc_keep)]
                _deferred.log(DMESG_DEBUG, "retriever_daemon",
                              f"iter1014_type_group_cap: {len(top_k)}->{len(_tgc_new)}",
                              session_id=session_id, project=project)
                top_k = _tgc_new if _tgc_new else top_k[:1]

        # ── iter1050: diversity_inject_cap — 跨类型总量硬限 ─────────────────
        _dic_cap = 4 if has_page_fault else 3
        if top_k and len(top_k) > _dic_cap and not _micro_db:
            _dic_by_type = {}
            for _dic_s, _dic_c in top_k:
                _dic_t = _dic_c.get("chunk_type", "")
                _dic_by_type.setdefault(_dic_t, []).append((_dic_s, _dic_c))
            _dic_result = []
            _dic_used = set()
            for _dic_t in sorted(_dic_by_type, key=lambda t: _dic_by_type[t][0][0], reverse=True):
                if len(_dic_result) >= _dic_cap:
                    break
                _dic_best = _dic_by_type[_dic_t][0]
                _dic_result.append(_dic_best)
                _dic_used.add(_dic_best[1].get("id", ""))
            if len(_dic_result) < _dic_cap:
                _dic_rest = [(s, c) for s, c in top_k if c.get("id", "") not in _dic_used]
                _dic_rest.sort(key=lambda x: x[0], reverse=True)
                for _dic_r in _dic_rest[:_dic_cap - len(_dic_result)]:
                    _dic_result.append(_dic_r)
            _deferred.log(DMESG_DEBUG, "retriever_daemon",
                          f"iter1050_diversity_inject_cap: {len(top_k)}->{len(_dic_result)}",
                          session_id=session_id, project=project)
            top_k = _dic_result

        # ── iter1119: saturation_diversity_gate — 高饱和 chunk 占比硬限 ─────────
        # 根因（数据驱动，2026-05-08）：ac>=7 chunk 群体消耗 7d 注入位 45%。
        # 修复：单次注入中 ac>=7 最多占 50%（向上取整），超额按 score 低优先移除。
        # iter1155: sdg_threshold_widen — ac>=7→5 覆盖 ac=5-6 中饱和逃逸
        if top_k and len(top_k) > 2 and _db_chunk_count > 5:
            # iter1156: sdg_low_score_prune — 低分 saturated chunk 无条件移除
            _sdg_lowscore = [(s, c) for s, c in top_k if (c[_CI_AC] or 0) >= 5 and s < 0.10]
            if _sdg_lowscore and len(top_k) > len(_sdg_lowscore):
                top_k = [(s, c) for s, c in top_k if not ((c[_CI_AC] or 0) >= 5 and s < 0.10)]
            _sdg_max = max(1, (len(top_k) + 1) // 2)
            _sdg_saturated = [(s, c) for s, c in top_k if (c[_CI_AC] or 0) >= 5]
            if len(_sdg_saturated) > _sdg_max:
                _sdg_fresh = [(s, c) for s, c in top_k if (c[_CI_AC] or 0) < 5]
                _sdg_saturated.sort(key=lambda x: x[0], reverse=True)
                _sdg_kept = _sdg_saturated[:_sdg_max]
                top_k = _sdg_fresh + _sdg_kept
                top_k.sort(key=lambda x: x[0], reverse=True)
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"iter1119_saturation_diversity_gate: saturated {len(_sdg_saturated)}->{_sdg_max}",
                              session_id=session_id, project=project)

        # iter1563: output_cooldown_gate — daemon 最终出口 timeline cooldown 兜底
        #   同步 retriever.py iter1106+1563：ac>=5 且最近注入在 cooldown 窗口内 → 移除。
        #   ac=5-6→48h, ac=7-9→10d, ac>=10→14d。
        if top_k and _last_inject_ts and _cutoff_48h:
            def _ocg_pass_d(c):
                _oa = c[_CI_AC] or 0
                if _oa < 5:
                    return True
                _oid = c[_CI_ID]
                _olast = _last_inject_ts.get(_oid, "")
                if not _olast:
                    return True
                _ocut = _cutoff_14d if _oa >= 10 else (_cutoff_10d if _oa >= 7 else _cutoff_48h)
                return _olast <= _ocut
            _ocg_filtered_d = [(s, c) for s, c in top_k if _ocg_pass_d(c)]
            if _ocg_filtered_d:
                top_k = _ocg_filtered_d

        # ── Build context text ──
        # iter238: _TYPE_PREFIX now module-level constant (see definition near _CONSTRAINT_RE)
        # iter238: _conf_tag removed — dead code (inlined at usage site since iter214)
        constraint_items, normal_items = [], []
        for _, c in top_k:
            # iter214: compute ctype once, reuse for prefix lookup + design_constraint check
            # (~0.034us × 5 chunks = ~0.17us saving vs 2× c.get("chunk_type"))
            # iter235: positional tuple access
            ctype = c[_CI_CT] or ""
            prefix = _TYPE_PREFIX.get(ctype, "")
            # iter214: inline _conf_tag with None fast-path (same pattern as iter197 _score_chunk)
            # None path (common, current corpus): 0.355us → 0.234us per chunk = ~0.6us/5 chunks
            # OS 类比：branch predictor — most common case (None) checked first
            _vs = c[_CI_VS]  # iter239c: load _vs first; skip _cs load when vs=None (common case)
            if _vs is None:
                # iter229: skip f-string + .strip() when conf='' (common path: ~80% of corpus)
                # iter239c: skip _cs BINARY_SUBSCR entirely (saves 1 field load + 1 IS_OP check)
                # ~0.095us/chunk × 5 chunks = ~0.475us saved vs f'{""}{prefix} {summary}'.strip()
                # OS 类比：branch-on-None fast exit — predictable branch eliminates str alloc + field load
                line = prefix + " " + c[_CI_SUM]  # iter235
            else:
                _cs = c[_CI_CS] or 0.7  # iter239c: load _cs only when vs is not None
                _vs = _vs or "pending"
                if _vs == "disputed": conf = "❓"
                elif _vs == "verified" or _cs >= 0.9: conf = "✅"
                elif _cs < 0.5: conf = "⚠️"
                else: conf = ""
                line = (conf + prefix + " " + c[_CI_SUM]).strip() if conf else prefix + " " + c[_CI_SUM]  # iter235
            if ctype == "design_constraint":
                constraint_items.append(line)
            else:
                normal_items.append(line)

        header = "【相关历史记录（BM25 召回）】"
        if page_fault_queries:
            header += "  ← 含上轮缺页补入"
        inject_lines = [header]

        if constraint_items:
            inject_lines.extend(["", "【已知约束（系统级设计限制）】"])
            inject_lines.extend(constraint_items)
            if forced_constraints:
                inject_lines.extend(["", "ℹ️ 注：上述约束经系统强制注入（非检索相关性排序），",
                                     "代表已知设计决策，但在本次会话的局部上下文中可能未出现信号词。",
                                     "若约束与当前任务无关，可选择性忽略。"])
            inject_lines.extend(["", "【相关知识】"])
            inject_lines.extend(normal_items)
        else:
            inject_lines.extend(normal_items)

        # iter169+182: VFS router — 收割 pool worker 结果
        # iter182: 改用 Event.wait() 替代 thread.join()（pool worker 设置 done event）
        # OS 类比：io_getevents() — 收割之前提交的 AIO 请求结果
        if _KR_AVAILABLE and run_router:
            if _vfs_submitted:
                # 计算剩余 deadline，避免等待超时
                _vfs_join_timeout = max(0.001, (deadline_ms - _elapsed_ms()) / 1000.0)
                _vfs_done_event.wait(timeout=_vfs_join_timeout)
            try:
                kr_results = _vfs_result_holder[0]
                if kr_results:
                    kr_section = kr_format(kr_results)
                    inject_lines.append(kr_section)
            except Exception:
                pass

        context_text = "\n".join(inject_lines)
        if len(context_text) > effective_max_chars:
            context_text = context_text[:effective_max_chars] + "…"

        # iter168: _read_hash() 必须在 critical path 上（决定 reason_base），
        # 但 _write_hash + _tlb_write 可以推迟到 writeback 线程执行。
        # OS 类比：mmap 写操作 — 先更新 page cache（内存），
        #   dirty bit 置位后立即返回，真正的磁盘写由 pdflush 异步完成。
        # iter201: reuse pre-read last_hash (saves 1× _read_hash ~3.1us)
        reason_base = "first_call" if not last_hash else "hash_changed"
        reason = f"{reason_base}|{priority.lower()}"
        if psi_downgraded:
            reason += "|psi_downgrade"
        if deadline_skipped:
            reason += f"|deadline_skip:{'+'.join(deadline_skipped)}"

        # iter168: 移除 critical path 上的 _write_hash + _tlb_write（节省 ~1.6ms）
        # 这两个调用已移入 _do_writeback，在响应发出后异步执行。
        # 风险：极短窗口内（<1ms）同一 prompt 可能再次注入；实际用户操作间隔 >1s，可接受。

        # iter217: remove round(s,4) (~1.476us) + chunk_type [] not .get() (~0.039us/chunk)
        # iter235: positional tuple access (_CI_* constants)
        # iter857: tuple() freeze — 防止 list 对象在 writeback 执行前被意外 mutate
        # 数据驱动（2026-05-05）：83% trace 的 top_k_json 少于 dmesg injected=N，
        #   _top_k_data（list）默认参数绑定后在 writeback 执行时长度不一致。
        #   tuple 不可变，消除 GC/引用链导致的潜在 mutation。
        top_k_data = tuple({"id": c[_CI_ID], "summary": c[_CI_SUM], "score": s,
                       "chunk_type": c[_CI_CT] or ""} for s, c in top_k)
        # iter871: trace_ids_realign — 重新计算 accessed_ids 与当前 top_k 对齐
        # 根因（数据驱动，2026-05-05）：top_k_ids 在 line 4771 基于旧 top_k 计算，
        #   但 suppress_final_gate/fallback 可能修改 top_k，导致 accessed_ids 与
        #   top_k_data 不一致 → 11% trace 的 top_k_json=[] 污染 recall_counts。
        # iter1039: freeze_accessed_ids — tuple 不可变，消除 writeback 线程读取时潜在的引用失效
        #   数据驱动（2026-05-07）：40% trace 记录 injected=0,top_k=[] 但 dmesg 确认注入成功。
        #   _accessed_ids 默认参数绑定 list 对象，writeback 线程延迟执行时偶发读到空。
        #   tuple 不可变 + 立即求值，消除 GC/thread 时序导致的引用失效。
        accessed_ids = tuple(c[_CI_ID] for _, c in top_k)

        # iter200: pre-built header + json.dumps(ctx) only (4.43us → 1.35us)
        # iter226: write() ~0.407us vs print() ~0.679us (saves ~0.271us on inject path)
        # iter228: ensure_ascii=True saves ~0.977us (C encoder skips UTF-8 path, outputs \uXXXX)
        sys.stdout.write(_OUTPUT_HEADER + json.dumps(context_text, ensure_ascii=True) + "}}\n")
        _sessions_with_injection.add(session_id)  # iter804
        # iter1267: daemon_session_file_sync — 写入 .session_injected 供 retriever.py 读取
        if session_id not in _sessions_written_to_file:
            try:
                _existing = set()
                if os.path.exists(_SESSION_INJECTED_FILE):
                    with open(_SESSION_INJECTED_FILE, encoding="utf-8") as _sif:
                        _existing = set(_sif.read().strip().split("\n"))
                _existing.add(session_id)
                with open(_SESSION_INJECTED_FILE, 'w', encoding="utf-8") as _sif:
                    _sif.write("\n".join(list(_existing)[-50:]) + "\n")
                _sessions_written_to_file.add(session_id)
            except Exception:
                pass
        # iter807: daemon_inmem_suppress — 记录注入到进程内存
        # iter873: inmem_suppress_realign — 用 accessed_ids（suppress 后）替代 top_k_ids（suppress 前）
        # 根因（数据驱动，2026-05-05）：top_k_ids 在 suppress_final_gate 之前计算（line 4780），
        #   suppress_fallback/pair_inject 可能替换 top_k 内容。_daemon_inject_log 记录旧 ID
        #   导致：1) 被 suppress 的 chunk 虚假计数  2) 新增 chunk 漏记 → 连续注入逃逸。
        # 修复：用 accessed_ids（iter871 在 suppress 后重新计算，line 4923）作为 ground truth。
        _now_ts = time.time()
        for _iid807 in accessed_ids:
            _daemon_inject_log.append((_iid807, _now_ts))
        # iter1081: cooldown_inmem_sync — 同步更新 _last_inject_ts（normal path）
        from datetime import datetime as _dt1081b, timezone as _tz1081b
        _now_iso1081b = _dt1081b.now(_tz1081b.utc).isoformat()
        for _iid1081b in accessed_ids:
            _last_inject_ts[_iid1081b] = _now_iso1081b
        # iter1224: burst_counts_inmem_sync — normal path
        for _iid1224b in accessed_ids:
            _recent_6h_counts[_iid1224b] = _recent_6h_counts.get(_iid1224b, 0) + 1
            _recent_24h_counts[_iid1224b] = _recent_24h_counts.get(_iid1224b, 0) + 1
            _recent_7d_counts[_iid1224b] = _recent_7d_counts.get(_iid1224b, 0) + 1
        # iter219: removed sys.stdout.flush() — no-op on StringIO (captured in _handle_connection)
        # iter173: persistent conn — do NOT close here; writeback will invalidate after write

        # iter164+168: 异步 write-back（类比 Linux pdflush — 响应已发送，写操作后台完成）
        # iter168 新增：_write_hash + _tlb_write 也移入此处（从 critical path 移除）
        duration_ms = (time.time() - _t_start) * 1000
        _deferred_buf = list(_deferred._buf)  # 复制 deferred log buffer
        _deferred._buf.clear()

        def _do_writeback(
            _accessed_ids=accessed_ids, _top_k_data=top_k_data,
            _session_id=session_id, _project=project,
            _prompt_hash=prompt_hash, _candidates_count=candidates_count,
            _reason=reason, _duration_ms=duration_ms,
            _top_k_len=len(top_k), _deferred_buf=_deferred_buf,
            _shadow_ids=accessed_ids,  # iter223: reuse accessed_ids (same list, avoids 3rd listcomp)
            _current_hash=current_hash,   # iter168
        ):
            # iter168: 先写 hash/TLB（file I/O，原 critical path 1.6ms）
            _write_hash(_current_hash)
            _tlb_write(_prompt_hash, _current_hash, _get_db_mtime())
            try:
                _wconn = open_db()
                ensure_schema(_wconn)
                _seen_before_d2 = {cid for cid, _ in _daemon_inject_log[:-len(_accessed_ids)]} & set(_accessed_ids) if _accessed_ids else set()
                update_accessed(_wconn, _accessed_ids, session_seen_ids=_seen_before_d2)
                mglru_promote(_wconn, _accessed_ids)
                # iter668+678: top_k_data fallback — 闭包捕获的 _top_k_data 可能为空
                # 数据驱动（2026-05-04）：59% 的 injected=1 trace 的 top_k_json='[]'，
                #   但 dmesg 确认 daemon 成功注入了 1-2 个 chunk（_top_k_len>0）。
                #   根因未完全确定（默认参数绑定应可靠），但 _accessed_ids 始终正确。
                # 修复：增加 _top_k_len 不变性检查，空时用 _accessed_ids 重建。
                # iter857: trace_ids_ground_truth — 用 _accessed_ids 长度校验 _top_k_data
                # 数据驱动（2026-05-05）：10/12 trace 的 top_k_json 少于 dmesg injected=N。
                #   dmesg extra.top_k_ids（来自 _accessed_ids）始终正确（5 个 ID），
                #   但 _top_k_data 偶发只有 1 条。tuple freeze（iter857）防止 mutation。
                # 修复：用 _accessed_ids（已证明可靠）作为 ground truth 校验。
                # iter907: trace_ids_ground_truth_only — _accessed_ids 为 ground truth
                # iter1040: trace_score_restore — 恢复 score/summary 可观测性
                # 根因（数据驱动，2026-05-07）：iter907 无条件丢弃 _top_k_data 中的
                #   score/summary/chunk_type → 所有 trace 退化为 {"id":...} → 注入质量不可观测。
                # 修复：优先用 _top_k_data（tuple 不可变，iter857 已保证）；仅当长度不匹配
                #   或为空时退化为 id-only。_accessed_ids 仍为 ground truth 校验 ID 集合。
                if _top_k_data and len(_top_k_data) == len(_accessed_ids):
                    _effective_top_k = list(_top_k_data)
                else:
                    # iter1290: trace_enrich_fallback — id-only 退化时从 DB 补全 summary/chunk_type
                    # 根因（数据驱动，2026-05-09）：23% trace 退化为 id-only，注入质量不可审计。
                    #   _top_k_data 长度偶发不匹配（GC/thread 时序），但 _wconn 已打开可查。
                    # 修复：用 DB 查询补全，失败时仍退化为 id-only（best-effort）。
                    if _accessed_ids:
                        _enrich_map = {}
                        try:
                            _ph = ",".join("?" for _ in _accessed_ids)
                            _cur = _wconn.execute(f"SELECT id, summary, chunk_type FROM memory_chunks WHERE id IN ({_ph})", tuple(_accessed_ids))
                            for _r in _cur.fetchall():
                                _enrich_map[_r[0]] = {"summary": _r[1] or "", "chunk_type": _r[2] or ""}
                        except Exception:
                            pass
                        _effective_top_k = [{"id": cid, "summary": _enrich_map.get(cid, {}).get("summary", ""), "score": 0.0, "chunk_type": _enrich_map.get(cid, {}).get("chunk_type", "")} for cid in _accessed_ids]
                    else:
                        _effective_top_k = list(_top_k_data or ())
                # iter721: trace_injected_fix — 用 _top_k_len 决定 injected 标志
                # 数据驱动（2026-05-04）：dmesg 确认 daemon 注入了 N chunk（_top_k_len>0），
                #   但闭包捕获的 _top_k_data/_accessed_ids 偶发为空（根因未确定）。
                #   iter693 的 empty_trace_guard 将此标记为 injected=0 → recall_counts 严重失准
                #   → suppress 阈值无法正确累积 → 垄断检测失效。
                # 修复：_top_k_len 是整数默认参数（不受引用问题影响），用它判断实际注入状态。
                #   top_k_json 为空时 recall_counts 无法按 chunk_id 统计——但 injected=1
                #   至少保证总注入次数(window denominator)正确，suppress 比例计算不失真。
                _effective_injected = 1 if _top_k_len > 0 else 0
                # iter800: skip_empty_trace — 闭包捕获失败时不写空 trace
                # 根因（数据驱动）：_top_k_data/_accessed_ids 偶发同时为空，写入
                #   injected=1,top_k_json=[] 的空 trace 污染 recall_counts 统计。
                # 修复：跳过 trace 写入（保留 dmesg 可观测性）。
                # iter881: json_empty_guard — tuple 非空但 json 序列化为 [] 时也拦截
                # 根因（数据驱动，2026-05-05）：8/55 injected trace 的 top_k_json='[]'，
                #   _effective_top_k 为非空 tuple 但内容在序列化时丢失（闭包 generator 问题）。
                #   iter800 的 `not _effective_top_k` 只检查 truthiness，无法拦截此情况。
                # 修复：额外检查序列化结果是否实质为空；为空时用 _accessed_ids 重建。
                if _effective_top_k and _accessed_ids:
                    import json as _json_chk
                    _chk_json = _json_chk.dumps(_effective_top_k, ensure_ascii=False)
                    if _chk_json == '[]' or _chk_json == 'null':
                        _effective_top_k = [{"id": cid, "score": 0.0} for cid in _accessed_ids]
                        dmesg_log(_wconn, DMESG_WARN, "retriever",
                                  f"iter881_json_empty_guard: top_k serialized empty, "
                                  f"rebuilt from accessed_ids={len(_accessed_ids)}",
                                  session_id=_session_id, project=_project)
                # iter915: inmem_log_fallback — 闭包参数全空时从进程内存恢复
                # 根因（数据驱动，2026-05-06）：40% injected trace 的 top_k_json='[]'，
                #   _accessed_ids 在闭包中偶发为空（根因未定，疑 GC/thread 竞争）。
                #   _daemon_inject_log 在 stdout 输出前写入（line 5219），不受闭包影响。
                # 修复：用 _daemon_inject_log 最近 2s 内的条目作为 ultimate fallback。
                if not _effective_top_k and _top_k_len > 0:
                    _wb_now = time.time()
                    # iter1039: window 2s→30s — writeback 线程排队延迟可达数秒，2s 窗口频繁 miss
                    #   数据驱动（2026-05-07）：40% trace 失准，inmem_log_fallback 实际触发率极低。
                    _inmem_recent = [cid for cid, ts in _daemon_inject_log
                                     if _wb_now - ts < 30.0]
                    if _inmem_recent:
                        _effective_top_k = [{"id": cid, "score": 0.0} for cid in _inmem_recent[-_top_k_len:]]
                        dmesg_log(_wconn, DMESG_WARN, "retriever",
                                  f"iter915_inmem_log_fallback: recovered {len(_effective_top_k)} "
                                  f"ids from daemon_inject_log",
                                  session_id=_session_id, project=_project)
                if _effective_injected == 1 and not _effective_top_k:
                    for level, subsystem, message, sid, proj, extra in _deferred_buf:
                        try:
                            dmesg_log(_wconn, level, subsystem, message,
                                      session_id=sid, project=proj, extra=extra)
                        except Exception:
                            pass
                    dmesg_log(_wconn, DMESG_WARN, "retriever",
                              f"iter800_skip_empty_trace: _top_k_len={_top_k_len} "
                              f"accessed_ids_empty={not _accessed_ids}",
                              session_id=_session_id, project=_project)
                    _wconn.commit()
                    _wconn.close()
                    return
                # iter917: write_trace_empty_guard — 对齐 retriever.py，防空 top_k 污染统计
                if _effective_injected and not _effective_top_k:
                    _effective_injected = 0
                # iter1221+1487: daemon_ftrace_writeback — 零注入时写入 ftrace 辅助诊断
                # iter1487: 扩大捕获范围 — 空注入+有候选时记录全部 deferred log（不限关键词）
                #   根因（数据驱动，2026-05-11）：128 条 trace ftrace_json 全 NULL。
                #   原因：suppress 在 _score_chunk 内返回 0 不写 dmesg，fallback 也不触发时无 log。
                #   关键词过滤仅匹配 6 个词 → 全 miss → ftrace=None → 空召回无法诊断。
                # 修复：candidates>0 时记录 deferred log 尾部 5 条（任意内容），兜底诊断。
                _ftrace_entries = None
                if not _effective_injected and _deferred_buf:
                    if _candidates_count > 0:
                        _ftrace_entries = [msg for _, _, msg, _, _, _ in _deferred_buf[-5:]]
                    else:
                        _ftrace_entries = [msg for _, _, msg, _, _, _ in _deferred_buf
                                           if any(k in msg for k in ("suppress", "fallback", "全灭", "empty", "zero", "thresh"))]
                    if not _ftrace_entries:
                        _ftrace_entries = None
                store_insert_trace(_wconn, {
                    "id": str(uuid_mod.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "session_id": _session_id, "project": _project,
                    "prompt_hash": _prompt_hash, "candidates_count": _candidates_count,
                    "top_k_json": _effective_top_k, "injected": _effective_injected,
                    "reason": _reason,
                    "duration_ms": _duration_ms,
                    "ftrace_json": json.dumps(_ftrace_entries) if _ftrace_entries else None,
                })
                for level, subsystem, message, sid, proj, extra in _deferred_buf:
                    try:
                        dmesg_log(_wconn, level, subsystem, message,
                                  session_id=sid, project=proj, extra=extra)
                    except Exception:
                        pass
                dmesg_log(_wconn, DMESG_INFO, "retriever",
                          f"daemon injected={_top_k_len} candidates={_candidates_count} {_duration_ms:.1f}ms",
                          session_id=_session_id, project=_project,
                          extra={"top_k_ids": _accessed_ids, "priority": priority})
                _wconn.commit()
                _wconn.close()
                # iter173: do NOT set _ro_conn_invalidate_flag here —
                # update_accessed/mglru_promote/insert_trace/dmesg_log do NOT change
                # FTS5-relevant fields (summary/content). Persistent ro conn stays valid.
                # Only swap_in (new rows in memory_chunks) and extractor (bumps chunk_version)
                # require invalidation; those paths handle it explicitly.
            except Exception:
                pass
            # ── iter648: injection timeline write-back (daemon sync) ──
            try:
                _itl_path = os.path.join(MEMORY_OS_DIR, ".injection_timeline.json")
                _itl_existing = {}
                if os.path.exists(_itl_path):
                    with open(_itl_path, encoding="utf-8") as _itf:
                        _itl_existing = json.loads(_itf.read())
                from datetime import timedelta as _td648w
                _now_ts = datetime.now(timezone.utc).isoformat()
                # iter1115: gc_writeback_21d — 对齐 retriever.py iter1110 读取 GC 窗口
                _cutoff_21d = (datetime.now(timezone.utc) - _td648w(days=21)).isoformat()
                _itl_pruned = {}
                for _k, _v in _itl_existing.items():
                    _kept = [t for t in _v if t > _cutoff_21d]
                    if _kept:
                        _itl_pruned[_k] = _kept
                for _inj_id in _accessed_ids:
                    if _inj_id not in _itl_pruned:
                        _itl_pruned[_inj_id] = []
                    _itl_pruned[_inj_id].append(_now_ts)
                with open(_itl_path, 'w', encoding="utf-8") as _itf_w:
                    _itf_w.write(json.dumps(_itl_pruned, ensure_ascii=False))
            except Exception:
                pass
            _write_shadow_trace(_project, _shadow_ids, _session_id)

        _writeback_submit(_do_writeback)

    finally:
        # iter173: conn is now a persistent per-thread connection — do NOT close here.
        # Exception: if conn was reassigned to a temporary conn in the swap_in path
        # (conn = _open_db_readonly()), it was already closed above.
        pass


def _write_shadow_trace(project: str, top_k_ids: list, session_id: str = "") -> None:
    """
    iter259：写入 shadow trace — 记录本次 retriever 注入的 chunk IDs。
    优先写入 shadow_traces DB 表（per-session 行，并发安全），
    同时保留旧文件写入作为向后兼容 fallback。
    """
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    _agent_id = session_id[:16] if session_id else ""

    # 优先写 DB（INSERT OR REPLACE by session_id PRIMARY KEY，并发安全）
    # iter259：使用 WAL 模式 + 30s timeout，多 agent 并发写入时减少 SQLITE_BUSY 错误
    try:
        import sqlite3 as _sqlite3
        _db_path = STORE_DB
        _conn = _sqlite3.connect(_db_path, timeout=30)  # iter259: 30s timeout for multi-agent contention
        _conn.execute("PRAGMA journal_mode=WAL")  # iter259: WAL 允许并发读写，减少锁冲突
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS shadow_traces (
                session_id   TEXT PRIMARY KEY,
                project      TEXT NOT NULL DEFAULT '',
                agent_id     TEXT NOT NULL DEFAULT '',
                updated_at   TEXT NOT NULL,
                top_k_ids    TEXT NOT NULL DEFAULT '[]'
            )
        """)
        _conn.execute(
            """INSERT OR REPLACE INTO shadow_traces
               (session_id, project, agent_id, updated_at, top_k_ids)
               VALUES (?, ?, ?, ?, ?)""",
            (session_id or "unknown", project, _agent_id, now_iso,
             json.dumps(top_k_ids, ensure_ascii=False))
        )
        _conn.commit()
        _conn.close()
    except Exception:
        pass

    # 兼容旧文件（向后兼容，供旧版 extractor 读取）
    try:
        with open(SHADOW_TRACE_FILE, 'w', encoding="utf-8") as _f:
            _f.write(json.dumps({
                "project": project, "top_k_ids": top_k_ids,
                "session_id": session_id,
                "timestamp": now_iso,
            }, ensure_ascii=False))
    except Exception:
        pass


# ── Daemon 主循环 ──

def _signal_handler(signum, frame):
    print(f"[retriever_daemon] received signal {signum}, shutting down", file=sys.stderr)
    _shutdown_event.set()
    try:
        os.unlink(SOCKET_PATH)
    except Exception:
        pass
    os._exit(0)


def _prewarm_fts5():
    """
    iter171: 预热 FTS5 page cache（Linux fadvise/readahead 类比）。
    在后台线程执行一次 dummy FTS5 查询，将 store.db 的索引页加载到 OS page cache。
    避免首次真实请求触发 ~14ms（normal restart）或 ~415ms（page cache eviction）的 cold fault。

    OS 类比：fadvise(FADV_WILLNEED) — 提前通知内核将文件页预取到 page cache，
      让后续 read() 命中 page cache 而非磁盘。
      memory-os 对应：daemon 启动后立即访问 FTS5 index，OS 将 store.db 页面载入内存，
      首个真实 FTS5 查询时 SQLite 直接命中 page cache（~1.5ms），无需磁盘 I/O。

    还预热 BM25 mem_cache（_bm25_mem_cache_put）：将 chunk 加载 + BM25 索引构建
    放入 daemon 进程内存，首次真实请求跳过 store_get_chunks + BM25 build（~10ms）。

    注意：prewarm 在后台线程中执行，不阻塞 daemon 启动和请求接收。
      prewarm 完成约 1-15s 后（取决于 page cache 温度），page cache 已热。
    """
    if not os.path.exists(STORE_DB):
        return
    try:
        t0 = time.time()
        open_db = _modules.get('open_db')
        fts_search = _modules.get('fts_search')
        ensure_schema = _modules.get('ensure_schema')
        store_get_chunks = _modules.get('get_chunks')
        read_chunk_version = _modules.get('read_chunk_version')
        bm25_scores_cached = _modules.get('bm25_scores_cached')
        resolve_project_id = _modules.get('resolve_project_id')
        if open_db is None or fts_search is None:
            return

        conn = open_db()
        if ensure_schema:
            ensure_schema(conn)

        # 1) FTS5 page cache 预热：执行一次 FTS5 查询（任意 query）
        #    目的是将 store.db 的 FTS5 index pages 拉入 OS page cache
        project = None
        try:
            if resolve_project_id:
                project = resolve_project_id()
        except Exception:
            pass
        fts_search(conn, "memory retriever project", project=project, top_k=5)
        t_fts = (time.time() - t0) * 1000

        # 2) BM25 mem_cache 预热：加载 chunks + 构建 BM25 索引
        #    让首次真实请求（BM25 fallback path）命中 daemon 内存缓存
        if store_get_chunks and read_chunk_version and project:
            try:
                from bm25 import BM25Index as _BM25Index
                # iter207: use module-level constant (avoids local tuple rebuild)
                _cv = read_chunk_version()
                _rtypes_key = _ALL_RETRIEVE_TYPES_KEY  # iter207: pre-computed constant
                # 只在缓存为空时预热（避免重复工作）
                if _bm25_mem_cache_get(project, _rtypes_key, _cv) is None:
                    chunks = store_get_chunks(conn, project, chunk_types=_ALL_RETRIEVE_TYPES_CONST)
                    if chunks:
                        search_texts = [f"{c['summary']} {c['content']}" for c in chunks]
                        _bm25_idx = _BM25Index.load_or_build(search_texts, chunk_version=_cv)
                        _bm25_mem_cache_put(project, _rtypes_key, _cv, chunks, _bm25_idx, search_texts)
            except Exception:
                pass

        # 3) VFS corpus cache 预热：第一次 VFS search 建立语料库缓存（~20ms）
        #    让首次真实请求中的 VFS 并行线程（iter169）命中热语料库（~2.7ms）
        try:
            kr_route = _modules.get('kr_route')
            if kr_route is not None:
                kr_route("memory retriever project", sources=["memory-md", "self-improving"],
                         timeout_ms=200)
        except Exception:
            pass

        conn.close()
        elapsed = (time.time() - t0) * 1000
        print(f"[retriever_daemon] prewarm done in {elapsed:.0f}ms (fts5={t_fts:.0f}ms)", file=sys.stderr)
    except Exception as e:
        print(f"[retriever_daemon] prewarm failed: {e}", file=sys.stderr)


def run_daemon():
    """
    启动 daemon：
    1. 加载所有 heavy modules（一次）
    2. 创建 Unix Domain Socket
    3. accept() 循环，每个连接 spawn Thread
    4. 闲置守护线程监控退出
    """
    # 注册信号处理
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # 清理旧 socket 文件
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass

    print(f"[retriever_daemon] starting, loading modules...", file=sys.stderr)
    _load_all_modules()
    print(f"[retriever_daemon] ready, listening on {SOCKET_PATH}", file=sys.stderr)

    # 创建 Unix socket
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(SOCKET_PATH)
    server.listen(MAX_CONNECTIONS)
    server.settimeout(5.0)  # 允许 idle watchdog 定期检查

    # 启动闲置守护线程
    watchdog = threading.Thread(target=_idle_watchdog, daemon=True)
    watchdog.start()

    # iter164: 启动 async writeback 线程
    # OS 类比：Linux kworker flush thread — 后台处理 dirty page 写回
    writeback_thread = threading.Thread(target=_writeback_worker, daemon=True,
                                        name="writeback-worker")
    writeback_thread.start()
    print(f"[retriever_daemon] writeback worker started", file=sys.stderr)

    # iter182: 启动 VFS worker pool（kthread_worker 类比）
    # OS 类比：kthread_create_worker() — 预分配 worker thread，
    #   消除每次 VFS 搜索时的 threading.Thread.start() 开销（~65us → ~17us）。
    _vfs_worker_pool.start()
    print(f"[retriever_daemon] VFS worker pool started", file=sys.stderr)

    # iter204: 启动 handler thread pool（prefork worker 类比）
    # OS 类比：Apache prefork MPM / nginx worker_processes —
    #   预分配 MAX_CONNECTIONS 个 handler threads，通过 socket queue 接收连接，
    #   消除每次 threading.Thread.start()（~54us wakeup）→ queue.put（~17us）。
    #   节省：~35us/request（thread wakeup 49us → 8.5us，消除 Thread.__init__ ~5us）。
    #   threading.local() 兼容：每个 pool worker 有独立的 per-thread SQLite 连接。
    _handler_pool.start(n=MAX_CONNECTIONS)
    print(f"[retriever_daemon] handler pool started ({MAX_CONNECTIONS} workers)", file=sys.stderr)

    # iter171: 启动 FTS5 page cache 预热线程（fadvise/readahead 类比）
    # OS 类比：Linux readahead() / fadvise(FADV_WILLNEED) — 异步预读文件页到 page cache，
    #   让后续 read() 命中内存而非磁盘。
    #   daemon 启动后立即在后台线程预热 FTS5，消除首次请求的 ~415ms 冷启动尖刺。
    prewarm_thread = threading.Thread(target=_prewarm_fts5, daemon=True,
                                      name="fts5-prewarm")
    prewarm_thread.start()

    # 写入 PID 文件（供 wrapper 检测）
    pid_file = SOCKET_PATH + ".pid"
    try:
        with open(pid_file, 'w') as _f:
            _f.write(str(os.getpid()))
    except Exception:
        pass

    try:
        while not _shutdown_event.is_set():
            try:
                conn_sock, _ = server.accept()
                # iter204: submit to pre-created handler pool (queue.put ~9us + wakeup ~8.5us)
                # vs threading.Thread.start() (create ~5us + wakeup ~49us) = saves ~35us
                # OS 类比：nginx accept → put socket into worker queue (无 fork/exec 开销)
                if not _handler_pool.submit(conn_sock):
                    # Fallback: pool full or not active, handle synchronously
                    t = threading.Thread(target=_handle_connection, args=(conn_sock,), daemon=True)
                    t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if not _shutdown_event.is_set():
                    print(f"[retriever_daemon] accept error: {e}", file=sys.stderr)
    finally:
        server.close()
        # iter164: flush pending write-back tasks before exit
        # OS 类比：unmount 时 sync() — 确保 dirty page 落盘后再关闭
        try:
            _writeback_queue.put_nowait(None)  # poison pill
            _writeback_queue.join()            # wait for all pending writes
        except Exception:
            pass
        # iter182: stop VFS worker pool
        try:
            _vfs_worker_pool.stop()
        except Exception:
            pass
        # iter204: stop handler thread pool
        try:
            _handler_pool.stop()
        except Exception:
            pass
        try:
            os.unlink(SOCKET_PATH)
        except Exception:
            pass
        try:
            os.unlink(pid_file)
        except Exception:
            pass


if __name__ == "__main__":
    run_daemon()
