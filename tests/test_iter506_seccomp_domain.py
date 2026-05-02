"""
iter506: seccomp-bpf Content Domain Filter — 非技术域知识拦截测试

OS 类比：Linux seccomp-bpf (Will Drewry, 2012) — 系统调用入口强制访问控制。
验证：生活类内容被拦截，技术内容不被误杀。
"""
import sys
from pathlib import Path

# tmpfs 隔离
sys.path.insert(0, str(Path(__file__).parent.parent))
import tmpfs  # noqa: F401 — 设置测试隔离环境

from hooks.extractor import _is_quality_chunk


class TestSeccompDomainFilter:
    """iter506: 非技术域内容过滤"""

    # ── 应被拦截的生活类内容 ──

    def test_food_durian(self):
        """榴莲相关问题 — 非技术域"""
        assert _is_quality_chunk("榴莲外壳青色的是什么意思？") is False

    def test_food_durian_texture(self):
        """榴莲刺间隔 — 非技术域"""
        assert _is_quality_chunk("榴莲壳上面的刺间隔密好还是间隔疏好？") is False

    def test_restaurant_social_anxiety(self):
        """订餐厅社恐 — 非技术域"""
        assert _is_quality_chunk("订餐厅、不用面对服务员、不用在公共场合表演浪漫 |") is False

    def test_photo_studio_nostalgia(self):
        """影楼拍照 — 非技术域"""
        assert _is_quality_chunk("影楼，手机自拍+三脚架，穿当年的风格，做当年的动作，用当年的台词") is False

    def test_speech_stumble(self):
        """磕巴笑场 — 非技术域"""
        assert _is_quality_chunk("讲得好听，磕巴、笑场、沉默都留着") is False

    def test_romance_anniversary(self):
        """浪漫纪念日 — 非技术域"""
        assert _is_quality_chunk("两个人都比较社恐，思考下专属于两个人的浪漫，站在许多老人的遗憾或者难忘的记忆上来思考") is False

    def test_shopping_taobao(self):
        """购物推荐 — 非技术域"""
        assert _is_quality_chunk("淘宝上有很多好看的穿搭推荐，可以看看评论区") is False

    def test_pet_care(self):
        """宠物话题 — 非技术域"""
        assert _is_quality_chunk("猫咪今天又把花盆打翻了，需要买个更稳的架子") is False

    # ── 不应被误杀的技术内容 ──

    def test_tech_python_file(self):
        """含 .py 文件路径 — 技术域"""
        assert _is_quality_chunk("store_vfs.py 新增 writeback_pressure() 函数实现写入反压") is True

    def test_tech_performance_metric(self):
        """含性能指标 — 技术域"""
        assert _is_quality_chunk("FTS5 搜索延迟从 58ms 优化到 10ms，提升 5.8x") is True

    def test_tech_code_identifier(self):
        """含代码标识符 — 技术域"""
        assert _is_quality_chunk("调用 `fts5_checkpoint()` 修复索引孤儿") is True

    def test_tech_api_term(self):
        """含 API 术语 — 技术域"""
        assert _is_quality_chunk("API 返回 404 时需要 fallback 到缓存层") is True

    def test_tech_chinese_term(self):
        """含中文技术术语 — 技术域"""
        assert _is_quality_chunk("迭代实现了新的缓存淘汰算法") is True

    def test_tech_database_query(self):
        """含 DB 相关 — 技术域"""
        assert _is_quality_chunk("SQL 查询在大表上需要添加索引避免全表扫描") is True

    def test_tech_kernel_patch(self):
        """含 kernel 相关 — 技术域"""
        assert _is_quality_chunk("kernel patch 修复了 check_for_migration 条件写反的问题") is True

    def test_tech_git_commit(self):
        """含 git 相关 — 技术域"""
        assert _is_quality_chunk("git commit 消息应该描述 why 而不是 what") is True

    # ── 边界情况 ──

    def test_pure_natural_language_no_life_signal(self):
        """纯自然语言但无生活信号 — 应通过（宁可漏过）"""
        # 没有生活域信号的非技术文本不触发过滤（zero false positive 设计）
        assert _is_quality_chunk("这个方案看起来不错，可以继续推进验证一下效果") is True

    def test_mixed_tech_and_life(self):
        """技术内容中提到生活词汇 — 应通过"""
        assert _is_quality_chunk("部署餐厅点餐系统的 API 接口需要 OAuth 认证") is True

    def test_short_slash_command(self):
        """纯斜杠命令 — 应被之前的规则拦截（< 10 字）"""
        assert _is_quality_chunk("/scan") is False
