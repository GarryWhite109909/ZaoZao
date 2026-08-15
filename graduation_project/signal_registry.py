"""
信号注册表 —— 第 2.5 代架构核心：模型→工具 的信任分级回填。

背景（docs/方法论_工具模型自适应闭环.md §十）：
  模型帮助工具必须"更谨慎或更聪明"，否则模型回填给工具的错误信息会把工具教坏。
  本模块把"LLM 裁决结果回填工具层"建模为**带门控的信号增删改**（ISAM 的索引维护
  类比：插入要校验、冲突要检查、删除要可撤销、完整性要审计）：

    A/B 级判定（可信）   → 回填信号置信表（工具下次优先召回 + 类型校正）
    C 级判定（碰巧对）   → 被反事实扰动/跨样本聚合拦截，不入池
    D 级判定（误报）     → 进抑制池（工具见到该特征直接跳过，反向"教工具避坑"）

门控规则（每条对应 §10.3 设计原则）：
  1. 全票门槛：仅 votes_true==N（或 votes_false==N）的判定可回填；低置信摇摆不进池。
  2. 跨样本聚合（延迟回填）：同信号须在 ≥K 个独立样本上被一致判定才 commit 到工具层，
     单样本偶发判定（哪怕模型自信）不污染工具。
  3. 双向撤销：已回填信号若后续被高置信否定，降权/移出（工具的记忆可被新判定覆盖）。
  4. 类型校正分离：模型输出的真实漏洞类型仅在"高置信 + 与工具 rule_id 冲突"时更新
     类型映射；模型无把握时保留工具原标注。

线程安全：模块级全局单例 + 锁；持久化到 models/signal_registry.json（可被 eval 关闭）。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "models" / "signal_registry.json"
# 延迟回填的跨样本一致性门槛：同一信号被 ≥K 个独立样本一致判定才 commit
MIN_AGREE_SAMPLES = 2


@dataclass
class Signal:
    """单个信号（rule_id / 特征指纹）的置信记录。"""
    rule_id: str
    taint_type: str = ""
    confirmed: int = 0            # 被 LLM 高置信确认的次数（跨样本）
    rejected: int = 0             # 被 LLM 高置信否定的次数（跨样本）
    confirmed_files: list[str] = field(default_factory=list)  # 确认样本（跨样本聚合用）
    rejected_files: list[str] = field(default_factory=list)   # 否定样本
    # 类型校正映射：rule_id → (真实漏洞类型, 样本数)（仅高置信且与工具标注冲突时更新）
    corrected_type: str = ""
    corrected_type_samples: int = 0
    suppressed: bool = False      # 是否被抑制（D 级，工具见到跳过）
    suppressed_samples: int = 0

    @property
    def confidence(self) -> float:
        """确认比例（跨样本），未回填前为候选置信。"""
        total = self.confirmed + self.rejected
        return self.confirmed / total if total else 0.0

    @property
    def ready(self) -> bool:
        """是否达到回填条件：≥K 个独立样本一致确认，且未被抑制。"""
        return (not self.suppressed
                and self.confirmed >= MIN_AGREE_SAMPLES
                and self.confirmed > self.rejected)


class SignalRegistry:
    """信号注册表：模型裁决 → 工具层记忆的持久化载体。"""

    def __init__(self, path: Optional[Path] = None, enabled: bool = True) -> None:
        self._path = Path(path) if path else _REGISTRY_PATH
        self._enabled = enabled
        self._lock = threading.RLock()
        self._signals: dict[str, Signal] = {}
        # 待学习池：工具漏召且 LLM 高置信判中的 sink 特征（供后续指纹级召回）
        self._learn_pool: list[dict] = []
        self._load()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self._enabled or not self._path.is_file():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            for rid, s in (data.get("signals", {}) or {}).items():
                self._signals[rid] = Signal(**s)
            self._learn_pool = data.get("learn_pool", []) or []
        except Exception as e:
            print(f"[SignalRegistry] 加载失败（从头开始）: {e}")

    def save(self) -> None:
        if not self._enabled:
            return
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "signals": {rid: s.__dict__ for rid, s in self._signals.items()},
                "learn_pool": self._learn_pool,
            }
            self._path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # 回填（模型裁决 → 工具记忆）
    # ------------------------------------------------------------------
    def record(self, rule_id: str, *, confirmed: bool, n: int, votes_true: int,
               votes_false: int, votes_invalid: int, file: str = "",
               taint_type: str = "", corrected_type: str = "",
               suppress_on_neg: bool = True) -> None:
        """记录一次裁决，按信任分级门控更新信号。

        Args:
            rule_id: 候选规则 id（信号主键）
            confirmed: 裁决是否判真
            n / votes_true / votes_false / votes_invalid: 投票统计（全票门槛依据）
            file: 当前样本名（跨样本聚合去重用）
            taint_type: 工具标注的漏洞类型
            corrected_type: LLM 判定后输出的真实类型（空则不改写）
            suppress_on_neg: 高置信否定是否进抑制池（默认 True）
        """
        if not self._enabled or not rule_id:
            return
        # 门控 1：全票门槛——只有全票一致（votes_true==n 或 votes_false==n）才记录，
        # 低置信摇摆不进入信号（它们正是"模型没把握"的 review 来源）
        unanimous = (votes_true == n and votes_false == 0 and votes_invalid == 0) or \
                    (votes_false == n and votes_true == 0 and votes_invalid == 0)
        if not unanimous:
            return

        with self._lock:
            sig = self._signals.setdefault(rule_id, Signal(rule_id=rule_id, taint_type=taint_type))
            if confirmed:
                if file and file not in sig.confirmed_files:
                    sig.confirmed_files.append(file)
                sig.confirmed += 1
                # 类型校正（门控 4）：仅当 LLM 明确给出与工具不同的类型且工具未记录过时更新
                if corrected_type and corrected_type != taint_type and not sig.corrected_type:
                    sig.corrected_type = corrected_type
                    sig.corrected_type_samples = 1
                elif corrected_type and corrected_type == sig.corrected_type:
                    sig.corrected_type_samples += 1
            else:
                if file and file not in sig.rejected_files:
                    sig.rejected_files.append(file)
                sig.rejected += 1
                # 门控 3 + 抑制：高置信否定 → 若此前误回填则降权，D 级进抑制池
                if suppress_on_neg and sig.confirmed >= MIN_AGREE_SAMPLES:
                    # 双向撤销：确认过又高置信否定，说明信号不可靠 → 降权
                    sig.confirmed = 0
                    sig.confirmed_files = []
                sig.suppressed = True
                sig.suppressed_samples += 1

    # ------------------------------------------------------------------
    # 查询（工具层扫描时使用）
    # ------------------------------------------------------------------
    def get_signal(self, rule_id: str) -> Optional[Signal]:
        if not self._enabled:
            return None
        with self._lock:
            return self._signals.get(rule_id)

    def is_suppressed(self, rule_id: str) -> bool:
        """该规则是否在抑制池（D 级：工具见到直接跳过）。"""
        sig = self.get_signal(rule_id)
        return bool(sig and sig.suppressed)

    def boost_priority(self, rule_id: str) -> float:
        """返回该规则的召回优先级权重（已回填的高置信信号权重高，供候选排序）。"""
        sig = self.get_signal(rule_id)
        if not sig or not sig.ready:
            return 1.0
        return 1.0 + sig.confidence  # 已回填：权重 1.0~2.0

    def corrected_taint_type(self, rule_id: str) -> str:
        """返回该规则被模型校正后的真实漏洞类型（空 = 未校正）。"""
        sig = self.get_signal(rule_id)
        if sig and sig.corrected_type and sig.corrected_type_samples >= MIN_AGREE_SAMPLES:
            return sig.corrected_type
        return ""

    # ------------------------------------------------------------------
    # 待学习池（工具漏召 + LLM 判中的代码特征，供指纹级召回）
    # ------------------------------------------------------------------
    def add_to_learn_pool(self, entry: dict) -> None:
        """收录"工具漏召但 LLM 判中"的代码特征（recheck_vuln_trusted 路径）。"""
        if not self._enabled:
            return
        with self._lock:
            # 简单去重：同 file + 同特征不重复收录
            key = (entry.get("file", ""), entry.get("feature", ""))
            if any((p.get("file", ""), p.get("feature", "")) == key for p in self._learn_pool):
                return
            self._learn_pool.append(entry)

    def learn_pool_snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._learn_pool)

    # ------------------------------------------------------------------
    # 状态
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        with self._lock:
            ready = sum(1 for s in self._signals.values() if s.ready)
            suppressed = sum(1 for s in self._signals.values() if s.suppressed)
            corrected = sum(1 for s in self._signals.values() if s.corrected_type)
            return {
                "signals_total": len(self._signals),
                "signals_ready": ready,
                "signals_suppressed": suppressed,
                "signals_type_corrected": corrected,
                "learn_pool": len(self._learn_pool),
                "path": str(self._path),
            }


# 模块级全局单例（与 _MONITOR 同风格，供 scanner 复用）
_registry_lock = threading.Lock()
_registry: Optional[SignalRegistry] = None


def get_signal_registry() -> SignalRegistry:
    """返回全局信号注册表单例（首次调用时创建）。"""
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = SignalRegistry()
    return _registry


def reset_signal_registry(path: Optional[Path] = None, enabled: bool = True) -> SignalRegistry:
    """重建注册表（测试/eval 隔离用）。"""
    global _registry
    with _registry_lock:
        _registry = SignalRegistry(path=path, enabled=enabled)
    return _registry
