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
import sys
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
    confirmed: int = 0            # 被 LLM 高置信确认的总次数（含同文件重复扫描）
    rejected: int = 0             # 被 LLM 高置信否定的总次数（含同文件重复扫描）
    confirmed_files: list[str] = field(default_factory=list)  # 确认样本（跨样本聚合用）
    rejected_files: list[str] = field(default_factory=list)   # 否定样本
    # 类型校正映射：rule_id → (真实漏洞类型, 样本数)（仅高置信且与工具标注冲突时更新）
    corrected_type: str = ""
    corrected_type_samples: int = 0
    # 各候选类型的累计计数（多数投票决定 corrected_type，2026-08-15 修复"先到先得锁死"）：
    # 首个类型不再永久锁死——更准的类型积累到更高票数后自然替换。
    corrected_type_counts: dict[str, int] = field(default_factory=dict)
    # 类型校正去重（审查 #5，2026-08-16）：(file, corrected_type) 键集合，同文件重扫不再
    # 累计——与 confirmed_files/rejected_files 的去重口径一致，防"同文件凑满 ≥K 门槛"。
    corrected_type_files: list[str] = field(default_factory=list)
    suppressed: bool = False      # 是否被抑制（D 级，工具见到跳过）
    suppressed_samples: int = 0

    def __post_init__(self) -> None:
        # 旧持久化数据迁移：无 counts 时从 (corrected_type, samples) 初始化
        if self.corrected_type and not self.corrected_type_counts:
            self.corrected_type_counts = {self.corrected_type: max(1, self.corrected_type_samples)}

    @property
    def confidence(self) -> float:
        """确认比例（按去重文件数），未回填前为候选置信。"""
        a, b = len(self.confirmed_files), len(self.rejected_files)
        return a / (a + b) if (a + b) else 0.0

    @property
    def ready(self) -> bool:
        """是否达到回填条件：≥K 个**独立文件**一致确认，且未被抑制。

        2026-08-15 修复：原实现用 confirmed 计数（同一文件重复扫描即 +1），
        后端用户重复点扫描两次就 ready=True，"≥2 独立样本"门槛名存实亡。
        现改用 confirmed_files 去重数判定。
        """
        return (not self.suppressed
                and len(self.confirmed_files) >= MIN_AGREE_SAMPLES
                and len(self.confirmed_files) > len(self.rejected_files))


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
        """持久化到磁盘（原子写：先写临时文件再替换，避免并发/中断写坏）。

        2026-08-15 修复：此前全仓库无任何调用方，"持久化到 models/signal_registry.json"
        的承诺名存实亡——进程重启学习成果归零。现在 record()/add_to_learn_pool()
        变更后自动保存。
        """
        if not self._enabled:
            return
        with self._lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                data = {
                    "signals": {rid: s.__dict__ for rid, s in self._signals.items()},
                    "learn_pool": self._learn_pool,
                }
                tmp = self._path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
                os.replace(tmp, self._path)
            except Exception as e:
                print(f"[SignalRegistry] 保存失败: {e}")

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
                # 抑制池双向可撤销（审查 #3，2026-08-16 修复）：
                # 原实现确认分支无任何 suppressed=False 路径——候选被丢弃→该规则
                # 不再产生裁决→永无 record 复活它，模型的两次全票假阴性（纯模型
                # 能力问题）就能永久杀死一条规则召回（"模型能力问题写进工具"的
                # 主通道）。修复：高置信确认 ≥K 独立文件且确认数 > 否定数 →
                # 解除抑制（模型的正确判定可覆盖此前的误判）。
                if sig.suppressed:
                    if (len(sig.confirmed_files) >= MIN_AGREE_SAMPLES
                            and len(sig.confirmed_files) > len(sig.rejected_files)):
                        sig.suppressed = False
                        sig.suppressed_samples = 0
                # 类型校正（门控 3，2026-08-16 按原则修正）：
                # 仅当「模型输出类型 ≠ 工具标注类型」且该校正类型累计 ≥ MIN_AGREE_SAMPLES
                # 独立样本时才生效——防"模型判对但标号错（B 级）污染工具类型映射"。
                # 原实现纯票数多数即改（corrected_type_counts 首个高票就锁），
                # 违反文档 §10.3 原则 3「类型回填分离：标号回填只采与工具 rule_id
                # 冲突且模型高置信的情形」。未达门槛时保留工具原标注。
                # 审查 #5 修复：counts 按文件去重（同一文件重扫不再累计，与
                # confirmed_files/rejected_files 的去重口径一致——§11.12"读端写端一致"）。
                if corrected_type and corrected_type != taint_type:
                    key = (file, corrected_type)
                    if key not in sig.corrected_type_files:
                        sig.corrected_type_files.append(key)
                        sig.corrected_type_counts[corrected_type] = \
                            sig.corrected_type_counts.get(corrected_type, 0) + 1
                    best_type, best_cnt = max(sig.corrected_type_counts.items(),
                                              key=lambda kv: kv[1])
                    if best_cnt >= MIN_AGREE_SAMPLES:
                        sig.corrected_type = best_type
                        sig.corrected_type_samples = best_cnt
                    else:
                        # 未达跨样本门槛：不锁死，保留工具原标注（防 B 级污染）
                        sig.corrected_type = ""
                        sig.corrected_type_samples = best_cnt
            else:
                if file and file not in sig.rejected_files:
                    sig.rejected_files.append(file)
                sig.rejected += 1
                # 门控 3 + 抑制：高置信否定 → 若此前误回填则降权，D 级进抑制池。
                # Bug 修复（2026-08-16）：原实现无条件 suppressed=True，单次全票
                # 否决就把规则永久抑制（suppressed_samples=1），与 is_suppressed
                # 读取端"≥2 独立文件"语义不一致——评估跨样本累积导致工具召回被
                # 系统性过滤（triage_default 轮 recall 崩塌至 0.25 的根因）。
                # 修复：仅当"否定文件数 ≥ MIN_AGREE_SAMPLES"才进抑制池；单次否定
                # 只累加计数（供后续跨样本聚合），不立即抑制。
                if suppress_on_neg:
                    # 双向可撤销（原则 4）：只要被高置信否定过，就撤销已积累的
                    # 确认记录——防"确认1次+否定1次+再确认1次"凑满 ready 门槛的
                    # 污染信号（D 级误报被回填的典型路径）。
                    if sig.confirmed > 0:
                        sig.confirmed = 0
                        sig.confirmed_files = []
                    if len(sig.rejected_files) >= MIN_AGREE_SAMPLES:
                        sig.suppressed = True
                sig.suppressed_samples += 1
        # 变更后自动持久化（2026-08-15：此前 save() 全仓库无调用方，重启归零）
        self.save()

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
        """收录"工具漏召但 LLM 判中"的代码特征（recheck_vuln_trusted 路径）。

        独立验证集门控（原则 5，2026-08-16 补齐）：
          - 只收 `recheck_vuln_trusted`（工具漏召 + LLM 全票判中）的条目，
            且必须带 `unanimous=True` 标记（全票门槛，防 C 级碰巧对）。
          - 待学习池特征不直接参与召回，须经 `approve_learn_pool`（独立验证集
            复验）才转正。原实现无任何门控，仅去重即入库——违反文档 §10.3
            原则 5「独立验证集门控：待学习池新增信号须在独立验证集上复验，
            误报爆炸的候选直接淘汰」。
        """
        if not self._enabled:
            return
        if not entry.get("unanimous"):
            return  # 非全票判中：可能是 C 级碰巧对，不入池
        with self._lock:
            # 简单去重：同 file + 同特征不重复收录
            key = (entry.get("file", ""), entry.get("feature", ""))
            if any((p.get("file", ""), p.get("feature", "")) == key for p in self._learn_pool):
                return
            self._learn_pool.append(entry)
        self.save()

    def approve_learn_pool(self, predicate) -> int:
        """独立验证集门控：按 predicate 审批待学习池条目（转正/淘汰）。

        用法：调用方在独立验证集（真实 CVE 仓库，非 87 段）上复验每条特征，
        predicate 返回 True 的转正（approved）、False 的淘汰（removed）。
        返回转正数。误报爆炸的候选直接淘汰，绝不进工具召回。
        """
        if not self._enabled:
            return 0
        approved = 0
        with self._lock:
            kept = []
            for p in self._learn_pool:
                if predicate(p):
                    approved += 1
                    p["approved"] = True
                    kept.append(p)  # approved 条目保留（可被工具层消费）
                # else: 淘汰（不保留）
            self._learn_pool = kept
        self.save()
        return approved

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


# ---------------------------------------------------------------------------
# 自检（离线，2026-08-15 新增：此前无自检——正是 #2/#3/#4 长期未被发现的原因）
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile

    print("=== 信号注册表自检（离线） ===\n")
    tmp = Path(tempfile.mkdtemp()) / "signal_registry_test.json"
    r = SignalRegistry(path=tmp, enabled=True)

    # 1) 同一文件重复扫描不得 ready（≥2 独立样本门槛）
    for _ in range(3):  # app.py 连扫 3 次
        r.record("py.taint.sql", confirmed=True, n=3, votes_true=3,
                 votes_false=0, votes_invalid=0, file="app.py", taint_type="CWE-89")
    sig = r.get_signal("py.taint.sql")
    ok1 = (sig.confirmed == 3 and len(sig.confirmed_files) == 1 and not sig.ready)
    print(f"[{'PASS' if ok1 else 'FAIL'}] 同文件重复扫描: confirmed={sig.confirmed}, "
          f"files={len(sig.confirmed_files)}, ready={sig.ready} (期望 ready=False)")

    # 2) 第 2 个独立文件确认后 ready
    r.record("py.taint.sql", confirmed=True, n=3, votes_true=3,
             votes_false=0, votes_invalid=0, file="service.py", taint_type="CWE-89")
    ok2 = sig.ready and r.boost_priority("py.taint.sql") > 1.0
    print(f"[{'PASS' if ok2 else 'FAIL'}] 跨文件聚合: files={len(sig.confirmed_files)}, "
          f"ready={sig.ready}, boost={r.boost_priority('py.taint.sql'):.2f}")

    # 3) 高置信否定 → 抑制池（2026-08-16 门槛修正后：单次否决只累计计数，
    #    仅 ≥2 独立文件一致否决才进抑制池——防跨样本偶然性误杀规则）
    r.record("py.taint.sql", confirmed=False, n=3, votes_true=0,
             votes_false=3, votes_invalid=0, file="x.py")
    ok3a = not r.is_suppressed("py.taint.sql")  # 单次否决不抑制
    r.record("py.taint.sql", confirmed=False, n=3, votes_true=0,
             votes_false=3, votes_invalid=0, file="y.py")
    ok3 = ok3a and r.is_suppressed("py.taint.sql")  # 第 2 个独立文件否决 → 抑制
    print(f"[{'PASS' if ok3 else 'FAIL'}] 抑制池(≥2独立文件): "
          f"单次={not r.is_suppressed('py.taint.sql')}")

    # 4) 类型校正多数投票：首个类型可被更高票类型替换（不再先到先得）。
    #    门槛（2026-08-16 修正后）：单文件校正不生效（< MIN_AGREE_SAMPLES=2 时
    #    保留工具原标注防 B 级污染），≥2 独立文件一致才提交。
    r2 = SignalRegistry(path=tmp.with_name("t2.json"), enabled=True)
    r2.record("b608", confirmed=True, n=3, votes_true=3, votes_false=0,
              votes_invalid=0, file="a.py", taint_type="B608",
              corrected_type="CWE-79 XSS")
    first = r2.get_signal("b608").corrected_type
    # C 级更准类型连续 2 个文件出现 → 应提交 CWE-862 并替换先到候选
    for f in ("b.py", "c.py"):
        r2.record("b608", confirmed=True, n=3, votes_true=3, votes_false=0,
                  votes_invalid=0, file=f, taint_type="B608",
                  corrected_type="CWE-862 Missing Authorization")
    sig2 = r2.get_signal("b608")
    ok4 = first == "" and sig2.corrected_type == "CWE-862 Missing Authorization"
    print(f"[{'PASS' if ok4 else 'FAIL'}] 类型多数投票(≥2独立文件): "
          f"单文件={first!r} -> {sig2.corrected_type!r}")

    # 5) 自动持久化 + 重启恢复（record 后无需手动 save）
    ok5 = tmp.is_file()
    r3 = SignalRegistry(path=tmp, enabled=True)  # 模拟进程重启
    sig3 = r3.get_signal("py.taint.sql")
    ok5 = ok5 and sig3 is not None and sig3.suppressed and len(sig3.confirmed_files) == 0
    print(f"[{'PASS' if ok5 else 'FAIL'}] 自动持久化/重启恢复: file_exists={tmp.is_file()}, "
          f"suppressed={sig3.suppressed if sig3 else None}")

    all_ok = all([ok1, ok2, ok3, ok4, ok5])
    print(f"\n{'=== 自检通过 ===' if all_ok else '!!! 自检失败 !!!'}")
    sys.exit(0 if all_ok else 1)
