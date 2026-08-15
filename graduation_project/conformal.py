"""
共形预测校准 —— 第 2.5 代架构 Layer 1：给 N 采样裁决提供统计保证的三分类。

背景（docs/技术研究报告.md 报告二§二）：self-consistency 投票比（如 4/5）没有
形式化保证。共形预测把"多数票比例"升级为**分布无关的有限样本覆盖率保证**。

非一致性分数必须**标签相关**（分类共形的标准形式）：
    s(x, 漏洞) = 1 - votes_true/valid    （越不像漏洞 → 分数越大）
    s(x, 安全) = votes_true/valid        （越不像安全 → 分数越大）
对每个标签 y 在校准集（真实标签=y 的样本）上取 (1-α) 分位数 q_y，
预测集 C(x) = {y : s(x,y) ≤ q_y}。

对二元漏洞分类，预测集三态：
    {漏洞}           → 高置信真阳性（覆盖率保证）
    {安全}           → 高置信真阴性
    {漏洞, 安全}      → 不确定 → 路由反事实扰动验证（Layer 2）或人工复核

同时作为**回填门控的统计层**（与 signal_registry 配合）：只有落入单元素预测集
的判定才具备"模型帮助工具"的回填资格；{不确定} 天然被排除（弃权=门控的数学定义）。

用法：
    cp = ConformalPredictor(alpha=0.1)
    cp.fit([dict(votes_true=3, votes_false=0, votes_invalid=0, n=3, label=True), ...])
    cp.predict(votes_true=3, votes_false=0, votes_invalid=0, n=3)  # → "vulnerable"
"""

from __future__ import annotations

import math
from typing import Optional

import numpy as np


class ConformalPredictor:
    """基于 N 采样投票的标签条件共形预测器（二元分类）。"""

    def __init__(self, alpha: float = 0.1) -> None:
        """alpha: 覆盖率误差上限（1-alpha = 保证覆盖率）。"""
        self.alpha = alpha
        self._q_vuln: Optional[float] = None   # 标签=漏洞 条件分位数
        self._q_safe: Optional[float] = None   # 标签=安全 条件分位数
        self._n_calib = 0

    # ------------------------------------------------------------------
    # 标签相关非一致性分数
    # ------------------------------------------------------------------
    @staticmethod
    def score_vuln(votes_true: int, votes_false: int, votes_invalid: int) -> float:
        """样本"不符合漏洞标签"的程度：1 - 判漏洞比例。"""
        valid = votes_true + votes_false
        if valid == 0:
            return 1.0  # 全无效票：完全不像漏洞
        return 1.0 - votes_true / valid

    @staticmethod
    def score_safe(votes_true: int, votes_false: int, votes_invalid: int) -> float:
        """样本"不符合安全标签"的程度：判漏洞比例。"""
        valid = votes_true + votes_false
        if valid == 0:
            return 1.0
        return votes_true / valid

    # ------------------------------------------------------------------
    # 校准
    # ------------------------------------------------------------------
    def fit(self, samples: list[dict]) -> None:
        """在校准集上拟合标签条件分位数。

        Args:
            samples: 每个元素含 votes_true / votes_false / votes_invalid / n /
                     label（True=漏洞, False=安全）。真实标签来自历史评估已知结果。
        """
        if not samples:
            return
        vuln_scores = [self.score_vuln(s["votes_true"], s["votes_false"], s["votes_invalid"])
                       for s in samples if s["label"]]
        safe_scores = [self.score_safe(s["votes_true"], s["votes_false"], s["votes_invalid"])
                       for s in samples if not s["label"]]
        self._n_calib = len(samples)
        self._q_vuln = self._quantile(vuln_scores, 1 - self.alpha) if vuln_scores else None
        self._q_safe = self._quantile(safe_scores, 1 - self.alpha) if safe_scores else None

    @staticmethod
    def _quantile(sorted_vals: list[float], level: float) -> float:
        if not sorted_vals:
            return float("inf")
        arr = np.sort(np.asarray(sorted_vals, dtype=float))
        if len(arr) == 1:
            return float(arr[0])
        idx = (level * (len(arr) + 1) - 1)
        lo = int(math.floor(idx))
        hi = int(math.ceil(idx))
        lo = max(0, min(lo, len(arr) - 1))
        hi = max(0, min(hi, len(arr) - 1))
        if lo == hi:
            return float(arr[lo])
        frac = idx - lo
        return float(arr[lo] * (1 - frac) + arr[hi] * frac)

    # ------------------------------------------------------------------
    # 预测
    # ------------------------------------------------------------------
    def predict(self, votes_true: int, votes_false: int, votes_invalid: int, n: int) -> str:
        """对一次 N 采样投票做三分类。

        Returns:
            "vulnerable" / "safe" / "uncertain"
        """
        # 直出档 / 确定性工具：1/1 票视为高置信
        if n <= 1:
            return "vulnerable" if votes_true > votes_false else "safe"
        s_vuln = self.score_vuln(votes_true, votes_false, votes_invalid)
        s_safe = self.score_safe(votes_true, votes_false, votes_invalid)

        in_vuln = self._q_vuln is not None and s_vuln <= self._q_vuln + 1e-9
        in_safe = self._q_safe is not None and s_safe <= self._q_safe + 1e-9
        if in_vuln and not in_safe:
            return "vulnerable"
        if in_safe and not in_vuln:
            return "safe"
        return "uncertain"  # 两含/两不含/未校准 → 不确定（路由 Layer 2 / 人工）

    def calibrated(self) -> bool:
        return self._q_vuln is not None and self._q_safe is not None

    def thresholds(self) -> dict:
        return {
            "alpha": self.alpha,
            "q_vulnerable": self._q_vuln,
            "q_safe": self._q_safe,
            "n_calib": self._n_calib,
        }

    # ------------------------------------------------------------------
    # 校准持久化（2026-08-15：让生产路径能加载评估侧产出的校准阈值，
    # Layer 1 不再只活在 exp_07 实验里）
    # ------------------------------------------------------------------
    def save_calibration(self, path) -> bool:
        """把已拟合的校准阈值导出为 JSON（供生产端 TwoStageScanner 加载）。

        仅保存阈值与元信息（不保存校准样本本身）；未校准时返回 False。
        """
        import json as _json
        if not self.calibrated():
            return False
        from pathlib import Path as _Path
        p = _Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_json.dumps({
            "alpha": self.alpha,
            "q_vulnerable": self._q_vuln,
            "q_safe": self._q_safe,
            "n_calib": self._n_calib,
            "exported_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        return True

    def load_calibration(self, path) -> bool:
        """从 JSON 加载校准阈值（与 save_calibration 对应）。

        文件不存在/解析失败返回 False（调用方保持未校准状态，门控自动降级
        为旧投票逻辑，行为安全）。
        """
        import json as _json
        from pathlib import Path as _Path
        p = _Path(path)
        if not p.is_file():
            return False
        try:
            d = _json.loads(p.read_text(encoding="utf-8"))
            q_v, q_s = d.get("q_vulnerable"), d.get("q_safe")
            if q_v is None or q_s is None:
                return False
            self.alpha = float(d.get("alpha", self.alpha))
            self._q_vuln = float(q_v)
            self._q_safe = float(q_s)
            self._n_calib = int(d.get("n_calib", 0))
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# 自检（离线，2026-08-15 新增：覆盖三分类 + 校准持久化往返）
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import tempfile
    from pathlib import Path

    print("=== 共形预测器自检（离线） ===\n")
    cp = ConformalPredictor(alpha=0.1)

    # 1) 未校准 → predict 全部 uncertain
    ok1 = cp.predict(3, 0, 0, 3) == "uncertain" and not cp.calibrated()
    print(f"[{'PASS' if ok1 else 'FAIL'}] 未校准降级: predict={cp.predict(3,0,0,3)}, calibrated={cp.calibrated()}")

    # 2) 拟合后三分类
    samples = ([dict(votes_true=3, votes_false=0, votes_invalid=0, n=3, label=True)] * 8
               + [dict(votes_true=0, votes_false=3, votes_invalid=0, n=3, label=False)] * 8)
    cp.fit(samples)
    ok2 = (cp.calibrated()
           and cp.predict(3, 0, 0, 3) == "vulnerable"
           and cp.predict(0, 3, 0, 3) == "safe"
           and cp.predict(2, 1, 0, 3) in ("uncertain", "vulnerable"))
    print(f"[{'PASS' if ok2 else 'FAIL'}] 拟合三分类: vuln={cp.predict(3,0,0,3)}, "
          f"safe={cp.predict(0,3,0,3)}, thresholds={cp.thresholds()}")

    # 3) 校准持久化往返（生产接线的载体）
    p = Path(tempfile.mkdtemp()) / "conformal_calibration.json"
    ok3 = cp.save_calibration(p)
    cp2 = ConformalPredictor(alpha=0.1)
    ok3 = ok3 and cp2.load_calibration(p) and cp2.calibrated() \
        and cp2.predict(3, 0, 0, 3) == "vulnerable" and cp2.predict(0, 3, 0, 3) == "safe"
    print(f"[{'PASS' if ok3 else 'FAIL'}] 校准导出/加载往返: file={p.is_file()}, calibrated={cp2.calibrated()}")

    # 4) 加载不存在文件 → 安全降级
    cp3 = ConformalPredictor()
    ok4 = not cp3.load_calibration(Path(tempfile.mkdtemp()) / "nope.json") and not cp3.calibrated()
    print(f"[{'PASS' if ok4 else 'FAIL'}] 无校准文件降级: {not cp3.calibrated()}")

    all_ok = all([ok1, ok2, ok3, ok4])
    print(f"\n{'=== 自检通过 ===' if all_ok else '!!! 自检失败 !!!'}")
    sys.exit(0 if all_ok else 1)
