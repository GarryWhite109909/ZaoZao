"""
多模型投票扫描器 —— 顺序加载/卸载模型，避免 OOM

设计思路：
- 逐个模型加载 → 扫描全部样本 → 立即卸载 → 加载下一个模型
- 全部模型扫完后，按样本聚合投票，多数票决定最终结论
- 牺牲速度换显存安全：任一时刻显存中只驻留一个模型
- **仅 Ollama 后端**：多模型投票需要多个可独立拉取/加载的模型；
  transformers / llamacpp / vllm 等进程内后端每次只能加载一个本地模型，
  强制走 Ollama（backend="ollama"），否则会出现"多个模型名指向同一模型"的假投票。

适用场景：
- 需要多模型交叉验证提升判定可信度
- 单卡显存无法同时容纳多个大模型（如 2×8B 模型在 16GB 显卡上并行会 OOM）
- 可接受 N 倍于单模型的耗时（N 为模型数量）

依赖说明：
属于业务服务层（app/backend/services/）。数据容器 SingleResult/BatchResult
来自核心层 graduation_project.result_types，扫描编排复用同级 Scanner。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from graduation_project.result_types import SingleResult
from app.backend.services.scanner import Scanner


@dataclass
class VoteResult(SingleResult):
    """多模型投票扫描结果。

    在 SingleResult 全部字段基础上增加投票元信息：
    - model_votes: 每个模型的投票明细（模型名 + 判定）
    - consensus: 共识类型（unanimous 全票一致 / majority 多数 / split 势均力敌）
    - agreement_ratio: 一致率（多数方票数 / 有效票数，0.0~1.0）
    """
    model_votes: list[dict] = field(default_factory=list)
    consensus: str = "split"
    agreement_ratio: float = 0.0

    def to_dict(self) -> dict:
        """序列化为字典（供前端 JSON 展示）。"""
        base = super().to_dict()
        base.update({
            "model_votes": self.model_votes,
            "consensus": self.consensus,
            "agreement_ratio": round(self.agreement_ratio, 4),
        })
        return base


class MultiModelScanner:
    """多模型投票扫描器。

    顺序加载每个模型，扫描完成后立即卸载（keep_alive=0），
    避免多模型同时驻留显存导致 OOM。

    Args:
        models: 参与投票的模型列表（≥2 个）
        base_url: Ollama 服务地址
        use_rag: 是否启用 RAG 知识库增强
        use_prefilter: 是否启用传统规则预筛层
        keep_alive: 模型卸载策略（0=用完即卸，-1=常驻）
        backend: 推理后端，固定 "ollama"（多模型投票专用 Ollama 通道，
            调用方 /api/multi-model-scan 已按当前后端门控）

    Raises:
        ValueError: 模型数量 < 2
    """

    def __init__(
        self,
        models: list[str],
        base_url: str = "http://localhost:11434",
        use_rag: bool = False,
        use_prefilter: bool = True,
        keep_alive=0,
        backend: str = "ollama",
    ):
        if len(models) < 2:
            raise ValueError("多模型投票至少需要 2 个模型，当前仅 " + str(len(models)) + " 个")
        self.models = models
        self.base_url = base_url
        self.use_rag = use_rag
        self.use_prefilter = use_prefilter
        self.keep_alive = keep_alive
        self.backend = backend

    # ------------------------------------------------------------------
    # 核心扫描接口
    # ------------------------------------------------------------------

    def scan_code(
        self,
        code: str,
        language: str = "python",
        filename: str = "",
        use_rag: Optional[bool] = None,
    ) -> VoteResult:
        """扫描单段代码：逐模型扫描 → 卸载 → 投票聚合。

        Args:
            code: 代码文本
            language: 代码语言
            filename: 文件名（给模型作上下文）
            use_rag: 是否启用 RAG（None 表示用构造器默认值）

        Returns:
            VoteResult: 含各模型投票明细与聚合结论
        """
        rag_enabled = self.use_rag if use_rag is None else use_rag
        per_model_results: list[tuple[str, SingleResult]] = []

        for model in self.models:
            scanner = Scanner(
                model=model,
                base_url=self.base_url,
                use_rag=rag_enabled,
                use_prefilter=self.use_prefilter,
                keep_alive=self.keep_alive,
                backend=self.backend,
            )
            try:
                result = scanner.scan_code(code, language, filename, use_rag=use_rag)
            except Exception as e:
                # 单模型失败不影响其他模型投票；记录 error 后继续
                result = SingleResult(
                    filename=filename, language=language,
                    has_vulnerability=None, error=str(e),
                )
            per_model_results.append((model, result))
            # 关键安全：扫完立即卸载，释放显存给下一个模型
            scanner.unload()

        return self._aggregate(filename, language, per_model_results)

    def scan_files(
        self,
        files: list[tuple[str, str, str]],
        use_rag: Optional[bool] = None,
    ) -> list[VoteResult]:
        """批量扫描：每个模型扫完所有文件再卸载（摊薄模型加载耗时）。

        相比逐文件多模型扫描，本方法让每个模型一次性处理全部文件，
        模型加载次数 = 模型数（而非 模型数×文件数）。

        Args:
            files: [(filename, language, code), ...]
            use_rag: 是否启用 RAG

        Returns:
            每个文件一个 VoteResult，顺序与输入 files 一致
        """
        rag_enabled = self.use_rag if use_rag is None else use_rag
        n = len(files)
        # per_file_results[i] = [(model_name, SingleResult), ...]
        per_file_results: list[list[tuple[str, SingleResult]]] = [[] for _ in range(n)]

        for model in self.models:
            scanner = Scanner(
                model=model,
                base_url=self.base_url,
                use_rag=rag_enabled,
                use_prefilter=self.use_prefilter,
                keep_alive=self.keep_alive,
                backend=self.backend,
            )
            try:
                for i, (filename, language, code) in enumerate(files):
                    try:
                        r = scanner.scan_code(code, language, filename, use_rag=use_rag)
                    except Exception as e:
                        r = SingleResult(
                            filename=filename, language=language,
                            has_vulnerability=None, error=str(e),
                        )
                    per_file_results[i].append((model, r))
            finally:
                # 关键安全：该模型所有文件扫完，立即卸载释放显存
                # 放在 finally 确保即使中途异常也能卸载，避免显存泄漏
                scanner.unload()

        vote_results: list[VoteResult] = []
        for i, (filename, language, _) in enumerate(files):
            vr = self._aggregate(filename, language, per_file_results[i])
            vote_results.append(vr)
        return vote_results

    # ------------------------------------------------------------------
    # 投票聚合
    # ------------------------------------------------------------------

    @staticmethod
    def _aggregate(
        filename: str,
        language: str,
        per_model_results: list[tuple[str, SingleResult]],
    ) -> VoteResult:
        """聚合多模型投票结果。

        聚合规则：
        - has_vulnerability: 多数票决定（True 票数 vs False 票数）；
          50/50 平票时返回 True（保守判定，宁误报不漏报）
        - consensus: 全票一致=unanimous，有少数派=majority，平票=split
        - agreement_ratio: 多数方票数 / 有效票数（排除 error 的 None 票）
        - vulnerability_type / risk_level / source / sink / fix_suggestion:
          取自多数方首个模型的判定
        - explanation / raw_output: 取自首个与最终结论一致的模型
        """
        # 构建投票明细
        model_votes: list[dict] = []
        for model_name, r in per_model_results:
            model_votes.append({
                "model": model_name,
                "verdict": {
                    "has_vulnerability": r.has_vulnerability,
                    "vulnerability_type": r.vulnerability_type,
                    "risk_level": r.risk_level,
                    "error": r.error,
                },
            })

        # 统计有效票（排除因 error 导致 has_vulnerability=None 的票）
        valid = [(m, r) for m, r in per_model_results if r.has_vulnerability is not None]
        true_votes = [(m, r) for m, r in valid if r.has_vulnerability is True]
        false_votes = [(m, r) for m, r in valid if r.has_vulnerability is False]

        true_count = len(true_votes)
        false_count = len(false_votes)
        total_valid = true_count + false_count

        # 判定最终 has_vulnerability 与共识类型
        # 平票时倾向 True（保守判定为漏洞：安全审计场景宁误报不漏报）。
        # 与 experiments/utils.py 的 majority_vote 在"平票→True"上一致；差异：
        # 产品路径不设有效票过半的法定人数（有效票即表决），utils.py 为论文
        # 聚合口径要求有效票 > 总票数一半，两次 parse_fail 时不承认唯一票多数。
        majority_side: list[tuple[str, SingleResult]] = []
        if total_valid == 0:
            # 所有模型都失败
            final_verdict: Optional[bool] = None
            consensus = "split"
            agreement_ratio = 0.0
        elif true_count == false_count:
            # 平票（如 2 个模型 1 True 1 False）→ 保守判定为漏洞（True）
            final_verdict = True
            consensus = "split"
            agreement_ratio = 0.5
            # 平票时多数方取 true_votes（倾向漏洞），用于结构化字段填充
            majority_side = true_votes
        else:
            final_verdict = true_count > false_count
            majority_side = true_votes if final_verdict else false_votes
            minority_count = min(true_count, false_count)
            consensus = "unanimous" if minority_count == 0 else "majority"
            agreement_ratio = max(true_count, false_count) / total_valid

        # 从多数方模型取结构化字段
        if majority_side:
            _, majority_result = majority_side[0]
            vuln_type = majority_result.vulnerability_type
            risk_level = majority_result.risk_level
            source = majority_result.source
            sink = majority_result.sink
            fix_suggestion = majority_result.fix_suggestion
        elif valid:
            # 平票或全 error：退回到首个有效结果的结构化字段
            _, first_valid = valid[0]
            vuln_type = first_valid.vulnerability_type
            risk_level = first_valid.risk_level
            source = first_valid.source
            sink = first_valid.sink
            fix_suggestion = first_valid.fix_suggestion
        else:
            vuln_type = "none"
            risk_level = "None"
            source = "N/A"
            sink = "N/A"
            fix_suggestion = "no fix needed"

        # explanation / raw_output：取首个与最终结论一致的模型
        explanation = ""
        raw_output = ""
        if final_verdict is not None:
            for _, r in per_model_results:
                if r.has_vulnerability == final_verdict:
                    explanation = r.explanation
                    raw_output = r.raw_output
                    break
        elif per_model_results:
            # 平票或全失败：取第一个模型的说明
            explanation = per_model_results[0][1].explanation
            raw_output = per_model_results[0][1].raw_output

        # 累加所有模型耗时（总墙钟时间近似）
        total_duration = sum(r.duration for _, r in per_model_results)

        # 切片信息：取首个有效结果（各模型切片策略一致）
        sliced = False
        chunk_count = 1
        for _, r in per_model_results:
            if r.has_vulnerability is not None:
                sliced = r.sliced
                chunk_count = r.chunk_count
                break

        # 预筛信息：取首个有效结果
        prefilter_verdict: Optional[bool] = None
        prefilter_rules: list[str] = []
        for _, r in per_model_results:
            if r.has_vulnerability is not None:
                prefilter_verdict = r.prefilter_verdict
                prefilter_rules = r.prefilter_rules
                break

        return VoteResult(
            filename=filename,
            language=language,
            has_vulnerability=final_verdict,
            vulnerability_type=vuln_type,
            risk_level=risk_level,
            source=source,
            sink=sink,
            explanation=explanation,
            fix_suggestion=fix_suggestion,
            raw_output=raw_output,
            duration=total_duration,
            error=None if total_valid > 0 else "all models failed",
            sliced=sliced,
            chunk_count=chunk_count,
            prefilter_verdict=prefilter_verdict,
            prefilter_rules=prefilter_rules,
            model_votes=model_votes,
            consensus=consensus,
            agreement_ratio=agreement_ratio,
        )

    # ------------------------------------------------------------------
    # 资源管理
    # ------------------------------------------------------------------

    def unload(self) -> None:
        """卸载所有模型。

        本扫描器采用"用完即卸"策略（keep_alive=0），每个模型在完成自己的
        扫描批次后已即时调用 scanner.unload() 释放显存。因此此处为 no-op，
        仅保留接口以与单模型 Scanner 的 API 对齐，方便上层统一调用。
        """
        # no-op: 每个模型在 scan_code/scan_files 内已即时卸载
        return None

    @staticmethod
    def resource_warning(model_count: int = 2) -> str:
        """返回资源占用警告文案（供前端展示）。

        Args:
            model_count: 参与投票的模型数量

        Returns:
            警告字符串，说明预计耗时与显存占用情况
        """
        return (
            f"多模型投票模式将顺序加载 {model_count} 个模型，"
            f"预计耗时 {model_count}×单模型时间，"
            f"显存峰值约单个模型大小（已做卸载优化）"
        )


if __name__ == "__main__":
    # ----------------- 自测块 -----------------
    # 1. 资源警告文案
    print("=== 资源警告 ===")
    print(MultiModelScanner.resource_warning(3))
    print()

    # 2. 参数校验
    print("=== 参数校验 ===")
    try:
        MultiModelScanner(models=["only-one"])
    except ValueError as e:
        print(f"预期内的 ValueError: {e}")
    print()

    # 3. 聚合逻辑离线测试（不依赖 Ollama）
    print("=== 聚合逻辑测试（离线） ===")

    def make_result(verdict: Optional[bool], vuln_type: str = "none",
                    risk: str = "None", explanation: str = "") -> SingleResult:
        return SingleResult(
            filename="test.py", language="python",
            has_vulnerability=verdict,
            vulnerability_type=vuln_type,
            risk_level=risk,
            explanation=explanation,
        )

    # 场景 A：全票一致（2 True）
    r_a = MultiModelScanner._aggregate("a.py", "python", [
        ("modelA", make_result(True, "CWE-89 SQL注入", "High", "A 发现 SQL 注入")),
        ("modelB", make_result(True, "CWE-89 SQL注入", "High", "B 确认同样问题")),
    ])
    print(f"[A 全票一致] verdict={r_a.has_vulnerability} consensus={r_a.consensus} "
          f"ratio={r_a.agreement_ratio} type={r_a.vulnerability_type}")
    assert r_a.has_vulnerability is True
    assert r_a.consensus == "unanimous"
    assert r_a.agreement_ratio == 1.0

    # 场景 B：多数票（2 True 1 False）
    r_b = MultiModelScanner._aggregate("b.py", "python", [
        ("modelA", make_result(True, "CWE-79 XSS", "Medium", "A 发现 XSS")),
        ("modelB", make_result(True, "CWE-79 XSS", "Medium", "B 确认")),
        ("modelC", make_result(False, "none", "None", "C 认为安全")),
    ])
    print(f"[B 多数票] verdict={r_b.has_vulnerability} consensus={r_b.consensus} "
          f"ratio={r_b.agreement_ratio:.4f} type={r_b.vulnerability_type}")
    assert r_b.has_vulnerability is True
    assert r_b.consensus == "majority"
    assert abs(r_b.agreement_ratio - 2 / 3) < 1e-6

    # 场景 C：平票（1 True 1 False → 保守判定 True）
    r_c = MultiModelScanner._aggregate("c.py", "python", [
        ("modelA", make_result(True, "CWE-89", "High", "A 认为有漏洞")),
        ("modelB", make_result(False, "none", "None", "B 认为安全")),
    ])
    print(f"[C 平票] verdict={r_c.has_vulnerability} consensus={r_c.consensus} "
          f"ratio={r_c.agreement_ratio}")
    assert r_c.has_vulnerability is True
    assert r_c.consensus == "split"
    assert r_c.agreement_ratio == 0.5

    # 场景 D：含一个 error（2 True 1 None → 排除 None 后全票一致 True）
    # 验证 error 票（has_vulnerability=None）不参与投票统计
    r_d = MultiModelScanner._aggregate("d.py", "python", [
        ("modelA", make_result(True, "CWE-79", "High", "A 发现 XSS")),
        ("modelB", make_result(None, "none", "None", "B 超时")),
        ("modelC", make_result(True, "CWE-79", "High", "C 确认 XSS")),
    ])
    print(f"[D 含error] verdict={r_d.has_vulnerability} consensus={r_d.consensus} "
          f"ratio={r_d.agreement_ratio:.4f} type={r_d.vulnerability_type}")
    assert r_d.has_vulnerability is True
    assert r_d.consensus == "unanimous"
    assert r_d.agreement_ratio == 1.0

    print("\n所有离线聚合测试通过。")
    print()

    # 4. 端到端测试（需要 Ollama 服务 + 模型已 pull）
    print("=== 端到端测试（需 Ollama） ===")
    test_models = ["qwen3:8b", "gemma3:4b"]
    scanner = MultiModelScanner(
        models=test_models,
        use_prefilter=False,
        keep_alive=0,
    )

    # 先检查 Ollama 是否可用
    probe = Scanner(model=test_models[0], base_url="http://localhost:11434")
    if not probe.client.check_connection():
        print("[跳过] Ollama 服务未启动，请先运行 `ollama serve`")
    else:
        available = probe.client.list_models()
        missing = [m for m in test_models if m not in available]
        if missing:
            print(f"[跳过] 缺少模型: {missing}，请先 `ollama pull`")
        else:
            test_code = (
                "import sqlite3\n"
                "def get_user(name):\n"
                "    c = sqlite3.connect('db').cursor()\n"
                "    c.execute(\"SELECT * FROM users WHERE name='\" + name + \"'\")\n"
                "    return c.fetchone()\n"
            )
            print(f"扫描测试代码（SQL 注入样本），模型: {test_models}")
            vr = scanner.scan_code(test_code, "python", "vuln.py")
            print(f"最终判定: has_vulnerability={vr.has_vulnerability}")
            print(f"共识: {vr.consensus}（一致率 {vr.agreement_ratio:.2%}）")
            print(f"漏洞类型: {vr.vulnerability_type}  风险: {vr.risk_level}")
            print(f"总耗时: {vr.duration:.2f}s")
            print("各模型投票:")
            for v in vr.model_votes:
                print(f"  - {v['model']}: {v['verdict']['has_vulnerability']} "
                      f"({v['verdict']['vulnerability_type']})")
