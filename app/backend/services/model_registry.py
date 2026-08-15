"""
模型注册表 —— 定义允许管理的模型清单。

前端模型管理 UI（拉取 / 删除 / 切换）只能操作此处登记的模型，
防止用户误操作其他无关模型。

注册表包含两类模型：
- 自研发布模型（garrywhite109909 命名空间）：alpha0 / v9max / v5 等微调模型
- Ollama 官方库对照模型（gemma4 / qwen3.5 系列）：未微调的通用模型，供显存
  充足的用户在 Ollama 后端做多模型交叉验证 / 对照实验。拉取时同样写入
  OLLAMA_MODELS（启动器已锁定到项目 models/ollama），与自研模型同目录，
  可被 /api/tags 探测、被 scanner 直接调用，无需二次迁移。

每个模型条目包含：
- tag: Ollama 模型标签（不含命名空间前缀）
- full_name: 完整模型名（命名空间:tag）
- display_name: 前端展示名
- description: 模型描述
- prompt_variant: 推理时使用的 system prompt 变体
    统一为 "v3" → V3_PROMPT（当前所有登记模型共用，训练/推理一致）
- is_default: 是否为默认模型（首次启动时自动拉取）
- deprecated: 是否已废弃（仍可拉取使用，但 UI 标记"已过时"）
"""

from __future__ import annotations

from typing import Optional

from graduation_project.prompts import V3_PROMPT

NAMESPACE = "garrywhite109909"
REPO = "graduation-vuln-scanner"

# ---------------------------------------------------------------------------
# 已登记模型（未来 Nivis-alpha.1 训练完后在此添加即可）
# ---------------------------------------------------------------------------
# 2026-08-15: α0.5 训练数据（final_train_chatml_alpha05.jsonl）使用 ALPHA05_PROMPT，
# 因此 α0.5 推理 prompt 切换为 ALPHA05_PROMPT（1467 字符，精简版）。
# 注意：triage 裁决任务（two_stage_scanner）的 system prompt 由调用方决定，
# 若使用本注册表默认 prompt，α0.5 在 triage 任务上会看到 ALPHA05_PROMPT（含
# has_vulnerability schema），但 build_triage_prompt 的 user prompt 显式指定了
# is_confirmed 格式，模型会优先遵循 user prompt 的显式指令。若实测发现格式
# 冲突，对 triage 任务单独传入 get_eval_system_prompt("triage_default")。
# 旧模型（v9max/v5）继续使用 V3_PROMPT，不受影响。
_REGISTRY: list[dict] = [
    {
        "tag": "alpha0",
        "full_name": f"{NAMESPACE}/nivis-alpha0",
        "display_name": "Nivis-α0",
        "description": "Qwen3-8B + rsLoRA(r8) 训练的新发布模型，当前活动模型。已训练未评估；"
                       "基于数据口径（8616 条、二次蒸馏 + 全量 combined prompt）推断优于 v9max，待测评证实。",
        "prompt_variant": "v3",
        "is_default": True,
        "deprecated": False,
    },
    {
        "tag": "alpha05",
        "full_name": f"{NAMESPACE}/nivis-alpha05",
        "display_name": "Nivis-α0.5",
        "description": "Qwen3-8B + rsLoRA(r8) 训练，数据 final_train_chatml_alpha05.jsonl（7953 条，"
                       "统一 ALPHA05_PROMPT，含盲区/痛点/归因/真实CVE 补充，泄露门禁+审计 PASS）。"
                       "精简 prompt(1467字) 替代 V3_PROMPT(4448字)，训练/推理一致。",
        "prompt_variant": "alpha05",
        "is_default": False,   # α0.5 训练完成并部署到 Ollama 后，再把默认切到此模型
        "deprecated": False,
    },
    {
        "tag": "v9max",
        "full_name": f"{NAMESPACE}/{REPO}:v9max",
        "display_name": "Nivis v9max",
        "description": "三模型蒸馏 + A800 云端训练。论文口径当前已发布最佳：合成集 recall 1.0，CVE-fix recall 0.95（均为 HF NF4+FP16 LoRA 评估管道口径；Ollama Q4_K_M 发布形态下合成集 recall 0.951 / FPR 0.077，CVE-fix recall 0.75~0.79）。默认活动模型已切换为 Nivis-α0（未评估）。",
        "prompt_variant": "v3",
        "is_default": False,
        "deprecated": False,
    },
    {
        "tag": "v5",
        "full_name": f"{NAMESPACE}/{REPO}:v5",
        "display_name": "Nivis v5",
        "description": "首个可信基线。合成集低误报（FPR 0.231）但真实集 recall 偏低（0.571），已过时。",
        "prompt_variant": "v3",
        "is_default": False,
        "deprecated": True,
    },
    # ------------------------------------------------------------------
    # Ollama 官方库对照模型（未微调，供多模型交叉验证 / 对照实验）
    # 拉取目标 = OLLAMA_MODELS = 项目 models/ollama（启动器锁定），
    # 与自研模型同目录，探测 / 调用链路完全一致。
    # ------------------------------------------------------------------
    {
        "tag": "gemma4",
        "full_name": "gemma4",
        "display_name": "Gemma 4（官方库）",
        "description": "Google Gemma 4 8B（Ollama 官方库，未微调通用模型）。用于多模型交叉验证；下载到项目 models/ollama。",
        "prompt_variant": "v3",
        "is_default": False,
        "deprecated": False,
    },
    {
        "tag": "gemma4:12b",
        "full_name": "gemma4:12b",
        "display_name": "Gemma 4 12B（官方库）",
        "description": "Google Gemma 4 12B（Ollama 官方库，未微调通用模型）。适合 16GB 以上显存；下载到项目 models/ollama。",
        "prompt_variant": "v3",
        "is_default": False,
        "deprecated": False,
    },
    {
        "tag": "qwen3.5:4b",
        "full_name": "qwen3.5:4b",
        "display_name": "Qwen3.5 4B（官方库）",
        "description": "Qwen3.5 4B（Ollama 官方库，未微调通用模型）。低显存对照选项；下载到项目 models/ollama。",
        "prompt_variant": "v3",
        "is_default": False,
        "deprecated": False,
    },
    {
        "tag": "qwen3.5:9b",
        "full_name": "qwen3.5:9b",
        "display_name": "Qwen3.5 9B（官方库）",
        "description": "Qwen3.5 9B（Ollama 官方库，未微调通用模型）。与 Qwen3-8B 同量级，适合 12GB 以上显存；下载到项目 models/ollama。",
        "prompt_variant": "v3",
        "is_default": False,
        "deprecated": False,
    },
    {
        "tag": "qwen3.5:27b",
        "full_name": "qwen3.5:27b",
        "display_name": "Qwen3.5 27B（官方库）",
        "description": "Qwen3.5 27B（Ollama 官方库，未微调通用模型）。需 24GB 以上显存；下载到项目 models/ollama。",
        "prompt_variant": "v3",
        "is_default": False,
        "deprecated": False,
    },
    {
        "tag": "qwen3.5:35b-a3b",
        "full_name": "qwen3.5:35b-a3b",
        "display_name": "Qwen3.5 35B-A3B MoE（官方库）",
        "description": "Qwen3.5 35B-A3B（MoE，官方库，未微调通用模型）。激活参数少，中等显存可跑；下载到项目 models/ollama。",
        "prompt_variant": "v3",
        "is_default": False,
        "deprecated": False,
    },
]


def _get_prompt(variant: str) -> str:
    """根据变体名返回对应的 system prompt 文本。"""
    if variant == "v3":
        return V3_PROMPT
    if variant == "alpha05":
        from graduation_project.prompts import ALPHA05_PROMPT
        return ALPHA05_PROMPT
    # 兼容旧配置（环境变量/历史配置仍可能写 lite/base）
    from graduation_project.prompts import BASE_PROMPT, SYSTEM_PROMPT_LITE
    if variant == "lite":
        return SYSTEM_PROMPT_LITE
    if variant == "base":
        return BASE_PROMPT
    raise ValueError(f"未知 prompt 变体: {variant}（支持 'v3'/'base'/'lite'/'alpha05'）")


def list_registry() -> list[dict]:
    """返回完整注册表（深拷贝，调用方可安全修改）。"""
    return [dict(m) for m in _REGISTRY]


def get_model_info(full_name: str) -> Optional[dict]:
    """按完整模型名查注册表，返回模型信息或 None。"""
    for m in _REGISTRY:
        if m["full_name"] == full_name:
            return dict(m)
    return None


def get_prompt_for_model(full_name: str) -> str:
    """按模型名获取对应的 system prompt。未登记的模型回退到 BASE_PROMPT。"""
    info = get_model_info(full_name)
    variant = info["prompt_variant"] if info else "base"
    return _get_prompt(variant)


def get_default_model() -> str:
    """返回默认模型全名。"""
    for m in _REGISTRY:
        if m["is_default"]:
            return m["full_name"]
    return _REGISTRY[0]["full_name"] if _REGISTRY else f"{NAMESPACE}/{REPO}:v9max"


def is_allowed(full_name: str) -> bool:
    """判断模型是否在注册表中（前端只允许操作已登记模型）。"""
    return get_model_info(full_name) is not None


def normalize_ollama_name(name: str) -> str:
    """去掉 Ollama 报告名称末尾的 :latest 标签，统一为注册表使用的无标签形式。

    例如 `garrywhite109909/nivis-alpha0:latest` → `garrywhite109909/nivis-alpha0`。
    Ollama 对不带 tag 的模型（create/pull 时未指定）总是以 :latest 上报，
    而注册表 full_name 不带 tag，导致各处精确匹配失效、误判“未安装”重复拉取。
    """
    if name.endswith(":latest"):
        return name[: -len(":latest")]
    return name
