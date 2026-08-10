"""
模型注册表 —— 定义 garrywhite109909 命名空间下允许管理的模型清单。

前端模型管理 UI（拉取 / 删除 / 切换）只能操作此处登记的模型，
防止用户误操作其他无关模型。

每个模型条目包含：
- tag: Ollama 模型标签（不含命名空间前缀）
- full_name: 完整模型名（命名空间:tag）
- display_name: 前端展示名
- description: 模型描述
- prompt_variant: 推理时使用的 system prompt 变体
    "lite"  → SYSTEM_PROMPT_LITE（v5 训练/推理一致）
    "base"  → BASE_PROMPT（v9max 训练/推理一致）
- is_default: 是否为默认模型（首次启动时自动拉取）
- deprecated: 是否已废弃（仍可拉取使用，但 UI 标记"已过时"）
"""

from __future__ import annotations

import os
from typing import Optional

from graduation_project.prompts import V3_PROMPT

NAMESPACE = "garrywhite109909"
REPO = "graduation-vuln-scanner"

# ---------------------------------------------------------------------------
# 已登记模型（未来 Nivis-alpha.1 训练完后在此添加即可）
# ---------------------------------------------------------------------------
# 2026-08-09: 模型已统一用 v3 训练数据（final_train_chatml_v3.jsonl）的 CoT prompt
# 训练，因此所有登记模型的推理 prompt 统一为 V3_PROMPT，不再按模型区分变体。
_REGISTRY: list[dict] = [
    {
        "tag": "alpha0",
        "full_name": f"{NAMESPACE}/nivis-alpha0",
        "display_name": "Nivis-α0",
        "description": "Qwen3-8B + rsLoRA(r8) 训练的新发布模型，当前活动模型。",
        "prompt_variant": "v3",
        "is_default": True,
        "deprecated": False,
    },
    {
        "tag": "v9max",
        "full_name": f"{NAMESPACE}/{REPO}:v9max",
        "display_name": "Nivis v9max",
        "description": "三模型蒸馏 + A800 云端训练，已被 Nivis-α0 取代。合成集 recall 1.0，CVE-fix recall 0.95。",
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
]


def _get_prompt(variant: str) -> str:
    """根据变体名返回对应的 system prompt 文本。"""
    if variant == "v3":
        return V3_PROMPT
    # 兼容旧配置（环境变量/历史配置仍可能写 lite/base）
    from graduation_project.prompts import BASE_PROMPT, SYSTEM_PROMPT_LITE
    if variant == "lite":
        return SYSTEM_PROMPT_LITE
    if variant == "base":
        return BASE_PROMPT
    raise ValueError(f"未知 prompt 变体: {variant}（支持 'v3'/'base'/'lite'）")


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
