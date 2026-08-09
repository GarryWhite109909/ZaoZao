"""
项目路径解析工具 —— 统一处理模型、adapter、配置文件等路径。

设计原则：
- 优先尊重用户显式配置（环境变量 / 构造函数参数）
- 其次按项目内约定目录自动探测（models/、outputs/ 等）
- 所有路径解析都返回绝对路径或空字符串，避免相对路径在不同 cwd 下歧义
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def find_project_root(anchor: Optional[Path] = None) -> Path:
    """定位项目根目录（Graduation-Project/）。

    策略：
        1. 已设置 VULN_SCANNER_ROOT 环境变量时直接采用
        2. 从 anchor 文件所在目录向上查找 pyproject.toml / .git 标记
        3. 以上都失败时回退到当前工作目录

    在常规 uvicorn / python -m 启动方式下，anchor 默认指向 graduation_project/paths.py，
    向上两级即可得到项目根目录。
    """
    env_root = os.environ.get("VULN_SCANNER_ROOT", "").strip()
    if env_root:
        p = Path(env_root)
        if p.is_dir():
            return p.resolve()

    start = anchor or Path(__file__).resolve()
    cur = start if start.is_dir() else start.parent
    for _ in range(5):
        if (cur / "pyproject.toml").exists() or (cur / ".git").is_dir():
            return cur
        parent = cur.parent
        if parent == cur:
            break
        cur = parent

    return Path.cwd().resolve()


def is_valid_adapter_dir(path: Path) -> bool:
    """检查目录是否是合法的 LoRA adapter 目录（含权重文件）。"""
    if not path.is_dir():
        return False
    weight_names = (
        "adapter_model.safetensors",
        "adapter_model.bin",
        "adapter_model.gguf",
    )
    return any((path / name).is_file() for name in weight_names)


def _pick_best(candidates: list[Path]) -> Path:
    """从候选目录中按名称启发式挑选最优 adapter 目录。

    优先选择包含 "v9max" / "best" / "adapter" 字样的目录；仍无法确定时返回第一个。
    """
    if len(candidates) == 1:
        return candidates[0]
    score_map = {"v9max": 3, "best": 2, "adapter": 1}

    def _score(p: Path) -> int:
        lowered = p.name.lower()
        return max((score_map.get(k, 0) for k in score_map if k in lowered), default=0)

    return sorted(candidates, key=_score, reverse=True)[0]


def discover_adapter_dir(project_root: Optional[Path] = None) -> Optional[Path]:
    """在项目约定目录中自动探测 LoRA adapter。

    搜索范围（按优先级分层，主位置永远优先于兜底位置）：
        1. 主位置 project_root / "models" / "adapter"（现行分类标准）
           - 兼容旧布局：models/ 本身直接放 adapter 权重文件
        2. 兜底位置 project_root / "experiments" / "exp_06_finetune" / "outputs" / ** / "best"

    仅当主位置没有任何合法 adapter 时，才回退到训练输出目录。
    """
    root = (project_root or find_project_root()).resolve()

    # 1) 主位置：models/adapter/（现行标准），兼容 models/ 根目录直接放置
    tier1: list[Path] = []
    models_dir = root / "models"
    if models_dir.is_dir():
        adapter_dir = models_dir / "adapter"
        if is_valid_adapter_dir(adapter_dir):
            tier1.append(adapter_dir)
        # 旧布局兼容：models/ 本身直接放权重
        if is_valid_adapter_dir(models_dir):
            tier1.append(models_dir)
    if tier1:
        return _pick_best(tier1)

    # 2) 兜底位置：训练输出目录（兼容旧路径）
    tier2: list[Path] = []
    outputs_dir = root / "experiments" / "exp_06_finetune" / "outputs"
    if outputs_dir.is_dir():
        for best_dir in sorted(outputs_dir.rglob("best")):
            if is_valid_adapter_dir(best_dir):
                tier2.append(best_dir)
    if tier2:
        return _pick_best(tier2)

    return None


def resolve_adapter_path(
    explicit: str = "",
    project_root: Optional[Path] = None,
) -> str:
    """解析 LoRA adapter 目录路径。

    解析优先级：
        1. explicit 参数（非空且目录存在）
        2. VULN_SCANNER_ADAPTER 环境变量（非空且目录存在）
        3. 项目根目录下 models/ 等约定位置自动探测

    Returns:
        adapter 目录的绝对路径字符串；未找到时返回空字符串。
    """
    # 1. explicit
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_absolute():
            p = (project_root or find_project_root()) / p
        if is_valid_adapter_dir(p):
            return str(p.resolve())

    # 2. 环境变量
    env_val = os.environ.get("VULN_SCANNER_ADAPTER", "").strip()
    if env_val:
        p = Path(env_val).expanduser()
        if not p.is_absolute():
            p = (project_root or find_project_root()) / p
        if is_valid_adapter_dir(p):
            return str(p.resolve())

    # 3. 自动探测
    found = discover_adapter_dir(project_root)
    if found:
        return str(found.resolve())

    return ""


def resolve_base_model_path(explicit: str = "") -> str:
    """解析基座模型路径（HF id 或本地目录）。

    解析优先级：
        1. explicit 参数（非空）
        2. VULN_SCANNER_MODEL_ID 环境变量（用户显式指定，可为 HF id 或本地路径）
        3. 项目本地缓存 models/transformers/Qwen3-8B（存在时优先本地，离线可用）
        4. 回退官方 HF id Qwen/Qwen3-8B
    """
    if explicit:
        return explicit

    env_id = os.environ.get("VULN_SCANNER_MODEL_ID", "").strip()
    if env_id:
        return env_id

    local = find_project_root() / "models" / "transformers" / "Qwen3-8B"
    if (local / "config.json").is_file():
        return str(local)

    return "Qwen/Qwen3-8B"


def local_hf_model_dir(repo_id: str) -> Path:
    """HF 仓库 id → 项目本地基座下载目录（models/transformers/<名称>）。

    这是 transformers 后端**唯一**的基座下载/检测位置：
    - 自动下载（首次加载）落到这里；
    - 设置页手动下载按钮也落到这里；
    - 就绪检测只检查这个目录。
    """
    name = repo_id.split("/")[-1] if "/" in repo_id else repo_id
    return find_project_root() / "models" / "transformers" / name


def ollama_models_dir(project_root: Optional[Path] = None) -> Path:
    """项目内 Ollama 模型存储目录（models/ollama）。"""
    return (project_root or find_project_root()) / "models" / "ollama"


def ollama_default_store() -> Path:
    """Ollama 默认模型存储：优先 OLLAMA_MODELS 环境变量，否则 ~/.ollama/models。"""
    env_val = os.environ.get("OLLAMA_MODELS", "").strip()
    if env_val:
        return Path(env_val).expanduser()
    return Path.home() / ".ollama" / "models"


def hf_home_dir(project_root: Optional[Path] = None) -> Path:
    """HuggingFace 缓存/元数据根目录（models/transformers/.hf_home）。

    设置 HF_HOME 指向这里，保证 huggingface_hub 的任何缓存/元数据
    （模型权重、tokenizer、锁文件等）都不落 C 盘。
    """
    return (project_root or find_project_root()) / "models" / "transformers" / ".hf_home"
