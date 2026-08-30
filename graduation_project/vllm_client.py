"""
vLLM LLM 客户端
封装本地 vLLM 服务调用，支持 RAG 增强的漏洞检测。

vLLM 通过 OpenAI 兼容 API 暴露服务（默认 http://localhost:8000/v1），
利用 PagedAttention + continuous batching 提供高吞吐批量推理。
接口与 OllamaClient 完全一致，便于无缝切换后端。
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Union

import requests

# schema 与 prompt 统一从 graduation_project.schema / graduation_project.prompts 导入（全项目唯一来源）。
from graduation_project.schema import VERDICT_SCHEMA, parse_verdict, normalize_has_vulnerability
from graduation_project.prompts import V3_PROMPT, build_user_prompt

__all__ = [
    "VLLMClient",
    "create_llm_client",
    "VERDICT_SCHEMA",
    "parse_verdict",
    "normalize_has_vulnerability",
]


# 约束解码用的 JSON Schema（与 OllamaClient 保持一致，确保两个后端输出格式相同）
# vLLM 通过 guided_json 参数支持 JSON Schema 约束解码（guided decoding），
# 底层依赖 outlines / xgrammar 等库在采样阶段强制输出合法 JSON。
_STRUCTURED_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "has_vulnerability": {
            "type": "boolean",
            "description": "true 表示存在漏洞，false 表示未发现漏洞"
        },
        "vulnerability_type": {
            "type": "string",
            "description": "单个字符串，格式如 'CWE-89 SQL注入'；无漏洞填 'none'"
        },
        "risk_level": {
            "type": "string",
            "enum": ["Critical", "High", "Medium", "Low", "None"],
            "description": "风险等级；无漏洞填 'None'"
        },
        "source": {
            "type": "string",
            "description": "污染来源（用户可控输入点）。必须锚定行号，如 'line 12: request.args.get(\"id\")'；无漏洞填 'N/A'"
        },
        "sink": {
            "type": "string",
            "description": "危险函数或触发点。必须锚定行号，如 'line 18: cursor.execute(query)'；无漏洞填 'N/A'"
        },
        "explanation": {
            "type": "string",
            "description": "漏洞或安全现状说明（数据流/成因，用 -> 箭头描述）"
        },
        "fix_suggestion": {
            "type": "string",
            "description": "行号锚定的简短修复建议（单行、不含换行），格式如 'line 3: 应改为 ...' 或 '第 3 行：... 建议改为 ...'；指出应修改的具体行与改法即可，禁止输出完整代码/补丁/围栏代码块，行号必须是代码中真实存在的；无漏洞填 'no fix needed'"
        }
    },
    "required": ["has_vulnerability", "vulnerability_type", "risk_level",
                 "source", "sink", "explanation", "fix_suggestion"]
}


class VLLMClient:
    """vLLM 推理客户端（OpenAI 兼容 API）。

    接口与 OllamaClient 完全一致，便于通过 create_llm_client() 工厂切换后端。
    vLLM 通过 PagedAttention + continuous batching 提供高吞吐批量推理，
    适合大批量数据集评测场景。
    """

    def __init__(self, base_url: str = "http://localhost:8000", model: Optional[str] = None):
        """
        Args:
            base_url: vLLM 服务地址（不含 /v1 后缀，默认 http://localhost:8000）
            model: 模型名称（vLLM 启动时通过 --served-model-name 指定，需与服务端一致）。
                   默认 None 时从注册表取 `get_default_model()`（当前为 Nivis-α0），
                   避免与 Web 默认模型漂移。
        """
        if model is None:
            from app.backend.services.model_registry import get_default_model
            model = get_default_model()
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_base = f"{self.base_url}/v1"
        self.api_completions = f"{self.api_base}/completions"
        self.api_chat = f"{self.api_base}/chat/completions"
        self.api_models = f"{self.api_base}/models"

    def check_connection(self) -> bool:
        """检查 vLLM 服务是否运行"""
        try:
            resp = requests.get(self.api_models, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def list_models(self) -> List[str]:
        """列出可用模型（返回模型 ID 列表）"""
        try:
            resp = requests.get(self.api_models, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            # OpenAI 兼容 API 返回格式: {"data": [{"id": "...", ...}, ...]}
            return [m.get("id", "") for m in data.get("data", [])]
        except Exception as e:
            print(f"[VLLMClient] 获取模型列表失败: {e}")
            return []

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = 2048,
        keep_alive=0,
        timeout: int = 300,
        num_ctx: int = 16384,
        num_gpu: Optional[int] = None,
        num_thread: Optional[int] = None,
        think: Optional[bool] = None,
        format: Optional[Union[str, dict]] = None,
    ) -> Dict:
        """
        生成文本（使用 vLLM OpenAI 兼容的 /v1/chat/completions 接口）

        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词（通过 chat/completions 的 system 消息传递，
                           由 vLLM 服务端按模型 chat template 正确拼接）
            temperature: 温度（越低越确定）
            max_tokens: 最大生成长度；None 表示不设上限
            keep_alive: 兼容 OllamaClient 参数；vLLM 无对应概念，作为 no-op 忽略
            timeout: 请求超时秒数
            num_ctx: 兼容 OllamaClient 参数；vLLM 上下文长度在启动时由 --max-model-len
                     指定，运行时无法修改，作为 no-op 忽略
            num_gpu: 兼容 OllamaClient 参数；vLLM GPU 配置在启动时确定，作为 no-op 忽略
            num_thread: 兼容 OllamaClient 参数；vLLM 线程配置在启动时确定，作为 no-op 忽略
            think: 兼容 OllamaClient 参数；vLLM 不分离 thinking 字段，作为 no-op 忽略
            format: 结构化输出约束。None 表示不约束；
                    "json" 表示约束输出为合法 JSON（通过 guided_json）；
                    传入 dict（JSON Schema）表示约束输出匹配该 Schema（通过 guided_json）。

        Returns:
            {"text": str, "duration": float, "tokens": dict, "meta": dict, "error": str|None}
            error 为 None 表示成功；非 None 时 text 为空字符串。
        """
        # vLLM 不支持 keep_alive / num_ctx / num_gpu / num_thread / think 参数，
        # 这些由 vLLM 启动参数统一管理，此处接受但忽略，保持接口兼容。

        start_time = time.time()

        try:
            # 使用 chat/completions 接口：由 vLLM 服务端按模型的 chat template
            # 正确拼接 system/user 消息（手拼 system+prompt 走 completions 会丢失模板）
            messages: List[Dict[str, str]] = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            payload: Dict = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "stream": False,
            }
            if max_tokens is not None:
                payload["max_tokens"] = max_tokens

            # format 参数处理：vLLM 通过 guided_json 支持结构化输出约束解码
            if format is not None:
                if isinstance(format, dict):
                    # JSON Schema dict：使用 vLLM guided_json 约束解码
                    payload["guided_json"] = format
                elif isinstance(format, str) and format == "json":
                    # "json" 字符串：约束输出为合法 JSON（无具体 Schema）
                    # vLLM guided_json 既可传 Schema 也可传字符串 "json"
                    payload["guided_json"] = "json"

            resp = requests.post(self.api_chat, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()

            # OpenAI 兼容 chat/completions 返回格式:
            # {"choices": [{"message": {"content": "..."}, ...}], "usage": {...}}
            choices = data.get("choices", [])
            message = choices[0].get("message", {}) if choices else {}
            text = message.get("content", "") if message else ""

            usage = data.get("usage", {})
            prompt_count = usage.get("prompt_tokens", 0)
            completion_count = usage.get("completion_tokens", 0)

            duration = time.time() - start_time

            return {
                "text": text,
                "duration": duration,
                "tokens": {
                    "prompt": prompt_count,
                    "completion": completion_count,
                    "total": prompt_count + completion_count,
                },
                "meta": {
                    "id": data.get("id"),
                    "model": data.get("model"),
                    "finish_reason": choices[0].get("finish_reason") if choices else None,
                    "usage": usage,
                    "backend": "vllm",
                },
                "error": None,
            }
        except Exception as e:
            return {
                "text": "",
                "duration": time.time() - start_time,
                "tokens": {"prompt": 0, "completion": 0, "total": 0},
                "meta": {},
                "error": f"{type(e).__name__}: {e}",
            }

    def generate_n(
        self,
        prompt: str,
        n: int,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = 2048,
        keep_alive=0,
        timeout: int = 300,
        num_ctx: int = 16384,
        num_gpu: Optional[int] = None,
        num_thread: Optional[int] = None,
        think: Optional[bool] = None,
        format: Optional[Union[str, dict]] = None,
    ) -> List[Dict]:
        """一次请求生成 n 条独立采样（OpenAI 兼容 n 参数）。

        供两阶段扫描的多票裁决复用：此前 N 次采样 = N 次串行请求，
        每次 pay 全量 prefill；vLLM 服务端对同一 prompt 的 n 条采样共享
        prefill（PagedAttention + parallel sampling），吞吐提升显著。

        Args:
            n: 采样条数（1~10）；n<=1 或 temperature<=0 时退化为循环
               generate()（OpenAI 语义下 n>1 需要 temperature>0）。
            其余参数与 generate() 一致（keep_alive/num_ctx/num_gpu/num_thread/
            think 为兼容占位，vLLM 侧 no-op）。

        Returns:
            list[dict]，每项与 generate() 返回结构相同（text/duration/tokens/
            meta/error）。服务端异常时整体退化为循环 generate()，单条失败时
            该项 error 非空——调用方按逐票无效处理，语义与循环版一致。
        """
        n = max(1, min(int(n), 10))
        # n<=1 无批量收益；temperature<=0（贪心）与 n>1 组合在 OpenAI 语义下
        # 非法（vLLM 会拒绝），且贪心采样 n 票必然相同、无自一致率意义
        if n <= 1 or temperature is None or temperature <= 0:
            return [
                self.generate(
                    prompt=prompt, system_prompt=system_prompt,
                    temperature=temperature, max_tokens=max_tokens,
                    keep_alive=keep_alive, timeout=timeout, num_ctx=num_ctx,
                    num_gpu=num_gpu, num_thread=num_thread, think=think,
                    format=format,
                )
                for _ in range(n)
            ]

        start_time = time.time()
        try:
            messages: List[Dict[str, str]] = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            payload: Dict = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "n": n,
                "stream": False,
            }
            if max_tokens is not None:
                payload["max_tokens"] = max_tokens
            if format is not None:
                payload["guided_json"] = format if isinstance(format, dict) else "json"

            resp = requests.post(self.api_chat, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()

            choices = data.get("choices", [])
            usage = data.get("usage", {})
            prompt_count = usage.get("prompt_tokens", 0)
            # completion_tokens 是全部 n 条的总和，按条均摊供逐票统计参考
            completion_count = usage.get("completion_tokens", 0)
            duration = time.time() - start_time

            results: List[Dict] = []
            for choice in choices:
                msg = choice.get("message", {}) or {}
                results.append({
                    "text": msg.get("content", ""),
                    "duration": duration,
                    "tokens": {
                        "prompt": prompt_count // max(len(choices), 1),
                        "completion": completion_count // max(len(choices), 1),
                        "total": (prompt_count + completion_count) // max(len(choices), 1),
                    },
                    "meta": {
                        "id": data.get("id"),
                        "model": data.get("model"),
                        "finish_reason": choice.get("finish_reason"),
                        "usage": usage,
                        "backend": "vllm",
                        "batched_n": n,
                    },
                    "error": None,
                })
            # 服务端返回条数不足（极端情况）时，缺失票按 error 占位，
            # 调用方按 invalid 票处理，保持票数对齐 n
            while len(results) < n:
                results.append({
                    "text": "", "duration": duration,
                    "tokens": {"prompt": 0, "completion": 0, "total": 0},
                    "meta": {"backend": "vllm", "batched_n": n},
                    "error": "vllm 返回采样数不足",
                })
            return results
        except Exception as e:
            # 整体失败退化为循环 generate：批量路径故障不改变扫描可用性
            print(f"[VLLMClient] generate_n 失败，退化为逐条采样: {e}")
            return [
                self.generate(
                    prompt=prompt, system_prompt=system_prompt,
                    temperature=temperature, max_tokens=max_tokens,
                    keep_alive=keep_alive, timeout=timeout, num_ctx=num_ctx,
                    num_gpu=num_gpu, num_thread=num_thread, think=think,
                    format=format,
                )
                for _ in range(n)
            ]

    def generate_structured(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = 1024,
        keep_alive=0,
        timeout: int = 300,
        num_ctx: int = 16384,
        num_gpu: Optional[int] = None,
        num_thread: Optional[int] = None,
        think: Optional[bool] = None,
    ) -> Dict:
        """使用 vLLM guided_json 约束解码生成结构化输出。

        约束模型输出为匹配 _STRUCTURED_OUTPUT_SCHEMA 的合法 JSON，
        消除 JSON 解析失败的风险。适用于不需要 CoT 分析的快速判定场景。

        num_ctx / num_gpu / num_thread 为兼容 OllamaClient 接口而保留，
        vLLM 在启动时统一管理这些参数，运行时忽略（no-op）。

        注意：此方法约束整个输出为 JSON（无 CoT 分析文本）。
        如需 CoT + 结构化输出，请用两轮调用（先 CoT 分析再结构化提取）。

        Returns:
            与 generate() 相同的返回结构，text 字段为合法 JSON 字符串。
        """
        return self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            keep_alive=keep_alive,
            timeout=timeout,
            num_ctx=num_ctx,
            num_gpu=num_gpu,
            num_thread=num_thread,
            think=think,
            format=_STRUCTURED_OUTPUT_SCHEMA,
        )

    def unload_model(self, timeout: int = 60) -> bool:
        """主动从显存卸载模型。

        vLLM 不支持运行时卸载模型（模型在服务启动时加载，常驻显存），
        此处为 no-op，直接返回 True 以保持接口兼容。
        多模型场景下 vLLM 通过 --tensor-parallel-size 等启动参数管理显存。

        Returns:
            始终返回 True
        """
        return True

    def analyze_vulnerability(
        self,
        code: str,
        language: str = "python",
        rag_context: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> Dict:
        """
        分析代码漏洞（RAG 增强版）

        Args:
            code: 待分析代码
            language: 代码语言
            rag_context: RAG 检索到的相关知识（可选）
            filename: 代码文件名（可选，提供给模型作为上下文）

        Returns:
            generate() 的返回值，text 字段为模型输出（含 JSON 结论块）。
            统一输出 schema 见 VERDICT_SCHEMA（定义在 graduation_project.schema）。
        """
        prompt = build_user_prompt(
            code=code,
            language=language,
            filename=filename,
            rag_context=rag_context,
        )
        return self.generate(prompt, system_prompt=V3_PROMPT)


def create_llm_client(backend: str = "ollama", **kwargs) -> Union["OllamaClient", "VLLMClient"]:
    """LLM 客户端工厂函数，根据 backend 返回对应后端客户端。

    便于在配置文件中切换推理后端，无需修改调用方代码。

    Args:
        backend: 后端类型，"ollama" 或 "vllm"
        **kwargs: 传递给对应客户端构造函数的参数（如 base_url、model）

    Returns:
        OllamaClient 或 VLLMClient 实例

    Raises:
        ValueError: backend 不支持时
    """
    # 延迟导入 OllamaClient 以避免循环依赖
    from graduation_project.llm_client import OllamaClient

    backend_lower = backend.lower().strip()
    if backend_lower == "ollama":
        return OllamaClient(**kwargs)
    elif backend_lower == "vllm":
        return VLLMClient(**kwargs)
    else:
        raise ValueError(f"不支持的 backend: {backend}，目前仅支持 'ollama' 或 'vllm'")


if __name__ == "__main__":
    # 使用 vLLM 后端测试
    from app.backend.services.model_registry import get_default_model
    client = VLLMClient(model=get_default_model())

    # 检查连接
    if not client.check_connection():
        print("[VLLMClient] 无法连接到 vLLM，请确保服务已启动（默认 http://localhost:8000）")
        exit(1)

    print(f"[VLLMClient] 已连接，可用模型: {client.list_models()}")

    # 简单测试
    test_code = '''
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchone()
'''

    result = client.analyze_vulnerability(test_code, "python")
    if result["error"]:
        print(f"\n[错误] {result['error']}")
    else:
        print(f"\n分析耗时: {result['duration']:.2f}s")
        print(f"Token 数: {result['tokens']}")
        print(f"\n分析结果:\n{result['text']}")

    # 测试工厂函数
    print("\n--- 测试工厂函数 ---")
    try:
        vllm_via_factory = create_llm_client(backend="vllm", model=get_default_model())
        print(f"工厂函数创建 VLLMClient 成功: {type(vllm_via_factory).__name__}")
    except Exception as e:
        print(f"工厂函数创建失败: {e}")
