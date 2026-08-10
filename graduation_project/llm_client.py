"""
Ollama LLM 客户端
封装本地模型调用，支持 RAG 增强的漏洞检测
"""

import json
import sys
import requests
import time
from typing import Dict, List, Optional, Union

# schema 与 prompt 统一从 graduation_project.schema / graduation_project.prompts 导入（全项目唯一来源）。
# 此处 re-export 仅为向后兼容历史代码 `from graduation_project.llm_client import parse_verdict`。
from graduation_project.schema import VERDICT_SCHEMA, parse_verdict, normalize_has_vulnerability
from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt


def _strip_latest(name: str) -> str:
    """去掉 Ollama 报告名称末尾的 :latest，统一为无标签形式（与注册表 full_name 对齐）。"""
    if name.endswith(":latest"):
        return name[: -len(":latest")]
    return name

__all__ = [
    "OllamaClient",
    "VERDICT_SCHEMA",
    "parse_verdict",
    "normalize_has_vulnerability",
]


# Ollama format=json 约束解码用的 JSON Schema（Pydantic 风格）
# Ollama 0.1.34+ 支持 format 参数传入 JSON Schema dict，约束模型输出为合法 JSON
# 参考: https://ollama.com/blog/structured-outputs
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


class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "garrywhite109909/graduation-vuln-scanner:v9max"):
        self.base_url = base_url
        self.model = model
        self.api_generate = f"{base_url}/api/generate"
        self.api_chat = f"{base_url}/api/chat"
        
    def check_connection(self) -> bool:
        """检查 Ollama 服务是否运行"""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
    
    def list_models(self) -> List[str]:
        """列出可用模型"""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=10)
            data = resp.json()
            # 去掉 :latest，与注册表 full_name（无标签）对齐，避免误判“未安装”
            return [_strip_latest(m["name"]) for m in data.get("models", [])]
        except Exception as e:
            print(f"[OllamaClient] 获取模型列表失败: {e}")
            return []
    
    @staticmethod
    def _normalize_keep_alive(keep_alive) -> object:
        """规范化 keep_alive 参数。

        Ollama 0.x 旧版本接受字符串 "-1" / "0"；新版本（2024+）要求
        字符串必须带单位（如 "30m"），但整数 -1 / 0 仍可用。

        为兼容历史调用方（脚本中传字符串），此处把无单位的字符串 "-1" / "0"
        自动转为整数。带单位的字符串（如 "5m"）原样透传。
        """
        if isinstance(keep_alive, str):
            if keep_alive == "-1":
                return -1
            if keep_alive == "0":
                return 0
        return keep_alive

    @staticmethod
    def _is_thinking_model(model: str) -> bool:
        """判断模型是否为 thinking-capable 模型（如 Qwen3）。

        Ollama 0.30+ 把这类模型的思考内容分离到 thinking 字段，
        generate API 的 response 字段会为空。必须用 chat API + think:false 禁用。
        """
        name = model.lower()
        return "qwen3" in name or "qwq" in name or "deepseek-r1" in name

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
        生成文本

        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词
            temperature: 温度（越低越确定）
            max_tokens: 最大生成长度；None 表示不设上限（用 Ollama 默认）
            keep_alive: 模型保留时间；0 表示用完卸载，-1 表示常驻，
                        也可传带单位的字符串如 "5m"（兼容旧版字符串 "-1"/"0"）
            timeout: 请求超时秒数
            num_ctx: 上下文窗口 token 数（默认 16384）。
                     Ollama 默认仅 4096，对长文件/RAG 场景不足，
                     exp_04 中 4 个难样本因 4096 截断导致输出为空。
                     gemma4:12b 原生支持 256K，16384 足够覆盖长文件+RAG。
            num_gpu: GPU offload 层数。None 表示 Ollama 自动判断（默认）；
                     0 表示纯 CPU；-1 表示全部 GPU；正数 N 表示前 N 层在 GPU，
                     其余在 CPU。大模型（20b+）在 16k 上下文时，显存可能不足以
                     放全部层，Ollama 自动混合模式下 GPU 利用率可能偏低，
                     可手动调整此参数优化 CPU+GPU 协同（配合高带宽 DDR5）。
            num_thread: CPU 推理线程数。None 表示 Ollama 默认（通常=物理核数）。
                        大模型 CPU offload 部分受 CPU 线程数影响，DDR5 高带宽
                        场景可适当增大以充分利用内存带宽。
            think: 是否启用 thinking mode。None 表示自动判断（thinking-capable
                   模型默认 False，其他模型忽略）。Ollama 0.30+ 把 Qwen3 等
                   模型的思考内容分离到 thinking 字段，generate API 的 response
                   会为空；必须用 chat API + think:false 禁用思考块。
            format: Ollama 结构化输出约束。None 表示不约束（默认，CoT+JSON 模式）；
                    "json" 表示约束输出为合法 JSON（不含 CoT 文本）；
                    传入 dict（JSON Schema）表示约束输出匹配该 Schema。
                    注意：format=json 会约束整个输出为 JSON，不能与 CoT 分析共存。
                    如需 CoT + 结构化输出，请用 generate_structured() 两轮调用。

        Returns:
            {"text": str, "duration": float, "tokens": dict, "meta": dict, "error": str|None}
            error 为 None 表示成功；非 None 时 text 为空字符串。
        """
        options = {"temperature": temperature, "num_ctx": num_ctx}
        if max_tokens is not None:
            options["num_predict"] = max_tokens
        if num_gpu is not None:
            options["num_gpu"] = num_gpu
        if num_thread is not None:
            options["num_thread"] = num_thread

        # thinking-capable 模型（Qwen3 等）必须用 chat API + think:false，
        # 否则 Ollama 0.30+ 会把思考内容放进 thinking 字段，response 为空。
        # /no_think 后缀在 generate API 上不生效（实测 Ollama 0.30.11）。
        use_chat_api = self._is_thinking_model(self.model)
        if think is None:
            think = False if use_chat_api else None

        start_time = time.time()

        try:
            if use_chat_api:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                payload = {
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": options,
                    "keep_alive": self._normalize_keep_alive(keep_alive),
                }
                if think is not None:
                    payload["think"] = think
                if format is not None:
                    payload["format"] = format

                resp = requests.post(self.api_chat, json=payload, timeout=timeout)
                resp.raise_for_status()
                data = resp.json()

                msg = data.get("message", {})
                text = msg.get("content", "")
            else:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": options,
                    "keep_alive": self._normalize_keep_alive(keep_alive),
                }
                if system_prompt:
                    payload["system"] = system_prompt
                if format is not None:
                    payload["format"] = format

                resp = requests.post(self.api_generate, json=payload, timeout=timeout)
                resp.raise_for_status()
                data = resp.json()

                text = data.get("response", "")

            duration = time.time() - start_time

            prompt_count = data.get("prompt_eval_count") or 0
            completion_count = data.get("eval_count") or 0

            return {
                "text": text,
                "duration": duration,
                "tokens": {
                    "prompt": prompt_count,
                    "completion": completion_count,
                    "total": prompt_count + completion_count,
                },
                "meta": {
                    "eval_count": data.get("eval_count"),
                    "eval_duration_ns": data.get("eval_duration"),
                    "load_duration_ns": data.get("load_duration"),
                    "total_duration_ns": data.get("total_duration"),
                    "prompt_eval_count": data.get("prompt_eval_count"),
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
        """使用 Ollama format=json 约束解码生成结构化输出。

        约束模型输出为匹配 _STRUCTURED_OUTPUT_SCHEMA 的合法 JSON，
        消除 JSON 解析失败的风险。适用于不需要 CoT 分析的快速判定场景。

        num_ctx / num_gpu / num_thread 与 generate() 语义一致，由 scanner.py
        从环境变量（bootstrap.py 硬件检测写入）传入，确保约束解码兜底也使用
        与首轮 CoT 推理相同的硬件适配参数，避免低显存设备上 num_ctx 过大导致 OOM。

        注意：此方法约束整个输出为 JSON（无 CoT 分析文本）。
        如需 CoT + 结构化输出，请用 analyze_with_cot_and_structure() 两轮调用。

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
        """主动从显存卸载模型（keep_alive=0）。多模型场景下避免爆显存。

        返回 True 表示卸载请求成功发出。
        """
        payload = {"model": self.model, "keep_alive": 0}
        try:
            resp = requests.post(self.api_generate, json=payload, timeout=timeout)
            resp.raise_for_status()
            return True
        except Exception as e:
            print(f"[OllamaClient] 卸载模型失败: {e}", file=sys.stderr)
            return False

    # ------------------------------------------------------------------
    # 模型管理：拉取 / 删除 / 查询（供前端模型管理 UI 调用）
    # ------------------------------------------------------------------
    def pull_model(self, model: str, stream_callback=None, timeout: int = 600) -> dict:
        """流式拉取模型（调用 Ollama /api/pull）。

        拉取完成后模型即可使用（Modelfile 已内置 SYSTEM prompt 和推理参数）。
        Ollama 会把模型文件存入 ~/.ollama 目录。

        Args:
            model: 模型全名（如 garrywhite109909/graduation-vuln-scanner:v9max）
            stream_callback: 可选回调，每收到一行 NDJSON 就调用 callback(chunk_dict)
            timeout: 总超时秒数（大模型拉取可能需要数分钟）

        Returns:
            {"success": bool, "error": str|None, "final_status": str}
        """
        url = f"{self.base_url}/api/pull"
        payload = {"name": model, "stream": True}
        final_status = ""
        try:
            resp = requests.post(url, json=payload, timeout=timeout, stream=True)
            resp.raise_for_status()
            for line in resp.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue
                final_status = chunk.get("status", "")
                if stream_callback:
                    stream_callback(chunk)
                # error 字段存在时表示拉取失败
                if chunk.get("error"):
                    return {"success": False, "error": chunk["error"], "final_status": final_status}
            # success 状态表示拉取完成
            return {"success": final_status == "success", "error": None, "final_status": final_status}
        except Exception as e:
            return {"success": False, "error": str(e), "final_status": final_status}

    def delete_model(self, model: str, timeout: int = 60) -> dict:
        """删除模型（调用 Ollama /api/delete）。

        从 ~/.ollama 目录彻底删除模型的 blob 文件，释放磁盘空间。
        与 unload_model 不同：unload 只是卸载显存，delete 删除文件。

        Returns:
            {"success": bool, "error": str|None}
        """
        url = f"{self.base_url}/api/delete"
        payload = {"name": model}
        try:
            resp = requests.delete(url, json=payload, timeout=timeout)
            if resp.status_code == 404:
                return {"success": False, "error": "模型不存在（可能已被删除）"}
            resp.raise_for_status()
            return {"success": True, "error": None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def show_model(self, model: str, timeout: int = 30) -> Optional[dict]:
        """查询模型详情（调用 Ollama /api/show）。

        返回模型的 Modelfile、参数、模板等信息；模型不存在时返回 None。
        """
        url = f"{self.base_url}/api/show"
        payload = {"name": model}
        try:
            resp = requests.post(url, json=payload, timeout=timeout)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    def get_model_size(self, model: str) -> Optional[int]:
        """返回模型磁盘占用字节数（从 /api/tags 的 details.size 获取）。"""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=10)
            data = resp.json()
            for m in data.get("models", []):
                if _strip_latest(m.get("name") or "") == model or m.get("model") == model:
                    details = m.get("details", {})
                    return details.get("size") or m.get("size")
            return None
        except Exception:
            return None
    
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
        return self.generate(prompt, system_prompt=SYSTEM_PROMPT)


if __name__ == "__main__":
    client = OllamaClient(model="garrywhite109909/graduation-vuln-scanner:v9max")
    
    # 检查连接
    if not client.check_connection():
        print("[OllamaClient] 无法连接到 Ollama，请确保服务已启动")
        exit(1)
    
    print(f"[OllamaClient] 已连接，可用模型: {client.list_models()}")
    
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
