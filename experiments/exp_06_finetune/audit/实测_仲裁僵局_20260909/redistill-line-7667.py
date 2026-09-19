# ---- 文件级上下文（imports/全局量，仅供参考） ----

# === 文件级上下文（imports / 全局常量 / 类骨架） ===

"""

Custom code guardrail for LiteLLM.



This module provides a guardrail that executes user-defined Python-like code

to implement custom guardrail logic. The code runs in a sandboxed environment

with access to LiteLLM-provided primitives for common guardrail operations.



Example custom code (sync):



    def apply_guardrail(inputs, request_data, input_type):

        '''Block messages containing SSNs'''

        for text in inputs["texts"]:

            if regex_match(text, r"\\d{3}-\\d{2}-\\d{4}"):...（截断）

import asyncio

import threading

from typing import TYPE_CHECKING, Any, Dict, Literal, Optional, Type, cast

from fastapi import HTTPException

from litellm._logging import verbose_proxy_logger

from litellm.integrations.custom_guardrail import (

    CustomGuardrail,

    log_guardrail_information,

)

from litellm.types.guardrails import GuardrailEventHooks

from litellm.types.proxy.guardrails.guardrail_hooks.base import GuardrailConfigModel

from litellm.types.utils import GenericGuardrailAPIInputs

from .code_validator import CustomCodeValidationError, validate_custom_code

from .primitives import get_custom_code_primitives

class CustomCodeGuardrailError(Exception):

    """Raised when custom code guardrail execution fails."""

    # ... (其他方法见各切片)

class CustomCodeCompilationError(CustomCodeGuardrailError):

    """Raised when custom code fails to compile."""

    # ... (其他方法见各切片)

class CustomCodeExecutionError(CustomCodeGuardrailError):

    """Raised when custom code fails during execution."""

    # ... (其他方法见各切片)

class CustomCodeGuardrailConfigModel(GuardrailConfigModel):

    """Configuration parameters for the custom code guardrail."""

    custom_code: str

    """The Python-like code containing the apply_guardrail function."""

    # ... (其他方法见各切片)

class CustomCodeGuardrail(CustomGuardrail):

    """

    Guardrail that executes user-defined Python-like code.



    The code runs in a sandboxed environment that provides:

    - Access to LiteLLM primitives (regex_match, json_parse, etc.)

    - No file I/O or network access

    - No imports allowed



    Users write an `apply_guardrail(inputs, request_data, input_type)` function

    that returns one of:

    - allow() - let the request/response through

    - block(reason) - reject with a message

    - modify(texts=...) - transform the content



    Example:

        def apply_guardrail(inputs, request_data, input_type):

            for text in inputs["texts"]:

                if regex_match(text, r"password"):

                    return block("Sensitive content detected")

            return allow()

    """

    # ... (其他方法见各切片)



# === 当前分析目标：函数 CustomCodeGuardrail.apply_guardrail ===

202|     async def apply_guardrail(
203|         self,
204|         inputs: GenericGuardrailAPIInputs,
205|         request_data: dict,
206|         input_type: Literal["request", "response"],
207|         logging_obj: Optional["LiteLLMLoggingObj"] = None,
208|     ) -> GenericGuardrailAPIInputs:
209|         """
210|         Apply the custom code guardrail to the inputs.
211| 
212|         This method calls the user-defined apply_guardrail function and
213|         processes its result to determine the appropriate action.
214| 
215|         The user-defined function can be either sync or async:
216|         - Sync: def apply_guardrail(inputs, request_data, input_type): ...
217|         - Async: async def apply_guardrail(inputs, request_data, input_type): ...
218| 
219|         Async functions are recommended when using http_request, http_get, or
220|         http_post primitives to avoid blocking the event loop.
221| 
222|         Args:
223|             inputs: Dictionary containing texts, images, tool_calls
224|             request_data: The original request data with metadata
225|             input_type: "request" for pre-call, "response" for post-call
226|             logging_obj: Optional logging object
227| 
228|         Returns:
229|             GenericGuardrailAPIInputs - possibly modified
230| 
231|         Raises:
232|             HTTPException: If content is blocked
233|             CustomCodeExecutionError: If execution fails
234|         """
235|         if self._compiled_function is None:
236|             if self._compile_error:
237|                 raise CustomCodeExecutionError(
238|                     f"Custom code guardrail not compiled: {self._compile_error}"
239|                 )
240|             raise CustomCodeExecutionError("Custom code guardrail not compiled")
241| 
242|         try:
243|             # Prepare inputs dict for the function
244| 
245|             # Prepare request_data with safe subset of information
246|             safe_request_data = self._prepare_safe_request_data(request_data)
247| 
248|             # Execute the custom function - handle both sync and async functions
249|             result = self._compiled_function(inputs, safe_request_data, input_type)
250| 
251|             # If the function is async (returns a coroutine), await it
252|             if asyncio.iscoroutine(result):
253|                 result = await result
254| 
255|             # Process the result
256|             return self._process_result(
257|                 result=result,
258|                 inputs=inputs,
259|                 request_data=request_data,
260|                 input_type=input_type,
261|             )
262| 
263|         except HTTPException:
264|             # Re-raise HTTP exceptions (from block action)
265|             raise
266|         except Exception as e:
267|             verbose_proxy_logger.error(
268|                 f"Custom code guardrail '{self.guardrail_name}' execution error: {e}"
269|             )
270|             raise CustomCodeExecutionError(
271|                 f"Custom code guardrail execution failed: {e}",
272|                 details={
273|                     "guardrail_name": self.guardrail_name,
274|                     "input_type": input_type,
275|                 },
276|             ) from e

# ---- 该函数的外部调用点（函数参数来源证据，关键于判定是否用户可控） ----

1| L19: async def apply_guardrail(inputs, request_data, input_type):
2| L91: Users write an `apply_guardrail(inputs, request_data, input_type)` function
3| L178: "Expected signature: apply_guardrail(inputs, request_data, input_type)"
4| L202: async def apply_guardrail(
5| L216: - Sync: def apply_guardrail(inputs, request_data, input_type): ...
6| L217: - Async: async def apply_guardrail(inputs, request_data, input_type): ...

{"has_vulnerability": true/false, "vulnerability_type": "CWE-编号 漏洞名（true 时必填，须基于代码分析而非工具标注；false 填 none）", "explanation": "数据流/成因（用 -> 描述）", "fix_suggestion": "最小局部改正；false 填 no fix needed"}

