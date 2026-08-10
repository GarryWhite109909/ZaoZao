"""AST 代码切片模块 —— 用 tree-sitter 按函数/方法切分长文件。

解决长文件（如 hard_longfile_*）中 LLM 注意力衰减导致隐藏漏洞漏检的问题。

切片策略：
- 文件总行数 < min_lines（默认 150）→ 不切片，整文件作为单个 chunk 返回
- 文件 >= min_lines → 按顶层函数 / 类方法切分，每个切片包含：
    * 顶部 imports / 全局常量 / 模块 docstring（"上下文头"）
    * 类定义骨架（class ClassName: + docstring，不含方法体）
    * 当前函数 / 方法的完整代码
- 跨文件样本（hard_crossfile_*_sink.*）已在 run_experiment.py 层处理，本模块只切单文件

支持的 language 值：python / javascript / js / java / php / typescript / ts。
其他语言或不传 language → 退化为整文件返回（不报错）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
import tree_sitter_java as tsjava
import tree_sitter_php as tsphp
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser


# ---------------------------------------------------------------------------
# tree-sitter 语言对象注册表（各官方语言包，tree-sitter 0.25+ API）
# ---------------------------------------------------------------------------
_TS_LANGUAGE_OBJECTS = {
    "python": Language(tspython.language()),
    "javascript": Language(tsjs.language()),
    "java": Language(tsjava.language()),
    "php": Language(tsphp.language_php()),
    "typescript": Language(tsts.language_typescript()),
}


# ---------------------------------------------------------------------------
# 语言映射：项目内 language 标签 → tree-sitter parser 名
# ---------------------------------------------------------------------------
_LANGUAGE_MAP = {
    "python": "python",
    "py": "python",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "java": "java",
    "php": "php",
}


# tree-sitter 中"函数/方法定义"节点的 type（按语言）
_FUNCTION_NODE_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "function_expression", "arrow_function"},
    "typescript": {"function_declaration", "method_definition", "function_expression", "arrow_function"},
    "java": {"method_declaration", "constructor_declaration"},
    "php": {"function_definition", "method_declaration", "creation_expression"},
}

# 类定义节点 type
_CLASS_NODE_TYPES = {"class_declaration", "class_definition"}

# 顶层声明/导入节点 type（保留为上下文头）
_TOPLEVEL_KEEP_TYPES = {
    "python": {"import_statement", "import_from_statement", "expression_statement", "assignment"},
    "javascript": {"import_statement", "export_statement", "lexical_declaration", "variable_declaration"},
    "typescript": {"import_statement", "export_statement", "lexical_declaration", "variable_declaration"},
    "java": {"import_declaration", "package_declaration", "field_declaration"},
    "php": {"include_declaration", "include_expression", "require_expression", "simple_parameter", "assignment_expression"},
}


@dataclass
class SliceChunk:
    """单个代码切片。"""
    chunk_id: int
    name: str
    code: str
    start_line: int  # 1-indexed
    end_line: int     # 1-indexed
    node_type: str
    char_count: int = 0
    is_full_file: bool = False  # 整文件未切片时为 True

    def __post_init__(self):
        self.char_count = len(self.code)


@dataclass
class SliceResult:
    """切片结果。"""
    filename: str
    language: str
    total_lines: int
    sliced: bool  # 是否实际切片（False = 整文件单 chunk）
    chunks: list[SliceChunk] = field(default_factory=list)
    context_header: str = ""  # 切片时保留的上下文头（imports + 全局常量 + 类骨架）

    @property
    def chunk_count(self) -> int:
        return len(self.chunks)


class CodeSlicer:
    """按函数/方法切分长代码文件。

    Args:
        min_lines: 文件行数 < min_lines 时不切片，整文件返回（默认 150）
        min_chunk_lines: 切片后单个 chunk 最小行数，过短则合并到上下文头（默认 5）
    """

    def __init__(self, min_lines: int = 150, min_chunk_lines: int = 5):
        self.min_lines = min_lines
        self.min_chunk_lines = min_chunk_lines

    # ------------------------------------------------------------------
    # 公共 API
    # ------------------------------------------------------------------
    def slice(self, code: str, language: str, filename: str = "") -> SliceResult:
        """切分代码文件。

        Returns:
            SliceResult，chunks 至少含 1 个切片
        """
        ts_lang = _LANGUAGE_MAP.get((language or "").lower())
        total_lines = 0 if not code else code.count("\n") + (0 if code.endswith("\n") else 1)

        # 不支持的语言或文件太短 → 整文件单 chunk
        if not ts_lang or total_lines < self.min_lines:
            return self._full_file_result(code, language, filename, total_lines)

        try:
            parser = Parser(_TS_LANGUAGE_OBJECTS[ts_lang])
            tree = parser.parse(code.encode("utf-8"))
        except Exception:
            # 解析失败 → 退化为整文件
            return self._full_file_result(code, language, filename, total_lines)

        # 统一用 UTF-8 字节切片（tree-sitter 偏移是字节，str 切片遇中文会错位）
        code_bytes = code.encode("utf-8")

        # 提取上下文头（imports + 全局常量 + 顶层非函数声明）
        header_lines = self._extract_context_header(tree.root_node, code_bytes, ts_lang)

        # 提取所有顶层函数 + 类方法
        func_nodes = self._collect_function_nodes(tree.root_node, ts_lang)

        # 没有任何函数节点 → 整文件
        if not func_nodes:
            return self._full_file_result(code, language, filename, total_lines)

        # 构建切片：每个函数一个 chunk，前置 header
        chunks: list[SliceChunk] = []
        for idx, (node, qualname) in enumerate(func_nodes, 1):
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            # 短函数（< min_chunk_lines）也保留为切片：
            # 否则小函数既不在上下文头里、也不送 LLM，会被漏检
            func_code = self._slice_node_text(node, code_bytes)
            # 拼上下文头
            chunk_code = self._assemble_chunk(header_lines, func_code, qualname, ts_lang)
            chunks.append(SliceChunk(
                chunk_id=idx,
                name=qualname,
                code=chunk_code,
                start_line=start_line,
                end_line=end_line,
                node_type=node.type,
            ))

        if not chunks:
            return self._full_file_result(code, language, filename, total_lines)

        return SliceResult(
            filename=filename,
            language=language,
            total_lines=total_lines,
            sliced=True,
            chunks=chunks,
            context_header="\n".join(header_lines),
        )

    # ------------------------------------------------------------------
    # 内部实现
    # ------------------------------------------------------------------
    def _full_file_result(self, code: str, language: str, filename: str, total_lines: int) -> SliceResult:
        chunk = SliceChunk(
            chunk_id=1,
            name=filename or "<full_file>",
            code=code,
            start_line=1,
            end_line=total_lines,
            node_type="full_file",
            is_full_file=True,
        )
        return SliceResult(
            filename=filename,
            language=language,
            total_lines=total_lines,
            sliced=False,
            chunks=[chunk],
        )

    def _collect_function_nodes(self, root: Node, ts_lang: str) -> list[tuple[Node, str]]:
        """递归收集所有函数/方法定义节点，返回 (node, 限定名) 列表。

        限定名格式：Python `Class.method` / Java `Class.method` / JS `Class.method` / 顶层 `func`。
        """
        func_types = _FUNCTION_NODE_TYPES.get(ts_lang, set())
        class_types = _CLASS_NODE_TYPES
        result: list[tuple[Node, str]] = []

        def walk(node: Node, class_name: Optional[str] = None):
            for child in node.children:
                # 优先判断类，进入类后给方法加限定名
                if child.type in class_types:
                    # 找类名
                    cls_name = self._node_name(child) or "AnonymousClass"
                    # 把类级别的字段/常量也保留（不作为切片，但已在 header 提取过）
                    walk(child, cls_name)
                elif child.type in func_types:
                    fn_name = self._node_name(child) or "anonymous"
                    qual = f"{class_name}.{fn_name}" if class_name else fn_name
                    result.append((child, qual))
                    # 不再深入函数内部（不切嵌套函数）
                else:
                    walk(child, class_name)

        walk(root)
        return result

    def _node_name(self, node: Node) -> Optional[str]:
        """从函数/类定义节点提取名字（找第一个 identifier 子节点）。"""
        for child in node.children:
            if child.type in ("identifier", "property_identifier", "type_identifier"):
                return child.text.decode("utf-8")
        return None

    def _slice_node_text(self, node: Node, code_bytes: bytes) -> str:
        """提取节点的源代码文本（tree-sitter 偏移为字节，按字节切再解码）。"""
        return code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _extract_context_header(self, root: Node, code_bytes: bytes, ts_lang: str) -> list[str]:
        """提取文件顶部的 imports / 全局常量 / 模块 docstring，作为每个切片的上下文头。

        策略：遍历 root 的直接子节点，凡是"非函数/非类"的顶层声明都保留。
        类定义保留类头（class ClassName(Parent): + docstring），不含方法体——
        这样模型能看到类有哪些方法签名但不会重复方法代码。
        """
        keep_types = _TOPLEVEL_KEEP_TYPES.get(ts_lang, set())
        class_types = _CLASS_NODE_TYPES
        func_types = _FUNCTION_NODE_TYPES.get(ts_lang, set())

        header_parts: list[str] = []
        for child in root.children:
            t = child.type
            if t == "decorated_definition":
                # 装饰器定义：保留装饰器文本，内部定义走各自分支
                inner = next((c for c in child.children if c.type in class_types), None)
                if inner is not None:
                    skeleton = self._class_skeleton(inner, code_bytes, ts_lang)
                    if skeleton:
                        dec_text = code_bytes[child.start_byte:inner.start_byte].decode("utf-8", errors="replace")
                        header_parts.append(dec_text + skeleton)
                # 装饰器函数：跳过（函数体由切片负责）
                continue
            if t in func_types:
                continue  # 函数定义不进 header（切片本身）
            if t in class_types:
                # 类骨架：class ClassName(...): + docstring，不含方法体
                skeleton = self._class_skeleton(child, code_bytes, ts_lang)
                if skeleton:
                    header_parts.append(skeleton)
                continue
            # 其他顶层节点：imports / 全局赋值 / 装饰器 / 注释
            # 仅保留前若干行（避免噪音），但全量保留更安全
            if t in keep_types or t in ("comment", "block_comment", "documentation_string", "string"):
                text = code_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                # 过滤过长的多行字符串（如模块 docstring 限制到 500 字符）
                if len(text) > 500:
                    text = text[:500] + "...（截断）"
                header_parts.append(text)

        return header_parts

    def _class_skeleton(self, class_node: Node, code_bytes: bytes, ts_lang: str) -> str:
        """提取类骨架：class 头 + docstring + 字段声明，但不含方法体。"""
        cls_name = self._node_name(class_node) or "AnonymousClass"
        # 取类头第一行（class ClassName(Base):）
        start_line = class_node.start_point[0]
        end_line = class_node.end_point[0]
        code = code_bytes.decode("utf-8", errors="replace")
        lines = code.split("\n")[start_line:end_line + 1]

        skeleton_lines: list[str] = []
        # 第一行：class 定义头
        skeleton_lines.append(lines[0])
        # 找 docstring（Python）/ 第一个字段声明
        body_started = False
        for line in lines[1:]:
            stripped = line.strip()
            if not stripped:
                skeleton_lines.append(line)
                continue
            # Python: 跳过方法定义（def ...）
            if ts_lang == "python":
                if stripped.startswith("def ") or stripped.startswith("async def "):
                    continue
                # 类字段（简单赋值）保留
                if "=" in stripped and not stripped.startswith("@"):
                    skeleton_lines.append(line)
                # docstring 保留
                elif stripped.startswith('"""') or stripped.startswith("'''"):
                    skeleton_lines.append(line)
                else:
                    # 其他（装饰器、注释等）
                    if stripped.startswith("#") or stripped.startswith("@"):
                        skeleton_lines.append(line)
            elif ts_lang == "java":
                # Java 字段声明（不含方法体）：保留 ; 结尾的简单声明
                if stripped.endswith(";") and "(" not in stripped:
                    skeleton_lines.append(line)
            elif ts_lang in ("javascript", "typescript"):
                # JS 字段声明
                if "=" in stripped and not stripped.startswith("function") and "(" not in stripped:
                    skeleton_lines.append(line)
            elif ts_lang == "php":
                # PHP 类字段
                if "=" in stripped and "function" not in stripped:
                    skeleton_lines.append(line)

        # 末尾加注释说明
        skeleton_lines.append(f"    # ... (其他方法见各切片)")
        return "\n".join(skeleton_lines)

    def _assemble_chunk(self, header_lines: list[str], func_code: str, qualname: str, ts_lang: str) -> str:
        """组装单个切片：上下文头 + 当前函数。"""
        parts = []
        if header_lines:
            parts.append("# === 文件级上下文（imports / 全局常量 / 类骨架） ===")
            parts.extend(header_lines)
            parts.append("")
        parts.append(f"# === 当前分析目标：函数 {qualname} ===")
        parts.append(func_code)
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# 模块级便捷函数
# ---------------------------------------------------------------------------
_DEFAULT_SLICER = CodeSlicer()


def slice_code(code: str, language: str, filename: str = "", min_lines: int = 150) -> SliceResult:
    """便捷函数：切分代码。复用模块级单例 _DEFAULT_SLICER，仅自定义 min_lines 时新建实例。"""
    if min_lines == _DEFAULT_SLICER.min_lines:
        slicer = _DEFAULT_SLICER
    else:
        slicer = CodeSlicer(min_lines=min_lines)
    return slicer.slice(code, language=language, filename=filename)


if __name__ == "__main__":
    # 自检：用 hard_longfile_01 测试
    import sys
    from pathlib import Path

    if len(sys.argv) > 1:
        sample_path = Path(sys.argv[1])
    else:
        sample_path = Path(__file__).resolve().parents[1] / "experiments" / "exp_04_hard_samples" / "samples" / "hard_longfile_01_hidden_sql.py"

    code = sample_path.read_text(encoding="utf-8")
    result = slice_code(code, language="python", filename=sample_path.name)
    print(f"文件: {result.filename}")
    print(f"总行数: {result.total_lines}, 是否切片: {result.sliced}, 切片数: {result.chunk_count}")
    for c in result.chunks:
        print(f"  [#{c.chunk_id}] {c.name} ({c.node_type}, L{c.start_line}-L{c.end_line}, {c.char_count} 字符)")
    if result.chunks:
        print("\n=== 第一个切片预览（前 600 字符）===")
        print(result.chunks[0].code[:600])
