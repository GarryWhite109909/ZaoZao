# -*- coding: utf-8 -*-
"""agent 执行版全量审计（v2_14）公共模块。

id = 源文件行号（1-based），此后一切输出用 id 对账。
"""
import hashlib
import json
import re
import sys
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]          # exp_06_finetune/
SRC = BASE / "data/final_train_chatml_alpha06_v2_14.jsonl"
OUT = Path(__file__).resolve().parent / "out"
OUT.mkdir(exist_ok=True)

FENCE = re.compile(r"```([\w+#.\-/]*)[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
JSON_BLOCK = re.compile(r"```json\s*(.*?)(?:```|\Z)", re.S)
FILE_SEP = re.compile(
    r"^(?:={3,}\s*(?:文件|File)|#{1,3}\s*(?:文件|File)\s*[:# ]|//\s*====\s*File|【文件\s*\d|File\s*\d+\s*[:：]|###\s*文件\s*[:：])",
    re.M)

# 教师行号引用：JSON 锚定式 "line 12:" / 叙事式 "第12行" / "lines 12-14"
RE_LINE_ANCHOR = re.compile(r"line\s*(\d{1,4})", re.I)
RE_LINE_CN = re.compile(r"第\s*(\d{1,4})\s*行")


def load_rows():
    rows = []
    bad_parse = []
    with SRC.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                rows.append({"id": i, "rec": json.loads(line)})
            except Exception as e:
                bad_parse.append({"id": i, "error": str(e)[:120]})
    return rows, bad_parse


def get_msgs(rec):
    return rec["rec"]["messages"] if isinstance(rec, dict) and "rec" in rec else rec["messages"]


def user_text(rec):
    m = rec["rec"]["messages"] if "rec" in rec else rec["messages"]
    return m[1]["content"]


def asst_text(rec):
    m = rec["rec"]["messages"] if "rec" in rec else rec["messages"]
    return m[2]["content"]


def sys_text(rec):
    m = rec["rec"]["messages"] if "rec" in rec else rec["messages"]
    return m[0]["content"]


def code_blocks(user):
    """返回 [(lang, code)]，按出现顺序。"""
    return [(m.group(1).lower(), m.group(2)) for m in FENCE.finditer(user)]


def joined_code(user):
    return "\n".join(c for _, c in code_blocks(user))


def is_multi_file(user):
    blocks = code_blocks(user)
    return len(blocks) >= 2 or bool(FILE_SEP.search(user))


def last_json(assistant):
    """返回 (obj|None, raw_block|None, error|None)。取最后一个 ```json 块。"""
    ms = list(JSON_BLOCK.finditer(assistant))
    if not ms:
        return None, None, "no_json_block"
    raw = ms[-1].group(1)
    try:
        return json.loads(raw), raw, None
    except Exception as e:
        return None, raw, f"parse_fail: {e}"


def analysis_body(assistant):
    return assistant.split("```json")[0] if "```json" in assistant else assistant


def strip_code(user):
    """去掉 fence 内容后的 user 文本（用于任务前缀/语言标签检查）。"""
    return FENCE.sub(lambda m: f"```{m.group(1)}```", user)


def hash01(s):
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:16]


def wcjk(s):
    return sum(1 for ch in s if "\u4e00" <= ch <= "\u9fff")


def token_est(text):
    """v2.12 体检拟合式：total = 1.616*中文 + 0.240*非中文。"""
    if not text:
        return 0
    c = wcjk(text)
    return 1.616 * c + 0.240 * (len(text) - c)


def pct(x, n):
    return f"{100.0 * x / n:.1f}%" if n else "n/a"


def write_jsonl(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
