# -*- coding: utf-8 -*-
"""diffpair API 自动蒸馏（20260910）——DeepSeek API 并发调用，全量无人值守。

用法：
  export DEEPSEEK_API_KEY=sk-...   # 或 set DEEPSEEK_API_KEY=sk-... (Windows)
  python scripts/diffpair_api_distill_20260910.py [--limit N] [--model deepseek-chat]

产出：corpus/diffpair_wave1/api_results/ 逐样本 .jsonl + 汇总报告
"""
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import aiohttp
except ImportError:
    print("需要 aiohttp: pip install aiohttp"); sys.exit(1)

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
KITS = BASE / "corpus/diffpair_wave1/kits"
OUT = BASE / "corpus/diffpair_wave1/api_results"
OUT.mkdir(exist_ok=True)

API_URL = "https://api.deepseek.com/chat/completions"
MODEL = "deepseek-chat"  # 或 deepseek-reasoner
CONCURRENCY = 5          # 并发数
MAX_RETRY = 3
TIMEOUT = 120

SYSTEM_PROMPT = (BASE / "corpus/diffpair_wave1/learner_framed_prompt_v3.md").read_text(encoding="utf-8")


def parse_kit(path: Path):
    """解析 diffpair kit txt → (sample_id, version_a_code, version_b_code, lang)"""
    text = path.read_text(encoding="utf-8", errors="replace")
    mid = re.search(r'### id=(diffpair-\S+)', text)
    ml = re.search(r'lang=(\w+)', text)
    if not mid:
        return None
    sid = mid.group(1)
    lang = ml.group(1) if ml else "text"
    # 提取版本A/B
    parts = re.split(r'#### 版本[AB]', text)
    if len(parts) < 3:
        return None
    code_a = re.search(r'```\w*\n(.*?)```', parts[1], re.S)
    code_b = re.search(r'```\w*\n(.*?)```', parts[2], re.S)
    if not code_a or not code_b:
        return None
    return sid, lang, code_a.group(1).strip(), code_b.group(1).strip()


def build_messages(lang, code_a, code_b):
    user = (
        f"代码片段（语言: {lang}）：\n"
        f"#### 版本A（修复前）\n```{lang}\n{code_a}\n```\n\n"
        f"#### 版本B（修复后）\n```{lang}\n{code_b}\n```\n\n"
        "请按系统提示的格式，分别对版本A和版本B各输出一条完整分析记录。"
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


async def call_api(session, sample_id, messages, sem):
    async with sem:
        for attempt in range(1, MAX_RETRY + 1):
            try:
                async with session.post(API_URL, json={
                    "model": MODEL,
                    "messages": messages,
                    "max_tokens": 65536,
                    "temperature": 0.3,
                }, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as resp:
                    if resp.status == 429:
                        wait = 10 * attempt
                        print(f"  {sample_id} 429 限速，等 {wait}s")
                        await asyncio.sleep(wait)
                        continue
                    data = await resp.json()
                    content = data["choices"][0]["message"]["content"]
                    return sample_id, content, None
            except Exception as e:
                if attempt < MAX_RETRY:
                    await asyncio.sleep(5 * attempt)
                else:
                    return sample_id, None, str(e)[:120]
    return sample_id, None, "max retries"


async def main(limit, model):
    global MODEL
    MODEL = model
    api_key = os.environ.get("DEEPSEEK_API_KEY", "sk-1918f838bc3e45ea8215caeaaa61322b")
    if not api_key:
        print("错误：请设置 DEEPSEEK_API_KEY 环境变量"); sys.exit(1)

    # 收集全部 kit，跳过已完成的（api_results 或 deepseek_adapter 中已有产出）
    done_ids = set()
    adapter = BASE / "corpus/diffpair_wave1/parsed/deepseek_adapter.jsonl"
    if adapter.exists():
        for l in adapter.open(encoding="utf-8"):
            o = json.loads(l)
            done_ids.add(o.get("orig_id", ""))
    for p in OUT.glob("*.jsonl"):
        try:
            o = json.loads(p.read_text(encoding="utf-8"))
            if o.get("response") and len(o.get("response", "")) > 100:
                done_ids.add(o["id"])
        except Exception:
            pass

    kits = []
    for p in sorted(KITS.glob("diffpair-corpus_*.txt")):
        parsed = parse_kit(p)
        if not parsed:
            continue
        if parsed[0] in done_ids:
            continue
        kits.append(parsed)
    if limit:
        kits = kits[:limit]
    print(f"待处理: {len(kits)} 样本（跳过已完成 {len(done_ids)}）| 模型: {MODEL} | 并发: {CONCURRENCY}")

    sem = asyncio.Semaphore(CONCURRENCY)
    conn = aiohttp.TCPConnector(limit=CONCURRENCY + 2)
    async with aiohttp.ClientSession(
        connector=conn,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    ) as session:
        tasks = []
        for sid, lang, ca, cb in kits:
            msgs = build_messages(lang, ca, cb)
            tasks.append(call_api(session, sid, msgs, sem))

        done = 0
        for coro in asyncio.as_completed(tasks):
            sid, content, err = await coro
            done += 1
            outp = OUT / f"{sid}.jsonl"
            if err:
                print(f"[{done}/{len(kits)}] {sid} ✗ {err}")
                outp.write_text(json.dumps({"id": sid, "error": err}, ensure_ascii=False), encoding="utf-8")
            else:
                outp.write_text(json.dumps({"id": sid, "response": content}, ensure_ascii=False) + "\n", encoding="utf-8")
                print(f"[{done}/{len(kits)}] {sid} ✓ {len(content)} chars")

    ok = sum(1 for p in OUT.glob("*.jsonl") if "error" not in p.read_text(encoding="utf-8")[:50])
    print(f"\n完成: {ok}/{len(kits)} → {OUT}")


if __name__ == "__main__":
    limit = None
    model = "deepseek-chat"
    args = sys.argv[1:]
    if "--limit" in args:
        limit = int(args[args.index("--limit") + 1])
    if "--model" in args:
        model = args[args.index("--model") + 1]
    asyncio.run(main(limit, model))
