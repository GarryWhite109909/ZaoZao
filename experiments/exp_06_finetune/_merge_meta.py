# -*- coding: utf-8 -*-
"""查 merge 评估文件 combined.20260812_082222 的完整元数据，验证 merge 评估是否合理。"""
import json
from pathlib import Path

RES = Path(r"d:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\results")
p = RES / "exp_06_eval.finetuned_custom.combined.20260812_082222.json"
d = json.loads(p.read_text(encoding="utf-8"))

print("=== 元数据 ===")
for k in ["experiment", "model", "checkpoint", "ollama_model", "started_at", "decoding", "note"]:
    print(f"{k}: {d.get(k)}")
print("samples:", len(d.get("samples", [])))
print("all_runs:", json.dumps(d.get("all_runs", {}), ensure_ascii=False)[:500])
print("multiseed_summary:", json.dumps(d.get("multiseed_summary", {}), ensure_ascii=False)[:300])
print("metrics:", json.dumps(d.get("metrics", {}), ensure_ascii=False))
print("strict_metrics:", json.dumps(d.get("strict_metrics", {}), ensure_ascii=False))

# 看第一个样本的 raw_output，判断推理质量
s0 = d["samples"][0]
print("\n=== 首个样本 ===")
print("file:", s0["file"], "| outcome:", s0.get("outcome"))
print("expected_cwe:", s0.get("expected_cwe"), "| model_vt:", s0.get("model_vulnerability_type"))
print("raw_output 前 600:")
print((s0.get("raw_output") or "")[:600])
