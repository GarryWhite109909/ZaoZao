# alpha06-v2.6 增量构建报告

- 基底：final_train_chatml_alpha06_v2_5.jsonl（8639 条，原样保留全部修复层）
- 增量候选 441 → 并入 **101** （基底重复 331 | 自身/尾哈希重复 0 | 断言拦 7 | 泄漏拦 2）
- 按来源：{'checklist': 5, 'wave2': 96}
- 按 kind：{'checklist_cot': 5, 'variant_framework': 25, 'variant_trust_vuln': 1, 'variant_crossfile': 70}
- **最终：8740 条** → `final_train_chatml_alpha06_v2_6.jsonl`

## 拦截明细（前40）
- [checklist] 泄漏 rdev/corpus_00067.py(J=0.837,C=0.987)（次近 rdev/corpus_00067.py J=0.837）
- [wave2] 泄漏 realsafe/corpus_00067.py(J=0.254,C=0.508)（次近 realsafe/corpus_00067.py J=0.254）