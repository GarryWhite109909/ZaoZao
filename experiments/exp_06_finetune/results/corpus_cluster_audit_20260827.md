# 真实语料近重复聚类审计（2026-08-27）

- 参与文件 504 | 近重复簇 **69** 个（阈值 J>=0.3 或 C>=0.45）
- 隔离淘汰的训练种子（训练候选与评测同簇）：**4** 个

## 隔离淘汰明细（这些 train_pool 文件今后不得作为蒸馏种子）

- `train_pool/corpus_00188.py` ↔ `rolling_dev_safe/corpus_00067.py`（相似度 1.000）
- `train_pool/corpus_00274.py` ↔ `rolling_dev/corpus_00077.py`（相似度 1.000）
- `train_pool/corpus_00064.js` ↔ `rolling_dev/corpus_00032.js`（相似度 0.957）
- `train_pool/corpus_00053.js` ↔ `rolling_dev/corpus_00032.js`（相似度 0.947）

## 使用方式
- `corpus_cluster_manifest.json`：构建管线组级校验（P2）数据源
- `corpus_cluster_blocklist.json`：生成器 seed 过滤（已接入两脚本）