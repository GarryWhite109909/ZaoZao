# redistill 待替换清单（2026-09-09）

merged_stage 220 条：结论一致 待替换 **79** 条，代码定位不到 **6** 条

| 档 | 数量 | 含义 |
|---|---:|---|
| A_直接替换 | 36 | verify 干净，仅 CWE 重归类（has_vuln 不变）|
| B_补锚句后换 | 8 | C6 近邻族缺互斥锚句，补锚句后可换 |
| C_人工终裁 | 35 | FLIP 翻转（has_vuln 变化），且部分与执行证据冲突 |

## C_人工终裁
| 行号 | redistill id | 旧结论 | 新结论 | flags |
|---|---|---|---|---|
| 1044 |  | False/ | True/CWE-916 | FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 110 |  | True/CWE-125 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 1126 |  | True/CWE-441 | True/CWE-798 | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 116 |  | True/CWE-415 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 1587 |  | True/CWE-416 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 165 |  | True/CWE-120 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 227 |  | True/CWE-416 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 235 |  | True/CWE-120 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 3020 |  | False/ | True/CWE-78 | C6 近邻族 CWE-78 缺互斥锚句; FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 3957 |  | False/ | True/CWE-22 | C6 近邻族 CWE-22 缺互斥锚句; FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 4848 |  | False/ | True/CWE-321 | FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 5119 |  | False/ | True/CWE-416 | FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 61 |  | True/CWE-416 | True/CWE-200 | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 7377 |  | True/CWE-441 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 7435 |  | True/CWE-441 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 7463 |  | True/CWE-327 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 7470 |  | True/CWE-22 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 7472 |  | True/CWE-22 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 7730 |  | False/ | True/CWE-755 | FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 7771 |  | False/ | True/CWE-732 | FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 7846 |  | False/ | True/CWE-22 | C6 近邻族 CWE-22 缺互斥锚句; FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 7859 |  | False/ | True/CWE-79 | FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 8084 |  | False/ | True/CWE-22 | FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 8085 |  | True/CWE-918 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8088 |  | True/CWE-639 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8090 |  | True/CWE-862 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8091 |  | True/CWE-79 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8093 |  | True/CWE-807 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8096 |  | True/CWE-79 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8097 |  | True/CWE-22 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8098 |  | True/CWE-22 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8100 |  | True/CWE-770 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8101 |  | True/CWE-770 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |
| 8178 |  | False/ | True/CWE-22 | C6 近邻族 CWE-22 缺互斥锚句; FLIP 判定翻转（原 False → 新 True）→ 人工复核 |
| 82 |  | True/CWE-415 | False/ | FLIP 判定翻转（原 True → 新 False）→ 人工复核 |

## B_补锚句后换
| 行号 | redistill id | 旧结论 | 新结论 | flags |
|---|---|---|---|---|
| 1321 |  | True/CWE-326 | True/CWE-327 | C6 近邻族 CWE-327 缺互斥锚句 |
| 1372 |  | True/CWE-326 | True/CWE-327 | C6 近邻族 CWE-327 缺互斥锚句 |
| 1433 |  | True/CWE-326 | True/CWE-327 | C6 近邻族 CWE-327 缺互斥锚句 |
| 273 |  | True/CWE-912 | True/CWE-78 | C6 近邻族 CWE-78 缺互斥锚句 |
| 361 |  | True/CWE-912 | True/CWE-78 | C6 近邻族 CWE-78 缺互斥锚句 |
| 591 |  | True/CWE-912 | True/CWE-78 | C6 近邻族 CWE-78 缺互斥锚句 |
| 685 |  | True/CWE-798 | True/CWE-22 | C6 近邻族 CWE-22 缺互斥锚句 |
| 851 |  | True/CWE-1336 | True/CWE-94 | C6 近邻族 CWE-94 缺互斥锚句 |

## A_直接替换
| 行号 | redistill id | 旧结论 | 新结论 | flags |
|---|---|---|---|---|
| 7135 |  | True/CWE-208 | True/CWE-321 |  |
| 2255 |  | True/CWE-208 | True/CWE-203 |  |
| 6855 |  | True/CWE-862 | True/CWE-306 |  |
| 6861 |  | True/CWE-862 | True/CWE-306 |  |
| 1630 |  | True/CWE-918 | True/CWE-862 |  |
| 1721 |  | True/CWE-502 | True/CWE-565 |  |
| 228 |  | True/CWE-367 | True/CWE-61 |  |
| 1515 |  | True/CWE-502 | True/CWE-150 |  |
| 39 |  | True/CWE-122 | True/CWE-787 |  |
| 163 |  | True/CWE-120 | True/CWE-122 |  |
| 1724 |  | True/CWE-798 | True/CWE-321 |  |
| 2471 |  | True/CWE-330 | True/CWE-338 |  |
| 155 |  | True/CWE-416 | True/CWE-401 |  |
| 1530 |  | True/CWE-798 | True/CWE-321 |  |
| 809 |  | True/CWE-90 | True/CWE-798 |  |
| 2489 |  | True/CWE-330 | True/CWE-338 |  |
| 913 |  | True/CWE-611 | True/CWE-1236 |  |
| 66 |  | True/CWE-122 | True/CWE-125 |  |
| 2476 |  | True/CWE-330 | True/CWE-338 |  |
| 2487 |  | True/CWE-330 | True/CWE-338 |  |
| 529 |  | True/CWE-78 | True/CWE-798 |  |
| 1512 |  | True/CWE-798 | True/CWE-916 |  |
| 1046 |  | True/CWE-601 | True/CWE-79 |  |
| 185 |  | True/CWE-367 | True/CWE-362 |  |
| 1015 |  | True/CWE-441 | True/CWE-321 |  |
| 2492 |  | True/CWE-330 | True/CWE-338 |  |
| 58 |  | True/CWE-120 | True/CWE-122 |  |
| 230 |  | True/CWE-121 | True/CWE-908 |  |
| 1168 |  | True/CWE-352 | True/CWE-640 |  |
| 1593 |  | True/CWE-798 | True/CWE-321 |  |
| 144 |  | True/CWE-415 | True/CWE-787 |  |
| 54 |  | True/CWE-121 | True/CWE-787 |  |
| 7436 |  | True/CWE-90 | True/CWE-295 |  |
| 40 |  | True/CWE-125 | True/CWE-787 |  |
| 10051 |  | True/CWE-20 | True/CWE-129 |  |
| 7870 |  | True/CWE-862 | True/CWE-639 |  |

## 代码定位不到（6 条，需人工核对是新样本还是代码被改）
-  flags=[]
-  flags=[]
-  flags=[]
-  flags=[]
-  flags=[]
-  flags=[]