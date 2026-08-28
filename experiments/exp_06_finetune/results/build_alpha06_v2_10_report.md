# alpha06-v2.10 行号吸附二段升级报告

- 输入 v2.9 8759 → 输出 8759（行数不变）
- Stage A 系统性偏移：22 条记录 / 76 处改写
- Stage B 计分消歧：419 处改写
- source/sink 精确命中：13934/16840 = 82.7% → 14358/16840 = 85.3%

## Stage A 抽样
#319 source line 30→40 (k=10)
#319 sink line 31→41 (k=10)
#319 fix_suggestion line 30→40 (k=10)
#360 source line 27→41 (k=14)
#360 sink line 28→42 (k=14)
#360 fix_suggestion line 27→41 (k=14)
#360 fix_suggestion line 28→42 (k=14)
#453 source line 33→43 (k=10)
#453 sink line 34→44 (k=10)
#453 fix_suggestion line 33→43 (k=10)
#453 fix_suggestion line 34→44 (k=10)
#453 fix_suggestion line 34→44 (k=10)
#472 source line 19→32 (k=13)
#472 sink line 20→33 (k=13)
#472 fix_suggestion line 19→32 (k=13)
#700 fix_suggestion line 24→25 (k=1)
#700 fix_suggestion line 24→25 (k=1)
#700 fix_suggestion line 24→25 (k=1)
#1115 source line 12→14 (k=2)
#1115 sink line 24→26 (k=2)
#1115 fix_suggestion line 12→14 (k=2)
#1115 fix_suggestion line 24→26 (k=2)
#1285 source line 19→29 (k=10)
#1285 sink line 20→30 (k=10)
#1285 fix_suggestion line 19→29 (k=10)
#1285 fix_suggestion line 20→30 (k=10)
#1536 source line 27→33 (k=6)
#1536 sink line 28→34 (k=6)
#1536 fix_suggestion line 27→33 (k=6)
#1536 fix_suggestion line 28→34 (k=6)
#1591 source line 31→49 (k=18)
#1591 sink line 32→50 (k=18)
#1591 fix_suggestion line 31→49 (k=18)
#1591 fix_suggestion line 32→50 (k=18)
#1771 source line 9→15 (k=6)
#1771 sink line 11→17 (k=6)
#1771 fix_suggestion line 9→15 (k=6)
#1771 fix_suggestion line 11→17 (k=6)
#1929 source line 1→2 (k=1)
#1929 sink line 3→4 (k=1)

## Stage B 抽样
#1 sink line 24→23
#12 sink line 45→47
#36 source line 49→45
#39 source line 24→28
#48 sink line 24→27
#67 source line 37→32
#71 source line 24→29
#74 source line 30→25
#79 sink line 47→50
#83 fix_suggestion line 32→35
#98 source line 18→21
#99 source line 18→23
#100 sink line 26→28
#106 sink line 31→35
#106 fix_suggestion line 31→35
#112 fix_suggestion line 62→59
#126 source line 31→27
#139 source line 25→26
#152 sink line 24→29
#153 sink line 45→40
#156 source line 22→25
#164 fix_suggestion line 16→17
#167 sink line 84→88
#175 sink line 24→25
#183 source line 24→26
#191 source line 20→19
#196 source line 22→25
#224 source line 21→24
#233 source line 18→13
#237 source line 42→46
#243 source line 28→27
#246 source line 19→20
#246 fix_suggestion line 19→18
#267 source line 13→15
#267 fix_suggestion line 13→15
#287 source line 22→25
#290 sink line 23→20
#294 source line 16→15
#297 fix_suggestion line 37→38
#297 fix_suggestion line 48→50