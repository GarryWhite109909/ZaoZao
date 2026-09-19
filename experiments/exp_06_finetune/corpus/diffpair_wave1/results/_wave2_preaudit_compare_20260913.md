# wave2 预审统一比对报告（20260913）

46 对。分类：{'TAG_DISPUTE': 7, 'COND_A': 7, 'PASS': 29, 'SIDE_B_HOLE': 2, 'VULN_INVALID': 1}

## SIDE_B_HOLE（2）

| 对 | oracle | A 判定 | B 判定 | 备注 |
|---|---|---|---|---|
| 441-09 | CWE-441 | true/CWE-799 | true/CWE-799 | B: CWE-799 | CWE-799 Improper Control of Interaction Frequenc |
| 441-10 | CWE-441 | true/CWE-799 | true/CWE-799 | B: CWE-799 | CWE-799 Improper Control of Interaction Frequenc |

## VULN_INVALID（1）

| 对 | oracle | A 判定 | B 判定 | 备注 |
|---|---|---|---|---|
| 95-09 | CWE-95 | false/CWE-915 | false/CWE-915 |  |

## COND_A（7）

| 对 | oracle | A 判定 | B 判定 | 备注 |
|---|---|---|---|---|
| 441-05 | CWE-441 | false/- | false/- | | CWE-无 无 | Low |
| 441-06 | CWE-441 | false/- | false/- | | CWE-无 无 | Low |
| 78-S-02b | CWE-78 | false/CWE-78 | false/CWE-78 | | CWE-78 OS Command Injection（无 shell 层未触发） | Low |
| 78-S-05 | CWE-78 | false/CWE-78 | false/CWE-78 | | CWE-78 OS Command Injection（预期注入被 Runtime.exec 单串切分破坏，不可达） |
| 78-S-10b | CWE-78 | false/CWE-78 | false/CWE-78 | | CWE-78 OS Command Injection（无 shell 层未触发；残余提权/参数注入面均依赖样本外） |
| 78-S-15 | CWE-78 | false/CWE-78 | true/CWE-22 | | CWE-78 OS Command Injection（注释声称的注入不可达） | Low |
| 95-10 | CWE-95 | false/CWE-95 | true/CWE-79 | | CWE-95 Eval Injection（/e 求值位存在但被类型声明与 PHP 版本互斥封死，链不可达） | L |

## TAG_DISPUTE（7）

| 对 | oracle | A 判定 | B 判定 | 备注 |
|---|---|---|---|---|
| 441-01 | CWE-441 | true/CWE-799 | false/- | 教师判 CWE-799 |
| 441-02 | CWE-441 | true/CWE-799 | false/- | 教师判 CWE-799 |
| 441-03 | CWE-441 | true/CWE-290 | false/- | 教师判 CWE-290 |
| 441-04 | CWE-441 | true/CWE-290 | false/- | 教师判 CWE-290 |
| 441-11 | CWE-441 | true/CWE-640 | false/- | 教师判 CWE-640 |
| 441-12 | CWE-441 | true/CWE-640 | false/- | 教师判 CWE-640 |
| 441-15 | CWE-441 | true/CWE-807 | false/- | 教师判 CWE-807 |

## PASS（29）

| 对 | oracle | A 判定 | B 判定 | 备注 |
|---|---|---|---|---|
| 441-07 | CWE-441 | true/CWE-918 | false/- |  |
| 441-08 | CWE-441 | true/CWE-918 | false/- |  |
| 441-13 | CWE-441 | true/CWE-918 | false/- |  |
| 441-14 | CWE-441 | true/CWE-918 | false/- |  |
| 78-S-01 | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-01b | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-02 | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-03 | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-04 | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-04b | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-06 | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-07 | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-08 | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-09 | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-09b | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 78-S-10 | CWE-78 | true/CWE-78 | false/CWE-78 |  |
| 95-01 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-02 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-03 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-04 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-05 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-06 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-07 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-08 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-11 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-12 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-13 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-14 | CWE-95 | true/CWE-95 | false/CWE-95 |  |
| 95-15 | CWE-95 | true/CWE-95 | false/CWE-95 |  |

