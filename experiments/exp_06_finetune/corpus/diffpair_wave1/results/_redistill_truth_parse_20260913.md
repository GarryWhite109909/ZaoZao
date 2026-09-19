# 任务1 复核包产出对照（20260913）

31 包全覆盖。四分类：{'agree_qualified': 4, 'agree': 23, 'disagree': 5}

## 分类明细

### agree（23）

| id | flags | 真值 | 教师结论 | CWE对照 | 防御行号数 |
|---|---|---|---|---|---|
| redistill-00008-A | R4 | 有洞 CWE-346 | true / CWE-346 | 一致 | 5 |
| redistill-00018-A | R4 | 有洞 CWE-1336 | true / CWE-1336 | 一致 | 5 |
| redistill-00037-A | R4+R5 | 无洞  | false / - | - | 38 |
| redistill-00094-A | R4 | 有洞 CWE-441 | true / CWE-441 | 一致 | 10 |
| redistill-00098-A | R4+R5 | 无洞  | false / - | - | 28 |
| redistill-00117-A | R4+R5 | 无洞  | false / - | - | 5 |
| redistill-00145-A | R4 | 有洞 CWE-409 | true / CWE-409 | 一致 | 7 |
| redistill-00162-A | R4 | 有洞 CWE-863 | true / CWE-863 | 一致 | 5 |
| redistill-00177-A | R4+R5 | 无洞  | false / - | - | 46 |
| redistill-neg-00011 | R5 | 无洞  | false / - | - | 34 |
| redistill-neg-00020 | R5 | 无洞  | false / - | - | 33 |
| redistill-neg-00034 | R5 | 无洞  | false / - | - | 16 |
| redistill-neg-00035 | R5 | 无洞  | false / - | - | 27 |
| redistill-neg-00048 | R5 | 无洞  | false / - | - | 18 |
| redistill-neg-00049 | R5 | 无洞  | false / - | - | 21 |
| redistill-neg-00096 | R5 | 无洞  | false / - | - | 27 |
| redistill-neg-00049 | R5 | 无洞  | false / - | - | 21 |
| redistill-neg-00108 | R5 | 无洞  | false / - | - | 8 |
| redistill-neg-00133 | R5 | 无洞  | false / - | - | 45 |
| redistill-neg-00139 | R5 | 无洞  | false / CWE-611 | - | 18 |
| redistill-neg-00143 | R5 | 无洞  | false / - | - | 17 |
| redistill-neg-00150 | R5 | 无洞  | false / - | - | 14 |
| redistill-neg-00158 | R5 | 无洞  | false / - | - | 38 |


### agree_qualified（结论=真值但证据链断在样本外，降档可用）（4）

| id | flags | 真值 | 教师结论 | CWE对照 | 防御行号数 |
|---|---|---|---|---|---|
| redistill-00007-A-L56 | R4+R5 | 有洞 CWE-22 | true / CWE-22 | - | 10 |
| redistill-00007-A-L68 | R4+R5 | 有洞 CWE-22 | true / CWE-248 | - | 7 |
| redistill-00097-A | R4+R5 | 无洞  | false / - | - | 22 |
| redistill-neg-00124 | R5 | 无洞  | false / - | - | 5 |

- **redistill-00007-A-L56 disagree**: 官方“安全”结论在 L80/L84/L156 的防御链上断裂；样本内可证 `[.][.]` 绕过 L80 且 L85 只验 glob 语法。样本外假设：`DefaultProjectFinder` 确实用 doublestar 展开 `v.Dir`，且展开后没有仓库根边界检查；若该检查存在，本条应降为防御纵深缺失。
- **redistill-00007-A-L68 disagree**: 官方“存在漏洞=false”不成立。代码事实是 L112 对 `branch == "/"` 放行，L115 立即切片越界 panic；L161 在 `ToValid` 中同样存在该切片。风险等级定为 Medium 是因为代码内可证 panic，但是否进程级 DoS 取决于样本外调用方是否 recover；若已 rec
- **redistill-00097-A disagree**: 官方“安全”结论的关键一步在样本外——L82/L85 的 `buildURL` 实现未提供；仅凭本文件无法证明 `req.url` 经 L73-L75 进入 `source` 后不能通过 `//evil.com` 或 `../` 改变上游主机/路径。需要补 `./lib/utils.js` 中 `buildURL` 的
- **redistill-neg-00124 disagree**: 官方“`IsSameSite` 安全”无法从当前样本验证。断点：`IsSameSite` 函数实现、调用点、URL 解析库行为均不在样本内；L25 只显示调用，未显示任何防御。若官方结论仅指“该测试文件无洞”，则支持；若指被调函数无洞，需要补 `IsSameSite` 定义及调用点。

### disagree（教师拒绝/反对真值 → 回流人工）（5）

| id | flags | 真值 | 教师结论 | CWE对照 | 防御行号数 |
|---|---|---|---|---|---|
| redistill-00019-A | R4 | 有洞 CWE-1336 | false / CWE-1336 | - | 9 |
| redistill-00132-A | R4 | 有洞 CWE-601 | None / - | - | 6 |
| redistill-00155-A | R4 | 有洞 CWE-400 | false / CWE-400 | - | 14 |
| redistill-00160-A | R4 | 有洞 CWE-639 | None / - | - | 8 |
| redistill-neg-00147 | R5 | 无洞  | true / CWE-776 | - | 11 |

- **redistill-00019-A disagree**: 官方结论的“不可信 Twig 模板字符串”一步在样本内断了：代码只证明 L240/L245 公开方法接收 `$templateString`，L242/L248 直接 `createTemplate()->render()`，L91-L94 未加载 `SecurityPolicy`；没有调用点证明攻击者能控制该参数。因
- **redistill-00132-A disagree**: 样本内推导断在 L36 `$t->send()` → 样本外 `casserver:loggedOut.twig`；代码事实是 L33 仅把 `$_GET['url']` 写入 `$t->data['url']`，是否成为跳转目标取决于模板。若补出的模板将 `url` 用于 Location/meta refresh/
- **redistill-00155-A disagree**: 官方备注的 SVG `<image xlink:href>` 自引用检测不在本样本内） | CWE-400 Uncontrolled Resource Consumption（官方结论不成立） | Low
- **redistill-00160-A disagree**: 样本内无法证明官方 CWE-863 的完整链。断点在“管理员收窄 BasePath”和“旧分享未重校验 IsSubPath”均在样本外；本文件没有 `BasePath` 字段、`IsSubPath` 函数、管理员收窄入口、分享访问端点到文件 sink 的代码。代码内可证的是：L90-L112 `GetSharingUn
- **redistill-neg-00147 disagree**: 官方“无洞”只对 XXE/外部实体成立；L30-L35 未关闭内部 DTD/实体扩展，L147 创建默认 StAX 解析器，L171-L184 消费文本，CWE-776 在样本内可达，但严重度受 JDK 实体扩展限制影响。

## 门E 检查（R5 负样本 23 条）

防御栏行号引用 <2 的 agree 条目：0 条（全部合格）
