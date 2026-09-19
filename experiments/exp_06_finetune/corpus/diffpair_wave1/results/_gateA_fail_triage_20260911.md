# 门 A fail 30 条分诊 v2（全文对齐复扫，20260911）

分类汇总：{'T2b短描述': 2, 'T2描述空洞': 25, 'T3可翻案': 3}

判据：T2 描述<30词（无对齐信号可用）；T3 机制词/描述词在 seed 全文+patch 联合命中≥阈值（词表/改动行窗口误伤，可翻案）；T2b 短描述且零命中；T1 长描述但全文零命中（取材错配嫌疑最大）。

| kit | CVE | 标签 | 分类 | 描述词 | 全文机制词命中 | 宽松重叠(前5) |
|---|---|---|---|---|---|---|
| diffpair-corpus_00016 | CVE-2026-61712 | CWE-400 | T2b短描述 | 33 | 无 | ['container'] |
| diffpair-corpus_00025 | CVE-2026-28697 | CWE-284 | T2描述空洞 | 28 | 无 | ['twig'] |
| diffpair-corpus_00034 | CVE-2026-24807 | 无洞 | T2描述空洞 | 13 | 无 | ['apache', 'awt', 'batik', 'codec', 'ext'] |
| diffpair-corpus_00089 | CVE-2026-40929 | CWE-352 | T2描述空洞 | 25 | 无 | ['forbidifisuntrustedrequest', 'json', 'objects', 'php'] |
| diffpair-corpus_00108 | CVE-2026-41699 | 无洞 | T2描述空洞 | 29 | 无 | ['execu', 'graphql', 'request', 'spring'] |
| diffpair-corpus_00117 | CVE-2026-40858 | 无洞 | T2描述空洞 | 21 | 无 | ['component'] |
| diffpair-corpus_00129 | CVE-2026-11477 | CWE-601 | T2描述空洞 | 19 | ['redirect'] | ['hswebframework', 'java', 'oauth2client', 'org'] |
| diffpair-corpus_00150 | CVE-2025-46726 | 无洞 | T3可翻案 | 30 | 无 | ['class', 'input', 'llm', 'local', 'summary'] |
| diffpair-corpus_00152 | CVE-2024-46455 | CWE-611 | T2描述空洞 | 14 | ['xml', 'document'] | ['unstructured', 'xml'] |
| diffpair-corpus_00168 | CVE-2026-49338 | CWE-639 | T2描述空洞 | 25 | ['owner'] | ['deleteplaylist', 'getplaylist', 'gonic', 'subsonic'] |
| diffpair-corpus_00176 | CVE-2026-41501 | CWE-829 | T2描述空洞 | 23 | ['path', 'require'] | ['instal', 'npm'] |
| diffpair-corpus_00197 | CVE-2026-36045 | CWE-78 | T2描述空洞 | 27 | ['command', 'execute', 'shell'] | ['command', 'exectool', 'guardcommand', 'restrict', 'shell'] |
| diffpair-corpus_00204 | CVE-2026-53608 | CWE-79 | T2描述空洞 | 11 | ['html', 'encoding'] | ['com'] |
| diffpair-corpus_00207 | CVE-2026-73428 | CWE-79 | T2b短描述 | 34 | 无 | ['trix'] |
| diffpair-corpus_00209 | CVE-2026-59929 | CWE-79 | T2描述空洞 | 27 | ['html'] | ['blocks', 'data', 'file', 'javascript', 'safe_url'] |
| diffpair-corpus_00250 | CVE-2026-63221 | CWE-89 | T2描述空洞 | 28 | ['sql', 'query', 'database', 'select'] | ['builder', 'clause', 'deletebatch', 'exists', 'method'] |
| diffpair-corpus_00251 | CVE-2026-69240 | CWE-89 | T3可翻案 | 30 | ['sql', 'query', 'database', 'select', 'statement'] | ['defined', 'dialect', 'escape', 'sequelize', 'sql'] |
| diffpair-corpus_00252 | CVE-2026-52775 | CWE-89 | T2描述空洞 | 25 | ['select'] | ['deleteuserreaction', 'reactionmanager', 'yeswiki'] |
| diffpair-corpus_00256 | CVE-2026-53474 | CWE-89 | T2描述空洞 | 28 | ['sql', 'query', 'database'] | ['file', 'migration-planner', 'rvtools'] |
| diffpair-corpus_00260 | CVE-2026-42550 | CWE-89 | T2描述空洞 | 24 | 无 | ['argument', 'array'] |
| diffpair-corpus_00263 | CVE-2026-39946 | CWE-89 | T3可翻案 | 32 | ['sql', 'query', 'database', 'select', 'statement', 'sanitize'] | ['database', 'failed', 'openbao', 'postgresql', 'privileges'] |
| diffpair-corpus_00270 | CVE-2022-2232 | CWE-90 | T2描述空洞 | 26 | 无 | ['found', 'keycloak', 'package'] |
| diffpair-corpus_00286 | CVE-2026-54735 | CWE-918 | T2描述空洞 | 27 | ['request', 'url', 'http'] | ['accept', 'adapters', 'bid', 'bidder', 'input'] |
| diffpair-corpus_00288 | CVE-2026-54690 | CWE-918 | T2描述空洞 | 27 | ['http'] | ['http', 'ref', 'validation', 'values'] |
| diffpair-corpus_00305 | CVE-2026-25526 | CWE-1336 | T2描述空洞 | 25 | 无 | ['execution', 'hubspot', 'jinjava', 'type'] |
| diffpair-corpus_00312 | CVE-2025-53833 | CWE-1336 | T2描述空洞 | 28 | 无 | 无 |
| diffpair-corpus_00315 | CVE-2024-55660 | CWE-1336 | T2描述空洞 | 25 | ['template'] | ['api', 'rendersprig', 'siyuan', 'sprig', 'template'] |
| diffpair-corpus_00316 | CVE-2024-45053 | CWE-1336 | T2描述空洞 | 26 | ['template'] | ['proper', 'template'] |
| diffpair-corpus_00332 | CVE-2024-40465 | CWE-327 | T2描述空洞 | 22 | 无 | ['beego', 'file'] |
| diffpair-corpus_00336 | CVE-2022-29217 | CWE-327 | T2描述空洞 | 29 | 无 | 无 |

## 描述摘录
### diffpair-corpus_00016 [T2b短描述] desc=33词
> ### Impact Maliciously crafted base image or build can cause a Denial of Service (DoS) condition. When creating a container from this image, memory exhaustion occurs, leading to an…

### diffpair-corpus_00025 [T2描述空洞] desc=28词
> ## Summary  An authenticated administrator can achieve Remote Code Execution (RCE) by injecting a Server-Side Template Injection (SSTI) payload into Twig template fields (e.g., Ema…

### diffpair-corpus_00034 [T2描述空洞] desc=13词
> Improper Verification of Cryptographic Signature vulnerability in liuyueyi quick-media (plugins/svg-plugin/batik-codec-fix/src/main/java/org/apache/batik/ext/awt/image/codec/util m…

### diffpair-corpus_00089 [T2描述空洞] desc=25词
> ## Summary  `objects/commentDelete.json.php` is a state-mutating JSON endpoint that deletes comments but performs no CSRF validation. It does not call `forbidIfIsUntrustedRequest()…

### diffpair-corpus_00108 [T2描述空洞] desc=29词
> Spring for GraphQL applications are vulnerable to Unsafe Deserialization when processing paginated GraphQL queries. An attacker can craft a malicious GraphQL request that can lead …

### diffpair-corpus_00117 [T2描述空洞] desc=21词
> The camel-infinispan component's ProtoStream-based remote aggregation repository deserializes data read from a remote Infinispan cache using java.io.ObjectInputStream without apply…

### diffpair-corpus_00129 [T2描述空洞] desc=19词
> A vulnerability was detected in hs-web hsweb-framework up to 5.0.1. This affects the function OAuth2Client of the file hsweb-authorization/hsweb-authorization-oauth2/src/main/java/…

### diffpair-corpus_00150 [T3可翻案] desc=30词
> ### Summary A LLM application leveraging `XMLToolMessage` class may be exposed to untrusted XML input that could result in DoS and/or exposing local files with sensitive informatio…

### diffpair-corpus_00152 [T2描述空洞] desc=14词
> unstructured v.0.14.2 and before is vulnerable to XML External Entity (XXE) via the XMLParser.…

### diffpair-corpus_00168 [T2描述空洞] desc=25词
> ## Summary  In gonic, the Subsonic API endpoints `/rest/deletePlaylist.view` and `/rest/getPlaylist.view` perform no per-resource authorization. Once authenticated as *any* user (a…

### diffpair-corpus_00176 [T2描述空洞] desc=23词
> ### Impact _What kind of vulnerability is it? Who is impacted?_  **Command Injection vulnerabilities in electerm:**  A command injection vulnerability exists in `github.com/elcterm…

### diffpair-corpus_00197 [T2描述空洞] desc=27词
> picoclaw <=v0.1.2 and earlier is vulnerable to OS command injection via the ExecTool component (pkg/tools/shell.go). The guardCommand() function attempts to restrict shell command …

### diffpair-corpus_00204 [T2描述空洞] desc=11词
> <img width="1919" height="1046" alt="curl" src="https://github.com/user-attachments/assets/8aa19ff1-7f4b-44ee-83d5-d0dd1a0269f6" /> <img width="1919" height="775" alt="xss" src="ht…

### diffpair-corpus_00207 [T2b短描述] desc=34词
> ### Impact  The Trix editor, in versions prior to 2.1.18, is vulnerable to XSS when crafted HTML is pasted into the editor. The `HTMLParser` processed a mock attachment, a `<span>`…

### diffpair-corpus_00209 [T2描述空洞] desc=27词
> ## Summary  **Type:** URL-scheme allowlist gap. The `safe_url` filter only blocks the four schemes `javascript:`, `vbscript:`, `file:`, `data:`. Several other schemes are accepted …

### diffpair-corpus_00250 [T2描述空洞] desc=28词
> ### Impact A SQL injection vulnerability exists in the Query Builder's `deleteBatch()` method. When `deleteBatch()` is used together with `where()` conditions, the bound values fro…

### diffpair-corpus_00251 [T3可翻案] desc=30词
> ### Summary SQL Injection is possible with strings only **if dialect is set to `oracle`**. The vulnerability was confirmed on Sequelize v6.37.3.  ### Details The `escape` function …

### diffpair-corpus_00252 [T2描述空洞] desc=25词
> ## Summary  YesWiki through the latest development branch contains a SQL injection vulnerability in `ReactionManager::deleteUserReaction()` that allows any authenticated user to in…

### diffpair-corpus_00256 [T2描述空洞] desc=28词
> A flaw was found in migration-planner. A remote authenticated attacker could exploit this vulnerability by uploading a specially crafted RVTools .xlsx file. Due to improper input s…

### diffpair-corpus_00260 [T2描述空洞] desc=24词
> ### Summary `SimplePdo::insert()`, `SimplePdo::update()`, and `SimplePdo::delete()` build SQL statements by concatenating the `$table` argument and the **keys** of the `$data` arra…

### diffpair-corpus_00263 [T3可翻案] desc=32词
> ### Impact  When OpenBao revoked privileges on a role in the PostgreSQL database secrets engine, OpenBao failed to use proper database quoting on schema names provided by PostgreSQ…

### diffpair-corpus_00270 [T2描述空洞] desc=26词
> A flaw was found in the Keycloak package. This flaw allows an attacker to benefit from an LDAP query and access existing usernames in the server.…

### diffpair-corpus_00286 [T2描述空洞] desc=27词
> ### Impact Certain bidder adapters accept user-supplied parameters that are interpolated into outbound request URLs. Without proper input validation, a malicious actor could craft …

### diffpair-corpus_00288 [T2描述空洞] desc=27词
> ### Summary  JSON-Schema `$ref` values pointing at HTTP or HTTPS URLs are silently dereferenced by `datamodel-code-generator` with no IP/host validation, no scheme allow-list, and …

### diffpair-corpus_00305 [T2描述空洞] desc=25词
> ## Impact  **Vulnerability Type**: Sandbox Bypass / Remote Code Execution  **Affected Component**: Jinjava  **Affected Users**: - Organizations using HubSpot's Jinjava template ren…

### diffpair-corpus_00312 [T2描述空洞] desc=28词
> ### Impact Attackers could: 1. Execute arbitrary commands on the server 2. Access sensitive environment variables 3. Escalate access depending on server configuration  A critical v…

### diffpair-corpus_00315 [T2描述空洞] desc=25词
> ### Summary Siyuan's /api/template/renderSprig endpoint is vulnerable to Server-Side Template Injection (SSTI) through the Sprig template engine. Although the engine has limitation…

### diffpair-corpus_00316 [T2描述空洞] desc=26词
> ### Summary The Email Templating feature uses Jinja2 without proper input sanitization or rendering environment restrictions, allowing for Server-Side Template Injection that grant…

### diffpair-corpus_00332 [T2描述空洞] desc=22词
> An issue in beego v.2.2.0 and before allows a remote attacker to escalate privileges via the `getCacheFileName` function in the `file.go` file.…

### diffpair-corpus_00336 [T2描述空洞] desc=29词
> ### Impact _What kind of vulnerability is it? Who is impacted?_  Disclosed by Aapo Oksman (Senior Security Specialist, Nixu Corporation).  > PyJWT supports multiple different JWT s…

