# 门 D 裁定单（42 条 pending_lead 机械预分类，20260911）

预分类：{'P3需读码': 30, 'P1缺失型': 12}

**怎么用**：P1/P2 基本可以批量采纳（抽 2-3 条复核即可）；你真正要逐条读码的只有 P3（和想更稳妥时的 P2b）。每条下面已给齐证据，裁定动作 = 在表里勾选：保留 / 改标 <CWE> / 判死踢出。

## P1缺失型（12 条）

| kit | CVE | 标签 | A版要件(s/w) | 修复行要件 | 建议 |
|---|---|---|---|---|---|
| diffpair-corpus_00104 | CVE-2026-49286 | CWE-502 | 0/0 | 1 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00127 | CVE-2026-41844 | CWE-601 | 0/0 | 3 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00132 | CVE-2025-65954 | CWE-601 | 0/0 | 1 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00134 | CVE-2026-44427 | CWE-918 | 0/0 | 1 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00155 | CVE-2021-3902 | CWE-400 | 0/0 | 1 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00207 | CVE-2026-73428 | CWE-79 | 0/0 | 3 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00212 | CVE-2026-54087 | CWE-79 | 0/0 | 2 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00229 | CVE-2024-23687 | CWE-798 | 0/0 | 4 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00230 | CVE-2023-1269 | CWE-798 | 0/0 | 2 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00247 | CVE-2026-53634 | CWE-862 | 0/0 | 2 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00274 | CVE-2026-70666 | CWE-918 | 0/0 | 19 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |
| diffpair-corpus_00336 | CVE-2022-29217 | CWE-327 | 0/0 | 2 | 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认 |

### diffpair-corpus_00104 · CWE-502 · CVE-2026-49286
- 描述: ### Summary

`pontedilana/php-weasyprint` guarded the output filename against the `phar://` stream wrapper with a case-sensitive blacklist:

```php
if (0 === \strpos($filename, 'phar://')) {
    throw…
- 修复新增行: `/** @var list<string> */` ; `protected const ALLOWED_PROTOCOLS = ['file'];` ; `protected const WINDOWS_LOCAL_FILENAME_REGEX = '/^[a-z]:(?:[`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00127 · CWE-601 · CVE-2026-41844
- 描述: A Spring MVC or Spring WebFlux application which configures a mapping for "/**" where the view name is not explicitly specified allows an attacker to craft a link resulting in a 302 redirect to an arb…
- 修复新增行: `import org.springframework.http.HttpStatus;` ; `import org.springframework.web.server.ResponseStatusExceptio` ; `* @author Sebastien Deleuze`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00132 · CWE-601 · CVE-2025-65954
- 描述: ### Summary

The logout endpoint accepts a `url` query parameter to redirect to.  casserver treats that url as trusted, and either (depending on configuration) redirects the browser there, or shows a …
- 修复新增行: `// This file is only to preserve this older path` ; `$http = new \SimpleSAML\Utils\HTTP();` ; `$http->redirectTrustedURL(`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00134 · CWE-918 · CVE-2026-44427
- 描述: ### Summary
The TrailingSlashMiddleware in internal/api/server.go is vulnerable to an open redirect attack. An attacker can craft a URL with a protocol-relative path (e.g., //evil.com/) that, after tr…
- 修复新增行: `"net"` ; `// Reject IP literals — this auth method proves domain owner` ; `// ownership, and IP literals are an SSRF vector into intern`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00155 · CWE-400 · CVE-2021-3902
- 描述: An improper restriction of external entities (XXE) vulnerability in dompdf/dompdf's SVG parser allows for Server-Side Request Forgery (SSRF) and deserialization attacks. This issue affects all version…
- 修复新增行: `if ($type === "svg") {` ; `$parser = xml_parser_create("utf-8");` ; `xml_parser_set_option($parser, XML_OPTION_CASE_FOLDING, fals`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00207 · CWE-79 · CVE-2026-73428
- 描述: ### Impact

The Trix editor, in versions prior to 2.1.18, is vulnerable to XSS when crafted HTML is pasted into the editor. The `HTMLParser` processed a mock attachment, a `<span>` carrying an empty `…
- 修复新增行: `import DOMPurify from "dompurify"` ; `const attributes = { ...pieceJSON.attributes }` ; `if (attributes.href && !DOMPurify.isValidAttribute("a", "hre`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00212 · CWE-79 · CVE-2026-54087
- 描述: EasyAdmin's `FileField` and `ImageField` accept browser-executable file types by default (`FileField` applies no MIME/extension restrictions; `ImageField`'s default `Image` constraint accepts SVG). Wh…
- 修复新增行: `$field->setFormTypeOption('risky_inline_render', $field->get`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00229 · CWE-798 · CVE-2024-23687
- 描述: ### Impact
The module creates a system user that is used to perform internal module-to-module operations.  Credentials for this user are hard-coded in the source code.  This makes it trivial to authen…
- 修复新增行: `import org.apache.commons.lang3.StringUtils;` ; `public static final String SYSTEM_USER_PASSWORD = "SYSTEM_US` ; `if (StringUtils.isEmpty(System.getenv(SYSTEM_USER_PASSWORD))`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00230 · CWE-798 · CVE-2023-1269
- 描述: Use of Hard-coded Credentials in GitHub repository alextselegidis/easyappointments 1.4.3 and prior. A patch is available and anticipated to be part of version 1.5.0.…
- 修复新增行: `$password = $this->instance->seed();` ; `response(PHP_EOL . '⇾ Installation completed, login with "ad`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00247 · CWE-862 · CVE-2026-53634
- 描述: ### Impact
The create and store endpoints of the Quick Creation Command feature did not enforce any authorization check. An authenticated Sharp user without create permission on a given entity could b…
- 修复新增行: `public function __construct(private readonly SharpUploadMana` ; `{` ; `$this->authorizationManager->check('create', $entityKey);`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00274 · CWE-918 · CVE-2026-70666
- 描述: ### Summary
The ACME client (used to issue certificates from Let's Encrypt / Google Public CA / private ACME CAs) connects to an `acme_url`, then issues requests to URLs that the **ACME server returns…
- 修复新增行: `from urllib.parse import urlparse` ; `from lemur.exceptions import InvalidConfiguration` ; `def _validate_acme_url(url: str) -> None:`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

### diffpair-corpus_00336 · CWE-327 · CVE-2022-29217
- 描述: ### Impact
_What kind of vulnerability is it? Who is impacted?_

Disclosed by Aapo Oksman (Senior Security Specialist, Nixu Corporation).

> PyJWT supports multiple different JWT signing algorithms. W…
- 修复新增行: `import re` ; `# Based on https://github.com/hynek/pem/blob/7ad94db26b0bc21` ; `_PEMS = {`
- 建议: 修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认

## P3需读码（30 条）

| kit | CVE | 标签 | A版要件(s/w) | 修复行要件 | 建议 |
|---|---|---|---|---|---|
| diffpair-corpus_00007 | CVE-2026-64679 | CWE-22 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00014 | CVE-2026-54256 | CWE-639 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00046 | CVE-2026-65600 | CWE-22 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00047 | CVE-2026-67309 | CWE-22 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00089 | CVE-2026-40929 | CWE-352 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00090 | CVE-2026-40928 | CWE-352 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00160 | CVE-2026-69160 | CWE-863 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00191 | CVE-2026-73414 | CWE-78 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00200 | CVE-2026-71497 | CWE-79 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00204 | CVE-2026-53608 | CWE-79 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00221 | CVE-2023-43637 | CWE-798 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00223 | CVE-2024-10451 | CWE-798 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00243 | CVE-2026-25038 | CWE-862 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00244 | CVE-2026-58434 | CWE-862 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00245 | CVE-2026-52870 | CWE-862 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00254 | CVE-2026-52763 | CWE-89 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00261 | CVE-2026-46364 | CWE-89 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00270 | CVE-2022-2232 | CWE-90 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00283 | CVE-2026-54725 | CWE-918 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00288 | CVE-2026-54690 | CWE-918 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00295 | CVE-2026-52833 | CWE-94 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00297 | CVE-2026-41523 | CWE-94 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00298 | CVE-2026-47722 | CWE-94 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00299 | CVE-2026-47117 | CWE-94 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00304 | CVE-2026-27641 | CWE-1336 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00308 | CVE-2026-21450 | CWE-1336 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00327 | CVE-2026-59946 | CWE-22 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00332 | CVE-2024-40465 | CWE-327 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00333 | CVE-2022-23540 | CWE-327 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |
| diffpair-corpus_00335 | CVE-2022-31157 | CWE-327 | 0/0 | 0 | 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方 |

### diffpair-corpus_00007 · CWE-22 · CVE-2026-64679
- 描述: ### Summary
Atlantis versions `>= 0.19.8` and `< 0.45.0` did not consistently validate user-controlled `workspace` values before using them to construct local workspace paths.

A crafted workspace val…
- 修复新增行: `validWorkspace := func(value any) error {` ; `strPtr := value.(*string)` ; `if strPtr == nil || *strPtr == "" {`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00014 · CWE-639 · CVE-2026-54256
- 描述: ### Impact

The backend `FileUpload` form widget trusted an attacker-controlled `file_id` POST parameter when resolving the attachment it operates on. The lookup (`FileUpload::getFileRecord()`) resolv…
- 修复新增行: `<?php` ; `namespace Backend\FormWidgets;` ; `use Backend\Widgets\Form;`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00046 · CWE-22 · CVE-2026-65600
- 描述: ## Summary

There is a critical authentication-bypass vulnerability in Traefik's `ReplacePathRegex` middleware. When it is configured with a regular expression that captures user-controlled path segme…
- 修复新增行: `logger := log.FromContext(middlewares.GetLoggerCtx(req.Conte` ; `// Here we are sanitizing the URL when the path is not empty` ; `// as the JoinPath method is adding a leading slash if the p`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00047 · CWE-22 · CVE-2026-67309
- 描述: ## Summary

There is a high severity vulnerability in Traefik's Kubernetes Ingress NGINX provider. When an Ingress uses the `nginx.ingress.kubernetes.io/rewrite-target` annotation with a regular expre…
- 修复新增行: `// Here we are sanitizing the URL when the path is not empty` ; `// as the JoinPath method is adding a leading slash if the p` ; `path := req.URL.Path`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00089 · CWE-352 · CVE-2026-40929
- 描述: ## Summary

`objects/commentDelete.json.php` is a state-mutating JSON endpoint that deletes comments but performs no CSRF validation. It does not call `forbidIfIsUntrustedRequest()`, does not verify a…
- 修复新增行: `forbidIfIsUntrustedRequest('{pluginName}::{classname}::add')`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00090 · CWE-352 · CVE-2026-40928
- 描述: ## Summary

Multiple AVideo JSON endpoints under `objects/` accept state-changing requests via `$_REQUEST`/`$_GET` and persist changes tied to the caller's session user, without any anti-CSRF token, o…
- 修复新增行: `forbidIfIsUntrustedRequest('categoryDeleteAssets');`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00160 · CWE-863 · CVE-2026-69160
- 描述: ### Summary
An authorization bypass vulnerability exists in the file sharing mechanism of `Openlist`. Due to a flawed, non-separator-aware path validation check, an authenticated user can create share…
- 修复新增行: `// Re-validate that the shared paths are still within the cr` ; `// BasePath. This prevents access to files that fell out-of-` ; `// creator's BasePath was changed by an admin.`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00191 · CWE-78 · CVE-2026-73414
- 描述: ### Impact

This impacts users of Shescape on Windows that explicitly configure `shell` to CMD, or `true` with the default shell being CMD, using the `escape` and `escapeAll` APIs.

An attacker may be…
- 修复新增行: `const fragments = flagFn(arg);` ; `let idx = 0;` ; `for (; idx < fragments.length - 2; idx += 2) {`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00200 · CWE-79 · CVE-2026-71497
- 描述: When a custom `Safelist` permits certain raw-text elements, jsoup may incorrectly sanitize malformed HTML containing a tag name that ends in a control character. The tag may acquire the parsing behavi…
- 修复新增行: `if (normalName == null) tagName = tagName.trim(); // public `
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00204 · CWE-79 · CVE-2026-53608
- 描述: <img width="1919" height="1046" alt="curl" src="https://github.com/user-attachments/assets/8aa19ff1-7f4b-44ee-83d5-d0dd1a0269f6" />
<img width="1919" height="775" alt="xss" src="https://github.com/use…
- 修复新增行: `// `uglyUrl` may be relative (local uploadfs) or absolute` ; `// (S3/CDN). For the relative case `streamProxy` resolves it` ; `// against `req.baseUrl`, which reflects the configured`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00221 · CWE-798 · CVE-2023-43637
- 描述: ### Impact

The deriveVaultKey function calls retrieveCloudKey which always returns "foobarfoobarfoobarfoobarfoobarfo". When merged with the randomly generated 32-byte key using mergeKeys (16 bytes fr…
- 修复新增行: `// VaultConfig represents vault key to be used` ; `type VaultConfig struct {` ; `TpmKeyOnly bool`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00223 · CWE-798 · CVE-2024-10451
- 描述: A flaw was found in Keycloak. This issue occurs because sensitive runtime values, such as passwords, may be captured during the Keycloak build process and embedded as default values in bytecode, leadi…
- 修复新增行: `import org.keycloak.quarkus.runtime.configuration.MicroProfi` ; `PropertyMapper<?> mapper = getMapper(name);` ; `// during re-aug do not resolve the server runtime propertie`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00243 · CWE-862 · CVE-2026-25038
- 描述: ## Summary

Gitea 1.26.2 does not properly enforce organization visibility restrictions on organization label read endpoints.

A user without access to a private organization can retrieve labels belon…
- 修复新增行: `"xorm.io/builder"` ; `// validateTOTP validates the provided passcode. It does not` ; `// surfaces must go through ValidateAndConsumeTOTP so that a`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00244 · CWE-862 · CVE-2026-58434
- 描述: ### Summary

A user who previously had access to a private repository can continue to obtain repository metadata through `GET /api/v1/user/starred` after their access to the repository has been revoke…
- 修复新增行: `// Actor is the user the private repositories are gated on: ` ; `// returned when Actor still has access to it, even if it wa` ; `Actor *user_model.User`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00245 · CWE-862 · CVE-2026-52870
- 描述: ### Summary
In affected versions, the default request handlers installed by the experimental tasks feature (`server.experimental.enable_tasks()`) did not check which session created a task before acti…
- 修复新增行: `import warnings` ; `from typing import Any, overload` ; `from typing_extensions import deprecated`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00254 · CWE-89 · CVE-2026-52763
- 描述: ### Summary

The `recentchanges` action (`actions/recentchanges.php`) accepts a `period` argument from two disjoint parameter spaces: the URL query string (`$_GET['period']`) and the action invocation…
- 修复新增行: `$period = isset($_GET['period']) ? $_GET['period'] : $this->` ; `$dateMin = '';` ; `if (in_array($period, ['day', 'week', 'month'], true)) {`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00261 · CWE-89 · CVE-2026-46364
- 描述: ## Summary

`BuiltinCaptcha::garbageCollector()` and `BuiltinCaptcha::saveCaptcha()` at `phpmyfaq/src/phpMyFAQ/Captcha/BuiltinCaptcha.php:298` and `:330` interpolate the `User-Agent` header and client…
- 修复新增行: `use Tivie\HtaccessParser\HtaccessContainer;` ; `$htaccess = $this->parseHtaccess();` ; `$htaccess = $this->parseHtaccess();`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00270 · CWE-90 · CVE-2022-2232
- 描述: A flaw was found in the Keycloak package. This flaw allows an attacker to benefit from an LDAP query and access existing usernames in the server.…
- 修复新增行: `if (username == null || username.isEmpty()) {`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00283 · CWE-918 · CVE-2026-54725
- 描述: ## Summary

The vault-secrets-webhook reads the `vault.security.banzaicloud.io/vault-addr` annotation from any ConfigMap or Secret being admitted and uses it as the Vault server address without any va…
- 修复新增行: `AddrFromObject                bool` ; `vaultConfig.AddrFromObject = true` ; `vaultConfig.SkipVerify = common.ResolveObjectSkipVerify(val,`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00288 · CWE-918 · CVE-2026-54690
- 描述: ### Summary

JSON-Schema `$ref` values pointing at HTTP or HTTPS URLs are silently dereferenced by `datamodel-code-generator` with no IP/host validation, no scheme allow-list, and redirects followed u…
- 修复新增行: `allow_private_network: NotRequired[bool]`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00295 · CWE-94 · CVE-2026-52833
- 描述: ## Summary

Nuclio's Java runtime generates a `build.gradle` file during function builds using Go's `text/template` package. The template renders `runtimeAttributes.repositories[]` values with the `{{…
- 修复新增行: `"regexp"` ; `"strings"` ; `// repositoryPattern matches a single no-argument Gradle rep`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00297 · CWE-94 · CVE-2026-41523
- 描述: ### Summary

An `assert`-based security check in vLLM's activation function loading allows any unauthenticated attacker to achieve arbitrary code execution on the server by publishing a malicious Hugg…
- 修复新增行: `if not function_name.startswith("torch.nn.modules."):` ; `raise ValueError(` ; `"Loading of activation functions is restricted to "`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00298 · CWE-94 · CVE-2026-47722
- 描述: `internal/configgen/generator.go:86,108,119` interpolates the operator-supplied `ListenHost` and `TunDevice` fields raw into a `text/template` that produces the agent's `config.yml`. `internal/web/adv…
- 修复新增行: `"gopkg.in/yaml.v3"` ; `// TestGenerate_TunDevice_StructuralBreakCharsAreQuoted is t` ; `// defense-in-depth assertion (issue #126): even if the upst`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00299 · CWE-94 · CVE-2026-47117
- 描述: OpenMed before 1.5.2 contains a remote code execution vulnerability in the PII privacy-filter model loading path. The privacy-filter dispatcher used broad substring matching on the user-supplied `mode…
- 修复新增行: `from openmed.torch.privacy_filter import (` ; `PrivacyFilterTorchPipeline,` ; `is_trusted_for_remote_code,`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00304 · CWE-1336 · CVE-2026-27641
- 描述: ### Impact
A critical path traversal and extension bypass vulnerability in Flask-Reuploaded allows remote attackers to achieve arbitrary file write and remote code execution through Server-Side Templa…
- 修复新增行: `# Track if name ends with dot before any processing` ; `name_ends_with_dot = name is not None and name.rstrip().ends` ; `# Check again after split`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00308 · CWE-1336 · CVE-2026-21450
- 描述: ### Summary
SSTI is possible in Bagisto via type parameter can lead to RCE and other exploitations.

### Details
1. Go to `http://127.0.0.1:8000/admin/reporting/products/view?type={{7*7}}`

<img width…
- 修复新增行: `$stats = $this->reportingHelper->{$this->resolveTypeFunction` ; `$stats = $this->reportingHelper->{$this->resolveTypeFunction` ; `$stats = $this->reportingHelper->{$this->resolveTypeFunction`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00327 · CWE-22 · CVE-2026-59946
- 描述: ## Summary

A Composer package declares its executables in the `bin` field of its `composer.json`. When Composer installs a package, it processes each `bin` entry and changes the file mode of the corr…
- 修复新增行: `use Composer\Package\Loader\ValidatingArrayLoader;` ; `ValidatingArrayLoader::validatePackage($package);`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00332 · CWE-327 · CVE-2024-40465
- 描述: An issue in beego v.2.2.0 and before allows a remote attacker to escalate privileges via the `getCacheFileName` function in the `file.go` file.…
- 修复新增行: `defer fd.Close()`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00333 · CWE-327 · CVE-2022-23540
- 描述: # Overview

In versions <=8.5.1 of jsonwebtoken library, lack of algorithm definition and a falsy secret or key in the `jwt.verify()` function can lead to signature validation bypass due to defaulting…
- 修复新增行: `const validateAsymmetricKey = require('./lib/validateAsymmet` ; `allowInsecureKeySizes: { isValid: isBoolean, message: '"allo` ; `allowInvalidAsymmetricKeyTypes: { isValid: isBoolean, messag`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

### diffpair-corpus_00335 · CWE-327 · CVE-2022-31157
- 描述: ### Impact

The function used to generate random nonces was not sufficiently cryptographically complex. As a result values may be predictable and tokens may be forgable.

### Patches

Users should upg…
- 修复新增行: `public function getLaunchData(string $key): ?array` ; `public function cacheLaunchData(string $key, array $jwtBody)` ; `public function cacheNonce(string $nonce, string $state): vo`
- 建议: 全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方

