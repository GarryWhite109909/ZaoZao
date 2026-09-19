# P3 30 条三方对照裁定单（20260911）

对照结果：{'教师未产出': 30}

**裁定规则**：同族 → 建议保留；冲突 → 按门 D 来源定（patch 语义已在列，必要时查 NVD）；教师判无洞且标签有洞 → 最高优先人工。

| kit | 标签 | 教师判断(A版) | 关系 | 修复行(来源①) |
|---|---|---|---|---|
| diffpair-corpus_00007 | CWE-22 | 未产出 | 教师未产出 | `validWorkspace := func(value any) error {` ; `strPtr := value.(*string)` |
| diffpair-corpus_00014 | CWE-639 | 未产出 | 教师未产出 | `<?php` ; `namespace Backend\FormWidgets;` |
| diffpair-corpus_00046 | CWE-22 | 未产出 | 教师未产出 | `logger := log.FromContext(middlewares.GetL` ; `// Here we are sanitizing the URL when the` |
| diffpair-corpus_00047 | CWE-22 | 未产出 | 教师未产出 | `// Here we are sanitizing the URL when the` ; `// as the JoinPath method is adding a lead` |
| diffpair-corpus_00089 | CWE-352 | 未产出 | 教师未产出 | `forbidIfIsUntrustedRequest('{pluginName}::` |
| diffpair-corpus_00090 | CWE-352 | 未产出 | 教师未产出 | `forbidIfIsUntrustedRequest('categoryDelete` |
| diffpair-corpus_00160 | CWE-863 | 未产出 | 教师未产出 | `// Re-validate that the shared paths are s` ; `// BasePath. This prevents access to files` |
| diffpair-corpus_00191 | CWE-78 | 未产出 | 教师未产出 | `const fragments = flagFn(arg);` ; `let idx = 0;` |
| diffpair-corpus_00200 | CWE-79 | 未产出 | 教师未产出 | `if (normalName == null) tagName = tagName.` |
| diffpair-corpus_00204 | CWE-79 | 未产出 | 教师未产出 | `// `uglyUrl` may be relative (local upload` ; `// (S3/CDN). For the relative case `stream` |
| diffpair-corpus_00221 | CWE-798 | 未产出 | 教师未产出 | `// VaultConfig represents vault key to be ` ; `type VaultConfig struct {` |
| diffpair-corpus_00223 | CWE-798 | 未产出 | 教师未产出 | `import org.keycloak.quarkus.runtime.config` ; `PropertyMapper<?> mapper = getMapper(name)` |
| diffpair-corpus_00243 | CWE-862 | 未产出 | 教师未产出 | `"xorm.io/builder"` ; `// validateTOTP validates the provided pas` |
| diffpair-corpus_00244 | CWE-862 | 未产出 | 教师未产出 | `// Actor is the user the private repositor` ; `// returned when Actor still has access to` |
| diffpair-corpus_00245 | CWE-862 | 未产出 | 教师未产出 | `import warnings` ; `from typing import Any, overload` |
| diffpair-corpus_00254 | CWE-89 | 未产出 | 教师未产出 | `$period = isset($_GET['period']) ? $_GET['` ; `$dateMin = '';` |
| diffpair-corpus_00261 | CWE-89 | 未产出 | 教师未产出 | `use Tivie\HtaccessParser\HtaccessContainer` ; `$htaccess = $this->parseHtaccess();` |
| diffpair-corpus_00270 | CWE-90 | 未产出 | 教师未产出 | `if (username == null || username.isEmpty()` |
| diffpair-corpus_00283 | CWE-918 | 未产出 | 教师未产出 | `AddrFromObject                bool` ; `vaultConfig.AddrFromObject = true` |
| diffpair-corpus_00288 | CWE-918 | 未产出 | 教师未产出 | `allow_private_network: NotRequired[bool]` |
| diffpair-corpus_00295 | CWE-94 | 未产出 | 教师未产出 | `"regexp"` ; `"strings"` |
| diffpair-corpus_00297 | CWE-94 | 未产出 | 教师未产出 | `if not function_name.startswith("torch.nn.` ; `raise ValueError(` |
| diffpair-corpus_00298 | CWE-94 | 未产出 | 教师未产出 | `"gopkg.in/yaml.v3"` ; `// TestGenerate_TunDevice_StructuralBreakC` |
| diffpair-corpus_00299 | CWE-94 | 未产出 | 教师未产出 | `from openmed.torch.privacy_filter import (` ; `PrivacyFilterTorchPipeline,` |
| diffpair-corpus_00304 | CWE-1336 | 未产出 | 教师未产出 | `# Track if name ends with dot before any p` ; `name_ends_with_dot = name is not None and ` |
| diffpair-corpus_00308 | CWE-1336 | 未产出 | 教师未产出 | `$stats = $this->reportingHelper->{$this->r` ; `$stats = $this->reportingHelper->{$this->r` |
| diffpair-corpus_00327 | CWE-22 | 未产出 | 教师未产出 | `use Composer\Package\Loader\ValidatingArra` ; `ValidatingArrayLoader::validatePackage($pa` |
| diffpair-corpus_00332 | CWE-327 | 未产出 | 教师未产出 | `defer fd.Close()` |
| diffpair-corpus_00333 | CWE-327 | 未产出 | 教师未产出 | `const validateAsymmetricKey = require('./l` ; `allowInsecureKeySizes: { isValid: isBoolea` |
| diffpair-corpus_00335 | CWE-327 | 未产出 | 教师未产出 | `public function getLaunchData(string $key)` ; `public function cacheLaunchData(string $ke` |

## 冲突条目证据明细
