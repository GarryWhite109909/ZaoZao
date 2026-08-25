# 补丁驱动词表素材（train_pool 291 条修复 diff）

- 解析成功 291 条 / 跳过 0 条

> 用法：每格 top_vuln_shapes 是该 CWE×语言 真实漏洞代码的高频调用骨架（新规则候选），
> defense_only_shapes 是只在防御侧出现的骨架（白名单/签名表候选）。


## CWE-22 · Go

- 漏洞侧行样本 68 / 防御侧行样本 295
- top 漏洞形状: ['checksumcalculator', 'os.getenv', 'len', 'urlpattern.getport', 'settingmanager.getvalue', 'getdefaulttargeturl', 'log.warning', 'stringreader', 'strings.split', 'append']
- 仅防御侧形状: ['filepath.join', 't.fatal', 'fmt.errorf', 't.run', 't.fatalf', 'filepath.abs', 't.tempdir', 'os.symlink']
- 例:
  - `corpus_00038.go`: `// We can overwrite stdout for "" only once.`
  - `corpus_00038.go`: `// So we need to clear the temporary stdout file before each test case.`
  - `corpus_00039.go`: `editor := os.Getenv("")`

## CWE-1336 · PHP

- 漏洞侧行样本 66 / 防御侧行样本 298
- top 漏洞形状: ['callable', '$view->renderstring', '$this->typefunctions[request', '->query', '$this->getrelationmodel', '->getvalue', 'preg_replace', 'starts_with', '->find', 'post']
- 仅防御侧形状: ['$view->rendersandboxedstring', 'number.isfinite', '$this->resolvetypefunction', 'patterns', 'closure', 'setlistbounds', 'levelcapacity', 'rtrim']
- 例:
  - `corpus_00010.php`: `return starts_with($path, $directory);`
  - `corpus_00014.php`: `<?php namespace Backend\FormWidgets;`
  - `corpus_00014.php`: `use Input;`

## CWE-611 · Java

- 漏洞侧行样本 65 / 防御侧行样本 89
- top 漏洞形状: ['mapdefaultobjectmodel', 'createxstream', 'xstream.fromxml', 'visualize', 'zipinputstream', 'handlezipstream', 'zipstream.getnextentry', 'e.getcause', 'factory.setproperty', 'xml_input_factory_supplier.get']
- 仅防御侧形状: ['dbf.setfeature', 'identifyschemaversion', 'extractallnamespacedeclarations', 'xmlreader.setfeature', 'inputsource', 'bom.setschemaversion', 'isxmlequalto', 'getxmlinputfactory']
- 例:
  - `corpus_00141.java`: `private EStandard findOutStandardFromRootNode(InputStream fis) {`
  - `corpus_00141.java`: `public String visualize(String xmlFilename, Language lang) throws IOException, TransformerException {`
  - `corpus_00141.java`: `public String visualize(InputStream inputXml, Language lang) throws IOException, TransformerException {`

## CWE-22 · Python

- 漏洞侧行样本 63 / 防御侧行样本 231
- top 漏洞形状: ['_build_agent', 'valueerror', 'function', 'path.abspath', '_pre_process', 'str', 'path.isabs', 'file.replace', '.split', 'self.encoding']
- 仅防御侧形状: ['$this->authorize', 'include_stack.pop', 'resolveclientip', 'callback', 'validatefluenttoken', 'path.open', 'object', 'isallowed']
- 例:
  - `corpus_00037.py`: `is_attack_pattern,`
  - `corpus_00037.py`: `cmd_injection_check,`
  - `corpus_00040.py`: `Return an open stream that can be used to read the given file.`

## CWE-441 · Go

- 漏洞侧行样本 55 / 防御侧行样本 42
- top 漏洞形状: ['errors.withstack', 'strconv.formatint', 'net.splithostport', 'regexp.mustcompile', 'errors.new', 'dl.isexternalnetwork', 'isexternalnetwork', 'strconv.parseint', 'strings.contains', 'err.error']
- 仅防御侧形状: ['init', 'defaulttransport.', '.clone']
- 例:
  - `corpus_00095.go`: `// Name of the secret resource to read connection parameters from`
  - `corpus_00095.go`: `// Namespace of the source secret. If not specified, defaults to the same namespace as the resource`
  - `corpus_00095.go`: `Namespace string ""`

## CWE-89 · PHP

- 漏洞侧行样本 54 / 防御侧行样本 117
- top 漏洞形状: ['exception', '$e->getmessage', '$datahandler->start', 'foreach', '$datahandler->process_datamap', 'preg_match', 'splfileobject', 'parser', '$parser->parse', 'document.setauthorreference']
- 仅防御侧形状: ['$this->db->quoteidentifier', '$this->dbservice->escape', '$this->persistenceguard->allowinvocation', '$this->persistenceguard->consumeinvocation', 'sprintf', 'preg_replace', 'self::assertvalididentifier', 'invalidargumentexception']
- 例:
  - `corpus_00005.php`: `document.setAuthorReference(xcontext.getUserReference());`
  - `corpus_00005.php`: `xcontext.getWiki().saveDocument(document, "", true, xcontext);`
  - `corpus_00249.php`: `AND LOWER(ud.display_name) LIKE ""`

## CWE-1336 · Python

- 漏洞侧行样本 53 / 防御侧行样本 164
- top 漏洞形状: ['environment', 'filesystemloader', 'extensions', 'template.render', 'str', '.render', 'template', 'len', 'render_template', 'expressions']
- 仅防御侧形状: ['secure_filename', 'valueerror', '_restrictedsandboxedenvironment', 'jinjacmd._create_jinja_environment', 'safeformatter', 'field_name.replace', 'name.rstrip', '.endswith']
- 例:
  - `corpus_00021.py`: `import uuid`
  - `corpus_00021.py`: `from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader, Template`
  - `corpus_00021.py`: `max_recursion_depth = N`

## CWE-90 · Java

- 漏洞侧行样本 52 / 防御侧行样本 5
- top 漏洞形状: ['temp.substring', 'parsedn', 'temp.indexof', 'temp.length', 'strings.tolowercase', 'temp.charat', 'filterencode', 'value.length', 'encodedvalue.append', 'string.valueof']
- 仅防御侧形状: ['ldaputils.parsedn', 'username.isempty']
- 例:
  - `corpus_00266.java`: `private static String[] FILTER_ESCAPE_TABLE = new String["" + N];`
  - `corpus_00266.java`: `// Filter encoding table -------------------------------------`
  - `corpus_00266.java`: `// fill with char itself`

## CWE-327 · Go

- 漏洞侧行样本 49 / 防御侧行样本 92
- top 漏洞形状: ['errors.new', 'value.replace', 'token_info.get', 'httpexception', 'import', 'render', 'render.status', 'errunauthorized', 'http.statustext', 'err.error']
- 仅防御侧形状: ['canmanagetargetrole', '.replace', 'hashalgorithmsupported', 'auth', 'open', 'profile', 'one', 'below']
- 例:
  - `corpus_00066.go`: `// mirrorGitEnv returns environment variables that keep git non-interactive`
  - `corpus_00066.go`: `// during mirror operations. Without these, a network failure or a missing`
  - `corpus_00066.go`: `// remote endpoint can make git ask for credentials and stall the server-side`

## CWE-502 · Java

- 漏洞侧行样本 44 / 防御侧行样本 307
- top 漏洞形状: ['getkeyfile', 'objectinputstream', 'objectoutputstream', 'bufferedoutputstream', 'files.newoutputstream', 'oos.writeobject', 'deserialize', 'bufferedinputstream', 'files.newinputstream', 'ois.readobject']
- 仅防御侧形状: ['jsonproperty', '_validatetypeparameter', 'files.writestring', 'objectmapper.writevalueasstring', 'getlegacykeyfile', 'ois.setobjectinputfilter', 'getprivatekeyfile', 'getpublickeyfile']
- 例:
  - `corpus_00108.java`: `Map<String, Object> getVariables();`
  - `corpus_00109.java`: `items.add(item);`
  - `corpus_00116.java`: `return ConsulRegistryUtils.deserialize(postDecodedValue);`

## CWE-89 · Go

- 漏洞侧行样本 42 / 防御侧行样本 112
- top 漏洞形状: ['int']
- 仅防御侧形状: ['escapesqlstring', 'len', 'scandollarquotetag', 'tag', 'isdollartagrune', 'errors', 'innererr.error', 'string']
- 例:
  - `corpus_00006.go`: `rootErr.Kind == KindInvalidFormat && e.Parameter.In == "" {`
  - `corpus_00006.go`: `Title: innerErr.Reason,`
  - `corpus_00256.go`: `ClusterFilter: filters.Cluster,`

## CWE-1336 · Go

- 漏洞侧行样本 34 / 防御侧行样本 88
- top 漏洞形状: ['len', 'fmt.sprintf', 'http.setcookie', 'websockets.setallowedorigins', 'strings.hasprefix', 'htmlpreviewroutere.matchstring', 'cookie.string', 'make', 'openuserfile', 'os.open']
- 仅防御侧形状: ['fmt.errorf', 'errors.withstack', 'f.close', 'errors.errorf', 'expand', 'delete', 'value.', 'strings.contains']
- 例:
  - `corpus_00008.go`: `// set allowed websocket origins from configuration`
  - `corpus_00008.go`: `// websockets.SetAllowedOrigins(AccessControlAllowWSOrigins)`
  - `corpus_00008.go`: `if strings.HasPrefix(r.RequestURI, config.Webroot+"") || htmlPreviewRouteRe.MatchString(r.RequestURI) {`

## CWE-77 · JavaScript

- 漏洞侧行样本 31 / 防御侧行样本 70
- top 漏洞形状: ['console.log', 'execasync', 'process.cwd', 'windows_cmd_safe_file_name_pattern.test', 'filename.trim', 'colors.red', 'path.basename', 'childprocess.spawn', 'editor].concat', 'promisify']
- 仅防御侧形状: ['validateworkspacedir', 'execfileasync', 'str.includes', 'error', 'escapecmdargs', 'cmdargs.replace', 'doublequoteifneeded', 'args.map']
- 例:
  - `corpus_00175.js`: `// cmd.exe on Windows is vulnerable to RCE attacks given a file name of the`
  - `corpus_00175.js`: `// form "". Use a safe file`
  - `corpus_00175.js`: `// name pattern to validate user-provided file names. This doesn't cover the`

## CWE-918 · Python

- 漏洞侧行样本 24 / 防御侧行样本 390
- top 漏洞形状: ['_get_httpx', 'str', 'ipaddress.ip_network', '_validate_url_for_fetch', '_get_redirect_url', 'httpx.url', '.join', 'httpadapter', 'link-local', 'tuple']
- 仅防御侧形状: ['isinstance', 'get', 'cast', '_normalize_dns_host', '_validate_acme_url_in_options', 'trestleerror', '_validate_acme_url', 'option.get']
- 例:
  - `corpus_00275.py`: `from requests.adapters import HTTPAdapter`
  - `corpus_00275.py`: `adapter = HTTPAdapter(max_retries=retry_strategy)`
  - `corpus_00276.py`: `ipaddress.ip_network(""), # Loopback`

## CWE-611 · Python

- 漏洞侧行样本 21 / 防御侧行样本 83
- top 漏洞形状: ['metadata', 'file_path', 'load_single_document', 'true', 'pd.eval', 'etree.iterparse']
- 仅防御侧形状: ['files', 'evernoteloader', 'loader.load', 'proc.set_configuration_property', 'document', 'loader.lazy_load', 'metadata.get', 'file']
- 例:
  - `corpus_00144.py`: `"""Load documents from Evernote.`
  - `corpus_00144.py`: `https://gist.github.com/foxmask/7b29c43a161e001ff04afdb2f181e31c`
  - `corpus_00144.py`: `"""Load from "".`

## CWE-502 · Python

- 漏洞侧行样本 19 / 防御侧行样本 150
- top 漏洞形状: ['file_path.open', 'pickle.dump', 'pickle.load', 're.search', 'path.exists', 'open', 'load', 'dict']
- 仅防御侧形状: ['self.new_session', '_compute_file_hmac', '_restrictedcookieunpickler', 'except', 'f.read', 'len', 'f.write', 'frozenset']
- 例:
  - `corpus_00110.py`: `with file_path.open(mode="") as f:`
  - `corpus_00110.py`: `pickle.dump(self._cookies, f, pickle.HIGHEST_PROTOCOL)`
  - `corpus_00110.py`: `with file_path.open(mode="") as f:`

## CWE-611 · PHP

- 漏洞侧行样本 18 / 防御侧行样本 68
- top 漏洞形状: ['$this->dom->loadxml', 'libxml_use_internal_errors', 'domdocument', '$dom->loadxml', 'libxml_clear_errors', 'fromstring', 'self::create', 'defined', 'runtimeexception', 'fromfile']
- 仅防御侧形状: ['libxml_set_external_entity_loader', 'func_num_args', 'empty', 'imageexception', '__construct', 'xmlscanner::getinstance', '$this->xmlscanner->scan', 'elseif']
- 例:
  - `corpus_00148.php`: `$this->dom->loadXML($content, LIBXML_DTDLOAD);`
  - `corpus_00149.php`: `\libxml_use_internal_errors(true);`
  - `corpus_00149.php`: `$dom = new \DOMDocument();`

## CWE-79 · JavaScript

- 漏洞侧行样本 18 / 防御侧行样本 103
- top 漏洞形状: ['function', 'this.addlistener', '.css', '$body.val', '.velocity', 'complete:function', '$screen.children', '$searchresultscontainer.height', '$body.velocity', 'encodeuricomponent']
- 仅防御侧形状: ['rawtext.slice', 'rawtext.charat', 'prefixes.get']
- 例:
  - `corpus_00202.js`: `return this.revisionList[this.selectedRevisionIndex];`
  - `corpus_00203.js`: `const parentClosingTag = "" + parentTag;`
  - `corpus_00203.js`: `new RegExp(parentClosingTag, ""),`

## CWE-601 · PHP

- 漏洞侧行样本 17 / 防御侧行样本 27
- top 漏洞形状: ['str_ends_with', 'substr', 'parse_url', 'strtr', 'elseif', 'declare', 'session_cache_limiter', 'configuration::getinstance', 'template', 'array_key_exists']
- 仅防御侧形状: ['str_contains', 'str_replace', 'str_starts_with', 'explode', 'foreach', 'implode', 'http', '$http->redirecttrustedurl']
- 例:
  - `corpus_00125.php`: `$parsed = parse_url($params[$redirectParam]);`
  - `corpus_00126.php`: `$url = strtr($url, ["" => "", "" => ""]);`
  - `corpus_00126.php`: `if (str_ends_with($url, "")) {`

## CWE-77 · Go

- 漏洞侧行样本 17 / 防御侧行样本 63
- top 漏洞形状: ['exec.command', 'os.lookupenv', 'runcmd', 'strings.join']
- 仅防御侧形状: ['fmt.errorf', 'strings.fields', 'os.environ', 'buildenvmap', 'make', 'strings.cut', 'expandvars', 'secutils.validatestdioconfig']
- 例:
  - `corpus_00177.go`: `CFlags string ""`
  - `corpus_00177.go`: `cFlags string`
  - `corpus_00177.go`: `"" + options.cFlags,`

## CWE-78 · Python

- 漏洞侧行样本 17 / 防御侧行样本 38
- top 漏洞形状: ['cmd.replace', 'subprocess.popen', 'getattr', 'self.get_command', 'hasattr', 'shutil.which', 'str']
- 仅防御侧形状: ['_shell_quote', 'self._remove_path_after_delay', 'variables', 'chain', 'space', '_remove_path_after_delay', 'os.startfile', 'any']
- 例:
  - `corpus_00188.py`: `_SHELL_OPERATORS = ("", "", "", "")`
  - `corpus_00192.py`: `subprocess.Popen(`
  - `corpus_00192.py`: `self.get_command(path, **options),`

## CWE-798 · Go

- 漏洞侧行样本 17 / 防御侧行样本 52
- top 漏洞形状: ['[]byte', 'fmt.errorf', 'servercfg.getdnskey', 'jwt.newsigner', 'validatetoken', 'kubernetes.configclient', 'kube.newforconfig', 'k8s.discovery', '.serverversion']
- 仅防御侧形状: ['errors.new', 'fmt.sprintf', 'time.now', '.unix', 'key', 'len', 'server.config', 'setjwtsecret']
- 例:
  - `corpus_00228.go`: `return tokens[N] == servercfg.GetDNSKey()`
  - `corpus_00231.go`: `var JwtSigKey = []byte("")`
  - `corpus_00231.go`: `jwtSigner: jwt.NewSigner(jwt.HS256, JwtSigKey, jwtMaxAge),`

## CWE-77 · Python

- 漏洞侧行样本 15 / 防御侧行样本 39
- top 漏洞形状: ['self.parse_mcp_command', 'get_pricing', 'get_model_pricing', 'password.replace', 'command.replace']
- 仅防御侧形状: ['shlex.quote', 'valueerror', 'str', 're.compile', 'self._validate_log_name', 'self.generate_log_file', '_validate_log_name', 'log_file_name_pattern.fullmatch']
- 例:
  - `corpus_00174.py`: `log_file = self.log_file_path / f""`
  - `corpus_00174.py`: `shell=True,`
  - `corpus_00174.py`: `shell=True,`

## CWE-78 · JavaScript

- 漏洞侧行样本 15 / 防御侧行样本 35
- top 漏洞形状: ['runwincmd', 'run', 'flagfn', 'escapefn', 'rest.join']
- 仅防御侧形状: ['cprecursive', 'fss.rm', 'path.join', 'async', 'fragments.slice', '.join', '7.0', 'fss.stat']
- 例:
  - `corpus_00191.js`: `let [preFlag, , ...rest] = flagFn(arg);`
  - `corpus_00191.js`: `while (rest.length > N && escapeFn(preFlag) === "") {`
  - `corpus_00191.js`: `arg = rest.join("");`