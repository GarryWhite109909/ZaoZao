/**
 * 凿凿 VSCode 插件 v1.3.0
 *
 * 功能：
 *  1. 右键编辑器 → "分析当前文件" → 调用后端 /api/analyze（两阶段：工具召回 +
 *     LLM 裁决 + 共形/反事实/证据门信任层）→ Webview 展示结论与信任层明细
 *  2. 命令面板 → "批量扫描工作区" → 递归扫描所有代码文件 → 汇总报告
 *  3. 资源管理器右键文件夹 → "扫描指定文件夹"
 *  4. 漏洞诊断标记：按 adjudications[].finding.sink_line/source_line 精确定位，
 *     支持一处文件多个漏洞；无 adjudications 时回退旧顶层字段定位（兼容旧后端）
 *  5. 状态栏显示扫描状态与漏洞计数
 *  6. 可选：保存文件时自动扫描（1.5s 防抖合并连续保存）
 *
 * 依赖：仅用 Node.js 内置模块（http），无需 npm install
 * 调试：在 VSCode 中打开本目录，按 F5 启动扩展开发宿主
 */

const vscode = require("vscode");
const http = require("http");
const path = require("path");

// 语言 ID 映射
const LANG_MAP = {
  python: "python",
  javascript: "javascript",
  typescript: "typescript",
  java: "java",
  php: "php",
  go: "go",
  html: "html",
  javascriptreact: "javascript",
  typescriptreact: "typescript",
  vue: "javascript",
};

// 扩展名 → 语言（用于批量扫描文件筛选）
const EXT_TO_LANG = {
  ".py": "python", ".js": "javascript", ".ts": "typescript",
  ".jsx": "javascript", ".tsx": "typescript",
  ".java": "java", ".php": "php", ".go": "go",
  ".html": "html", ".htm": "html",
  ".vue": "javascript", ".svelte": "javascript",
};

// 批量扫描默认排除项（与 package.json 的 workspaceExclude 默认值一致；
// 用户把配置清空时也回退到它，否则 findFiles 会连 node_modules 一起扫）
const DEFAULT_EXCLUDES = [
  "**/node_modules/**", "**/.git/**", "**/vendor/**",
  "**/__pycache__/**", "**/dist/**", "**/build/**",
];

// 全局状态
let diagnosticCollection;
let statusBar;
let outputChannel;

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  // 诊断集合
  diagnosticCollection = vscode.languages.createDiagnosticCollection("vulnScanner");
  context.subscriptions.push(diagnosticCollection);

  // 输出通道
  outputChannel = vscode.window.createOutputChannel("凿凿");
  context.subscriptions.push(outputChannel);

  // 状态栏
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = "vulnScanner.scanWorkspace";
  statusBar.text = "$(shield) 凿凿扫描";
  statusBar.tooltip = "点击批量扫描工作区";
  statusBar.show();
  context.subscriptions.push(statusBar);

  // ---- 命令注册 ----

  // 1. 分析当前文件（支持编辑器内触发 / 资源管理器右键文件触发）
  const analyzeCmd = vscode.commands.registerCommand(
    "vulnScanner.analyzeFile",
    async (uri) => {
      if (uri && uri.fsPath) {
        // 资源管理器右键文件触发
        try {
          const doc = await vscode.workspace.openTextDocument(uri);
          await analyzeDocument(doc, context);
        } catch (e) {
          vscode.window.showErrorMessage("无法打开文件: " + e.message);
        }
        return;
      }
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("请先打开一个文件");
        return;
      }
      await analyzeDocument(editor.document, context);
    }
  );

  // 2. 批量扫描工作区
  const scanWorkspaceCmd = vscode.commands.registerCommand(
    "vulnScanner.scanWorkspace",
    async () => {
      await scanWorkspace(context);
    }
  );

  // 3. 扫描指定文件夹（资源管理器右键）
  const scanFolderCmd = vscode.commands.registerCommand(
    "vulnScanner.scanFolder",
    async (folderUri) => {
      if (!folderUri) {
        // 命令面板触发时让用户选择文件夹
        const picked = await vscode.window.showOpenDialog({
          canSelectFiles: false,
          canSelectFolders: true,
          canSelectMany: false,
        });
        if (!picked || !picked.length) return;
        folderUri = picked[0];
      }
      await scanFolder(folderUri, context);
    }
  );

  // 4. 清除所有诊断标记
  const clearCmd = vscode.commands.registerCommand(
    "vulnScanner.clearDiagnostics",
    () => {
      diagnosticCollection.clear();
      statusBar.text = "$(shield) 凿凿扫描";
      statusBar.tooltip = "点击批量扫描工作区";
      statusBar.backgroundColor = undefined; // 同时清除漏洞告警的红色背景
      vscode.window.showInformationMessage("已清除所有漏洞诊断标记");
    }
  );

  context.subscriptions.push(analyzeCmd, scanWorkspaceCmd, scanFolderCmd, clearCmd);

  // ---- 保存后自动扫描 ----
  // 注意：必须用 onDidSave（保存完成后异步触发），不能用 onWillSave + waitUntil——
  // 后者会让 VSCode 等待扫描请求（最长 requestTimeout，默认 300s）才真正落盘，卡死保存。
  // 防抖（1.5s）：格式化/多步保存会连续触发 onDidSave，逐次发请求会让两阶段扫描
  // 在调度队列里互相排队、状态栏来回跳；合并为最后一次保存后统一扫。
  let saveTimer = null;
  let savePendingDoc = null;
  const saveListener = vscode.workspace.onDidSaveTextDocument((doc) => {
    const config = vscode.workspace.getConfiguration("vulnScanner");
    if (!config.get("autoScanOnSave", false)) return;
    if (!isSupportedDoc(doc)) return;

    savePendingDoc = doc; // 连续保存只保留最后一个版本
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saveTimer = null;
      const pending = savePendingDoc;
      savePendingDoc = null;
      if (!pending) return;

      // 异步执行，不阻塞保存流程；失败时仅提示，不清除已有诊断
      (async () => {
        statusBar.text = "$(loading~spin) 保存后自动扫描中...";
        statusBar.tooltip = `正在扫描: ${vscode.workspace.asRelativePath(pending.uri)}`;
        const result = await callAnalyzeApi(pending, undefined, "single");
        if (result && !result.error && result.has_vulnerability !== undefined) {
          applyDiagnostics(pending, result);
          updateStatusBarForSingle(result);
        } else if (result && result.error) {
          statusBar.text = "$(shield) 自动扫描失败";
          statusBar.tooltip = result.error;
        }
      })();
    }, 1500);
  });
  context.subscriptions.push(saveListener);
}

/**
 * 是否为支持的代码文档
 */
function isSupportedDoc(doc) {
  return LANG_MAP[doc.languageId] !== undefined;
}

// ---------------------------------------------------------------------------
// 单文件分析
// ---------------------------------------------------------------------------
async function analyzeDocument(doc, context) {
  const config = vscode.workspace.getConfiguration("vulnScanner");
  const code = doc.getText();
  const filename = vscode.workspace.asRelativePath(doc.uri);
  const language = LANG_MAP[doc.languageId] || "text";

  if (!code.trim()) {
    vscode.window.showWarningMessage("文件为空");
    return;
  }

  statusBar.text = "$(loading~spin) 扫描中...";
  statusBar.tooltip = `正在扫描: ${filename}`;

  const result = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `凿凿扫描: ${filename}`,
      cancellable: false,
    },
    async () => {
      return await callAnalyzeApi(doc, undefined, "single");
    }
  );

  if (result.error) {
    statusBar.text = "$(shield) 扫描失败";
    statusBar.tooltip = result.error;
    vscode.window.showErrorMessage(`扫描失败: ${result.error}`);
    return;
  }

  // 应用诊断标记
  if (config.get("markDiagnostics", true)) {
    applyDiagnostics(doc, result);
  }

  updateStatusBarForSingle(result);

  showResultPanel(result, context);
}

/**
 * 调用后端 /api/analyze
 * @param scanScope 'single'（交互式,HIGH 优先级）/ 'batch'（批量,LOW 优先级）
 *                  调度器据 X-Scan-Scope 分配优先级，X-Client-Type 标识来源为 vscode
 */
function callAnalyzeApi(doc, overrideCode, scanScope) {
  const config = vscode.workspace.getConfiguration("vulnScanner");
  const backendUrl = config.get("backendUrl", "http://localhost:8765");
  const useRag = config.get("useRag", false);
  const timeout = config.get("requestTimeout", 300000);

  const code = overrideCode !== undefined ? overrideCode : doc.getText();
  const filename = doc ? vscode.workspace.asRelativePath(doc.uri) : "pasted_code";
  const language = doc ? (LANG_MAP[doc.languageId] || "text") : "text";

  return new Promise((resolve) => {
    // 不用废弃的 url.resolve；直接基于 backendUrl 构造，同时支持 http/https
    let parsed;
    try {
      parsed = new URL("/api/analyze", backendUrl);
    } catch (e) {
      resolve({ error: `后端地址配置无效 (${backendUrl}): ${e.message}` });
      return;
    }
    const httpModule = parsed.protocol === "https:" ? require("https") : http;
    const body = JSON.stringify({
      code,
      language,
      filename,
      use_rag: useRag,
    });

    const headers = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
      "X-Client-Type": "vscode",
    };
    if (scanScope) headers["X-Scan-Scope"] = scanScope;

    const req = httpModule.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: "POST",
        headers,
        timeout,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          let parsedBody;
          try {
            parsedBody = JSON.parse(data);
          } catch (e) {
            resolve({ error: `响应解析失败 (HTTP ${res.statusCode}): ${e.message}` });
            return;
          }
          // 非 2xx：FastAPI 校验失败返回 {"detail":[...]}（无 error 字段），
          // 必须显式提取，否则会落入"无法判定"分支并清除已有诊断
          if (res.statusCode < 200 || res.statusCode >= 300) {
            let msg = parsedBody && parsedBody.error;
            if (!msg && parsedBody && parsedBody.detail !== undefined) {
              msg = typeof parsedBody.detail === "string"
                ? parsedBody.detail
                : (parsedBody.detail || [])
                    .map((d) => (d && d.msg) || JSON.stringify(d))
                    .join("; ");
            }
            resolve({ error: msg || `后端返回 HTTP ${res.statusCode}` });
            return;
          }
          resolve(parsedBody);
        });
      }
    );

    req.on("error", (e) => {
      resolve({
        error: `无法连接后端 (${backendUrl})。请确保后端服务已启动。详情: ${e.message}`,
      });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({ error: "请求超时" });
    });

    req.write(body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// 批量扫描工作区 / 文件夹
// ---------------------------------------------------------------------------
async function scanWorkspace(context) {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || !folders.length) {
    vscode.window.showWarningMessage("请先打开一个工作区文件夹");
    return;
  }
  const config = vscode.workspace.getConfiguration("vulnScanner");
  const maxFiles = config.get("workspaceMaxFiles", 50);

  // 多根工作区：遍历所有根目录收集文件（原先只扫 folders[0]，其余根被静默忽略）
  let files = [];
  for (const folder of folders) {
    const found = await collectFiles(folder.uri, maxFiles - files.length);
    files = files.concat(found);
    if (files.length >= maxFiles) break;
  }
  // label 列出所有根目录名，多根时用户可见
  await runBatchScan(files, folders.map((f) => f.name).join(", "), context);
}

async function scanFolder(folderUri, context) {
  const config = vscode.workspace.getConfiguration("vulnScanner");
  const maxFiles = config.get("workspaceMaxFiles", 50);
  const files = await collectFiles(folderUri, maxFiles);
  await runBatchScan(files, folderUri.fsPath, context);
}

/**
 * 收集指定目录下的代码文件（限定在该目录内，而非整个工作区）
 */
async function collectFiles(baseUri, maxResults) {
  if (maxResults <= 0) return [];
  const config = vscode.workspace.getConfiguration("vulnScanner");
  // 用户清空 workspaceExclude 时回退默认值（空数组 = 不排除任何目录，会扫进 node_modules）
  const configured = config.get("workspaceExclude", DEFAULT_EXCLUDES);
  const excludePatterns = Array.isArray(configured) && configured.length ? configured : DEFAULT_EXCLUDES;

  const includePattern = new vscode.RelativePattern(
    baseUri.fsPath,
    "**/*.{py,js,ts,jsx,tsx,java,php,go,html,htm,vue,svelte}"
  );
  const excludePattern = `{${excludePatterns.join(",")}}`;

  try {
    return await vscode.workspace.findFiles(includePattern, excludePattern, maxResults);
  } catch (e) {
    vscode.window.showErrorMessage(`查找文件失败: ${e.message}`);
    return [];
  }
}

async function runBatchScan(files, label, context) {
  const config = vscode.workspace.getConfiguration("vulnScanner");

  if (!files.length) {
    vscode.window.showInformationMessage("未找到可扫描的代码文件");
    return;
  }

  outputChannel.clear();
  outputChannel.appendLine(`════════════════════════════════════════`);
  outputChannel.appendLine(`  批量扫描开始: ${label}`);
  outputChannel.appendLine(`  文件数: ${files.length}  RAG: ${config.get("useRag", false) ? "开" : "关"}`);
  outputChannel.appendLine(`════════════════════════════════════════`);
  outputChannel.show(true);

  statusBar.text = `$(loading~spin) 批量扫描 0/${files.length}`;
  statusBar.tooltip = "正在批量扫描工作区";

  const results = [];
  let vulnerable = 0;
  let safe = 0;
  let errors = 0;
  let skipped = 0; // 空文件（无可分析内容）计数，汇总时单列，避免"总文件"口径缩水

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "凿凿扫描: 批量扫描",
      cancellable: true,
    },
    async (progress, token) => {
      for (let i = 0; i < files.length; i++) {
        if (token.isCancellationRequested) {
          outputChannel.appendLine(`  [取消] 用户中止扫描`);
          break;
        }

        const fileUri = files[i];
        const relName = vscode.workspace.asRelativePath(fileUri);
        progress.report({
          message: `(${i + 1}/${files.length}) ${relName}`,
          increment: 100 / files.length,
        });

        statusBar.text = `$(loading~spin) 批量扫描 ${i + 1}/${files.length}`;

        // 读取文件
        let code;
        try {
          const doc = await vscode.workspace.openTextDocument(fileUri);
          code = doc.getText();
        } catch (e) {
          outputChannel.appendLine(`  [✗] ${relName} — 读取失败: ${e.message}`);
          errors++;
          results.push({ filename: relName, error: "读取失败", has_vulnerability: null });
          continue;
        }

        if (!code.trim()) {
          skipped++;
          outputChannel.appendLine(`  [·] ${relName} — 空文件，跳过`);
          continue;
        }

        // 调用分析（复用 callAnalyzeApi，传入虚拟 doc；批量扫描标 batch 降为 LOW 优先级）
        const fakeDoc = { uri: fileUri, languageId: extToLangId(fileUri), getText: () => code };
        const result = await callAnalyzeApi(fakeDoc, code, "batch");

        if (result.error) {
          outputChannel.appendLine(`  [✗] ${relName} — ${result.error}`);
          errors++;
          results.push({ filename: relName, error: result.error, has_vulnerability: null });
          continue;
        }

        results.push(result);

        if (result.has_vulnerability === true) {
          vulnerable++;
          const mark = "✗";
          outputChannel.appendLine(`  [${mark}] ${relName} — ${result.vulnerability_type} (${result.risk_level})`);
          // 应用诊断
          if (config.get("markDiagnostics", true)) {
            try {
              const doc = await vscode.workspace.openTextDocument(fileUri);
              applyDiagnostics(doc, result);
            } catch (_) {}
          }
        } else if (result.has_vulnerability === false) {
          safe++;
          outputChannel.appendLine(`  [✓] ${relName}`);
        } else {
          errors++;
          outputChannel.appendLine(`  [?] ${relName} — 无法判定`);
        }
      }
    }
  );

  // 汇总
  outputChannel.appendLine("");
  outputChannel.appendLine(`────────────────────────────────────────`);
  outputChannel.appendLine(`  扫描汇总`);
  outputChannel.appendLine(`  总文件: ${files.length}  漏洞: ${vulnerable}  安全: ${safe}  错误: ${errors}  跳过(空文件): ${skipped}`);
  if (vulnerable > 0) {
    outputChannel.appendLine("");
    outputChannel.appendLine(`  漏洞清单:`);
    results
      .filter((r) => r.has_vulnerability === true)
      .forEach((r) => {
        outputChannel.appendLine(`    ● ${r.filename} — ${r.vulnerability_type} (${r.risk_level})`);
      });
  }
  outputChannel.appendLine(`────────────────────────────────────────`);

  // 更新状态栏
  if (vulnerable > 0) {
    statusBar.text = `$(warning) ${vulnerable} 个漏洞`;
    statusBar.tooltip = `${vulnerable} 个漏洞 / ${safe} 安全 / ${errors} 错误 — 点击重新扫描`;
    statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
  } else {
    statusBar.text = `$(check) ${safe} 文件安全`;
    statusBar.tooltip = `${safe} 文件安全 — 点击重新扫描`;
    statusBar.backgroundColor = undefined;
  }

  // 展示汇总面板
  showBatchPanel(results, vulnerable, safe, errors, context);
}

/**
 * 文件 URI → 语言 ID
 */
function extToLangId(fileUri) {
  const ext = path.extname(fileUri.fsPath).toLowerCase();
  const lang = EXT_TO_LANG[ext];
  // 反查 LANG_MAP 的 key
  for (const [k, v] of Object.entries(LANG_MAP)) {
    if (v === lang) return k;
  }
  return "plaintext";
}

// ---------------------------------------------------------------------------
// 诊断标记
// ---------------------------------------------------------------------------
/**
 * 从扫描结果提取诊断目标（一处目标 = 一个漏洞）。
 *
 * 两阶段响应：每个 confirmed 的 adjudication 一处，定位用 finding 的
 * sink_line/source_line 精确行号（后端结构化行号，比文本解析可靠）；
 * 旧后端（无 adjudications）：回退顶层 sink/source 文本定位。
 */
function collectDiagnosticTargets(result) {
  const targets = [];
  if (Array.isArray(result.adjudications)) {
    for (const adj of result.adjudications) {
      if (!adj || adj.confirmed !== true) continue;
      const f = adj.finding || {};
      const line = [f.sink_line, f.source_line].find((n) => Number.isInteger(n) && n > 0);
      targets.push({
        severity: mapRiskToSeverity(f.severity || result.risk_level),
        line: line || null, // 1 起始；null = 需文本定位
        sink: f.sink || result.sink,
        source: f.source || result.source,
        type: adj.vulnerability_type || f.taint_type || result.vulnerability_type || "",
        message: adj.reasoning || result.explanation || "",
      });
    }
  }
  if (!targets.length && result.has_vulnerability === true) {
    targets.push({
      severity: mapRiskToSeverity(result.risk_level),
      line: null,
      sink: result.sink,
      source: result.source,
      type: result.vulnerability_type || "",
      message: result.explanation || "",
    });
  }
  return targets;
}

function applyDiagnostics(doc, result) {
  if (!diagnosticCollection) return;
  if (result.has_vulnerability !== true) {
    // 安全文件清除该文件的诊断
    diagnosticCollection.delete(doc.uri);
    return;
  }

  const code = doc.getText();
  const lines = code.split("\n");
  const diagnostics = [];
  const usedLines = new Set(); // 同一行多个 finding 合并为一条，避免波浪线叠加

  for (const target of collectDiagnosticTargets(result)) {
    const located = locateTargetLine(target, lines);
    if (located !== null) {
      if (usedLines.has(located)) continue;
      usedLines.add(located);
      diagnostics.push(makeDiagnosticAtLine(located, lines, target));
    }
  }

  // 全部定位失败：标记第一行（文件级兜底）
  if (!diagnostics.length) {
    const range = new vscode.Range(0, 0, 0, lines[0] ? lines[0].length : 0);
    diagnostics.push(
      new vscode.Diagnostic(
        range,
        `[${result.vulnerability_type}] ${result.risk_level} — ${result.explanation || "发现漏洞"}`,
        mapRiskToSeverity(result.risk_level)
      )
    );
  }

  diagnosticCollection.set(doc.uri, diagnostics);
}

/** 把一个诊断目标定位到行号（0 起始）；失败返回 null。 */
function locateTargetLine(target, lines) {
  // 1) 后端结构化行号（1 起始）直接换算
  if (target.line !== null && target.line <= lines.length) {
    return target.line - 1;
  }
  // 2) 顶层 sink/source 文本里的 `line N:` 锚点
  for (const locator of [target.sink, target.source]) {
    if (!locator || locator === "N/A") continue;
    const anchored = extractLineAnchor(locator);
    if (anchored !== null && anchored - 1 < lines.length) {
      return anchored - 1;
    }
  }
  // 3) 无锚点时回退 token 匹配（可能误标首个同名标识符行）
  for (const locator of [target.sink, target.source]) {
    if (!locator || locator === "N/A") continue;
    for (const token of extractTokens(locator)) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(token)) return i;
      }
    }
  }
  return null;
}

/**
 * 从描述文本中解析 `line N:` 行号锚点（1 起始），解析失败返回 null。
 * 模型输出的 sink/source 常带精确行号，用它定位比 token 匹配可靠。
 */
function extractLineAnchor(text) {
  if (!text) return null;
  const m = text.match(/line\s*:?\s*(\d+)/i);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** 构造第 i 行（0 起始）的诊断对象。target 为 collectDiagnosticTargets 的条目。 */
function makeDiagnosticAtLine(i, lines, target) {
  const line = lines[i] || "";
  const startChar = line.search(/\S/);
  const col = startChar >= 0 ? startChar : 0;
  const range = new vscode.Range(i, col, i, line.length);
  return new vscode.Diagnostic(
    range,
    `[${target.type}] — ${target.message || target.sink || "发现漏洞"}`,
    target.severity
  );
}

/**
 * 从描述文本中提取可能的代码标识符
 */
function extractTokens(text) {
  if (!text) return [];
  const tokens = [];

  // 提取反引号包裹的代码
  const backtick = text.match(/`([^`]+)`/);
  if (backtick) tokens.push(backtick[1]);

  // 提取括号前的函数名（如 eval(...)）
  const funcMatches = text.match(/([a-zA-Z_][a-zA-Z0-9_\.]*)\s*\(/g);
  if (funcMatches) {
    for (const fm of funcMatches) {
      tokens.push(fm.replace(/\s*\($/, ""));
    }
  }

  // 提取常见危险关键字
  const keywords = ["eval", "exec", "system", "popen", "subprocess", "os.system",
    "pickle", "loads", "innerHTML", "document.write",
    "shell=True", "request.get", "request.post", "requests.get",
    "cursor.execute", "execute", "query", "render", "redirect",
    "open(", "yaml.load", "marshal", "base64", "md5", "sha1"];
  for (const kw of keywords) {
    if (text.toLowerCase().includes(kw.toLowerCase())) {
      tokens.push(kw);
    }
  }

  // 提取独立单词（去掉标点）
  const words = text.match(/[a-zA-Z_][a-zA-Z0-9_]+/g) || [];
  for (const w of words) {
    if (w.length >= 4 && !tokens.includes(w)) tokens.push(w);
  }

  // 去重，长的优先
  return [...new Set(tokens)].sort((a, b) => b.length - a.length).slice(0, 5);
}

function mapRiskToSeverity(risk) {
  const r = (risk || "").toLowerCase();
  if (r === "critical" || r === "high") return vscode.DiagnosticSeverity.Error;
  if (r === "medium") return vscode.DiagnosticSeverity.Warning;
  if (r === "low") return vscode.DiagnosticSeverity.Information;
  return vscode.DiagnosticSeverity.Warning;
}

// ---------------------------------------------------------------------------
// 状态栏更新
// ---------------------------------------------------------------------------
function updateStatusBarForSingle(result) {
  if (result.has_vulnerability === true) {
    statusBar.text = `$(warning) 发现漏洞`;
    statusBar.tooltip = `${result.vulnerability_type} (${result.risk_level}) — 点击扫描工作区`;
    statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
  } else if (result.has_vulnerability === false) {
    statusBar.text = `$(check) 安全`;
    statusBar.tooltip = "未发现漏洞 — 点击扫描工作区";
    statusBar.backgroundColor = undefined;
  } else {
    statusBar.text = `$(question) 无法判定`;
    statusBar.tooltip = "点击扫描工作区";
    statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
  }
}

// ---------------------------------------------------------------------------
// Webview 结果展示
// ---------------------------------------------------------------------------
// 面板复用：每次扫描新建面板会堆积，改为单实例 + reveal 更新内容
let resultPanel;
let batchPanel;

function showResultPanel(result, context) {
  if (!resultPanel) {
    resultPanel = vscode.window.createWebviewPanel(
      "vulnResult",
      `扫描结果: ${result.filename}`,
      vscode.ViewColumn.Two,
      {
        enableScripts: false,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, "assets")]
      }
    );
    resultPanel.onDidDispose(() => { resultPanel = undefined; });
  } else {
    resultPanel.title = `扫描结果: ${result.filename}`;
    resultPanel.reveal(vscode.ViewColumn.Two);
  }

  const isVuln = result.has_vulnerability === true;
  const isSafe = result.has_vulnerability === false;
  const isError = result.has_vulnerability === null || result.has_vulnerability === undefined;

  const iconUri = resultPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(context.extensionUri, "assets", "icon-light.png")
  );
  const wordUri = resultPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(context.extensionUri, "assets", "logo-light.png")
  );
  resultPanel.webview.html = renderHtml(result, isVuln, isSafe, isError, iconUri, wordUri);
}

function showBatchPanel(results, vulnerable, safe, errors, context) {
  if (!batchPanel) {
    batchPanel = vscode.window.createWebviewPanel(
      "vulnBatch",
      "批量扫描汇总",
      vscode.ViewColumn.One,
      {
        enableScripts: false,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, "assets")]
      }
    );
    batchPanel.onDidDispose(() => { batchPanel = undefined; });
  } else {
    batchPanel.reveal(vscode.ViewColumn.One);
  }

  const vulnList = results.filter((r) => r.has_vulnerability === true);

  const iconUri = batchPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(context.extensionUri, "assets", "icon-light.png")
  );
  const wordUri = batchPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(context.extensionUri, "assets", "logo-light.png")
  );
  batchPanel.webview.html = renderBatchHtml(results, vulnList, vulnerable, safe, errors, iconUri, wordUri);
}

// ---- 信任层展示辅助：decision / 共形 / 反事实 / 证据门 的中文标签 ----
function decisionLabel(d) {
  const map = {
    confirmed_vulnerability: "确认漏洞（高置信）",
    confirmed_review: "确认漏洞（建议复核）",
    dismissed_safe: "驳回（高置信安全）",
    dismissed_review: "驳回（低置信）",
    direct: "确定性直出（密钥/依赖，无 LLM 采样）",
  };
  return map[d] || d || "—";
}

function conformalLabel(c) {
  const map = { vulnerable: "判漏洞", safe: "判安全", uncertain: "不确定" };
  return map[c] || c || "—";
}

function counterfactualLabel(cf) {
  if (!cf || typeof cf !== "object") return "未启用";
  if (!cf.applicable) return "不适用";
  if (cf.flipped === true) return "扰动后翻转（模型理解防御，结论降级）";
  if (cf.already_defended) return "原代码已有防御（候选多为误报）";
  if (cf.flipped === false) return "扰动后结论不变（非模式匹配）";
  return "不可判定";
}

function gateLabel(g) {
  const map = { sink_defended: "sink 已有防御", no_input_entry: "无输入入口" };
  return map[g] || g;
}

/** 两阶段信任层区块：裁决明细 + 人工复核清单。非两阶段响应返回空串。 */
function trustSectionHtml(r) {
  if (!Array.isArray(r.adjudications) || !r.adjudications.length) return "";
  const rows = r.adjudications
    .map((adj) => {
      if (!adj) return "";
      const f = adj.finding || {};
      const confirmed = adj.confirmed === true;
      const conf = typeof adj.confidence === "number" ? `${Math.round(adj.confidence * 100)}%` : "—";
      const votes = `${adj.votes_true ?? 0} 真 / ${adj.votes_false ?? 0} 假 / ${adj.votes_invalid ?? 0} 无效`;
      const line = [f.sink_line, f.source_line].find((n) => Number.isInteger(n) && n > 0);
      const cf = counterfactualLabel(adj.counterfactual);
      return `<tr>
<td><span class="verdict ${confirmed ? "v-yes" : "v-no"}">${confirmed ? "判真" : "驳回"}</span></td>
<td>${escapeHtml(decisionLabel(adj.decision))}<br><span class="sub">置信度 ${escapeHtml(conf)}（${escapeHtml(votes)}）</span></td>
<td>${escapeHtml(adj.vulnerability_type || f.taint_type || "—")}</td>
<td>共形 ${escapeHtml(conformalLabel(adj.conformal_set))}<br><span class="sub">反事实: ${escapeHtml(cf)}</span></td>
<td>${escapeHtml(line ? `第 ${line} 行` : "—")}<br><span class="sub">${adj.evidence_gate ? "证据门: " + escapeHtml(gateLabel(adj.evidence_gate)) : "未拦截"}</span></td>
</tr>`;
    })
    .join("");

  let reviewerHtml = "";
  if (Array.isArray(r.reviewer_findings) && r.reviewer_findings.length) {
    const items = r.reviewer_findings
      .map((rv) => {
        const f = rv.finding || {};
        const conf = typeof rv.confidence === "number" ? `${Math.round(rv.confidence * 100)}%` : "—";
        return `<li>${escapeHtml(rv.vulnerability_type || f.taint_type || "未知类型")} — 置信度 ${escapeHtml(conf)}，${escapeHtml(decisionLabel(rv.decision))}</li>`;
      })
      .join("");
    reviewerHtml = `<div class="review-box"><b>需人工复核（${r.reviewer_findings.length} 项低置信候选）</b><ul>${items}</ul></div>`;
  }

  return `<div class="trust"><div class="field-label">信任层明细（Stage 2 裁决 ${r.adjudications.length} 项候选）</div>
<table class="adj"><thead><tr><th>结论</th><th>裁决档位 / 置信度</th><th>类型</th><th>共形 / 反事实</th><th>位置 / 证据门</th></tr></thead>
<tbody>${rows}</tbody></table>${reviewerHtml}</div>`;
}

function renderHtml(r, isVuln, isSafe, isError, iconUri, wordUri) {
  const statusColor = isVuln ? "#ea4335" : isSafe ? "#34a853" : "#f9ab00";
  const statusText = isVuln ? "发现漏洞" : isSafe ? "未发现漏洞" : "无法判定";

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<style>
.logo-row { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; }
.logo-row img.icon { width: 26px; height: 26px; }
.logo-row img.word { height: 18px; }
body { font-family: -apple-system, "Microsoft YaHei", sans-serif; padding: 20px; color: #0b0f14; background: #ffffff; max-width: 800px; }
.header { border-left: 4px solid ${statusColor}; padding-left: 16px; margin-bottom: 20px; }
.header h1 { font-size: 18px; margin: 0 0 4px 0; color: #0b0f14; }
.header .status { color: ${statusColor}; font-weight: 600; }
.meta { background: #f7f8fa; border: 1px solid #e4e7ec; padding: 12px; border-radius: 6px; margin-bottom: 16px; font-size: 13px; }
.meta div { margin: 4px 0; }
.field { margin-bottom: 12px; }
.field-label { font-weight: 600; color: #5a6573; margin-bottom: 4px; }
.field-value { line-height: 1.6; }
.fix { background: rgba(52, 168, 83, 0.08); border: 1px solid rgba(52, 168, 83, 0.35); padding: 12px; border-radius: 6px; }
.fix .label { color: #34a853; font-weight: 600; }
details { margin-top: 16px; }
summary { cursor: pointer; color: #1e7ea0; }
pre { background: #f7f8fa; border: 1px solid #e4e7ec; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; background: ${statusColor}; color: #fff; }
.trust { margin-top: 16px; }
.trust .field-label { margin-bottom: 8px; }
table.adj { width: 100%; border-collapse: collapse; font-size: 12px; }
table.adj th, table.adj td { padding: 6px 8px; border-bottom: 1px solid #e4e7ec; text-align: left; vertical-align: top; }
table.adj th { background: #f7f8fa; font-weight: 600; }
.verdict { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; color: #fff; }
.verdict.v-yes { background: #b3261e; }
.verdict.v-no { background: #1e7e34; }
.sub { color: #9aa4b2; font-size: 11px; }
.review-box { margin-top: 10px; background: rgba(249, 171, 0, 0.10); border: 1px solid rgba(249, 171, 0, 0.4); padding: 10px 12px; border-radius: 6px; font-size: 12px; }
.review-box ul { margin: 6px 0 0 18px; padding: 0; }
</style>
</head>
<body>
<div class="logo-row"><img class="icon" src="${iconUri}" alt=""><img class="word" src="${wordUri}" alt="凿凿"></div>
<div class="header">
  <h1>${escapeHtml(r.filename || "")}</h1>
  <div class="status">${statusText} ${r.risk_level ? `<span class="badge">${escapeHtml(r.risk_level)}</span>` : ""} <span style="color:#9aa4b2;font-size:12px">${r.duration || 0}s</span></div>
</div>

${isError ? `<div style="color:#ea4335">错误: ${escapeHtml(r.error || "未知")}</div>` : ""}

<div class="meta">
  <div>语言: ${escapeHtml(r.language || "")}</div>
  ${r.vulnerability_type && r.vulnerability_type !== "none" ? `<div>漏洞类型: ${escapeHtml(r.vulnerability_type)}</div>` : ""}
  ${Array.isArray(r.vulnerability_types) && r.vulnerability_types.length > 1 ? `<div>全部确认类型: ${escapeHtml(r.vulnerability_types.join("、"))}</div>` : ""}
  ${r.source && r.source !== "N/A" ? `<div>污染来源: ${escapeHtml(r.source)}</div>` : ""}
  ${r.sink && r.sink !== "N/A" ? `<div>触发点: ${escapeHtml(r.sink)}</div>` : ""}
</div>

${trustSectionHtml(r)}

${r.explanation ? `<div class="field"><div class="field-label">分析说明</div><div class="field-value">${escapeHtml(r.explanation)}</div></div>` : ""}

${isVuln && r.fix_suggestion ? `<div class="fix"><div class="label">修复建议</div><div>${escapeHtml(r.fix_suggestion)}</div></div>` : ""}

${modelProcessHtml(r)}
</body>
</html>`;
}

/**
 * 「查看模型分析过程」区块。
 * 两阶段模式下顶层 raw_output 为空（裁决原始输出在 adjudications[].raw_outputs），
 * 回退取首个判真裁决的 reasoning + N 次采样原文；都没有时返回空串（不渲染）。
 */
function modelProcessHtml(r) {
  let content = r.raw_output || "";
  if (!content && Array.isArray(r.adjudications)) {
    const confirmed = r.adjudications.find((a) => a && a.confirmed === true);
    if (confirmed) {
      const samples = Array.isArray(confirmed.raw_outputs) ? confirmed.raw_outputs.filter(Boolean) : [];
      content = samples.length
        ? `${confirmed.reasoning || ""}${samples.map((s) => "\n──── 采样 ────\n" + s).join("")}`
        : confirmed.reasoning || "";
    }
  }
  return content ? `<details><summary>查看模型分析过程</summary><pre>${escapeHtml(content)}</pre></details>` : "";
}

function renderBatchHtml(results, vulnList, vulnerable, safe, errors, iconUri, wordUri) {
  const vulnRows = vulnList
    .map(
      (r) =>
        `<tr><td>${escapeHtml(r.filename || "")}</td><td>${escapeHtml(r.vulnerability_type || "")}</td><td>${escapeHtml(r.risk_level || "")}</td><td>${escapeHtml(r.sink || "")}</td></tr>`
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<style>
.logo-row { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; }
.logo-row img.icon { width: 26px; height: 26px; }
.logo-row img.word { height: 18px; }
body { font-family: -apple-system, "Microsoft YaHei", sans-serif; padding: 20px; color: #0b0f14; background: #ffffff; max-width: 900px; }
h1 { font-size: 20px; color: #0b0f14; }
.summary { display: flex; gap: 16px; margin: 16px 0; }
.card { flex: 1; padding: 16px; border-radius: 8px; text-align: center; }
.card.total { background: #f7f8fa; border: 1px solid #e4e7ec; color: #0b0f14; }
.card.vuln { background: rgba(234, 67, 53, 0.08); color: #ea4335; }
.card.safe { background: rgba(52, 168, 83, 0.08); color: #34a853; }
.card.err { background: rgba(249, 171, 0, 0.08); color: #f9ab00; }
.card .num { font-size: 28px; font-weight: 700; }
.card .label { font-size: 12px; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; margin-top: 16px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e4e7ec; font-size: 13px; }
th { background: #f7f8fa; font-weight: 600; }
td:first-child { font-family: monospace; }
.risk-critical, .risk-high { color: #ea4335; font-weight: 600; }
.risk-medium { color: #f9ab00; }
.risk-low { color: #1e7ea0; }
</style>
</head>
<body>
<div class="logo-row"><img class="icon" src="${iconUri}" alt=""><img class="word" src="${wordUri}" alt="凿凿"></div>
<h1>批量扫描汇总</h1>
<div class="summary">
  <div class="card total"><div class="num">${results.length}</div><div class="label">总文件</div></div>
  <div class="card vuln"><div class="num">${vulnerable}</div><div class="label">发现漏洞</div></div>
  <div class="card safe"><div class="num">${safe}</div><div class="label">安全</div></div>
  <div class="card err"><div class="num">${errors}</div><div class="label">错误</div></div>
</div>

${vulnList.length ? `
<h2>漏洞清单</h2>
<table>
<thead><tr><th>文件</th><th>漏洞类型</th><th>风险</th><th>触发点</th></tr></thead>
<tbody>${vulnRows}</tbody>
</table>
` : "<p style='color:#34a853;margin-top:16px'>✓ 未发现漏洞</p>"}

<p style="color:#9aa4b2;font-size:12px;margin-top:24px">详细分析见输出面板（Output → 凿凿）</p>
</body>
</html>`;
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function deactivate() {}

// 导出内部纯函数供测试桩使用（下划线前缀，非公开 API）
module.exports = {
  activate,
  deactivate,
  _collectDiagnosticTargets: collectDiagnosticTargets,
  _trustSectionHtml: trustSectionHtml,
  _modelProcessHtml: modelProcessHtml,
};
