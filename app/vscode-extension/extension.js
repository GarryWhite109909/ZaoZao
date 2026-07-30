/**
 * AI 漏洞扫描器 VSCode 插件 v1.2.0
 *
 * 功能：
 *  1. 右键编辑器 → "分析当前文件" → 调用后端 API → Webview 展示结果
 *  2. 命令面板 → "批量扫描工作区" → 递归扫描所有代码文件 → 汇总报告
 *  3. 资源管理器右键文件夹 → "扫描指定文件夹"
 *  4. 发现漏洞时在编辑器中标记诊断波浪线（基于 source/sink 定位）
 *  5. 状态栏显示扫描状态与漏洞计数
 *  6. 可选：保存文件时自动扫描
 *
 * 依赖：仅用 Node.js 内置模块（http），无需 npm install
 * 调试：在 VSCode 中打开本目录，按 F5 启动扩展开发宿主
 */

const vscode = require("vscode");
const http = require("http");
const url = require("url");
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
  outputChannel = vscode.window.createOutputChannel("AI 漏洞扫描器");
  context.subscriptions.push(outputChannel);

  // 状态栏
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = "vulnScanner.scanWorkspace";
  statusBar.text = "$(shield) 漏洞扫描";
  statusBar.tooltip = "点击批量扫描工作区";
  statusBar.show();
  context.subscriptions.push(statusBar);

  // ---- 命令注册 ----

  // 1. 分析当前文件
  const analyzeCmd = vscode.commands.registerCommand(
    "vulnScanner.analyzeFile",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("请先打开一个文件");
        return;
      }
      await analyzeCurrentFile(editor, context);
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
      statusBar.text = "$(shield) 漏洞扫描";
      statusBar.tooltip = "点击批量扫描工作区";
      vscode.window.showInformationMessage("已清除所有漏洞诊断标记");
    }
  );

  context.subscriptions.push(analyzeCmd, scanWorkspaceCmd, scanFolderCmd, clearCmd);

  // ---- 保存时自动扫描 ----
  const saveListener = vscode.workspace.onWillSaveTextDocument((event) => {
    const config = vscode.workspace.getConfiguration("vulnScanner");
    if (!config.get("autoScanOnSave", false)) return;
    if (!isSupportedDoc(event.document)) return;

    event.waitUntil(
      (async () => {
        const result = await callAnalyzeApi(event.document);
        if (result && !result.error) {
          applyDiagnostics(event.document, result);
        }
      })()
    );
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
async function analyzeCurrentFile(editor, context) {
  const config = vscode.workspace.getConfiguration("vulnScanner");
  const backendUrl = config.get("backendUrl", "http://localhost:8765");
  const useRag = config.get("useRag", false);

  const doc = editor.document;
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
      title: `AI 漏洞扫描: ${filename}`,
      cancellable: false,
    },
    async () => {
      return await callAnalyzeApi(doc);
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
 */
function callAnalyzeApi(doc, overrideCode) {
  const config = vscode.workspace.getConfiguration("vulnScanner");
  const backendUrl = config.get("backendUrl", "http://localhost:8765");
  const useRag = config.get("useRag", false);
  const timeout = config.get("requestTimeout", 300000);

  const code = overrideCode !== undefined ? overrideCode : doc.getText();
  const filename = doc ? vscode.workspace.asRelativePath(doc.uri) : "pasted_code";
  const language = doc ? (LANG_MAP[doc.languageId] || "text") : "text";

  return new Promise((resolve) => {
    const endpoint = url.resolve(backendUrl, "/api/analyze");
    const parsed = new URL(endpoint);
    const body = JSON.stringify({
      code,
      language,
      filename,
      use_rag: useRag,
    });

    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
        timeout,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            resolve({ error: `JSON 解析失败: ${e.message}` });
          }
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
  await scanFolder(folders[0].uri, context);
}

async function scanFolder(folderUri, context) {
  const config = vscode.workspace.getConfiguration("vulnScanner");
  const excludePatterns = config.get("workspaceExclude", []);
  const maxFiles = config.get("workspaceMaxFiles", 50);

  // 收集代码文件
  const includePattern = "**/*.{py,js,ts,jsx,tsx,java,php,go,html,htm,vue,svelte}";
  const excludePattern = excludePatterns.length ? `{${excludePatterns.join(",")}}` : undefined;

  let files;
  try {
    files = await vscode.workspace.findFiles(includePattern, excludePattern, maxFiles);
  } catch (e) {
    vscode.window.showErrorMessage(`查找文件失败: ${e.message}`);
    return;
  }

  if (!files.length) {
    vscode.window.showInformationMessage("未找到可扫描的代码文件");
    return;
  }

  outputChannel.clear();
  outputChannel.appendLine(`════════════════════════════════════════`);
  outputChannel.appendLine(`  批量扫描开始: ${folderUri.fsPath}`);
  outputChannel.appendLine(`  文件数: ${files.length}  上限: ${maxFiles}  RAG: ${config.get("useRag", false) ? "开" : "关"}`);
  outputChannel.appendLine(`════════════════════════════════════════`);
  outputChannel.show(true);

  statusBar.text = `$(loading~spin) 批量扫描 0/${files.length}`;
  statusBar.tooltip = "正在批量扫描工作区";

  const results = [];
  let vulnerable = 0;
  let safe = 0;
  let errors = 0;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "AI 漏洞扫描: 批量扫描",
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

        if (!code.trim()) continue;

        // 调用分析（复用 callAnalyzeApi，传入虚拟 doc）
        const fakeDoc = { uri: fileUri, languageId: extToLangId(fileUri), getText: () => code };
        const result = await callAnalyzeApi(fakeDoc, code);

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
  outputChannel.appendLine(`  总文件: ${results.length}  漏洞: ${vulnerable}  安全: ${safe}  错误: ${errors}`);
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
function applyDiagnostics(doc, result) {
  if (!diagnosticCollection) return;
  if (result.has_vulnerability !== true) {
    // 安全文件清除该文件的诊断
    diagnosticCollection.delete(doc.uri);
    return;
  }

  const severity = mapRiskToSeverity(result.risk_level);
  const code = doc.getText();
  const lines = code.split("\n");

  const diagnostics = [];

  // 基于 sink / source 定位漏洞行
  const locators = [result.sink, result.source].filter((s) => s && s !== "N/A");
  let located = false;

  for (const locator of locators) {
    if (located) break;
    // 从描述中提取可能的标识符（函数名、关键字）
    const tokens = extractTokens(locator);
    for (const token of tokens) {
      if (located) break;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(token)) {
          const line = lines[i];
          const startChar = line.indexOf(token);
          const range = new vscode.Range(i, startChar, i, Math.min(startChar + token.length, line.length));
          diagnostics.push(
            new vscode.Diagnostic(
              range,
              `[${result.vulnerability_type}] ${result.risk_level} — ${result.explanation || result.sink}`,
              severity
            )
          );
          located = true;
          break;
        }
      }
    }
  }

  // 定位失败：标记第一行
  if (!located) {
    const range = new vscode.Range(0, 0, 0, lines[0] ? lines[0].length : 0);
    diagnostics.push(
      new vscode.Diagnostic(
        range,
        `[${result.vulnerability_type}] ${result.risk_level} — ${result.explanation || "发现漏洞"}`,
        severity
      )
    );
  }

  diagnosticCollection.set(doc.uri, diagnostics);
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
    "pickle", "loads", "innerHTML", "document.write", "innerHTML",
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
function showResultPanel(result, context) {
  const panel = vscode.window.createWebviewPanel(
    "vulnResult",
    `扫描结果: ${result.filename}`,
    vscode.ViewColumn.Two,
    { enableScripts: false }
  );

  const isVuln = result.has_vulnerability === true;
  const isSafe = result.has_vulnerability === false;
  const isError = result.has_vulnerability === null;

  panel.webview.html = renderHtml(result, isVuln, isSafe, isError);
}

function showBatchPanel(results, vulnerable, safe, errors, context) {
  const panel = vscode.window.createWebviewPanel(
    "vulnBatch",
    "批量扫描汇总",
    vscode.ViewColumn.One,
    { enableScripts: false }
  );

  const vulnList = results.filter((r) => r.has_vulnerability === true);
  panel.webview.html = renderBatchHtml(results, vulnList, vulnerable, safe, errors);
}

function renderHtml(r, isVuln, isSafe, isError) {
  const statusColor = isVuln ? "#ff6b6b" : isSafe ? "#40db88" : "#ffa657";
  const statusText = isVuln ? "发现漏洞" : isSafe ? "未发现漏洞" : "无法判定";

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<style>
body { font-family: -apple-system, "Microsoft YaHei", sans-serif; padding: 20px; color: #333; max-width: 800px; }
.header { border-left: 4px solid ${statusColor}; padding-left: 16px; margin-bottom: 20px; }
.header h1 { font-size: 18px; margin: 0 0 4px 0; }
.header .status { color: ${statusColor}; font-weight: 600; }
.meta { background: #f6f8fa; padding: 12px; border-radius: 6px; margin-bottom: 16px; font-size: 13px; }
.meta div { margin: 4px 0; }
.field { margin-bottom: 12px; }
.field-label { font-weight: 600; color: #555; margin-bottom: 4px; }
.field-value { line-height: 1.6; }
.fix { background: #f0fff4; border: 1px solid #abf7c8; padding: 12px; border-radius: 6px; }
.fix .label { color: #1a7f37; font-weight: 600; }
details { margin-top: 16px; }
summary { cursor: pointer; color: #0969da; }
pre { background: #f6f8fa; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; background: ${statusColor}; color: #fff; }
</style>
</head>
<body>
<div class="header">
  <h1>${escapeHtml(r.filename || "")}</h1>
  <div class="status">${statusText} ${r.risk_level ? `<span class="badge">${escapeHtml(r.risk_level)}</span>` : ""} <span style="color:#999;font-size:12px">${r.duration || 0}s</span></div>
</div>

${isError ? `<div style="color:#ff6b6b">错误: ${escapeHtml(r.error || "未知")}</div>` : ""}

<div class="meta">
  <div>语言: ${escapeHtml(r.language || "")}</div>
  ${r.vulnerability_type && r.vulnerability_type !== "none" ? `<div>漏洞类型: ${escapeHtml(r.vulnerability_type)}</div>` : ""}
  ${r.source && r.source !== "N/A" ? `<div>污染来源: ${escapeHtml(r.source)}</div>` : ""}
  ${r.sink && r.sink !== "N/A" ? `<div>触发点: ${escapeHtml(r.sink)}</div>` : ""}
</div>

${r.explanation ? `<div class="field"><div class="field-label">分析说明</div><div class="field-value">${escapeHtml(r.explanation)}</div></div>` : ""}

${isVuln && r.fix_suggestion ? `<div class="fix"><div class="label">修复建议</div><div>${escapeHtml(r.fix_suggestion)}</div></div>` : ""}

${r.raw_output ? `<details><summary>查看模型分析过程</summary><pre>${escapeHtml(r.raw_output)}</pre></details>` : ""}
</body>
</html>`;
}

function renderBatchHtml(results, vulnList, vulnerable, safe, errors) {
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
body { font-family: -apple-system, "Microsoft YaHei", sans-serif; padding: 20px; color: #333; max-width: 900px; }
h1 { font-size: 20px; }
.summary { display: flex; gap: 16px; margin: 16px 0; }
.card { flex: 1; padding: 16px; border-radius: 8px; text-align: center; }
.card.total { background: #f6f8fa; }
.card.vuln { background: #fff0f0; color: #d32f2f; }
.card.safe { background: #f0fff4; color: #1a7f37; }
.card.err { background: #fff8e1; color: #f57c00; }
.card .num { font-size: 28px; font-weight: 700; }
.card .label { font-size: 12px; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; margin-top: 16px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e0e0e0; font-size: 13px; }
th { background: #f6f8fa; font-weight: 600; }
td:first-child { font-family: monospace; }
.risk-critical, .risk-high { color: #d32f2f; font-weight: 600; }
.risk-medium { color: #f57c00; }
.risk-low { color: #1976d2; }
</style>
</head>
<body>
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
` : "<p style='color:#1a7f37;margin-top:16px'>✓ 未发现漏洞</p>"}

<p style="color:#999;font-size:12px;margin-top:24px">详细分析见输出面板（Output → AI 漏洞扫描器）</p>
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

module.exports = { activate, deactivate };
