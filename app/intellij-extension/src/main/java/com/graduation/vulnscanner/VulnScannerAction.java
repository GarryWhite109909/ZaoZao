package com.graduation.vulnscanner;

import com.intellij.ide.util.PropertiesComponent;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.application.ReadAction;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.editor.SelectionModel;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.VirtualFile;
import org.jetbrains.annotations.NotNull;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * AI 漏洞扫描器 IntelliJ 插件动作（桩代码）。
 *
 * 功能：
 *   1. 获取编辑器中当前选中的代码（未选中时取整个文件内容）
 *   2. 通过 HTTP POST 发送到后端 {@code http://localhost:8765/api/analyze}
 *   3. 将扫描结果通过通知（Notification）展示给用户
 *
 * 注意：本文件为桩代码，需在 IntelliJ Platform SDK 环境下编译运行。
 * 未配置 SDK 时无法构建，请参阅同目录 README.md。
 */
public class VulnScannerAction extends AnAction {

    /** 后端 API 默认地址（用户可在弹窗中修改，持久化到 IDE Properties） */
    private static final String DEFAULT_BACKEND_URL = "http://localhost:8765/api/analyze";
    private static final String BACKEND_URL_KEY = "vulnScanner.backendUrl";
    /** HTTP 请求超时（毫秒） */
    private static final int TIMEOUT_MS = (int) TimeUnit.MINUTES.toMillis(5);

    /** 读取用户配置的后端地址，未配置时返回默认值。 */
    private static String getBackendUrl() {
        String saved = PropertiesComponent.getInstance().getValue(BACKEND_URL_KEY);
        return (saved != null && !saved.trim().isEmpty()) ? saved.trim() : DEFAULT_BACKEND_URL;
    }

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        Editor editor = e.getData(CommonDataKeys.EDITOR);
        VirtualFile file = e.getData(CommonDataKeys.VIRTUAL_FILE);

        if (project == null || editor == null) {
            showNotification(project, "请先在编辑器中打开一个文件", NotificationType.WARNING);
            return;
        }

        // Shift+点击动作时，弹出后端地址配置框
        java.awt.event.InputEvent inputEvent = e.getInputEvent();
        if (inputEvent != null && inputEvent.isShiftDown()) {
            String current = getBackendUrl();
            String updated = Messages.showInputDialog(project,
                    "后端扫描服务地址：", "配置 Nivis 后端",
                    Messages.getQuestionIcon(), current, null);
            if (updated != null) {
                PropertiesComponent.getInstance().setValue(BACKEND_URL_KEY, updated.trim());
                showNotification(project, "已更新后端地址：" + updated.trim(), NotificationType.INFORMATION);
            }
            return;
        }

        // 获取选中文本；未选中时取整个文档内容
        String code = ReadAction.compute(() -> {
            SelectionModel selection = editor.getSelectionModel();
            String selected = selection.getSelectedText();
            if (selected != null && !selected.isEmpty()) {
                return selected;
            }
            return editor.getDocument().getText();
        });

        if (code == null || code.trim().isEmpty()) {
            showNotification(project, "文件内容为空，无可分析代码", NotificationType.WARNING);
            return;
        }

        // 推断语言：优先用文件扩展名，回退到 plain
        String language = detectLanguage(file);
        String filename = (file != null) ? file.getName() : "pasted_code";

        // 在后台线程发起 HTTP 请求，避免阻塞 EDT
        final String backendUrl = getBackendUrl();
        final String requestBody = buildRequestBody(code, language, filename);
        ProgressManager.getInstance().run(new Task.Backgroundable(project, "AI 漏洞扫描中...", true) {
            @Override
            public void run(@NotNull ProgressIndicator indicator) {
                indicator.setIndeterminate(true);
                indicator.setText("正在调用后端分析接口...");
                try {
                    String response = postJson(backendUrl, requestBody);
                    String summary = parseResult(response);
                    showNotification(project, summary, NotificationType.INFORMATION);
                } catch (IOException ex) {
                    showNotification(project, "扫描失败：无法连接后端 (" + backendUrl + ")。" +
                            "请确保后端服务已启动（Shift+点击本动作可修改后端地址）。\n详情：" + ex.getMessage(),
                            NotificationType.ERROR);
                }
            }
        });
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        // 仅在编辑器有内容时启用动作
        Editor editor = e.getData(CommonDataKeys.EDITOR);
        e.getPresentation().setEnabledAndVisible(editor != null);
    }

    /**
     * 根据文件扩展名推断代码语言。
     */
    private String detectLanguage(VirtualFile file) {
        if (file == null) return "text";
        String ext = file.getExtension();
        if (ext == null) return "text";
        switch (ext.toLowerCase()) {
            case "py": return "python";
            case "js": case "jsx": case "vue": case "svelte": return "javascript";
            case "ts": case "tsx": return "typescript";
            case "java": return "java";
            case "php": return "php";
            case "go": return "go";
            case "html": case "htm": return "html";
            default: return "text";
        }
    }

    /**
     * 构造 /api/analyze 请求体（JSON）。
     * 字段与后端 AnalyzeRequest 一致：code / language / filename。
     */
    private String buildRequestBody(String code, String language, String filename) {
        // 所有字符串字段都必须转义（原先只转义 code，filename 含引号/反斜杠会破坏 JSON）
        return String.format(
                "{\"code\":\"%s\",\"language\":\"%s\",\"filename\":\"%s\"}",
                escapeJson(code), escapeJson(language), escapeJson(filename)
        );
    }

    /**
     * 发送 JSON POST 请求并返回响应体。
     */
    private String postJson(String urlStr, String body) throws IOException {
        URL url = URI.create(urlStr).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            // 调度器优先级标识：交互式单文件扫描为 HIGH 优先级，来源标识为 intellij
            conn.setRequestProperty("X-Client-Type", "intellij");
            conn.setRequestProperty("X-Scan-Scope", "single");
            conn.setConnectTimeout((int) TimeUnit.SECONDS.toMillis(10));
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int code = conn.getResponseCode();
            InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
            if (is == null) {
                throw new IOException("HTTP " + code + " 无响应体");
            }
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(is, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                return sb.toString();
            }
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 从后端 JSON 响应中提取关键信息，生成用户可读的摘要。
     * 后端返回字段：has_vulnerability / vulnerability_type / risk_level / explanation。
     * 错误响应：{"error": "..."} 或 FastAPI 校验错误 {"detail": [...]}。
     */
    private String parseResult(String response) {
        if (response == null || response.trim().isEmpty()) {
            return "后端返回空响应";
        }
        // 优先识别错误响应（原先直接按正常结果解析，422 会误入"无法判定"）
        String error = extractJsonField(response, "error");
        if (error != null && !error.isEmpty()) {
            return "扫描失败: " + error;
        }
        String detail = extractJsonField(response, "detail");
        if (detail != null && extractJsonField(response, "has_vulnerability") == null) {
            // FastAPI 422 的 detail 是数组（[{"loc":...,"msg":"..."}]），提取首个 msg
            if (detail.startsWith("[") || detail.isEmpty()) {
                String msg = extractJsonField(response, "msg");
                return "请求被后端拒绝" + (msg != null ? ": " + msg : "（参数校验失败）");
            }
            return "请求被后端拒绝: " + detail;
        }
        String hasVuln = extractJsonField(response, "has_vulnerability");
        if ("true".equalsIgnoreCase(hasVuln)) {
            String vulnType = extractJsonField(response, "vulnerability_type");
            String risk = extractJsonField(response, "risk_level");
            String sink = extractJsonField(response, "sink");
            return "⚠ 发现漏洞\n"
                    + "类型: " + nullSafe(vulnType) + "\n"
                    + "风险: " + nullSafe(risk) + "\n"
                    + "触发点: " + nullSafe(sink)
                    + "\n\n详见后端 Web 界面的修复建议。";
        } else if ("false".equalsIgnoreCase(hasVuln)) {
            return "✓ 未发现漏洞";
        }
        return "扫描结果无法判定\n原始响应:\n" + response;
    }

    /**
     * 从 JSON 文本中提取指定字段值（手写解析，避免引入 JSON 库）。
     * 原先的正则 "([^\"]*)" 遇到值内含转义引号 \" 会截断；
     * 本实现逐字符扫描字符串、正确处理 \" \\ \n \\uXXXX 等转义，
     * 且要求 key 前是 '{' 或 ','，避免误匹配字段值里出现的同名文本。
     */
    private String extractJsonField(String json, String field) {
        String key = "\"" + field + "\"";
        int idx = json.indexOf(key);
        while (idx >= 0) {
            // key 前一个非空白字符必须是 '{' 或 ','（真正的对象键位置）
            int prev = idx - 1;
            while (prev >= 0 && Character.isWhitespace(json.charAt(prev))) prev--;
            boolean keyPosition = prev >= 0 && (json.charAt(prev) == '{' || json.charAt(prev) == ',');
            if (keyPosition) {
                int i = idx + key.length();
                while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
                if (i < json.length() && json.charAt(i) == ':') {
                    i++;
                    while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
                    if (i >= json.length()) return null;
                    if (json.charAt(i) == '"') {
                        return parseJsonString(json, i + 1);
                    }
                    // 字面量 true / false / null / 数字
                    int j = i;
                    while (j < json.length() && ",}] \t\r\n".indexOf(json.charAt(j)) < 0) j++;
                    return json.substring(i, j);
                }
            }
            idx = json.indexOf(key, idx + key.length());
        }
        return null;
    }

    /** 从 openingQuote 之后开始解析 JSON 字符串，正确处理转义序列。 */
    private String parseJsonString(String json, int start) {
        StringBuilder sb = new StringBuilder();
        int i = start;
        while (i < json.length()) {
            char ch = json.charAt(i);
            if (ch == '\\' && i + 1 < json.length()) {
                char esc = json.charAt(i + 1);
                switch (esc) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'n': sb.append('\n'); break;
                    case 't': sb.append('\t'); break;
                    case 'r': sb.append('\r'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'u':
                        if (i + 5 < json.length()) {
                            try {
                                // 用 Character.toChars 展开码点，避免 (char) 单字符拆坏代理对（emoji 等 BMP 外字符）
                                int codePoint = Integer.parseInt(json.substring(i + 2, i + 6), 16);
                                sb.append(Character.toChars(codePoint));
                            } catch (NumberFormatException ignored) { /* 非法转义按原样跳过 */ }
                            i += 4;
                        }
                        break;
                    default: sb.append(esc);
                }
                i += 2;
            } else if (ch == '"') {
                return sb.toString();
            } else {
                sb.append(ch);
                i++;
            }
        }
        return sb.toString(); // 未闭合字符串，尽力返回已解析部分
    }

    private String nullSafe(String s) {
        return (s == null || s.isEmpty() || "N/A".equalsIgnoreCase(s)) ? "无" : s;
    }

    /** 转义 JSON 字符串值中的特殊字符。 */
    private String escapeJson(String text) {
        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * 弹出通知（方法名不能叫 notify，否则与 Object#notify 冲突）。
     */
    private void showNotification(Project project, String content, NotificationType type) {
        NotificationGroupManager.getInstance()
                .getNotificationGroup("AI 漏洞扫描器")
                .createNotification(content, type)
                .notify(project);
    }
}
