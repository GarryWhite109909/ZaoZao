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
 * 凿凿 IntelliJ 插件动作。
 *
 * 功能：
 *   1. 获取编辑器中当前选中的代码（未选中时取整个文件内容）
 *   2. 通过 HTTP POST 发送到后端 {@code /api/analyze}（后端已统一为两阶段架构：
 *      Stage 1 工具召回 + Stage 2 LLM 裁决 + 共形/反事实/证据门信任层）
 *   3. 解析 TwoStageResult 响应（{@link BackendResponseParser}，Gson 树解析），
 *      以通知展示结论与信任层摘要
 *
 * Shift+点击动作可修改后端地址（支持填基础地址 http://localhost:8765，
 * 也兼容完整的 /api/analyze 端点，内部自动归一化）。
 * 构建需 IntelliJ Platform SDK（Gson 由平台捆绑提供），参见同目录 README.md。
 */
public class VulnScannerAction extends AnAction {

    /** 后端 API 默认地址（用户可在弹窗中修改，持久化到 IDE Properties） */
    private static final String DEFAULT_BACKEND_URL = "http://localhost:8765";
    private static final String BACKEND_URL_KEY = "vulnScanner.backendUrl";
    private static final String ANALYZE_PATH = "/api/analyze";
    /** HTTP 请求超时（毫秒） */
    private static final int TIMEOUT_MS = (int) TimeUnit.MINUTES.toMillis(5);
    /** 通知文本上限（Balloon 容量有限，超大内容会撑坏 UI） */
    private static final int NOTIFICATION_MAX_CHARS = 1500;

    /** 读取用户配置的后端地址（兼容历史保存的完整端点 URL），并归一化为端点。 */
    private static String getBackendUrl() {
        String saved = PropertiesComponent.getInstance().getValue(BACKEND_URL_KEY);
        String base = (saved != null && !saved.trim().isEmpty()) ? saved.trim() : DEFAULT_BACKEND_URL;
        return normalizeEndpoint(base);
    }

    /**
     * 归一化后端地址为完整分析端点：
     *   http://localhost:8765                        → http://localhost:8765/api/analyze
     *   http://localhost:8765/                       → http://localhost:8765/api/analyze
     *   http://localhost:8765/api/analyze（历史配置）  → 原样保留
     */
    static String normalizeEndpoint(String base) {
        String url = base.trim();
        while (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        if (!url.contains("/api/")) {
            url = url + ANALYZE_PATH;
        }
        return url;
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
            String current = PropertiesComponent.getInstance().getValue(BACKEND_URL_KEY, DEFAULT_BACKEND_URL);
            String updated = Messages.showInputDialog(project,
                    "后端扫描服务地址（填基础地址或完整端点均可）：", "配置 凿凿 后端",
                    Messages.getQuestionIcon(), current, null);
            if (updated != null) {
                String trimmed = updated.trim();
                PropertiesComponent.getInstance().setValue(BACKEND_URL_KEY, trimmed);
                showNotification(project, "已更新后端地址：" + normalizeEndpoint(trimmed), NotificationType.INFORMATION);
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
        ProgressManager.getInstance().run(new Task.Backgroundable(project, "凿凿 漏洞扫描中...", true) {
            @Override
            public void run(@NotNull ProgressIndicator indicator) {
                indicator.setIndeterminate(true);
                indicator.setText("正在调用后端分析接口（两阶段 + 信任层）...");
                try {
                    String response = postJson(backendUrl, requestBody);
                    BackendResponseParser.ScanResult result = BackendResponseParser.parse(response);
                    NotificationType type = notificationTypeOf(result);
                    showNotification(project, BackendResponseParser.buildNotification(result), type);
                } catch (Exception ex) {
                    // IOException = 连接失败；IllegalArgumentException 等 = 地址配置无效
                    String reason = (ex instanceof IOException)
                            ? "后端服务未启动或网络不通。详情：" + ex.getMessage()
                            : "地址或请求构造无效：" + ex.getMessage();
                    showNotification(project,
                            "扫描失败：无法连接后端 (" + backendUrl + ")\n"
                                    + reason + "\n（Shift+点击本动作可修改后端地址）",
                            NotificationType.ERROR);
                }
            }
        });
    }

    /** 按解析结果选择通知级别。 */
    private static NotificationType notificationTypeOf(BackendResponseParser.ScanResult r) {
        if (r.parseFailed || (r.error != null && !r.error.isEmpty())) {
            return NotificationType.ERROR;
        }
        if (Boolean.TRUE.equals(r.hasVuln)) {
            return NotificationType.WARNING;
        }
        return NotificationType.INFORMATION;
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
     * 内容统一截断，防止超大响应（N 采样 raw_outputs）撑坏 Balloon。
     */
    private void showNotification(Project project, String content, NotificationType type) {
        String safe = BackendResponseParser.truncate(content, NOTIFICATION_MAX_CHARS);
        NotificationGroupManager.getInstance()
                .getNotificationGroup("凿凿")
                .createNotification(safe, type)
                .notify(project);
    }
}
