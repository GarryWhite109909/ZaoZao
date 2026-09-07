package com.graduation.vulnscanner;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 后端扫描响应解析器 —— 纯 Java + Gson（IntelliJ Platform 内置捆绑，无额外依赖）。
 *
 * 解析 {@code POST /api/analyze} 的 TwoStageResult 结构（两阶段：Stage 1 工具召回
 * + Stage 2 LLM 裁决 + 共形/反事实/证据门信任层），顶层字段与旧 SingleResult 对齐。
 *
 * 历史教训（2026-09-07 审查）：手写逐字符解析器无法区分同名字段的层级——
 * 响应中 findings/adjudications 内部也含 "sink"/"vulnerability_type"，先匹配到的是
 * 被【驳回】的候选；且 JSON null 原样返回为字符串 "null" 被误判为错误。
 * 改用真正的 JSON 树解析后按顶层对象取值，两个问题一并消除。
 */
public final class BackendResponseParser {

    /** 解析结果。hasVuln 为 null 表示无法判定（后端 has_vulnerability 为 null）。 */
    public static final class ScanResult {
        public boolean parseFailed = false;
        public String error;                 // 后端 error 字段（null = 无错误）
        public Boolean hasVuln;              // null = 无法判定
        public String filename = "";
        public String vulnerabilityType = "";
        public List<String> vulnerabilityTypes = new ArrayList<>();
        public String riskLevel = "";
        public String source = "";
        public String sink = "";
        public String explanation = "";
        public String fixSuggestion = "";
        public double durationSeconds = 0.0;

        public int confirmedCount = 0;       // 判真裁决数
        public int adjudicationCount = 0;    // 全部裁决数
        public int reviewerCount = 0;        // 低置信需人工复核数
        public String topTrustLine = "";     // 最高严重度判真裁决的信任层摘要
    }

    private BackendResponseParser() {
    }

    /** 解析响应 JSON。任何解析层面的失败都以 parseFailed=true + error 表达，不抛异常。 */
    public static ScanResult parse(String response) {
        ScanResult r = new ScanResult();
        if (response == null || response.trim().isEmpty()) {
            r.parseFailed = true;
            r.error = "后端返回空响应";
            return r;
        }
        JsonObject root;
        try {
            root = JsonParser.parseString(response).getAsJsonObject();
        } catch (Exception e) {
            r.parseFailed = true;
            r.error = "响应不是合法 JSON：" + truncate(e.getMessage(), 200);
            return r;
        }

        // FastAPI 422 校验失败：{"detail":[{...,"msg":"..."}]}（无 has_vulnerability 字段）
        if (!root.has("has_vulnerability") && root.has("detail")) {
            r.parseFailed = true;
            r.error = "请求被后端拒绝: " + firstDetailMsg(root.get("detail"));
            return r;
        }

        r.error = optString(root, "error");
        r.filename = optString(root, "filename");
        r.vulnerabilityType = optString(root, "vulnerability_type");
        r.riskLevel = optString(root, "risk_level");
        r.source = optString(root, "source");
        r.sink = optString(root, "sink");
        r.explanation = optString(root, "explanation");
        r.fixSuggestion = optString(root, "fix_suggestion");
        JsonElement dur = root.get("duration");
        if (dur != null && dur.isJsonPrimitive()) {
            try {
                r.durationSeconds = dur.getAsDouble();
            } catch (NumberFormatException ignored) {
            }
        }

        JsonElement hv = root.get("has_vulnerability");
        r.hasVuln = (hv == null || hv.isJsonNull()) ? null : hv.getAsBoolean();

        JsonElement types = root.get("vulnerability_types");
        if (types != null && types.isJsonArray()) {
            for (JsonElement e : types.getAsJsonArray()) {
                if (e.isJsonPrimitive()) {
                    r.vulnerabilityTypes.add(e.getAsString());
                }
            }
        }

        JsonElement adjs = root.get("adjudications");
        if (adjs != null && adjs.isJsonArray()) {
            JsonArray arr = adjs.getAsJsonArray();
            r.adjudicationCount = arr.size();
            for (JsonElement e : arr) {
                if (!e.isJsonObject()) {
                    continue;
                }
                JsonObject adj = e.getAsJsonObject();
                boolean confirmed = optBool(adj, "confirmed", false);
                if (confirmed) {
                    r.confirmedCount++;
                    if (r.topTrustLine.isEmpty()) {
                        r.topTrustLine = trustLine(adj);
                    }
                }
            }
        }
        JsonElement reviewer = root.get("reviewer_findings");
        if (reviewer != null && reviewer.isJsonArray()) {
            r.reviewerCount = reviewer.getAsJsonArray().size();
        }
        return r;
    }

    /**
     * 生成用户可读的通知文本（Balloon 通知容量有限，总长截断到 1500 字符）。
     */
    public static String buildNotification(ScanResult r) {
        if (r.parseFailed) {
            return "扫描失败: " + r.error;
        }
        StringBuilder sb = new StringBuilder();
        if (r.error != null && !r.error.isEmpty()) {
            sb.append("⚠ 扫描异常: ").append(r.error).append("\n\n");
        }
        if (Boolean.TRUE.equals(r.hasVuln)) {
            sb.append("⚠ 发现漏洞\n");
            sb.append("类型: ").append(or(r.vulnerabilityType, "未知")).append("\n");
            sb.append("风险: ").append(or(r.riskLevel, "未知")).append("\n");
            sb.append("污染来源: ").append(or(r.source, "无")).append("\n");
            sb.append("触发点: ").append(or(r.sink, "无")).append("\n");
            if (r.confirmedCount > 1) {
                sb.append("共确认 ").append(r.confirmedCount).append(" 处漏洞\n");
            }
            if (!r.topTrustLine.isEmpty()) {
                sb.append(r.topTrustLine).append("\n");
            }
            if (!r.fixSuggestion.isEmpty()) {
                sb.append("\n修复建议: ").append(truncate(r.fixSuggestion, 400));
            }
        } else if (Boolean.FALSE.equals(r.hasVuln)) {
            sb.append("✓ 未发现漏洞");
            if (!r.topTrustLine.isEmpty() || r.adjudicationCount > 0) {
                sb.append("\nStage 2 裁决 ").append(r.adjudicationCount)
                  .append(" 项候选，全部驳回");
            }
        } else {
            sb.append("扫描结果无法判定（需人工复核）\n");
            if (r.reviewerCount > 0) {
                sb.append(r.reviewerCount).append(" 项候选置信度不足，已在 Web 界面列入复核清单\n");
            }
            if (r.explanation != null && !r.explanation.isEmpty()) {
                sb.append(truncate(r.explanation, 300));
            }
        }
        if (r.reviewerCount > 0 && !Boolean.TRUE.equals(r.hasVuln)) {
            sb.append("\n另有 ").append(r.reviewerCount).append(" 项低置信候选待人工复核");
        }
        if (r.durationSeconds > 0) {
            sb.append("\n（耗时 ").append(r.durationSeconds).append("s）");
        }
        return truncate(sb.toString(), 1500);
    }

    /**
     * 单条裁决的信任层摘要：置信度 · decision 档位 · 共形预测 · 反事实 · 证据门。
     */
    private static String trustLine(JsonObject adj) {
        Map<String, String> parts = new LinkedHashMap<>();
        JsonElement conf = adj.get("confidence");
        if (conf != null && conf.isJsonPrimitive()) {
            parts.put("置信度", Math.round(conf.getAsDouble() * 100) + "%");
        }
        String decision = optString(adj, "decision");
        if (!decision.isEmpty()) {
            parts.put("档位", decisionLabel(decision));
        }
        String conformal = optString(adj, "conformal_set");
        if (!conformal.isEmpty()) {
            parts.put("共形", conformalLabel(conformal));
        }
        JsonElement cf = adj.get("counterfactual");
        String cfLabel = counterfactualLabel(cf);
        if (!cfLabel.isEmpty()) {
            parts.put("反事实", cfLabel);
        }
        String gate = optString(adj, "evidence_gate");
        if (!gate.isEmpty()) {
            parts.put("证据门", gateLabel(gate));
        }
        StringBuilder sb = new StringBuilder("信任层: ");
        boolean first = true;
        for (Map.Entry<String, String> en : parts.entrySet()) {
            if (!first) {
                sb.append(" · ");
            }
            first = false;
            sb.append(en.getKey()).append(" ").append(en.getValue());
        }
        return sb.toString();
    }

    private static String decisionLabel(String d) {
        switch (d) {
            case "confirmed_vulnerability": return "确认漏洞";
            case "confirmed_review": return "确认漏洞(建议复核)";
            case "dismissed_safe": return "驳回(高置信安全)";
            case "dismissed_review": return "驳回(低置信)";
            case "direct": return "确定性直出";
            default: return d;
        }
    }

    private static String conformalLabel(String c) {
        switch (c) {
            case "vulnerable": return "判漏洞";
            case "safe": return "判安全";
            case "uncertain": return "不确定";
            default: return c;
        }
    }

    private static String gateLabel(String g) {
        switch (g) {
            case "sink_defended": return "sink已有防御";
            case "no_input_entry": return "无输入入口";
            default: return g;
        }
    }

    private static String counterfactualLabel(JsonElement cf) {
        if (cf == null || cf.isJsonNull() || !cf.isJsonObject()) {
            return "";
        }
        JsonObject o = cf.getAsJsonObject();
        if (!optBool(o, "applicable", false)) {
            return "";
        }
        boolean flipped = optBool(o, "flipped", false);
        if (flipped) {
            return "扰动后翻转(模型理解防御)";
        }
        if (optBool(o, "already_defended", false)) {
            return "原代码已有防御";
        }
        return "扰动后结论不变";
    }

    // ---- 取值工具：显式区分「字段不存在 / JSON null / 空串」 ----

    /** 字符串字段：不存在、null、或空串都返回 ""。 */
    private static String optString(JsonObject o, String key) {
        JsonElement e = o.get(key);
        if (e == null || e.isJsonNull() || !e.isJsonPrimitive()) {
            return "";
        }
        String v = e.getAsString();
        return v == null ? "" : v;
    }

    private static boolean optBool(JsonObject o, String key, boolean dflt) {
        JsonElement e = o.get(key);
        if (e == null || e.isJsonNull() || !e.isJsonPrimitive()) {
            return dflt;
        }
        try {
            return e.getAsBoolean();
        } catch (Exception ex) {
            return dflt;
        }
    }

    private static String or(String s, String dflt) {
        return (s == null || s.isEmpty()) ? dflt : s;
    }

    /** 从 FastAPI 422 的 detail（数组或字符串）提取首个可读信息。 */
    private static String firstDetailMsg(JsonElement detail) {
        if (detail == null || detail.isJsonNull()) {
            return "参数校验失败";
        }
        if (detail.isJsonPrimitive()) {
            return detail.getAsString();
        }
        if (detail.isJsonArray() && detail.getAsJsonArray().size() > 0) {
            JsonElement first = detail.getAsJsonArray().get(0);
            if (first.isJsonObject()) {
                JsonElement msg = first.getAsJsonObject().get("msg");
                if (msg != null && msg.isJsonPrimitive()) {
                    return msg.getAsString();
                }
            }
            return truncate(detail.toString(), 200);
        }
        return "参数校验失败";
    }

    public static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…(已截断)";
    }
}
