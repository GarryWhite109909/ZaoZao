// Pattern reference: CVE-2020-9488 —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:SQL injection in metric query
import java.sql.*;
import java.util.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/metrics")
public class MetricController {
    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/skywalking", "root", "");
    }

    @GetMapping("/query")
    public Map<String, Object> queryMetric(HttpServletRequest request) throws SQLException {
        String metricName = request.getParameter("metric");
        String serviceId = request.getParameter("serviceId");
        if (metricName == null || metricName.isEmpty()) {
            return Collections.singletonMap("error", "metric required");
        }
        // Vulnerable: metricName concatenated into SQL via string concatenation
        String sql = "SELECT service_id, value, time_bucket FROM metric_data " +
                     "WHERE metric_name = '" + metricName + "' " +
                     "AND service_id = '" + serviceId + "' " +
                     "ORDER BY time_bucket DESC LIMIT 100";
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        List<Map<String, Object>> results = new ArrayList<>();
        while (rs.next()) {
            Map<String, Object> row = new HashMap<>();
            row.put("service_id", rs.getString("service_id"));
            row.put("value", rs.getDouble("value"));
            row.put("time_bucket", rs.getLong("time_bucket"));
            results.add(row);
        }
        return Collections.singletonMap("data", results);
    }
}
