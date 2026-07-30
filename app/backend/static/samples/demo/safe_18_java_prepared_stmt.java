import java.sql.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class LoginSafeServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        // 凭证从环境变量读取，避免硬编码（CWE-798 防护）
        String dbUser = System.getenv("DB_USER");
        String dbPass = System.getenv("DB_PASSWORD");
        try (Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/test", dbUser, dbPass)) {
            String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, username);
            stmt.setString(2, password);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                resp.getWriter().println("Login success");
            } else {
                resp.getWriter().println("Invalid");
            }
        } catch (SQLException e) {
            resp.getWriter().println("DB error");
        }
    }
}
