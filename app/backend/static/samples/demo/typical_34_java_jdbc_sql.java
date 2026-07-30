import java.sql.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class LoginServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/test", "root", "root");
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE username='" + username
                       + "' AND password='" + password + "'";
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                resp.getWriter().println("Login success");
            } else {
                resp.getWriter().println("Invalid");
            }
        } catch (SQLException e) {
            resp.getWriter().println("DB error: " + e.getMessage());
        }
    }
}
