// Inspired by CVE-2021-24188 (Simple Buttons) - XSS in button label
// Real pattern: user input written to HTML output via PrintWriter without escaping
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ButtonServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String label = request.getParameter("label");
        String url = request.getParameter("url");
        String style = request.getParameter("style");

        if (label == null) label = "Click";
        if (url == null) url = "#";
        if (style == null) style = "primary";

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        // Vulnerable: user-controlled label, url, style written to HTML without escaping
        out.println("<html><body>");
        out.println("<div class='button-container'>");
        out.println("<a href='" + url + "' class='btn btn-" + style + "'>");
        out.println(label);  // Vulnerable: unescaped label
        out.println("</a>");
        out.println("</div>");
        out.println("</body></html>");
    }
}
