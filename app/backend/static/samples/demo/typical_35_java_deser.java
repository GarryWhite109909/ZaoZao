import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Base64;

public class ProfileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String token = req.getParameter("token");
        byte[] data = Base64.getDecoder().decode(token);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        try {
            Object obj = ois.readObject();
            resp.getWriter().println("Profile: " + obj.toString());
        } catch (ClassNotFoundException e) {
            resp.getWriter().println("Error: " + e.getMessage());
        }
    }
}
