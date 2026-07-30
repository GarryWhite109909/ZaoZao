/**
 * Struts2 multipart 请求处理示例。
 */
import org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest;
import com.opensymphony.xwork2.ActionContext;
import ognl.Ognl;
import ognl.OgnlContext;

public class Struts2VulnerableMultipart extends JakartaMultiPartRequest {
    @Override
    public void parse(HttpServletRequest request, String saveDir) {
        try {
            super.parse(request, saveDir);
        } catch (Exception e) {
            String contentType = request.getHeader("Content-Type");
            String errorMessage = "Error: " + contentType;
            OgnlContext ctx = (OgnlContext) ActionContext.getContext().getContextMap();
            try {
                Object result = Ognl.getValue(errorMessage, ctx, (Object) null);
                // ...
            } catch (Exception ignored) {}
        }
    }
}
