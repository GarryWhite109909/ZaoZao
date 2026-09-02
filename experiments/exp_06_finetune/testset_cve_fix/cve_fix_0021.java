// Pattern reference: CVE-2018-1000117 —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:XXE in XML parser
// Real pattern: XML input parsed without disabling external entities
import java.io.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/import")
public class XmlImportController {

    @PostMapping(value = "/xml", consumes = "application/xml")
    public String importXml(HttpServletRequest request) throws Exception {
        // Vulnerable: DocumentBuilderFactory created without disabling external entities
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Missing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // Missing: factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // Missing: factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        // Parses user-supplied XML — attacker can inject:
        // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
        Document doc = builder.parse(request.getInputStream());

        Element root = doc.getDocumentElement();
        NodeList children = root.getChildNodes();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                sb.append(child.getNodeName())
                  .append(": ")
                  .append(child.getTextContent())
                  .append("\n");
            }
        }
        return sb.toString();
    }
}
