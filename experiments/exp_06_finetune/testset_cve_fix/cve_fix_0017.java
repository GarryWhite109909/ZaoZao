// Pattern reference: CVE-2019-3396 —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:path traversal in zip extraction
// Real pattern: zip entry name joined to target dir without normalization
import java.io.*;
import java.util.zip.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/template")
public class TemplateUploadController {
    private static final String TEMPLATE_DIR = "/var/confluence/templates";

    @PostMapping("/upload")
    public String uploadTemplate(@RequestParam("file") MultipartFile file) throws IOException {
        File targetDir = new File(TEMPLATE_DIR);
        if (!targetDir.exists()) targetDir.mkdirs();

        // Vulnerable: zip entry name used directly without path validation
        try (ZipInputStream zis = new ZipInputStream(file.getInputStream())) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String entryName = entry.getName();
                // Vulnerable: entryName like "../../etc/cron.d/evil" escapes TEMPLATE_DIR
                File outFile = new File(targetDir, entryName);
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = zis.read(buffer)) > 0) {
                        fos.write(buffer, 0, len);
                    }
                }
                zis.closeEntry();
            }
        }
        return "Template uploaded successfully";
    }
}
