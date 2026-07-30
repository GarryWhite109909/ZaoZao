/**
 * Fastjson JSON 解析示例。
 */
import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;

@RestController
public class FastjsonController {

    @PostMapping("/api/parse")
    public String parse(@RequestBody String body) {
        Object obj = JSON.parseObject(body);
        return obj.toString();
    }
}
