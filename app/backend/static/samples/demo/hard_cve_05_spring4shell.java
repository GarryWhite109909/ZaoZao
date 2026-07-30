/**
 * Spring MVC 数据绑定示例。
 */
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;

@RestController
public class UserController {

    @PostMapping("/users/add")
    public String addUser(UserForm form) {
        return "User added: " + form.getName();
    }
}

class UserForm {
    private String name;
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}
