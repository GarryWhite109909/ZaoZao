import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;

@RestController
public class CalcController {

    @GetMapping("/calc")
    public String calc(@RequestParam String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(expr);
        return exp.getValue().toString();
    }
}
