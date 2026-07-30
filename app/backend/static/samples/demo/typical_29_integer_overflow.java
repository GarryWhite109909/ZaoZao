import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {

    @GetMapping("/calc_total")
    public String calcTotal(@RequestParam(defaultValue = "0") int qty,
                            @RequestParam(defaultValue = "100") int price) {
        int total = price * qty;
        return "Total: " + total;
    }
}
