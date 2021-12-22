package xohoon.Security.controller.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping(value="/message")
    public String mypage() throws Exception {

        return "user/messages";
    }

    @ResponseBody
    @GetMapping(value="/api/messages")
    public String apiMessage() {
        return "messages_ok";
    }
}
