package xohoon.Security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping(value="/")
    public String Home() throws Exception{
        return "/home";
    }

    @GetMapping(value="/login")
    public String login() throws Exception {
        return "/login";
    }
}
