package geno.oauth.server.controllers;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class IndexController {

    @RequestMapping(value = {"/", "/login", "/403"}, method = RequestMethod.GET)
    public String index(){
        return "index";
    }

    @RequestMapping(value = "/home", method = RequestMethod.GET)
    public String home(Model model){



        String userName = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("user = " + userName);
        model.addAttribute("");

        return "home";
    }

    @RequestMapping(value = "/admin/", method = RequestMethod.GET)
    public String admin(){
        return "admin";
    }
}
