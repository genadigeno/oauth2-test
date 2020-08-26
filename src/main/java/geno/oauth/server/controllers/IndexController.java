package geno.oauth.server.controllers;

import geno.oauth.server.oauth2.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class IndexController {


    @Autowired
    private JwtProvider jwtProvider;

    @RequestMapping(value = {"/", "/login"}, method = RequestMethod.GET)
    public String index(){
        return "index";
    }

    @RequestMapping(value = "/home", method = RequestMethod.GET)
    public String home(Model model, HttpServletRequest request, HttpServletResponse response){

        System.out.println("-----------------------------------------------------------------------------------------");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String userName = authentication.getName();

        /*SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtProvider.generateJwtToken(authentication);
        response.setHeader("access_token", token);*/

        model.addAttribute("");
        return "home";
    }

    @RequestMapping(value = {"/403"}, method = RequestMethod.GET)
    public String page403(){
        return "403";
    }

    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public String admin(){
        return "admin";
    }

    private boolean logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication){
        String userName = authentication.getName();
        if (!userName.equals("user")) {
            try {
                authentication.setAuthenticated(false);
                request.getSession().invalidate();
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
        return false;
    }
}
