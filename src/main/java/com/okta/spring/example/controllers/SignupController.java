package com.okta.spring.example.controllers;

import com.okta.sdk.client.Client;
import com.okta.sdk.resource.user.User;
import com.okta.sdk.resource.user.UserBuilder;
import com.okta.spring.example.model.Signup;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Controller
public class SignupController {

    private final Client oktaClient;

    public SignupController(
            Client oktaClient) {
        this.oktaClient = oktaClient;
    }

    @PostMapping("/register")
    public String createUser(@ModelAttribute Signup signup) {
        log.info("Creating new user: {}", signup);

        User user = UserBuilder.instance()
                .setEmail(signup.getEmail())
                .setPassword(signup.getPassword().toCharArray())
                .setFirstName(signup.getFirstName())
                .setLastName(signup.getLastName())
                .buildAndCreate(oktaClient);

        log.info("New user with email {} has been created!", user.getProfile().getEmail());
        return "redirect:/";
    }

    @GetMapping("/signup")
    public ModelAndView signup() {

        Map<String, Object> modelData = new HashMap<>();
        modelData.put("signup", new Signup());

        return new ModelAndView("signup", modelData);

    }

}
