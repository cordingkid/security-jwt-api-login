package com.example.securityjwtapilogin.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/")
    public String rootUri() {
        return "main page 입니다.";
    }

    @GetMapping("/hello")
    public String hello() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        return "hello, " + name + "님";
    }
}
