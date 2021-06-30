package com.company.oauth.rest.controllers;

import com.company.oauth.service.TestService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController()
@RequestMapping("/common")
public class TestController {

    protected TestService testService;

    public TestController(TestService testService) {
        this.testService = testService;
    }

    @GetMapping("/test")
    public String testMethod() {
//        return "";
        return testService.testExecution();
    }
}
