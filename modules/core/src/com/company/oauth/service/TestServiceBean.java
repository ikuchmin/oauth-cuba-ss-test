package com.company.oauth.service;

import org.springframework.stereotype.Service;

@Service(TestService.NAME)
public class TestServiceBean implements TestService {

    @Override
    public String testExecution() {
        return "testExecution";
    }
}