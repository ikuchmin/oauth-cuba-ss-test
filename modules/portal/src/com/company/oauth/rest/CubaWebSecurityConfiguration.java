package com.company.oauth.rest;

import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.inject.Inject;
import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME;

//@Configuration
public class CubaWebSecurityConfiguration extends WebSecurityConfiguration {

    @Inject
    protected ApplicationContext applicationContext;

//    @Primary
//    @Bean("mergedSpringSecurityFilterChain")
    @Override
    public Filter springSecurityFilterChain() throws Exception {
        var currFilterChainProxy = (FilterChainProxy) super.springSecurityFilterChain();
        var currFilterChainMatchersOnChain = currFilterChainProxy.getFilterChains().stream().map(sch -> (DefaultSecurityFilterChain) sch)
                .collect(Collectors.toMap(DefaultSecurityFilterChain::getRequestMatcher, List::of,
                        (v1, v2) -> Stream.concat(v1.stream(), v2.stream()).collect(toList())));

        var cubaFilterChainProxy = (FilterChainProxy) applicationContext.getBean(DEFAULT_FILTER_NAME);

        List<SecurityFilterChain> finalListOfChains = new ArrayList<>();
        for (var cubaFilterChain : cubaFilterChainProxy.getFilterChains()) {
            var cubaDefaultFilterChain = (DefaultSecurityFilterChain) cubaFilterChain;
            var defaultSecurityFilterChainsByMatcher = currFilterChainMatchersOnChain
                    .get(cubaDefaultFilterChain.getRequestMatcher());

            var mergedFilterChain = mergeFilterChain(cubaDefaultFilterChain,
                    defaultSecurityFilterChainsByMatcher);

            finalListOfChains.add(mergedFilterChain);
        }

        var newFilterChainProxy = new FilterChainProxy(finalListOfChains);

        var autowireCapableBeanFactory = applicationContext.getAutowireCapableBeanFactory();
        autowireCapableBeanFactory.initializeBean(newFilterChainProxy, DEFAULT_FILTER_NAME);

        return newFilterChainProxy;

    }

    private SecurityFilterChain mergeFilterChain(DefaultSecurityFilterChain cubaFilterChain, List<DefaultSecurityFilterChain> defaultSecurityFilterChainsByMatcher) {
        return null;
    }

    //    @Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
//    public Filter springSecurityFilterChain() throws Exception {
//        boolean hasConfigurers = webSecurityConfigurers != null
//                && !webSecurityConfigurers.isEmpty();
//        if (!hasConfigurers) {
//            WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
//                    .postProcess(new WebSecurityConfigurerAdapter() {
//                    });
//            webSecurity.apply(adapter);
//        }
//        return webSecurity.build();
//    }
}
