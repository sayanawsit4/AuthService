package com.lnl.config.resource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceConfigurer extends ResourceServerConfigurerAdapter {

    private static final String SECURED_PATTERN = "/api/**";

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable();
        http.requestMatchers()
                .antMatchers(SECURED_PATTERN).and().authorizeRequests().anyRequest().authenticated();
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.authenticationEntryPoint(customAuthEntryPoint());
    }

    @Bean
    public AuthenticationEntryPoint customAuthEntryPoint(){
        return new RestAuthenticationEntryPoint();
    }
}