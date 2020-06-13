package com.lnl.config.web;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class AuthenticationProcessingFilterEntryPoint extends LoginUrlAuthenticationEntryPoint {
    private final org.springframework.security.web.RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();


    public AuthenticationProcessingFilterEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String redirectUrl = getLoginFormUrl() + Optional.ofNullable(request.getQueryString()).map(s -> "?" + s).orElse("");
        this.redirectStrategy.sendRedirect(request, response, redirectUrl);
    }
}