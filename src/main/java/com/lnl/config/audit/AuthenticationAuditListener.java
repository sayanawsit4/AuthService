package com.lnl.config.audit;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.security.AbstractAuthenticationAuditListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.boot.actuate.security.AuthenticationAuditListener.AUTHENTICATION_FAILURE;
import static org.springframework.boot.actuate.security.AuthenticationAuditListener.AUTHENTICATION_SUCCESS;

@Component
public class AuthenticationAuditListener extends AbstractAuthenticationAuditListener {

    @Override
    public void onApplicationEvent(AbstractAuthenticationEvent event) {
        if (event instanceof AbstractAuthenticationFailureEvent) {
            onAuthenticationFailureEvent((AbstractAuthenticationFailureEvent) event);
        }

        if (event instanceof AuthenticationSuccessEvent) {
            onAuthenticationSuccessEvent((AuthenticationSuccessEvent) event);
        }
    }

    //Authentication  failure happens when user name/pwd mismatches(in case of UsernamePasswordAuthenticationToken)
    // or a token has expired/invalid(when PreAuthenticatedAuthenticationToken)
    //wraps up in an Audit event that Attempt logger uses to log events
    private void onAuthenticationFailureEvent(AbstractAuthenticationFailureEvent event) {
        Map<String, Object> data = new HashMap<>();
        data.put("type", event.getAuthentication().getClass().getName());
        data.put("message", event.getException().getMessage());
        data.put("details", event.getSource());
        publish(new AuditEvent(event.getAuthentication().getName(), AUTHENTICATION_FAILURE, data));
    }

    //A successfull authentication of the principal either by UsernamePasswordAuthenticationToken
    // or by token using OAuth2Authentication
    //wraps up in an Audit event that Attempt logger uses to log events
    private void onAuthenticationSuccessEvent(AuthenticationSuccessEvent event) {
        Map<String, Object> data = new HashMap<>();
        data.put("type", event.getAuthentication().getClass().getName());
        data.put("message", event.getAuthentication().isAuthenticated());
        data.put("details", event.getSource());
        publish(new AuditEvent(event.getAuthentication().getName(), AUTHENTICATION_SUCCESS, data));
    }
}