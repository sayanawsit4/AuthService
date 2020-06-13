package com.lnl.config.audit;

import com.lnl.config.auth.CustomJdbcTokenStore;
import com.lnl.config.constants.Config;
import com.lnl.config.user.ExtendedUser;
import com.lnl.domain.AccessAudit;
import com.lnl.domain.AttemptCounter;
import com.lnl.domain.OperationalAudit;
import com.lnl.domain.User;
import com.lnl.repository.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Component
@Slf4j
public class AttemptsLogger {

    @Autowired
    private AuditRepository auditRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Resource(name = "tokenStore")
    private CustomJdbcTokenStore customJdbcTokenStore;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OpsAuditRepository opsAuditRepository;

    @Autowired
    private AttemptCounterRepository attemptCounterRepository;

    @Autowired
    private HttpServletRequest request;

    private static final String PRINCIPAL = "Principal:";
    private static final String AUTHENTICATION = "Authentication:";
    private static final String REMOTE_IP = "Remote IP address:";
    private static final String SESSION_ID = "Session Id:";
    private static final String REQUEST_URL = "Request URL:";
    private static final String AUTHTYPE = "Authtype:";
    private static final String AUTHORITIES = "authorities:";
    private static final String GRANTTYPE = "Grantype:";
    private static final String SCOPE = "Scope:";
    private static final String USER_AGENT = "user agent:";
    private static final String DETAILS = "details";


    @EventListener
    public void auditEventHappened(AuditApplicationEvent auditApplicationEvent) {
        AuditEvent auditEvent = auditApplicationEvent.getAuditEvent();
        log.info("Principal " + auditEvent.getPrincipal() + " - " + auditEvent.getType() + auditEvent.getData().get(DETAILS));
        Date date = new Date();

        if (auditEvent.getData().get(DETAILS) instanceof WebAuthenticationDetails) {
            WebAuthenticationDetails details = (WebAuthenticationDetails) auditEvent.getData().get(DETAILS);
            log.info(PRINCIPAL + auditEvent.getPrincipal());
            log.info(AUTHENTICATION + auditEvent.getType());
            log.info(REMOTE_IP + details.getRemoteAddress());
            log.info(SESSION_ID + details.getSessionId());
            log.info(REQUEST_URL + auditEvent.getData().get("requestUrl"));
            log.info(AUTHTYPE + request.getAuthType());
        }

        if (auditEvent.getData().get(DETAILS) instanceof PreAuthenticatedAuthenticationToken) {
            log.info(PRINCIPAL + auditEvent.getPrincipal());
            log.info(AUTHENTICATION + auditEvent.getType());
            log.info(REMOTE_IP + request.getRemoteAddr());
            log.info(REQUEST_URL + request.getRequestURL());
            log.info(AUTHTYPE + request.getAuthType());
        }

        if (auditEvent.getData().get(DETAILS) instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken details = (UsernamePasswordAuthenticationToken) auditEvent.getData().get(DETAILS);
            if (request.getSession().getAttribute(Config.ACS_TRACE_ID) != null) {

                log.info("SESSION DETAILS"+Thread.currentThread().getName());
                log.info("SESSION DETAILS"+Thread.currentThread().getContextClassLoader());

                AccessAudit accessAudit = auditRepository.findOne(UUID.fromString(request.getSession().getAttribute(Config.ACS_TRACE_ID).toString()));
                Integer counter;

                log.info(PRINCIPAL + auditEvent.getPrincipal());
                log.info(AUTHENTICATION + details.isAuthenticated());
                log.info(REMOTE_IP + request.getRemoteAddr());
                log.info(REQUEST_URL + request.getRequestURL());
                log.info(AUTHTYPE + request.getAuthType());

                accessAudit.setStatus(auditEvent.getType());
                auditRepository.save(accessAudit);
                Optional<AttemptCounter> attemptCounter = Optional.ofNullable(attemptCounterRepository.findOne(accessAudit.getUserId()));
                if (details.isAuthenticated() && attemptCounter.isPresent()) {
                    attemptCounterRepository.delete(accessAudit.getUserId());
                } /*else {
                    counter = attemptCounter.map(s -> s.getCounter() + 1).orElse(1);
                    attemptCounterRepository.save(new AttemptCounter(accessAudit.getUserId(), counter, new Timestamp(date.getTime())));
                }*/

            }
        }

        if (auditEvent.getData().get(DETAILS) instanceof OAuth2Authentication) {
            OAuth2Authentication details = (OAuth2Authentication) auditEvent.getData().get(DETAILS);
            log.info(PRINCIPAL + auditEvent.getPrincipal());
            log.info(AUTHENTICATION + auditEvent.getType());
            log.info(REMOTE_IP + request.getRemoteAddr());
            log.info(REQUEST_URL + request.getRequestURL());
            log.info(AUTHTYPE + request.getAuthType());
            log.info(AUTHORITIES + details.getOAuth2Request().getAuthorities().toString());
            log.info(GRANTTYPE + details.getOAuth2Request().getGrantType());
            log.info(SCOPE + details.getOAuth2Request().getScope());
            log.info(SCOPE + details.getUserAuthentication().getDetails());
            log.info(USER_AGENT + request.getHeader("User-Agent"));

            OAuth2AuthenticationDetails oauthsDetails = (OAuth2AuthenticationDetails) details.getDetails();
            ExtendedUser extendedUser = (ExtendedUser) details.getPrincipal();
            log.info(extendedUser.getUserid().toString());
            String tokentemp = customJdbcTokenStore.extractTokenKey(oauthsDetails.getTokenValue());
            User user = userRepository.findByEmail(tokenRepository.findUsernameByToken(tokentemp));

            OperationalAudit operationalAudit = new OperationalAudit();
            operationalAudit.setOpsPerformedBy(extendedUser.getEmail().toLowerCase());
            operationalAudit.setTokenId(tokentemp);
            operationalAudit.setUser(user.getEmail().toLowerCase());
            operationalAudit.setClientId(details.getOAuth2Request().getClientId());
            operationalAudit.setCreatedTime(new Date());
            operationalAudit.setRemoteIP(request.getRemoteAddr());
            operationalAudit.setUrl(request.getRequestURL().toString());
            operationalAudit.setStatus(auditEvent.getType());
            operationalAudit.setUserAgent(request.getHeader("User-Agent"));
            opsAuditRepository.save(operationalAudit);

            request.getSession().setAttribute(Config.OPS_TRACE_ID, operationalAudit.getOpsAuditNo());
        }
    }

}