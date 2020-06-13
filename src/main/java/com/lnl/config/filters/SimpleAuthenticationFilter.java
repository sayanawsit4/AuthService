package com.lnl.config.filters;

import com.lnl.config.constants.Config;
import com.lnl.config.constants.HttpDTO;
import com.lnl.config.utils.StringUtils;
import com.lnl.domain.AccessAudit;
import com.lnl.domain.AttemptCounter;
import com.lnl.domain.User;
import com.lnl.repository.AttemptCounterRepository;
import com.lnl.repository.AuditRepository;
import com.lnl.repository.UserRepository;
import com.lnl.service.AttemptService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;

@Slf4j
//This class intercepts all login calls.Need to register this as a bean to HttpSecurity.
//this should intercept request prior to UsernamePasswordAuthenticationFilter gets executed
public class SimpleAuthenticationFilter extends UsernamePasswordAuthenticationFilter implements InitializingBean {

    @Autowired
    private AttemptService attemptService;

    @Autowired
    private AuditRepository auditRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AttemptCounterRepository attemptCounterRepository;

    @Autowired
    private SimpleUrlAuthenticationFailureHandler failureHandler;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        AccessAudit accessAudit = new AccessAudit();
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        String requestUrl = Optional.ofNullable(request.getParameter("request_url")).orElse("");
        String errorRemoved = StringUtils.sliceError(requestUrl);
        log.info("errorRemoved----" + errorRemoved);

        if (username.isEmpty() || password.isEmpty()) {
            log.info("username" + username);
            log.info("password" + password);
            this.loginError(response, username.isEmpty() ? HttpDTO.empty_user_name.name() : HttpDTO.empty_pwd_name.name(), errorRemoved);
            return null;
        }

        UUID userId = Optional.ofNullable(userRepository.findByEmail(username)).map(User::getUserId).orElse(UUID.randomUUID());
        accessAudit.setUserId(userId);
        Optional<AttemptCounter> attemptCounter = Optional.ofNullable(attemptCounterRepository.findOne(userId));
        Integer counter = 1;
        Optional<Timestamp> lastAceesTime = Optional.ofNullable(null);
        if (attemptCounter.isPresent()) {
            counter = attemptCounter.get().getCounter() + 1;
            lastAceesTime = Optional.ofNullable(new Timestamp(attemptCounter.get().getLastAttempt().getTime()));
        }

        accessAudit.setNoOfAttempts(counter);
        //if the account is blocked we dont even allow to enter to authentication process
        log.info("userId and lastAceesTime " + userId + lastAceesTime);
        if (attemptService.isBlocked(userId, lastAceesTime) && lastAceesTime.isPresent()) {
            log.info("account locked!");
            accessAudit.setStatus(HttpDTO.account_locked.toString());
            this.loginError(response, HttpDTO.account_locked.name() + "_" + (int) attemptService.calculateLockDown(userId), errorRemoved);
            auditRepository.save(accessAudit);
            return null;
        } else {
            auditRepository.save(accessAudit);
            request.getSession().setAttribute(Config.ACS_TRACE_ID, accessAudit.getAcsAuditNo());
            log.info("before authentication failure handler" + errorRemoved);
            return super.attemptAuthentication(request, response);
        }
    }

    private void loginError(HttpServletResponse response, String message, String errorRemoved) {
        try {
            response.sendRedirect("/login?error=" + message + errorRemoved);
        } catch (IOException e) {
            throw new AuthenticationServiceException("Recaptcha failed : " + HttpDTO.account_locked.toString());
        }
    }
}