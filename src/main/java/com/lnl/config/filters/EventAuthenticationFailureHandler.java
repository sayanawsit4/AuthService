package com.lnl.config.filters;

import com.lnl.config.constants.Config;
import com.lnl.config.constants.HttpDTO;
import com.lnl.config.utils.StringUtils;
import com.lnl.domain.AccessAudit;
import com.lnl.domain.AttemptCounter;
import com.lnl.repository.AttemptCounterRepository;
import com.lnl.repository.AuditRepository;
import com.lnl.service.AttemptService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Slf4j
public class EventAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    private AttemptCounterRepository attemptCounterRepository;

    @Autowired
    private AuditRepository auditRepository;

    @Autowired
    private AttemptService attemptService;

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception)
            throws IOException, ServletException {
        Date date = new Date();
        String requestUrl = Optional.ofNullable(request.getParameter("request_url")).orElse("");
        String errorRemoved = StringUtils.sliceError(requestUrl);
        log.info("errorRemoved----" + errorRemoved);
        AccessAudit accessAudit = auditRepository.findOne(UUID.fromString(request.getSession().getAttribute(Config.ACS_TRACE_ID).toString()));
        Optional<AttemptCounter> attemptCounter = Optional.ofNullable(attemptCounterRepository.findOne(accessAudit.getUserId()));
        log.info("attemptCounter value----" + attemptCounter + accessAudit.getUserId());
        Integer counter;
        counter = attemptCounter.map(s -> s.getCounter() + 1).orElse(1);
        attemptCounterRepository.save(new AttemptCounter(accessAudit.getUserId(), counter, new Timestamp(date.getTime())));

        if (attemptCounter.isPresent()) {
            if (attemptService.isMaxAttemptReached(accessAudit.getUserId())) {
                this.setDefaultFailureUrl("/login?error=" + HttpDTO.account_locked.name()
                        + "_"
                        + (int) attemptService.calculateLockDown(accessAudit.getUserId())
                        + errorRemoved);
            } else {
                this.setDefaultFailureUrl("/login?error=" + HttpDTO.invalid_user_name_pwd.name() + errorRemoved);
            }
        } else {
            this.setDefaultFailureUrl("/login?error=" + HttpDTO.invalid_user_name_pwd.name() + errorRemoved);
        }
        super.onAuthenticationFailure(request, response, exception);
    }
}