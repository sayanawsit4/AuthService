package com.lnl.config.filters;

import com.lnl.config.constants.Config;
import com.lnl.config.constants.HttpDTO;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.utils.StringUtils;
import com.lnl.domain.OperationalAudit;
import com.lnl.exception.InvalidCredentialException;
import com.lnl.exception.MissingParamException;
import com.lnl.repository.OpsAuditRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.Optional;
import java.util.TimeZone;

@Order(1) //this filter should get executed at first
@Component
@ControllerAdvice
@Slf4j
//Hmac filter implementation class
public class HmacFilter extends OncePerRequestFilter {

    @Autowired
    @Qualifier("handlerExceptionResolver")
    private HandlerExceptionResolver resolver;

    @Autowired
    private OpsAuditRepository opsAuditRepository;

    @Value("${hmac.clockSyncTolerance}")
    private String clockSyncTolerance;

    @Value("${server.contextPath}")
    private String contextPath;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        Optional<String> authDigest = Optional.ofNullable(httpServletRequest.getHeader(HttpDTO.AUTH_DIGEST.toString()));
        Optional<String> authTime = Optional.ofNullable(httpServletRequest.getHeader(HttpDTO.AUTH_TIME.toString()));
        Optional<String> intiatedBy = Optional.ofNullable(httpServletRequest.getHeader(HttpDTO.INITIATED_BY.toString()));
        Optional<String> passCode = Optional.ofNullable(httpServletRequest.getHeader(HttpDTO.PASS_CODE.toString()));

        if (httpServletRequest.getRequestURL().toString().contains(HttpDTO.EXTERNAL.toString())) {

            OperationalAudit operationalAudit = new OperationalAudit();
            operationalAudit.setRemoteIP(httpServletRequest.getRemoteAddr());
            operationalAudit.setUrl(httpServletRequest.getRequestURL().toString());
            operationalAudit.setUserAgent(Optional.ofNullable(httpServletRequest.getHeader("User-Agent"))
                                                  .orElse("No userAgent found"));
            operationalAudit.setCreatedTime(new Date());
            //operationalAudit.setOpsPerformedBy(intiatedBy.orElse("No info"));
            opsAuditRepository.save(operationalAudit);

            httpServletRequest.getSession().setAttribute(Config.OPS_TRACE_ID, operationalAudit.getOpsAuditNo());

            if (authDigest.isPresent() && authTime.isPresent()) {
                log.info("getRequestURI" + httpServletRequest.getRequestURI().substring(contextPath.length(), httpServletRequest.getRequestURI().length()));
                if (StringUtils.getHmacKeys(httpServletRequest.getRequestURI().substring(contextPath.length(), httpServletRequest.getRequestURI().length()),
                        authTime.get()).equals(authDigest.get()) && timestampValid(authTime.get()))
                    filterChain.doFilter(httpServletRequest, httpServletResponse);
                else
                    resolver.resolveException(httpServletRequest, httpServletResponse, null, new InvalidCredentialException(MessageDTO.INVALID_CREDENTIAL));
            } else {
                resolver.resolveException(httpServletRequest, httpServletResponse, null, new MissingParamException(MessageDTO.MISSING_HEADERS));

            }
        } else {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }


    }

    private Boolean timestampValid(String authTime) {
        return Math.abs(Long.parseLong(authTime) - Calendar.getInstance(TimeZone.getTimeZone("GMT"))
                .getTimeInMillis()) < Long.parseLong(clockSyncTolerance);
    }

}