package com.lnl.controller;

import com.lnl.config.auth.CustomJdbcTokenStore;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.user.ExtendedUser;
import com.lnl.domain.OperationalAudit;
import com.lnl.domain.User;
import com.lnl.dto.*;
import com.lnl.exception.*;
import com.lnl.repository.AttemptCounterRepository;
import com.lnl.repository.OpsAuditRepository;
import com.lnl.repository.UserRepository;
import com.lnl.service.AttemptService;
import com.lnl.service.TokenService;
import com.lnl.service.UserService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.sql.Timestamp;
import java.util.*;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.mockito.Matchers.contains;

@RunWith(SpringRunner.class)
@ActiveProfiles("test")
@TestPropertySource(properties = {"audit.maxLockdownPeriod=30" , "audit.maxVaiableAttempt=2"})
public class AttemptServiceTest {

    private static String CLIENT_ID = "authserver";
    private OAuth2Authentication auth;
    private OAuth2Authentication authAdmin;
    private User user;
    private User userAdmin;
    private UserRequest userRequest;
    private OperationalAudit operationalAudit;
    private String trackId = "41a7e31c-0793-481e-bd1d-88ed0c24cff5";
    private String userId = "582a4263-3dfd-4bea-897c-88f7612bc165";
    private String tokenId = "3f7a2c2b-751c-442c-89ab-6978e3bde0e2";
    private Date date = new Date();

    @MockBean
    private AttemptCounterRepository attemptCounterRepository;

    @TestConfiguration
    static class AttemptServiceTestContextConfiguration {

        @Bean
        public AttemptService attemptService() {
            return new AttemptService();
        }

    }

    @Value("${audit.maxLockdownPeriod}")
    private Double maxLockDownPeriod;

    @Value("${audit.maxVaiableAttempt}")
    private Double maxViableAttempt;

    @Autowired
    private AttemptService attemptService;

    @Before
    public void setUp() {

    }

    @Test
    public void when3unsucessfullAttempts_calculateLockFor2mins() {
        Mockito.when(attemptCounterRepository.countByUserId(UUID.fromString(userId))).thenReturn(3);
        assertThat(attemptService.calculateLockDown(UUID.fromString(userId))).isEqualTo(2);
    }

    @Test
    public void when3unsucessfullAttempts_calculateLockFor4mins() {
        Mockito.when(attemptCounterRepository.countByUserId(UUID.fromString(userId))).thenReturn(4);
        assertThat(attemptService.calculateLockDown(UUID.fromString(userId))).isEqualTo(4);
    }

    @Test
    public void when20unsucessfullAttempts_calculateLockMaxCap30mins() {
        Mockito.when(attemptCounterRepository.countByUserId(UUID.fromString(userId))).thenReturn(20);
        assertThat(attemptService.calculateLockDown(UUID.fromString(userId))).isEqualTo(30);
    }

    @Test
    public void whenNoattemptsYet_calculateLock0() {
        Mockito.when(attemptCounterRepository.countByUserId(UUID.fromString(userId))).thenReturn(null);
        assertThat(attemptService.calculateLockDown(UUID.fromString(userId))).isEqualTo(0);
    }

    @Test
    public void whenLockedDownExpires_thenisBlockFalse() {
        Date dt1 = new Date(2019, 3, 31); //long date back
        assertThat(attemptService.isBlocked(UUID.fromString(userId),Optional.of(new Timestamp(dt1.getTime())))).isFalse();
    }

}