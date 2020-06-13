package com.lnl.controller;

import com.lnl.config.constants.Config;
import com.lnl.config.constants.HttpDTO;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.constants.Tokens;
import com.lnl.config.user.ExtendedUser;
import com.lnl.config.utils.JsonUtil;
import com.lnl.config.utils.StringUtils;
import com.lnl.dto.*;
import com.lnl.exception.ClientNotFoundException;
import com.lnl.exception.MissingParamException;
import com.lnl.exception.UnableToPersistException;
import com.lnl.exception.UserNotFoundException;
import com.lnl.repository.OpsAuditRepository;
import com.lnl.service.TokenService;
import com.lnl.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.internal.verification.VerificationModeFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.*;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Slf4j
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(secure = false)
@ActiveProfiles("test")
@WebMvcTest(value = ResourceController.class)
@WebAppConfiguration //Need this to set the session variable at filter.
public class ResourceControllerMVCTest {

    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    private TokenService tokenService;

    @MockBean
    private OpsAuditRepository opsAuditRepository;

    @Autowired
    private ExtendedUser extendedUser;

    @Autowired
    WebApplicationContext wac;

    @Autowired
    MockHttpSession session;

    @TestConfiguration
    static class ResourceControllerMVCTestConfiguration {

        @Bean
        public ExtendedUser extendedUser() {
            return new ExtendedUser("admin789@lnl.com",
                    "", true, true, true,
                    true, Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")),
                    "admin@lnl.com",
                    UUID.fromString("582a4263-3dfd-4bea-897c-88f7612bc165"),
                    "admin789@lnl.com",
                    "");
        }
    }

    private OAuth2Authentication auth;
    private String trackId = "41a7e31c-0793-481e-bd1d-88ed0c24cff5";
    private String tokenId = "41a7e31c-0793-481e-bd1d-88ed0c24cff5";
    private static final String CLIENT_ID = "authserver";
    private HttpHeaders headers = new HttpHeaders();
    private String timeinmillis = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis() + "";


    @Before
    public void setUp() throws Exception {
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set(HttpDTO.AUTH_DIGEST.toString(), StringUtils.getHmacKeys("/external/getAccessTokenByEmail", timeinmillis));
        headers.set(HttpDTO.AUTH_TIME.toString(), timeinmillis);
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
        session.setAttribute(Config.OPS_TRACE_ID, trackId);
    }


    //All createUser testcase
    @Test
    public void whenPostCreateUser_thenReturnSuccessful() throws Exception {
        UserRequest userRequest = new UserRequest("testuat3311@gmail.com", "test", "test", "test", 1234567890L, "lnl");
        given(userService.createUser(userRequest, auth, trackId)).willReturn(MessageDTO.USER_CREATED_SUCCESSFULLY.toString());
        mockMvc.perform(post("/api/createUser")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(userRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_CREATED_SUCCESSFULLY.toString())));

        verify(userService, VerificationModeFactory.times(1)).createUser(userRequest, auth, trackId);
        reset(userService);
    }

    @Test
    public void whenPostCreateUser_thenUnableToPersists() throws Exception {
        UserRequest userRequest = new UserRequest("testuat3311@gmail.com", "test", "test", "test", 1234567890L, "lnl");
        given(userService.createUser(userRequest, auth, trackId)).willThrow(new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST));
        mockMvc.perform(post("/api/createUser")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(userRequest)))
                .andExpect(content().string(containsString(MessageDTO.UNABLE_TO_PERSIST.toString())));
    }

    @Test
    public void whenPostDuplicateUserCreateUser_thenReturnExists() throws Exception {
        UserRequest userRequest = new UserRequest("testuat3311@gmail.com", "test", "test", "test", 1234567890L, "lnl");
        given(userService.createUser(userRequest, auth, trackId)).willReturn(MessageDTO.USER_EXISTS.toString());
        mockMvc.perform(post("/api/createUser")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(userRequest)))
                .andExpect(status().isOk());
        verify(userService, VerificationModeFactory.times(1)).createUser(userRequest, auth, trackId);
        reset(userService);
    }

    //All updatePassword testcase
    @Test
    public void whenPostUpdatePassword_thenUpdatePassword() throws Exception {
        UpdatePasswordRequest updatePasswordRequest = new UpdatePasswordRequest("sayan@gmail.com", "test");
        given(userService.updatePassword(updatePasswordRequest, auth, trackId)).willReturn(MessageDTO.SUCCESSFULL.toString());
        mockMvc.perform(post("/api/updatePassword")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(updatePasswordRequest)))
                .andExpect(status().isOk());
        verify(userService, VerificationModeFactory.times(1)).updatePassword(updatePasswordRequest, auth, trackId);
        reset(userService);
    }


    @Test
    public void whenPostUpdatePasswordWrongEmail_thenuser_not_found() throws Exception {
        UpdatePasswordRequest updatePasswordRequest = new UpdatePasswordRequest("sayan123@gmail.com", "test");
        given(userService.updatePassword(updatePasswordRequest, auth, trackId)).willThrow(new UserNotFoundException(MessageDTO.USER_NOT_FOUND));
        mockMvc.perform(post("/api/updatePassword")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(updatePasswordRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_NOT_FOUND.toString())));
        //verify(userService, VerificationModeFactory.times(1)).updatePassword(UpdatePasswordRequest, auth, trackId);
        reset(userService);
    }

    @Test
    public void whenPostUpdatePasswordWrongEmail_thenunable_to_persist() throws Exception {
        UpdatePasswordRequest updatePasswordRequest = new UpdatePasswordRequest("sayan123@gmail.com", "test");
        given(userService.updatePassword(updatePasswordRequest, auth, trackId)).willThrow(new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST));
        mockMvc.perform(post("/api/updatePassword")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(updatePasswordRequest)))
                .andExpect(content().string(containsString(MessageDTO.UNABLE_TO_PERSIST.toString())));
        //verify(userService, VerificationModeFactory.times(1)).updatePassword(UpdatePasswordRequest, auth, trackId);
        reset(userService);
    }

    //All updateUser testcase
    @Test
    public void whenPostUpdateUser_thenReturnSuccessful() throws Exception {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest("testuat3311@gmail.com", "test", "test");
        given(userService.updateUser(updateUserRequest, auth, trackId)).willReturn(MessageDTO.UPDATE_USER_SUCESSFULLY.toString());
        mockMvc.perform(post("/api/updateUser")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(updateUserRequest)))
                .andExpect(content().string(containsString(MessageDTO.UPDATE_USER_SUCESSFULLY.toString())));
        reset(userService);
    }


    @Test
    public void whenPostWrongEmailUpdateUser_thenuser_not_found() throws Exception {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest("notexists@gmail.com", "test", "test");
        given(userService.updateUser(updateUserRequest, auth, trackId)).willThrow(new UserNotFoundException(MessageDTO.USER_NOT_FOUND));
        mockMvc.perform(post("/api/updateUser")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(updateUserRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_NOT_FOUND.toString())));
        reset(userService);
    }

    @Test
    public void whenPostWrongEmailUpdateUser_thenunable_to_persist() throws Exception {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest("sayan@gmail.com", "test", "test");
        given(userService.updateUser(updateUserRequest, auth, trackId)).willThrow(new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST));
        mockMvc.perform(post("/api/updateUser")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(updateUserRequest)))
                .andExpect(content().string(containsString(MessageDTO.UNABLE_TO_PERSIST.toString())));
        reset(userService);
    }

    // All changeUserActiveStatus Testcase
    @Test
    public void whenPostchangeUserActiveStatus_thenReturnSuccessful() throws Exception {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("testuat3311@gmail.com", true);
        given(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId)).willReturn(MessageDTO.USER_ACTIVATED.toString());
        mockMvc.perform(post("/api/changeUserActiveStatus")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(changeUserActiveStatusRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_ACTIVATED.toString())));
        reset(userService);
    }


    @Test
    public void whenPostAlreadyActivechangeUserActiveStatus_thenuser_already_set_to() throws Exception {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("testuat3311@gmail.com", true);
        given(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId)).willReturn(MessageDTO.USER_ALREADY_SET_TO.toString() + "true");
        mockMvc.perform(post("/api/changeUserActiveStatus")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(changeUserActiveStatusRequest)))
                .andExpect(content().string(containsString("already")));
        reset(userService);
    }

    @Test
    public void whenPostWrongEmailActivechangeUserActiveStatus_thenuser_not_found() throws Exception {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("testuat33114@gmail.com", true);
        given(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId)).willThrow(new UserNotFoundException(MessageDTO.USER_NOT_FOUND));
        mockMvc.perform(post("/api/changeUserActiveStatus")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(changeUserActiveStatusRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_NOT_FOUND.toString())));
        reset(userService);
    }

    @Test
    public void whenPostWrongEmailActivechangeUserActiveStatus_thenuser_deactivated() throws Exception {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("testuat33114@gmail.com", true);
        given(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId)).willThrow(new UserNotFoundException(MessageDTO.USER_NOT_FOUND));
        mockMvc.perform(post("/api/changeUserActiveStatus")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(changeUserActiveStatusRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_NOT_FOUND.toString())));
        reset(userService);
    }

    @Test
    public void whenPostWrongEmailActivechangeUserActiveStatus_theunable_to_persist() throws Exception {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("testuat33114@gmail.com", true);
        given(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId)).willThrow(new UserNotFoundException(MessageDTO.USER_NOT_FOUND));
        mockMvc.perform(post("/api/changeUserActiveStatus")
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .content(JsonUtil.toJson(changeUserActiveStatusRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_NOT_FOUND.toString())));
        reset(userService);
    }

    //All authenticateSSO Testcase

    @Test
    public void whenPostAuthenticateSSO_thenReturnSuccessful() throws Exception {
        AuthenticateUser authenticateUser = new AuthenticateUser("sayan@gmail.com", "test", "");
        given(userService.authenticateSSO(authenticateUser)).willReturn(MessageDTO.SUCCESSFULL.toString());
        mockMvc.perform(post("/authenticateSSO")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JsonUtil.toJson(authenticateUser)))
                .andExpect(status().isOk());
        reset(userService);
    }

    @Test
    public void whenPostAuthenticateSSO_WO_thenuser_not_found() throws Exception {
        AuthenticateUser authenticateUser = new AuthenticateUser("unkown@gmail.com", "test", "authserver");
        given(userService.authenticateSSO(authenticateUser)).willThrow(new UserNotFoundException(MessageDTO.USER_NOT_FOUND));
        mockMvc.perform(post("/authenticateSSO")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JsonUtil.toJson(authenticateUser)))
                .andExpect(content().string(containsString(MessageDTO.USER_NOT_FOUND.toString())));
        reset(userService);
    }

    @Test
    public void whenPostAuthenticateSSO_W_ClinetId_thenclient_id_not_found() throws Exception {
        AuthenticateUser authenticateUser = new AuthenticateUser("sayan@gmail.com", "test", "authserver");
        given(userService.authenticateSSO(authenticateUser)).willReturn(MessageDTO.SUCCESSFULL_HEADER.toString());
        mockMvc.perform(post("/authenticateSSO")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JsonUtil.toJson(authenticateUser)))
                .andExpect(status().isOk());
        reset(userService);
    }

    @Test
    public void whenPostAuthenticateSSO_internalerror_thenunable_to_persist() throws Exception {
        AuthenticateUser authenticateUser = new AuthenticateUser("sayan@gmail.com", "test", "authserver");
        given(userService.authenticateSSO(authenticateUser)).willThrow(new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST));
        mockMvc.perform(post("/authenticateSSO")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JsonUtil.toJson(authenticateUser)))
                .andExpect(content().string(containsString(MessageDTO.UNABLE_TO_PERSIST.toString())));
        reset(userService);
    }

    @Test
    public void whenPostAuthenticateSSO_W_ClinetId_thensucessfull_with_header() throws Exception {
        AuthenticateUser authenticateUser = new AuthenticateUser("sayan@gmail.com", "test", "authserver");
        given(userService.authenticateSSO(authenticateUser)).willReturn(MessageDTO.SUCCESSFULL_HEADER.toString());
        mockMvc.perform(post("/authenticateSSO")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JsonUtil.toJson(authenticateUser)))
                .andExpect(status().isOk());
        reset(userService);
    }

    //All getAccessTokenByEmail Testcase

    @Test
    public void whenGetAccessTokenByEmailMIssingclinetid_thenbad_request_missing_client_id() throws Exception {
        TokenRequest tokenRequest = new TokenRequest("admin@lnl.com");
        given(tokenService.createAuthenticationObject(extendedUser, Tokens.AD_HOC_AUTH_SSO, CLIENT_ID)).willReturn(auth);
        given(userService.getAccessTokenByEmail(tokenRequest, auth, Optional.empty(), Optional.empty(), trackId)).willThrow(new MissingParamException(MessageDTO.BAD_REQUEST_MISSING_CLIENT_ID));
        mockMvc.perform(post("/external/getAccessTokenByEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .headers(headers)
                .content(JsonUtil.toJson(tokenRequest)))
                .andExpect(content().string(containsString(MessageDTO.BAD_REQUEST_MISSING_CLIENT_ID.toString())));
        reset(userService);
    }

    @Test
    public void whenGetAccessTokenByEmailInvalidclinetid_thenclient_id_not_found() throws Exception {
        TokenRequest tokenRequest = new TokenRequest("admin@lnl.com");
        given(tokenService.createAuthenticationObject(extendedUser, Tokens.AD_HOC_AUTH_SSO, CLIENT_ID)).willReturn(auth);
        given(userService.getAccessTokenByEmail(tokenRequest, auth, Optional.of("abc"), Optional.empty(), trackId)).willThrow(new ClientNotFoundException(MessageDTO.CLIENT_ID_NOT_FOUND));
        mockMvc.perform(post("/external/getAccessTokenByEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .headers(headers)
                .param("client_id", "abc")
                .content(JsonUtil.toJson(tokenRequest)))
                .andExpect(content().string(containsString(MessageDTO.CLIENT_ID_NOT_FOUND.toString())));
        reset(userService);
    }

    @Test
    public void whenGetAccessTokenByEmail_internal_error_thenunable_to_persist() throws Exception {
        TokenRequest tokenRequest = new TokenRequest("admin@lnl.com");
        given(userService.getAccessTokenByEmail(tokenRequest, auth, Optional.empty(), Optional.empty(), trackId)).willThrow(new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST));
        mockMvc.perform(post("/external/getAccessTokenByEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers)
                .session(session)
                .content(JsonUtil.toJson(tokenRequest)))
                .andExpect(content().string(containsString(MessageDTO.UNABLE_TO_PERSIST.toString())));
        reset(userService);
    }

    @Test
    public void whenGetAccessTokenByEmail_thenReturnSuccessful() throws Exception {
        TokenRequest tokenRequest = new TokenRequest("admin@lnl.com");
        given(userService.getAccessTokenByEmail(tokenRequest, auth, Optional.empty(), Optional.empty(), trackId)).willReturn(tokenId);
        mockMvc.perform(post("/external/getAccessTokenByEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers)
                .sessionAttr(Config.OPS_TRACE_ID, trackId)
                .param("client_id", CLIENT_ID)
                .content(JsonUtil.toJson(tokenRequest)))
                .andExpect(status().isOk());
        reset(userService);
    }
}