package com.lnl.controller;

import com.lnl.config.auth.CustomJdbcTokenStore;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.user.ExtendedUser;
import com.lnl.domain.OperationalAudit;
import com.lnl.domain.User;
import com.lnl.dto.*;
import com.lnl.exception.*;
import com.lnl.repository.OpsAuditRepository;
import com.lnl.repository.UserRepository;
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
import java.util.*;

import static org.assertj.core.api.Java6Assertions.assertThat;

@RunWith(SpringRunner.class)
@ActiveProfiles("test")
@TestPropertySource(properties = {"token.validity=2000"})
public class UserServiceTest {

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


    @TestConfiguration
    static class UserServiceTestContextConfiguration {

        @MockBean
        public DataSource oauthDataSource;

        @MockBean
        public UserDetailsService userDetailsService;

        @Bean
        public TokenStore tokenStore() {
            return new CustomJdbcTokenStore(oauthDataSource);
        }

        @Bean
        public UserService userService() {
            return new UserService();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Bean
        public ExtendedUser extendedUser() {
            return new ExtendedUser("nonadmin@lnl.com",
                    "$2a$10$r8FwK5xjVRZwcd/fxehlH.Idp9NQgadd.pQR.JprZkmynyzCtUVqa",
                    true,
                    true,
                    true,
                    true,
                    Arrays.asList(
                            new SimpleGrantedAuthority("ROLE_USER")
                    ),
                    "nonadmin@lnl.com",
                    UUID.fromString("582a4263-3dfd-4bea-897c-88f7612bc165"),
                    "nonadmin@lnl.com",
                    "minkowski");
        }

        @Bean
        public ExtendedUser extendedUserAdmin() {
            return new ExtendedUser("admin@lnl.com",
                    "$2a$10$r8FwK5xjVRZwcd/fxehlH.Idp9NQgadd.pQR.JprZkmynyzCtUVqa",
                    true,
                    true,
                    true,
                    true,
                    Arrays.asList(
                            new SimpleGrantedAuthority("ROLE_ADMIN")
                    ),
                    "admin@lnl.com",
                    UUID.fromString("582a4263-3dfd-4bea-897c-88f7612bc165"),
                    "admin@lnl.com",
                    "minkowski");
        }
    }

    @Autowired
    private ExtendedUser extendedUser;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ExtendedUser extendedUserAdmin;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private UserService userService;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private OAuth2AccessToken oAuth2AccessToken;

    @MockBean
    OpsAuditRepository opsAuditRepository;

    @MockBean
    TokenService tokenService;

    @MockBean
    HttpServletResponse response;

    @Value("${token.validity}")
    private Integer validity;

    @Before
    public void setUp() {

        Map<String, String> requestParameters = new HashMap<String, String>();
        boolean approved = true;
        Set<String> responseTypes = new HashSet<String>();
        responseTypes.add("code");

        OAuth2Request oauth2Request = new OAuth2Request(requestParameters, CLIENT_ID, extendedUser.getAuthorities(), approved, new HashSet<String>(Arrays.asList("READ")), null, null, responseTypes, null);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(extendedUser, "N/A", extendedUser.getAuthorities());
        auth = new OAuth2Authentication(oauth2Request, authenticationToken);

        OAuth2Request oauth2RequestAdmin = new OAuth2Request(requestParameters, CLIENT_ID, extendedUserAdmin.getAuthorities(), approved, new HashSet<String>(Arrays.asList("READ")), null, null, responseTypes, null);
        UsernamePasswordAuthenticationToken authenticationTokenAdmin = new UsernamePasswordAuthenticationToken(extendedUserAdmin, "N/A", extendedUserAdmin.getAuthorities());
        authAdmin = new OAuth2Authentication(oauth2RequestAdmin, authenticationTokenAdmin);

        user = new User(UUID.fromString(userId),
                "test",
                "nonadmin@lnl.com",
                true,
                "nonadmin", "", null,null);
        userAdmin = new User(null,
                "test",
                "admin@lnl.com",
                true,
                "admin", "", null,null);

        operationalAudit = new OperationalAudit(UUID.fromString(trackId), "nonadmin@lnl.com",
                tokenId,
                "admin@lnl.com",
                CLIENT_ID,
                date, "",
                "",
                "",
                "",
                "",
                "");
    }

    @Test
    public void whenValidUserRequest_CreateUser() {
        UserRequest userRequest = new UserRequest("nonadmin2@lnl.com", "test", "test", "test", 1234567890L, "lnl");
        Mockito.when(userRepository.save(user)).thenReturn(user);
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.createUser(userRequest, authAdmin, trackId)).contains(MessageDTO.USER_CREATED_SUCCESSFULLY.toString());
    }

    @Test(expected = UserAlreadyExistsException.class)
    public void whenValidUserExists_UserExists() {
        UserRequest userRequest = new UserRequest("nonadmin@lnl.com", "test", "test", "test", 1234567890L, "lnl");
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(userRepository.findByEmail(user.getEmail().toLowerCase())).thenReturn(user);
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.createUser(userRequest, auth, trackId));
    }

    @Test(expected = UserNotAuthorizedException.class)
    public void whenUnauthorizeUser_UserNotAuthorizedException() {
        UserRequest userRequest = new UserRequest("nonadmin2@lnl.com", "test", "test", "test", 1234567890L, "lnl");
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(userRepository.findByEmail(user.getEmail().toLowerCase())).thenReturn(null);
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.createUser(userRequest, auth, trackId));
    }

    @Test
    public void whenchangeUserStatus_UpdateSuccessfull() {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("nonadmin@gmail.com", true);
        User currentUser = user.toBuilder().build();
        currentUser.setActivated(false);
        Mockito.when(userRepository.findByEmail(changeUserActiveStatusRequest.getEmail().toLowerCase())).thenReturn(currentUser);
        assertThat(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId)).contains(MessageDTO.USER_ACTIVATED.toString());
    }

    @Test
    public void whenchangeUserStatus_UpdateSuccessfull_DeActivated() {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("nonadmin@gmail.com", false);
        User currentUser = user.toBuilder().build();
        currentUser.setActivated(true);
        Mockito.when(userRepository.findByEmail(changeUserActiveStatusRequest.getEmail().toLowerCase())).thenReturn(currentUser);
        assertThat(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId)).contains(MessageDTO.USER_DEACTIVATED.toString());
    }

    @Test
    public void whenchangeUserStatusAlreadySet_AlreadySet() {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("nonadmin@gmail.com", true);
        Mockito.when(userRepository.findByEmail(changeUserActiveStatusRequest.getEmail().toLowerCase())).thenReturn(user);
        assertThat(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId)).contains(MessageDTO.USER_ALREADY_SET_TO.toString() + "true");
    }

    @Test
    public void whenchangeUserStatusAlreadySet_AlreadySetToFalse() {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("nonadmin@gmail.com", false);
        User currentUser = user.toBuilder().build();
        user.setActivated(false);
        Mockito.when(userRepository.findByEmail(changeUserActiveStatusRequest.getEmail().toLowerCase())).thenReturn(user);
        assertThat(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId)).contains(MessageDTO.USER_ALREADY_SET_TO.toString() + "false");
    }


    @Test(expected = UserNotFoundException.class)
    public void whenchangeUserStatusWrongEmail_UserNotFound() {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("nonadmin@gmail.com", true);
        Mockito.when(userRepository.findByEmail(changeUserActiveStatusRequest.getEmail().toLowerCase())).thenReturn(null);
        assertThat(userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId));
    }

    @Test
    public void whenupdateUser_updatedSuccessfully() {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest("nonadmin@lnl.com", "test", "test");
        Mockito.when(userRepository.findByEmail(updateUserRequest.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(userRepository.save(user)).thenReturn(user);
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(), Mockito.any(),Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.updateUser(updateUserRequest, auth, trackId)).contains(MessageDTO.UPDATE_USER_SUCESSFULLY.toString());
    }

    @Test(expected = UserNotAuthorizedException.class)
    public void whenupdateUser_UserNotAuthorizedException() {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest("nonadmin123@gmail.com", "test", "test");
        Mockito.when(userRepository.findByEmail(updateUserRequest.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(userRepository.save(user)).thenReturn(user);
        assertThat(userService.updateUser(updateUserRequest, auth, trackId));
    }

    @Test(expected = UserNotFoundException.class)
    public void whenupdateUserWrongEmail_userNotFound() {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest("nonadmin123@gmail.com", "test", "test");
        Mockito.when(userRepository.findByEmail(updateUserRequest.getEmail().toLowerCase())).thenReturn(null);
        Mockito.when(userRepository.save(user)).thenReturn(user);
        assertThat(userService.updateUser(updateUserRequest, auth, trackId));
    }

    @Test
    public void whenupdatePassword_Successfull() {
        UpdatePasswordRequest updatePasswordRequest = new UpdatePasswordRequest("nonadmin@lnl.com", "test");
        Mockito.when(userRepository.findByEmail(updatePasswordRequest.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(userRepository.save(user)).thenReturn(user);
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.updatePassword(updatePasswordRequest, auth, trackId)).contains(MessageDTO.SUCCESSFULL.toString());
    }

    @Test(expected = UnableToPersistException.class)
    public void whenUpdatePassword_UnableToPersistException() {
        UpdatePasswordRequest updatePasswordRequest = new UpdatePasswordRequest("nonadmin@lnl.com", "test");
        Mockito.when(userRepository.findByEmail(updatePasswordRequest.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(userRepository.save(user)).thenReturn(null);
        assertThat(userService.updatePassword(updatePasswordRequest, auth, trackId));
    }

    @Test(expected = UserNotAuthorizedException.class)
    public void whenUpdatePassword_UserNotAuthorizedException() {
        UpdatePasswordRequest updatePasswordRequest = new UpdatePasswordRequest("nonadmin123@lnl.com", "test");
        Mockito.when(userRepository.findByEmail(updatePasswordRequest.getEmail().toLowerCase())).thenReturn(user);
        assertThat(userService.updatePassword(updatePasswordRequest, auth, trackId)).contains(MessageDTO.UNAUTHORIZED.toString());
    }

    @Test(expected = UserNotFoundException.class)
    public void whenupdatePasswordWrongEmail_UserNotFound() {
        UpdatePasswordRequest updatePasswordRequest = new UpdatePasswordRequest("nonadmin123@lnl.com", "test");
        Mockito.when(userRepository.findByEmail(updatePasswordRequest.getEmail().toLowerCase())).thenReturn(null);
        Mockito.when(userRepository.save(user)).thenReturn(user);
        assertThat(userService.updatePassword(updatePasswordRequest, auth, trackId));
    }

    @Test
    public void whenGetAccessTokenByEmail_ThenReturnToken() {
        TokenRequest tokenRequest = new TokenRequest("nonadmin@lnl.com");
        Mockito.when(tokenService.createToken(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(new DefaultOAuth2AccessToken(tokenId));
        Mockito.when(tokenService.checkClientId(CLIENT_ID)).thenReturn(true);
        Mockito.when(userRepository.findByEmail(tokenRequest.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(userRepository.save(user)).thenReturn(user);
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.getAccessTokenByEmail(tokenRequest, Mockito.any(), Optional.of(CLIENT_ID), Optional.of(0), trackId)).contains(tokenId);
    }

    @Test(expected = UnableToPersistException.class)
    public void whenGetAccessTokenByEmail_UnableToPersistException() {
        TokenRequest tokenRequest = new TokenRequest("nonadmin@lnl.com");
        //Mockito.when(tokenService.createToken(Mockito.any(),Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(new DefaultOAuth2AccessToken(tokenId));
        Mockito.when(tokenService.checkClientId(CLIENT_ID)).thenReturn(true);
        Mockito.when(userRepository.findByEmail(tokenRequest.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(userRepository.save(user)).thenReturn(user);
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.getAccessTokenByEmail(tokenRequest, Mockito.any(), Optional.of(CLIENT_ID), Optional.of(0), trackId)).contains(tokenId);
    }

    @Test
    public void whenGetAccessTokenByEmail_ExpiryExtensionNonZero() {
        TokenRequest tokenRequest = new TokenRequest("nonadmin@lnl.com");
        Mockito.when(tokenService.createToken(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(new DefaultOAuth2AccessToken(tokenId));
        Mockito.when(tokenService.checkClientId(CLIENT_ID)).thenReturn(true);
        Mockito.when(userRepository.findByEmail(tokenRequest.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(userRepository.save(user)).thenReturn(user);
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.getAccessTokenByEmail(tokenRequest, Mockito.any(), Optional.of(CLIENT_ID), Optional.of(1), trackId)).contains(tokenId);
    }

    @Test(expected = ClientNotFoundException.class)
    public void whenGetAccessTokenByEmailInvalidClient_ClientNotFound() {
        TokenRequest tokenRequest = new TokenRequest("nonadmin@lnl.com");
        Mockito.when(tokenService.checkClientId(CLIENT_ID)).thenReturn(false);
        Mockito.when(userRepository.findByEmail(tokenRequest.getEmail().toLowerCase())).thenReturn(user);
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.getAccessTokenByEmail(tokenRequest, Mockito.any(), Optional.of(CLIENT_ID), Optional.of(0), trackId));
    }

    @Test(expected = UserNotFoundException.class)
    public void whenGetAccessTokenByEmailInvalidUser_UserNotFound() {
        TokenRequest tokenRequest = new TokenRequest("nonadmin123@lnl.com");
        Mockito.when(userRepository.findByEmail(tokenRequest.getEmail().toLowerCase())).thenReturn(null);
        Mockito.when(tokenService.checkClientId(CLIENT_ID)).thenReturn(true);
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.getAccessTokenByEmail(tokenRequest, Mockito.any(), Optional.of(CLIENT_ID), Optional.of(0), trackId));
    }

    @Test(expected = MissingParamException.class)
    public void whenGetAccessTokenByEmailNoClientIdPassed_MissingClientParam() {
        TokenRequest tokenRequest = new TokenRequest("nonadmin123@lnl.com");
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        Mockito.when(opsAuditRepository.findOne(UUID.fromString(trackId))).thenReturn(operationalAudit);
        assertThat(userService.getAccessTokenByEmail(tokenRequest, Mockito.any(), Optional.empty(), Optional.of(0), trackId));
    }

    @Test(expected = ClientNotFoundException.class)
    public void whenAuthenticateSSOInvalidClient_ClientNotFound() {
        AuthenticateUser aUser = new AuthenticateUser("nonadmin@lnl.com", "test", CLIENT_ID);
        Mockito.when(userService.loadextendedUserByEmail(aUser.getEmail().toLowerCase())).thenReturn(extendedUser);
        Mockito.when(tokenService.checkClientId(CLIENT_ID)).thenReturn(false);
        Mockito.when(userRepository.findByEmail(aUser.getEmail().toLowerCase())).thenReturn(user);
        assertThat(userService.authenticateSSO(aUser));
    }

    @Test(expected = UserNotFoundException.class)
    public void whenAuthenticateSSOUserNotFound_checkPasswordFails() {
        AuthenticateUser aUser = new AuthenticateUser("nonadmin@lnl.com", "test1", CLIENT_ID);
        Mockito.when(userService.loadextendedUserByEmail(aUser.getEmail().toLowerCase())).thenReturn(extendedUser);
        Mockito.when(userRepository.findByEmail(aUser.getEmail().toLowerCase())).thenReturn(user);
        assertThat(userService.authenticateSSO(aUser));
    }

    @Test(expected = UserNotFoundException.class)
    public void whenAuthenticateSSOUserNotFound_findByEmailFails() {
        AuthenticateUser aUser = new AuthenticateUser("nonadmin123@lnl.com", "test", CLIENT_ID);
        Mockito.when(userRepository.findByEmail(aUser.getEmail().toLowerCase())).thenReturn(null);
        assertThat(userService.authenticateSSO(aUser));
    }

    @Test
    public void whenAuthenticateSSO_SuccessWithHeader() {
        AuthenticateUser aUser = new AuthenticateUser("nonadmin@lnl.com", "test", CLIENT_ID);
        Mockito.when(userService.loadextendedUserByEmail(aUser.getEmail().toLowerCase())).thenReturn(extendedUser);
        Mockito.when(userRepository.findByEmail(aUser.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(tokenService.checkClientId(CLIENT_ID)).thenReturn(true);
        Mockito.when(tokenService.createToken(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(new DefaultOAuth2AccessToken(tokenId));
        assertThat(userService.authenticateSSO(aUser)).contains(MessageDTO.SUCCESSFULL_HEADER.toString());
    }

    @Test
    public void whenAuthenticateSSO_Success() {
        AuthenticateUser aUser = new AuthenticateUser("nonadmin@lnl.com", "test", "");
        Mockito.when(userService.loadextendedUserByEmail(aUser.getEmail().toLowerCase())).thenReturn(extendedUser);
        Mockito.when(userRepository.findByEmail(aUser.getEmail().toLowerCase())).thenReturn(user);
        //Mockito.when(tokenService.createToken(Mockito.any(),Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(new DefaultOAuth2AccessToken(tokenId));
        assertThat(userService.authenticateSSO(aUser)).contains(MessageDTO.SUCCESSFULL.toString());
    }

    @Test(expected = UnableToPersistException.class)
    public void whenAuthenticateSSO_UnableToPersistException() {
        AuthenticateUser aUser = new AuthenticateUser("nonadmin@lnl.com", "test", CLIENT_ID);
        Mockito.when(userService.loadextendedUserByEmail(aUser.getEmail().toLowerCase())).thenReturn(extendedUser);
        Mockito.when(userRepository.findByEmail(aUser.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(userRepository.findByEmail(aUser.getEmail().toLowerCase())).thenReturn(user);
        Mockito.when(tokenService.checkClientId(CLIENT_ID)).thenReturn(true);
        assertThat(userService.authenticateSSO(aUser));
    }

    @Test
    public void whenGetUser_Success() {
        Mockito.doNothing().when(tokenService).tokenServiceBuilder(Mockito.any(),Mockito.any(), Mockito.any(), Mockito.any());
        assertThat(userService.getUser(auth));
    }
}