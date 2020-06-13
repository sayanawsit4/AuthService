package com.lnl.service;

import com.lnl.config.constants.Config;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.constants.Tokens;
import com.lnl.config.user.ExtendedUser;
import com.lnl.domain.Authority;
import com.lnl.domain.OperationalAudit;
import com.lnl.domain.User;
import com.lnl.dto.*;
import com.lnl.exception.*;
import com.lnl.repository.OpsAuditRepository;
import com.lnl.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.SessionAttribute;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.google.common.collect.Sets.newHashSet;
import static com.lnl.config.constants.Roles.ROLE_ADMIN;
import static com.lnl.config.constants.Roles.ROLE_USER;
import static com.lnl.config.utils.StringUtils.checkpassword;

@Slf4j
@Service
public class UserService {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OpsAuditRepository opsAuditRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private TokenService tokenService;

    @Resource(name = "tokenStore")
    TokenStore tokenStore;

    @Value("${token.validity}")
    private Integer validity;

    @Autowired
    private HttpServletResponse response;

    public String changeUserStatus(ChangeUserActiveStatusRequest user,
                                   OAuth2Authentication auth,
                                   @SessionAttribute(Config.OPS_TRACE_ID) String trackId) {
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(user.getEmail().toLowerCase()));
        String userResponse;

        if (temp.isPresent()) {
            if (temp.get().isActivated() == user.getActive()) {
                userResponse = MessageDTO.USER_ALREADY_SET_TO.toString() + temp.get().isActivated();
                tokenService.tokenServiceBuilder(auth, Optional.of(user.getEmail().toLowerCase()), Optional.of(userResponse), Optional.of(trackId));
            } else {
                try {
                    temp.get().setActivated(user.getActive());
                    userRepository.save(temp.get());
                    userResponse = user.getActive() ? MessageDTO.USER_ACTIVATED.toString() : MessageDTO.USER_DEACTIVATED.toString();
                    tokenService.tokenServiceBuilder(auth, Optional.of(user.getEmail().toLowerCase()), Optional.of(userResponse), Optional.of(trackId));
                } catch (Exception e) {
                    log.info("exception is" + e.getMessage());
                    tokenService.tokenServiceBuilder(auth, Optional.of(user.getEmail().toLowerCase()), Optional.of(MessageDTO.UNABLE_TO_PERSIST.toString()), Optional.of(trackId));
                    throw new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST);
                }
            }

        } else {
            tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.of(MessageDTO.USER_NOT_FOUND.toString()), Optional.of(trackId));
            throw new UserNotFoundException(MessageDTO.USER_NOT_FOUND);
        }
        return userResponse;
    }

    public String updateUser(UpdateUserRequest updateUserRequest,
                             OAuth2Authentication auth,
                             @SessionAttribute(Config.OPS_TRACE_ID) String trackId) {
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(updateUserRequest.getEmail().toLowerCase()));
        String userResponse = null;
        ExtendedUser extendedUser = (ExtendedUser) auth.getPrincipal();
        OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
        if (temp.isPresent()) {
            if (isPermissible(updateUserRequest.getEmail().toLowerCase(), extendedUser)) {
                try {
                    temp.get().setFirstName(updateUserRequest.getFirstName());
                    temp.get().setLastName(updateUserRequest.getLastName());
                    userRepository.save(temp.get());
                    u.setUser(temp.get().getEmail().toLowerCase());
                } catch (Exception e) {
                    tokenService.tokenServiceBuilder(auth, Optional.of(updateUserRequest.getEmail().toLowerCase()), Optional.of(MessageDTO.UNABLE_TO_PERSIST.toString()), Optional.of(trackId));
                    throw new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST);
                }
                userResponse = MessageDTO.UPDATE_USER_SUCESSFULLY.toString();
                tokenService.tokenServiceBuilder(auth, Optional.of(updateUserRequest.getEmail().toLowerCase()), Optional.of(userResponse), Optional.of(trackId));
            } else {
                tokenService.tokenServiceBuilder(auth, Optional.of(updateUserRequest.getEmail().toLowerCase()), Optional.of(MessageDTO.UNAUTHORIZED.toString()), Optional.of(trackId));
                throw new UserNotAuthorizedException(MessageDTO.UNAUTHORIZED);
            }
        } else {
            tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.of(MessageDTO.USER_NOT_FOUND.toString()), Optional.of(trackId));
            throw new UserNotFoundException(MessageDTO.USER_NOT_FOUND);
        }
        return userResponse;
    }

    public String updateEmail(UpdateUserEmail updateUserEmail,
                              OAuth2Authentication auth,
                              @SessionAttribute(Config.OPS_TRACE_ID) String trackId) {
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(updateUserEmail.getEmail().toLowerCase()));
        Optional<User> newUser = Optional.ofNullable(userRepository.findByEmail(updateUserEmail.getNewEmail()));
        String userResponse = null;
        ExtendedUser extendedUser = (ExtendedUser) auth.getPrincipal();
        OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
        if (temp.isPresent()) {
            if (isPermissible(updateUserEmail.getEmail().toLowerCase(), extendedUser)) {
                if (newUser.isPresent()) {
                    throw new EmailAlreadyExistsException(MessageDTO.USER_EMAIL_ALREADY_EXISTS);
                } else {
                    try {
                        temp.get().setEmail(updateUserEmail.getNewEmail().toLowerCase());
                        userRepository.save(temp.get());
                        u.setUser(temp.get().getEmail().toLowerCase());
                    } catch (Exception e) {
                        tokenService.tokenServiceBuilder(auth, Optional.of(updateUserEmail.getEmail().toLowerCase()), Optional.of(MessageDTO.UNABLE_TO_PERSIST.toString()), Optional.of(trackId));
                        throw new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST);
                    }
                }
                userResponse = MessageDTO.EMAIL_UPDATED_SUCCESSFULLY.toString();
                tokenService.tokenServiceBuilder(auth, Optional.of(updateUserEmail.getEmail().toLowerCase()), Optional.of(userResponse), Optional.of(trackId));
            } else {
                tokenService.tokenServiceBuilder(auth, Optional.of(updateUserEmail.getEmail().toLowerCase()), Optional.of(MessageDTO.UNAUTHORIZED.toString()), Optional.of(trackId));
                throw new UserNotAuthorizedException(MessageDTO.UNAUTHORIZED);
            }
        } else {
            tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.of(MessageDTO.USER_NOT_FOUND.toString()), Optional.of(trackId));
            throw new UserNotFoundException(MessageDTO.USER_NOT_FOUND);
        }
        return userResponse;
    }

    public String createUser(UserRequest user,
                             OAuth2Authentication auth,
                             @SessionAttribute(Config.OPS_TRACE_ID) String trackId) {
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(user.getEmail().toLowerCase()));
        String userResponse;
        ExtendedUser extendedUser = (ExtendedUser) auth.getPrincipal();
        OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
        u.setUser(user.getEmail().toLowerCase());
        if (temp.isPresent()) {
            tokenService.tokenServiceBuilder(auth, Optional.of(user.getEmail().toLowerCase()), Optional.of(MessageDTO.USER_EXISTS.toString()), Optional.of(trackId));
            throw new UserAlreadyExistsException(MessageDTO.USER_EXISTS);
        } else {
            if (isPermissible(user.getEmail().toLowerCase(), extendedUser)) {
                try {
                    userRepository.save(new User(null,
                            passwordEncoder.encode(user.getPassword()),
                            user.getEmail().toLowerCase(),
                            true,
                            user.getFirstName(),
                            user.getLastName(),
                            null,
                            newHashSet(new Authority(ROLE_USER)) //hardcoded to role user,as currently no scope to create admin
                    ));
                    userResponse = MessageDTO.USER_CREATED_SUCCESSFULLY.toString();
                    tokenService.tokenServiceBuilder(auth, Optional.of(user.getEmail().toLowerCase()), Optional.of(userResponse), Optional.of(trackId));
                } catch (Exception e) {
                    tokenService.tokenServiceBuilder(auth, Optional.of(user.getEmail().toLowerCase()), Optional.of(MessageDTO.UNABLE_TO_PERSIST.toString()), Optional.of(trackId));
                    throw new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST);
                }
            } else {
                tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.of(MessageDTO.UNAUTHORIZED.toString()), Optional.of(trackId));
                throw new UserNotAuthorizedException(MessageDTO.UNAUTHORIZED);
            }
        }
        return userResponse;
    }

    public String deleteUser(DeleteUserRequest deleteUserRequest,
                             OAuth2Authentication auth,
                             @SessionAttribute(Config.OPS_TRACE_ID) String trackId) {
        String userResponse;
        ExtendedUser extendedUser = (ExtendedUser) auth.getPrincipal();
        OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
        Optional<User> temp = findByEmail(deleteUserRequest.getEmail().toLowerCase());

        if (temp.isPresent()) {
            if (isPermissible(deleteUserRequest.getEmail().toLowerCase(), extendedUser)) {
                try {
                    userRepository.delete(temp.get());
                    userResponse = MessageDTO.USER_DELETED_SUCCESSFULLY.toString();
                } catch (Exception e) {
                    tokenService.tokenServiceBuilder(auth, Optional.of(deleteUserRequest.getEmail().toLowerCase()), Optional.of(MessageDTO.UNABLE_TO_PERSIST.toString()), Optional.of(trackId));
                    throw new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST);
                }

            } else {
                tokenService.tokenServiceBuilder(auth, Optional.of(deleteUserRequest.getEmail().toLowerCase()), Optional.of(MessageDTO.UNAUTHORIZED.toString()), Optional.of(trackId));
                throw new UserNotAuthorizedException(MessageDTO.UNAUTHORIZED);
            }
        } else {
            tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.of(MessageDTO.USER_NOT_FOUND.toString()), Optional.of(trackId));
            throw new UserNotFoundException(MessageDTO.USER_NOT_FOUND);
        }
        return userResponse;
    }

    public String updatePassword(UpdatePasswordRequest updatePasswordRequest,
                                 OAuth2Authentication auth,
                                 @SessionAttribute(Config.OPS_TRACE_ID) String trackId) {

        String userResponse;
        ExtendedUser extendedUser = (ExtendedUser) auth.getPrincipal();
        OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
        Optional<User> temp = findByEmail(updatePasswordRequest.getEmail().toLowerCase());

        if (temp.isPresent()) {
            if (isPermissible(updatePasswordRequest.getEmail().toLowerCase(), extendedUser)) {
                try {
                    temp.get().setPassword(passwordEncoder.encode(updatePasswordRequest.getNewPassword()));
                    userRepository.save(temp.get());
                    u.setUser(temp.get().getEmail().toLowerCase());
                } catch (Exception e) {
                    throw new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST);
                }
                userResponse = MessageDTO.SUCCESSFULL.toString();

            } else {
                throw new UserNotAuthorizedException(MessageDTO.UNAUTHORIZED);
            }

        } else {
            throw new UserNotFoundException(MessageDTO.USER_NOT_FOUND);
        }

        tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.of(userResponse), Optional.of(trackId));
        return userResponse;
    }

    @java.lang.SuppressWarnings("squid:S3776")
    public String getAccessTokenByEmail(TokenRequest tokenRequest,
                                        OAuth2Authentication auth,
                                        Optional<String> clientId,
                                        Optional<Integer> expiryExtension,
                                        @SessionAttribute(Config.OPS_TRACE_ID) String trackId) {
        Integer extendedValidity;
        Tokens scope = Tokens.AD_HOC;
        String responseObj;
        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(tokenRequest.getEmail().toLowerCase()));
        OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
        u.setUser(tokenRequest.getEmail().toLowerCase());
        if (clientId.isPresent()) {
            if (temp.isPresent()) {
                if (tokenService.checkClientId(clientId.get())) {
                    if (expiryExtension.isPresent()) {
                        if (expiryExtension.get().equals(0)) {
                            scope = Tokens.ONE_TIME;
                            extendedValidity = 0;
                        } else {
                            scope = Tokens.AD_HOC_EXTN;
                            extendedValidity = validity + expiryExtension.get();
                        }
                    } else
                        extendedValidity = validity;

                    ExtendedUser ext = userService.loadextendedUserByEmail(tokenRequest.getEmail().toLowerCase());
                    try {
                        responseObj = tokenService.createToken(extendedValidity, ext, scope, clientId.get()).getValue();
                    } catch (Exception e) {
                        responseObj = MessageDTO.UNABLE_TO_PERSIST.toString();
                        throw new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST);
                    }
                } else {
                    responseObj = MessageDTO.UNABLE_TO_PERSIST.toString();
                    throw new ClientNotFoundException(MessageDTO.CLIENT_ID_NOT_FOUND);
                }
            } else {
                responseObj = MessageDTO.USER_NOT_FOUND.toString();
                tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.of(responseObj), Optional.of(trackId));
                throw new UserNotFoundException(MessageDTO.USER_NOT_FOUND);
            }
        } else {
            responseObj = MessageDTO.USER_NOT_FOUND.toString();
            tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.of(responseObj), Optional.of(trackId));
            throw new MissingParamException(MessageDTO.BAD_REQUEST_MISSING_CLIENT_ID);
        }
        tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.of(responseObj), Optional.of(trackId));
        return responseObj;
    }

    @java.lang.SuppressWarnings("squid:S3776")
    public String authenticateSSO(AuthenticateUser authenticateUser) {
        String responseObj;
        if (userService.findByEmail(authenticateUser.getEmail().toLowerCase()).isPresent()) {
            ExtendedUser ext = userService.loadextendedUserByEmail(authenticateUser.getEmail().toLowerCase());
            if (checkpassword(authenticateUser.getPassword(), ext.getPassword())) {
                if (!authenticateUser.getClientId().isEmpty()) {
                    if (tokenService.checkClientId(authenticateUser.getClientId())) {
                        try {
                            OAuth2AccessToken token = tokenService.createToken(validity, ext, Tokens.AD_HOC_AUTH_SSO, authenticateUser.getClientId());
                            response.addHeader("token", token.getValue());
                            responseObj = MessageDTO.SUCCESSFULL_HEADER.toString();
                        } catch (Exception e) {
                            throw new UnableToPersistException(MessageDTO.UNABLE_TO_PERSIST);
                        }
                    } else {
                        throw new ClientNotFoundException(MessageDTO.CLIENT_ID_NOT_FOUND);
                    }
                } else {
                    responseObj = MessageDTO.SUCCESSFULL.toString();
                }
            } else {
                throw new UserNotFoundException(MessageDTO.USER_NOT_FOUND);
            }
        } else {
            throw new UserNotFoundException(MessageDTO.USER_NOT_FOUND);
        }
        return responseObj;
    }

    public UserResponse getUser(OAuth2Authentication auth) {

        ExtendedUser extendedUser = (ExtendedUser) auth.getPrincipal();
        UserResponse userResponse = new UserResponse();
        userResponse.setId(extendedUser.getUserid());
        userResponse.setUsername(extendedUser.getEmail().toLowerCase());
        userResponse.setEmail(extendedUser.getEmail().toLowerCase());
        userResponse.setFirst_name(extendedUser.getfirstName());
        userResponse.setLast_name(extendedUser.getlastName());

        tokenService.tokenServiceBuilder(auth, Optional.empty(), Optional.empty(), Optional.empty());

        return userResponse;

    }

    public ExtendedUser loadextendedUserByEmail(String email) {
        return (ExtendedUser) userDetailsService.loadUserByUsername(email);
    }

    public Optional<User> findByEmail(String email) {
        return Optional.ofNullable(userRepository.findByEmail(email));
    }

    List<String> getCurrentUserRoles(ExtendedUser extendedUser) {
        return extendedUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    }

    Boolean isPermissible(String currentEmail, ExtendedUser extendedUser) {
        return getCurrentUserRoles(extendedUser).contains(ROLE_ADMIN) || currentEmail.equals(extendedUser.getEmail().toLowerCase());
    }

}