package com.lnl.controller;

import com.lnl.config.constants.Config;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.constants.SwaggerConstants;
import com.lnl.config.constants.Tokens;
import com.lnl.config.user.ExtendedUser;
import com.lnl.dto.*;
import com.lnl.service.TokenService;
import com.lnl.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.*;
import springfox.documentation.annotations.ApiIgnore;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.util.Optional;

import static com.lnl.config.constants.Roles.ROLE_ADMIN;
import static com.lnl.config.constants.Roles.ROLE_USER;

@Slf4j
@RestController
@Api(value = "Authentication API", description = "Authenticate user using authorization token.")
public class ResourceController {

    @Autowired
    private UserService userService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private HttpServletRequest request;

    @Autowired
    ExtendedUser extendedUserDefault;

    @Value("${token.validity}")
    private Integer validity;

    @PostMapping(value = "/api/createUser")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.USER_CREATED_SUCCESSFULLY, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Create user", notes = " 1. Creates a new user \n 2.returns already exists if duplicate ")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity createUserV1(
            @RequestBody @Valid UserRequest user,
            @ApiIgnore @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) {
        userService.createUser(user, auth, trackId);
        return new ResponseEntity<>(MessageDTO.USER_CREATED_SUCCESSFULLY.toString(), HttpStatus.OK);
    }

    @PostMapping(value = "/external/createUser")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.USER_CREATED_SUCCESSFULLY, response = String.class),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Create user", notes = " 1. Creates a new user \n 2.returns already exists if duplicate ")
    public ResponseEntity createUserV1Hmac(
            @RequestHeader(value = "InitiatedBy") Optional<String> initiatedBy,
            @RequestBody @Valid UserRequest user,
            @ApiIgnore @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            @RequestParam(value = "client_id") String clientId) {
        OAuth2Authentication auth = tokenService.createAuthenticationObject(initiatedBy, Tokens.AD_HOC_AUTH_SSO, clientId);
        userService.createUser(user, auth, trackId);
        return new ResponseEntity<>(MessageDTO.USER_CREATED_SUCCESSFULLY.toString(), HttpStatus.OK);
    }

    @PostMapping(value = "/genCode")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.USER_CREATED_SUCCESSFULLY, response = String.class),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Create user", notes = " 1. Creates a new user \n 2.returns already exists if duplicate ")
    public ResponseEntity genCode(
            @RequestBody @Valid TokenRequest user) {
        return new ResponseEntity<>(tokenService.genCode(user.getEmail().toLowerCase()), HttpStatus.OK);
    }

    @PostMapping(value = "/validateCode")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.USER_CREATED_SUCCESSFULLY, response = String.class),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Create user", notes = " 1. Creates a new user \n 2.returns already exists if duplicate ")
    public ResponseEntity validateCode(
            @RequestBody @Valid ValidateCodeRequest user) throws IOException {
        return new ResponseEntity<>(tokenService.validateCode(user.getCode(), user.getEmail().toLowerCase(),true), HttpStatus.OK);
    }

    @PostMapping(value = "/api/updateUser")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.UPDATE_USER_SUCESSFULLY, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Update an existing user", notes = "1.Updates an existing user\n 2.returns invalid if not present\n 3.Excepts empty values \n4.Needs to be a valid email \n5.Token scoped")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity updateUserV1(
            @RequestBody @Valid UpdateUserRequest updateUserRequest,
            @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) {
        userService.updateUser(updateUserRequest, auth, trackId);
        return new ResponseEntity<>(MessageDTO.UPDATE_USER_SUCESSFULLY.toString(), HttpStatus.OK);
    }

    @PostMapping(value = "/api/updateEmail")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.USER_EMAIL_ALREADY_EXISTS, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Update an existing user", notes = "1.Updates an existing user\n 2.returns invalid if not present\n 3.Excepts empty values \n4.Needs to be a valid email \n5.Token scoped")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity updateEmailV1(
            @RequestBody @Valid UpdateUserEmail updateUserEmail,
            @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) {
        userService.updateEmail(updateUserEmail, auth, trackId);
        return new ResponseEntity<>(MessageDTO.EMAIL_UPDATED_SUCCESSFULLY.toString(), HttpStatus.OK);
    }

    @PostMapping(value = "/api/updatePassword")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.UPDATE_PASSWORD_SUCESSFULLY, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 404, message = SwaggerConstants.USER_NOT_FOUND),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Update password of a user", notes = " 1. Update password of user \n2.returns already exists if duplicate \n3.Password cannot be empty")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity updatePasswordV1(
            @RequestHeader("passCode") Optional<String> passCode,
            @RequestBody @Valid UpdatePasswordRequest updatePasswordRequest,
            @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) throws IOException {
        if (passCode.isPresent()) {
            if (tokenService.validateCode(passCode.get(), updatePasswordRequest.getEmail().toLowerCase(),false).equals("Wrong code"))
                return new ResponseEntity<>(MessageDTO.INVALID_PASSCODE.toString(), HttpStatus.OK);
        }
        userService.updatePassword(updatePasswordRequest, auth, trackId);
        return new ResponseEntity<>(MessageDTO.UPDATE_PASSWORD_SUCESSFULLY.toString(), HttpStatus.OK);
    }

    @PostMapping(value = "/api/deleteUser")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.USER_DELETED_SUCCESSFULLY, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 404, message = SwaggerConstants.USER_NOT_FOUND),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Update password of a user", notes = " 1. Update password of user \n2.returns already exists if duplicate \n3.Password cannot be empty")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity deleteUserV1(
            @RequestBody @Valid DeleteUserRequest deleteUserRequest,
            @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) {
        userService.deleteUser(deleteUserRequest, auth, trackId);
        return new ResponseEntity<>(MessageDTO.USER_DELETED_SUCCESSFULLY.toString(), HttpStatus.OK);
    }

    @PostMapping(value = "/api/changeUserActiveStatus")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.USER_ACTIVATED, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 404, message = SwaggerConstants.USER_NOT_FOUND),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Change the user active status", notes = "1.Changes user active status \n2.Returns the existing status for idempotent calls \n3.Token scoped. \n4.Requires valid email id")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity changeUserActiveStatusV1(
            @RequestBody @Valid ChangeUserActiveStatusRequest changeUserActiveStatusRequest,
            @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) {
        String resObj = userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId);
        return new ResponseEntity<>(resObj, HttpStatus.OK);
    }

    @PostMapping(value = "/authenticateSSO")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.SUCCESSFULL, response = String.class),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    public ResponseEntity authenticateSSOV1(
            @RequestBody @Valid AuthenticateUser authenticateUser) {
        userService.authenticateSSO(authenticateUser);
        return new ResponseEntity<>(authenticateUser.getEmail().toLowerCase(), HttpStatus.OK);
    }

    @PostMapping(value = "/external/getAccessTokenByEmail")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.SUCCESSFULL, response = String.class),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    public ResponseEntity gettokenV1(
            @RequestHeader(value = "InitiatedBy") Optional<String> initiatedBy,
            @RequestBody @Valid TokenRequest tokenRequest,
            @RequestParam(value = "expiry_extension", required = false) Optional<Integer> expiryExtension,
            @RequestParam(value = "client_id", required = false) Optional<String> clientId,
            @ApiIgnore @SessionAttribute(Config.OPS_TRACE_ID) String trackId
    ) {
        OAuth2Authentication auth = tokenService.createAuthenticationObject(initiatedBy, Tokens.AD_HOC_AUTH_SSO, clientId.orElse("No info"));
        String resObj = userService.getAccessTokenByEmail(tokenRequest, auth, clientId, expiryExtension, trackId);
        return new ResponseEntity<>(resObj, HttpStatus.OK);
    }

    @GetMapping(value = "/api/user")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    @ApiOperation(value = "Returns principal of an user", notes = " 1.Returns user object post client authentication \n2.Token scoped")
    public UserResponse user(OAuth2Authentication auth) {
        return userService.getUser(auth);
    }
}