package com.lnl.controller;

import com.lnl.config.constants.Config;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.constants.SwaggerConstants;
import com.lnl.config.constants.Tokens;
import com.lnl.dto.*;
import com.lnl.service.TokenService;
import com.lnl.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.*;
import springfox.documentation.annotations.ApiIgnore;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Optional;

import static com.lnl.config.constants.Roles.ROLE_ADMIN;
import static com.lnl.config.constants.Roles.ROLE_USER;

//The Version 2.0 implementation of user management APIs.Note that this is under WIP.
@RestController
@Api(value = "Authentication API", description = "Authenticate user using authorization token.")
public class ResourceControllerV2 {

    @Autowired
    private UserService userService;

    @Autowired
    private HttpServletRequest request;

    @Autowired
    private TokenService tokenService;


    @PostMapping(value = "/api/v2.0/createUser")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.USER_CREATED_SUCCESSFULLY, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Create user", notes = " 1. Creates a new user \n 2.returns already exists if duplicate ")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity createUserV2(
            @RequestBody @Valid UserRequest user,
            @ApiIgnore @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) {
        userService.createUser(user, auth, trackId);
        return new ResponseEntity<>(new SuccessfullResponse(MessageDTO.USER_CREATED_SUCCESSFULLY.toString(),
                MessageDTO.USER_CREATED_SUCCESSFULLY.toString()),
                HttpStatus.OK);
    }

    @PostMapping(value = "/api/v2.0/updateUser")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.UPDATE_USER_SUCESSFULLY, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Update an existing user", notes = "1.Updates an existing user\n 2.returns invalid if not present\n 3.Excepts empty values \n4.Needs to be a valid email \n5.Token scoped")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity updateUserV2(
            @RequestBody @Valid UpdateUserRequest updateUserRequest,
            @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) {
        userService.updateUser(updateUserRequest, auth, trackId);
        return new ResponseEntity<>(new SuccessfullResponse(MessageDTO.UPDATE_USER_SUCESSFULLY.toString(),
                MessageDTO.UPDATE_USER_SUCESSFULLY.toString()),
                HttpStatus.OK);
    }

    @PostMapping(value = "/api/v2.0/updatePassword")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.UPDATE_PASSWORD_SUCESSFULLY, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 404, message = SwaggerConstants.USER_NOT_FOUND),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Update password of a user", notes = " 1. Update password of user \n2.returns already exists if duplicate \n3.Password cannot be empty")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity updatePasswordV2(
            @RequestBody @Valid UpdatePasswordRequest updatePasswordRequest,
            @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) {
        userService.updatePassword(updatePasswordRequest, auth, trackId);
        return new ResponseEntity<>(new SuccessfullResponse(MessageDTO.UPDATE_PASSWORD_SUCESSFULLY.toString(),
                MessageDTO.UPDATE_PASSWORD_SUCESSFULLY.toString()),
                HttpStatus.OK);
    }

    @PostMapping(value = "/api/v2.0/changeUserActiveStatus")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.USER_ACTIVATED, response = String.class),
            @ApiResponse(code = 401, message = SwaggerConstants.UNAUTHORIZED),
            @ApiResponse(code = 404, message = SwaggerConstants.USER_NOT_FOUND),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    @ApiOperation(value = "Change the user active status", notes = "1.Changes user active status \n2.Returns the existing status for idempotent calls \n3.Token scoped. \n4.Requires valid email id")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity changeUserActiveStatusV2(
            @RequestBody @Valid ChangeUserActiveStatusRequest changeUserActiveStatusRequest,
            @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
            OAuth2Authentication auth) {
        String resObj = userService.changeUserStatus(changeUserActiveStatusRequest, auth, trackId);
        return new ResponseEntity<>(new SuccessfullResponse(resObj, resObj), HttpStatus.OK);
    }

    @PostMapping(value = "/api/v2.0/authenticateSSO")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.SUCCESSFULL, response = String.class),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    public ResponseEntity authenticateSSOV2(
            @RequestBody @Valid AuthenticateUser authenticateUser) {
        userService.authenticateSSO(authenticateUser);
        return new ResponseEntity<>(new SuccessfullResponse(authenticateUser.getEmail().toLowerCase(),
                authenticateUser.getEmail().toLowerCase()),
                HttpStatus.OK);
    }

    @PostMapping(value = "/api/v2.0/getAccessTokenByEmail")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = SwaggerConstants.SUCCESSFULL, response = String.class),
            @ApiResponse(code = 500, message = SwaggerConstants.UNABLE_TO_PERSIST)})
    public ResponseEntity gettokenV2(
            @RequestBody @Valid TokenRequest tokenRequest,
            @RequestParam(value = "expiry_extension", required = false) Optional<Integer> expiryExtension,
            @RequestParam(value = "client_id", required = false) String clientId,
            @ApiIgnore @SessionAttribute(Config.OPS_TRACE_ID) String trackId
    ) {
        OAuth2Authentication auth = tokenService.createAuthenticationObject(Optional.empty(), Tokens.AD_HOC_AUTH_SSO, clientId);
        String resObj = userService.getAccessTokenByEmail(tokenRequest,auth,Optional.of(clientId), expiryExtension,trackId);
        return new ResponseEntity<>(new SuccessfullResponse(resObj, resObj), HttpStatus.OK);
    }

    @GetMapping(value = "/api/v2.0/user")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    @ApiOperation(value = "Returns principal of an user", notes = " 1.Returns user object post client authentication \n2.Token scoped")
    public UserResponse userV2(OAuth2Authentication auth) {
        return userService.getUser(auth);
    }
}