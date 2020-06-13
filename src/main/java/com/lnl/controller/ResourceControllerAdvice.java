package com.lnl.controller;

import com.lnl.config.constants.MessageDTO;
import com.lnl.dto.UnsuccessfullResponse;
import com.lnl.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

import static com.lnl.config.utils.StringUtils.apiVersionCheck;

//the global exceptional handler for all exceptions thrown at service,controller or filter layers
@ControllerAdvice
@Slf4j
public class ResourceControllerAdvice {

    @Autowired
    private HttpServletRequest request;

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler({UserAlreadyExistsException.class})
    public ResponseEntity handle(UserAlreadyExistsException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(MessageDTO.USER_EXISTS.toString(), HttpStatus.BAD_REQUEST);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), MessageDTO.USER_EXISTS.toString()), HttpStatus.BAD_REQUEST);
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler({EmailAlreadyExistsException.class})
    public ResponseEntity handle(EmailAlreadyExistsException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(MessageDTO.USER_EMAIL_ALREADY_EXISTS.toString(), HttpStatus.BAD_REQUEST);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), MessageDTO.USER_EMAIL_ALREADY_EXISTS.toString()), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({UnableToPersistException.class})
    public ResponseEntity handleDBError(UnableToPersistException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(MessageDTO.UNABLE_TO_PERSIST.toString(), HttpStatus.OK);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), MessageDTO.UNABLE_TO_PERSIST.toString()), HttpStatus.OK);
    }

    @ExceptionHandler({UserNotAuthorizedException.class})
    public ResponseEntity handleNotAuthorized(UserNotAuthorizedException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(MessageDTO.UNAUTHORIZED, HttpStatus.OK);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), MessageDTO.UNAUTHORIZED.toString()), HttpStatus.OK);
    }

    @ExceptionHandler({ClientNotFoundException.class})
    public ResponseEntity handleNotAuthorized(ClientNotFoundException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(MessageDTO.CLIENT_ID_NOT_FOUND.toString(), HttpStatus.NOT_FOUND);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), MessageDTO.CLIENT_ID_NOT_FOUND.toString()), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler({MissingParamException.class})
    public ResponseEntity handleNotAuthorized(MissingParamException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), MessageDTO.BAD_REQUEST_MISSING_CLIENT_ID.toString()), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({InvalidAccessTokenException.class})
    public ResponseEntity handleInvalidAccessToken(InvalidAccessTokenException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(MessageDTO.INVALID_TOKEN.toString(), HttpStatus.OK);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), MessageDTO.INVALID_TOKEN.toString()), HttpStatus.OK);
    }

    @ExceptionHandler({UserNotFoundException.class})
    public ResponseEntity userNotFound(UserNotFoundException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), e.getMessage()), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler({UserNotActivatedException.class})
    public ResponseEntity userNotActivated(UserNotActivatedException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), e.getMessage()), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler({InvalidCredentialException.class})
    public ResponseEntity invalidCredential(InvalidCredentialException e) {
        if (apiVersionCheck(request.getRequestURL().toString()))
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        else
            return new ResponseEntity<>(new UnsuccessfullResponse(e.getMessage(), e.getMessage()), HttpStatus.NOT_FOUND);
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity handleValidationExceptions(MethodArgumentNotValidException ex) {
        Optional<ObjectError> objectError = ex.getBindingResult().getAllErrors().stream().findFirst();
        return new ResponseEntity<>(objectError.map(ObjectError::getDefaultMessage)
                .orElse(MessageDTO.GENERIC_BAD_REQUEST.toString()), HttpStatus.BAD_REQUEST);
    }
}