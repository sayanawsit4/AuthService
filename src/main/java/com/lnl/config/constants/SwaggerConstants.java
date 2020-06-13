package com.lnl.config.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

//Annotation Attributes must be constants,so we need to use plain text only here for swagger,enum cannot be used
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SwaggerConstants {

    public static final String UNAUTHORIZED = "You are not authorized to perform this action";
    public static final String UNABLE_TO_PERSIST = "Unable to save data";
    public static final String USER_NOT_FOUND = "Invalid username or password.";
    public static final String CLIENT_ID_NOT_FOUND = "No application registered for this key.";
    public static final String BAD_REQUEST_MISSING_CLIENT_ID = "Missing Clinet Id";
    public static final String INVALID_EMAIL_FORMAT = "Invalid email format";
    public static final String SUCCESSFULL = "Successfull";
    public static final String SUCCESSFULL_HEADER = "Successfull with header";
    public static final String INVALID_CREDENTIAL = "Invalid Credential";
    public static final String MISSING_HEADERS = "upstream connect error or disconnect/reset before headers";

    public static final String USER_CREATED_SUCCESSFULLY = "User successfully created";
    public static final String USER_EXISTS = "User already exists. The existing user can be activated or deactivated by customer service.";

    //UpdateUser
    public static final String UPDATE_USER_SUCESSFULLY = "User successfully updated.";

    //UpdatePassword
    public static final String UPDATE_PASSWORD_SUCESSFULLY = "Password changed successfully";
    public static final String USER_ALREADY_SET_TRUE = "User active status already set to true";
    public static final String USER_ALREADY_SET_TO = "User active status already set to";

    //changeUserActiveStatus
    public static final String USER_ACTIVATED = "User successfully activated";
    public static final String USER_DEACTIVATED = "User successfully deactivated";

    //UpdateEmail
    public static final String USER_EMAIL_ALREADY_EXISTS = "Email id already exists.";
    public static final String EMAIL_UPDATED_SUCCESSFULLY = "Email changed successfully";

    //delete
    public static final String USER_DELETED_SUCCESSFULLY = "User deleted successfully";

    public static final String INVALID_TOKEN = "Invalid Token";

}