package com.lnl.config.constants;

public enum MessageDTO {

    //Global
    GENERIC_BAD_REQUEST("Invalid Request"),
    UNAUTHORIZED("You are not authorized to perform this action"),
    UNABLE_TO_PERSIST("Unable to save data"),
    USER_NOT_FOUND("Invalid username or password."),
    CLIENT_ID_NOT_FOUND("No application registered for this key."),
    BAD_REQUEST_MISSING_CLIENT_ID("Missing Clinet Id"),
    INVALID_EMAIL_FORMAT("Invalid email format"),
    SUCCESSFULL("Successfull"),
    SUCCESSFULL_HEADER("Successfull with header"),
    INVALID_CREDENTIAL("Invalid Credential"),
    MISSING_HEADERS("upstream connect error or disconnect/reset before headers"),

    //CreateUser
    USER_CREATED_SUCCESSFULLY("User successfully created"),
    USER_EXISTS("User already exists. The existing user can be activated or deactivated by customer service."),

    //UpdateUser
    UPDATE_USER_SUCESSFULLY("User successfully updated."),

    //UpdatePassword
    UPDATE_PASSWORD_SUCESSFULLY("Password changed successfully"),
    USER_ALREADY_SET_TRUE("User active status already set to true"),
    USER_ALREADY_SET_TO("User active status already set to"),
    INVALID_PASSCODE("Invalid passcode"),

    //changeUserActiveStatus
    USER_ACTIVATED("User successfully activated."),
    USER_DEACTIVATED("User successfully deactivated."),

    //updateEmail
    USER_EMAIL_ALREADY_EXISTS("Email id already exists."),
    EMAIL_UPDATED_SUCCESSFULLY("Email changed successfully"),

    //AuthenticateSSO

    //Token
    INVALID_TOKEN("Invalid Token"),

    //Delete
    USER_DELETED_SUCCESSFULLY("User deleted successfully");

    private final String statusValue;

    MessageDTO(String statusValue) {
        this.statusValue = statusValue;
    }

    @Override
    public String toString() {
        return statusValue;
    }

}