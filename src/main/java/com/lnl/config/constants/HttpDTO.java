package com.lnl.config.constants;

public enum HttpDTO {

    //Header
    AUTH_DIGEST("X-AuthDigest"),
    AUTH_TIME("X-AuthTime"),
    INITIATED_BY("InitiatedBy"),
    PASS_CODE("passCode"),

    //Request URLS
    TOKEN_BY_EMAIL_URL("getAccessTokenByEmail"),
    CREATE_USER("createUser"),
    EXTERNAL("external"),

    //http 3XX response
    account_locked("account locked!"),
    account_locked_2("Your account locked for 2 mins"),
    account_locked_4("Your account locked for 4 mins"),
    account_locked_8("Your account locked for 8 mins"),
    account_locked_16("Your account locked for 16 mins"),
    account_locked_30("Your account locked for 30 mins"),

    invalid_user_name_pwd("Invalid Username & Password"),

    //http 3XX response
    empty_user_name("Please enter your email."),
    empty_pwd_name("Please enter your password.");

    private final String statusValue;

    HttpDTO(String statusValue) {
        this.statusValue = statusValue;
    }

    private static final HttpDTO[] copyOfValues = values();

    public static HttpDTO forName(String name) {
        for (HttpDTO value : copyOfValues) {
            if (value.name().equals(name)) {
                return value;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return statusValue;
    }

}