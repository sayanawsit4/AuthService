package com.lnl.config.constants;

public enum Tokens {

    ONE_TIME("one-time"),
    AD_HOC("ad-hoc"),
    AD_HOC_EXTN("ad-hoc-extn"),
    AD_HOC_AUTH_SSO("ad-hoc-auth-sso"),
    READ("read"),
    WRITE("write");

    private final String value;

    Tokens(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }

}
