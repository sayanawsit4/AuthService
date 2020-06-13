package com.lnl.config.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

//Annotation Attributes must be constants,so we need to use plain text only here for roles,enum cannot be used
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Roles {

    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_USER = "ROLE_USER";
}
