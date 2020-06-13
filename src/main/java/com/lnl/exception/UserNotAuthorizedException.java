package com.lnl.exception;

import com.lnl.config.constants.MessageDTO;

public class UserNotAuthorizedException extends RuntimeException {
    public UserNotAuthorizedException(MessageDTO msg) {
        super(msg.toString());
    }
}
