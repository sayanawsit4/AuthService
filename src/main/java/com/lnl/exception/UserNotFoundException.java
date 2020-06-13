package com.lnl.exception;

import com.lnl.config.constants.MessageDTO;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(MessageDTO msg) {
        super(msg.toString());
    }
}
