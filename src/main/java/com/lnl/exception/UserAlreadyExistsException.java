package com.lnl.exception;

import com.lnl.config.constants.MessageDTO;

public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(MessageDTO msg) {
        super(msg.toString());
    }
}
