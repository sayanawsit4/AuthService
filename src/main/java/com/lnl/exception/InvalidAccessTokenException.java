package com.lnl.exception;

import com.lnl.config.constants.MessageDTO;

public class InvalidAccessTokenException extends RuntimeException {
    public InvalidAccessTokenException(MessageDTO msg) {
        super(msg.toString());
    }
}
