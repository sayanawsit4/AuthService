package com.lnl.exception;

import com.lnl.config.constants.MessageDTO;

public class InvalidCredentialException extends RuntimeException {
    public InvalidCredentialException(MessageDTO msg) {
        super(msg.toString());
    }
}
