package com.lnl.exception;

import com.lnl.config.constants.MessageDTO;

public class EmailAlreadyExistsException extends RuntimeException {
    public EmailAlreadyExistsException(MessageDTO msg) {
        super(msg.toString());
    }
}
