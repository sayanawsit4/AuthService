package com.lnl.exception;

import com.lnl.config.constants.MessageDTO;

public class UnableToPersistException extends RuntimeException {
    public UnableToPersistException(MessageDTO msg) {
        super(msg.toString());
    }
}
