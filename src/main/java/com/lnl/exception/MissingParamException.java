package com.lnl.exception;

import com.lnl.config.constants.MessageDTO;

public class MissingParamException extends RuntimeException {
    public MissingParamException(MessageDTO msg) {
        super(msg.toString());
    }
}