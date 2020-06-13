package com.lnl.exception;

import com.lnl.config.constants.MessageDTO;

public class ClientNotFoundException extends RuntimeException {
    public ClientNotFoundException(MessageDTO msg) {
        super(msg.toString());
    }
}
