package com.lnl.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

@Data
@AllArgsConstructor
@ToString
public class SuccessfullResponse {

    String message;
    String description;

}
