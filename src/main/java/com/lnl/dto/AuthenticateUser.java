package com.lnl.dto;

import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class AuthenticateUser {

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @Pattern(regexp = "^[a-zA-Z0-9\\.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            message="Invalid email format")
    private String email;

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private String password;

    @Builder.Default
    private String clientId = "";
}
