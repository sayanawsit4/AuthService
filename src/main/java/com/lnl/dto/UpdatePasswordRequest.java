package com.lnl.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
@ApiModel(description = "The incoming payload to update password")
public class UpdatePasswordRequest {

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @ApiModelProperty(notes = "Email id of the user whose property needs to be updated")
    @Pattern(regexp = "^[a-zA-Z0-9\\.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            message="Invalid email format")
    private String email;

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @ApiModelProperty(notes = "The new password of the user.Cannot be empty")
    //@Size(min = 1, max = 60)
    @NotEmpty(message = "Invalid username or password.")
    private  String newPassword;
}
