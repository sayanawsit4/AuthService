package com.lnl.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.validator.constraints.NotBlank;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
@ApiModel(description = "The incoming payload to update an user")
public class UpdateUserEmail {

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @ApiModelProperty(notes = "Email id of the user whose property needs to be updated")
    @Pattern(regexp = "^[a-zA-Z0-9\\.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            message = "Invalid email format")
    @NotEmpty(message = "Invalid email format")
    @NotBlank(message = "Invalid email format")
    private String email;

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @NotEmpty(message = "Invalid email format")
    @NotBlank(message = "Invalid email format")
    @Pattern(regexp = "^[a-zA-Z0-9\\.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            message = "Invalid email format")
    @ApiModelProperty(notes = "New Email Id")
    //@Size(min = 0, max = 60)
    private String newEmail;

}