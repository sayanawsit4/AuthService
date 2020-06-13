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
public class UpdateUserRequest {

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @ApiModelProperty(notes = "Email id of the user whose property needs to be updated")
    @Pattern(regexp = "^[a-zA-Z0-9\\.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            message = "Invalid email format123")
    private String email;

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @NotEmpty(message = "Invalid first or last name.")
    @NotBlank(message = "Invalid first or last name.")
    @ApiModelProperty(notes = "First Name of the user.Can be empty.Max 60 charcters")
    //@Size(min = 0, max = 60)
    private String firstName;

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @ApiModelProperty(notes = "Last Name of the user.Can be empty.Max 60 charcters")
    //@Size(min = 0, max = 60)
    @NotEmpty(message = "Invalid first or last name.")
    @NotBlank(message = "Invalid first or last name.")
    private String lastName;

}