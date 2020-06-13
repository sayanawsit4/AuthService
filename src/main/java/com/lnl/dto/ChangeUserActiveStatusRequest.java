package com.lnl.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.validation.constraints.NotNull;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
@ApiModel(description = "The incoming payload to change user active status")
public class ChangeUserActiveStatusRequest {

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @ApiModelProperty(notes = "Email id of the user whose property needs to be updated")
    private String email;

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @ApiModelProperty(notes = "boolean to activated/deactivate an user")
    private Boolean active;

}
