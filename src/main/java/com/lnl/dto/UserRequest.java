package com.lnl.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.validation.constraints.Pattern;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
@ApiModel(description = "The incoming payload to create an user")
public class UserRequest {


    @ApiModelProperty(notes = "Email Id of the user.Need to be a valid email id")
    @Pattern(regexp = "^[a-zA-Z0-9\\.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            message = "Invalid email format")
    private String email;

    //Checks suppressed to support Auth1
    //@NotNull(message = "Malformed request, could not parse or validate JSON object.")
    //@ApiModelProperty(notes = "FirstName of the user,max 60 characters allowed.")
    //@Size(min = 1, max = 60)
    private String firstName;

    //Checks suppressed to support Auth1
    //@NotNull(message = "Malformed request, could not parse or validate JSON object.")
    //@ApiModelProperty(notes = "LastName of the user,max 60 characters allowed.")
    //@Size(min = 1, max = 60)
    private String lastName;

    @ApiModelProperty(notes = "The initial password of the user")
    private String password;

    //this properties to support legacy clients.This values doesnt get persisted at all.Should be deprecated.

    //Checks suppressed to support Auth1
    //@NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @ApiModelProperty(notes = "The phone no of the user.Note that this is not persisted till v2 of endpoints.Client can neglted this properties all together")
    private Long phone;

    @ApiModelProperty(notes = "The phone no of the user.Note that this is not persisted till v2 of endpoints.Client can neglted this properties all together")
    //Checks suppressed to support Auth1
    // @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private String providerId;
}