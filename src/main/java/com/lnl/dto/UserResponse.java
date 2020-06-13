package com.lnl.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.util.UUID;

@Data
@ApiModel(description = "This is the user profile endpoints.Which OAuth2 clients will hit post authentication")
@java.lang.SuppressWarnings("squid:S00116")
public class UserResponse {

    private UUID id;

    @ApiModelProperty(notes = "Returns the username of the user")
    private String username;

    @ApiModelProperty(notes = "Returns the Email id of the user")
    private String email;

    @ApiModelProperty(notes = "Returns the firstname of the user.Naming convention needs to be followed for silhouetee client(lnlapp)")
    private String first_name;

    @ApiModelProperty(notes = "Returns the Email id of the user.Naming convention needs to be followed for silhouetee client(lnlapp)")
    private String last_name;

}