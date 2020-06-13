package com.lnl.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class UnsuccessfullResponse {

    String error;
    String errorDescription;
    List<String> listoferrorDescription;

    public UnsuccessfullResponse(String error, String errorDescription)
    {
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public UnsuccessfullResponse(String error, List<String> listoferrorDescription)
    {
        this.error = error;
        this.listoferrorDescription = listoferrorDescription;
    }


}
