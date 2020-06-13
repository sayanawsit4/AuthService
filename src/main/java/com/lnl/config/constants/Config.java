package com.lnl.config.constants;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

@Component
@PropertySource(value = {"classpath:application.yml"})
//@NoArgsConstructor(access = AccessLevel.PUBLIC)
public class Config {
    public static final String OPS_TRACE_ID = "OPS-TRACE-ID";
    public static final String ACS_TRACE_ID = "ACS-TRACE-ID";

    //Spring doesnt allow setting values to static variables
    //as a workaround add a setter method and set the static values
    public static String registerKit;
    public static String reset;
     public static String backToHomeUrl;

    @Value("${spring.registerKitUrl}")
    public void setRegisterKit(String val) {
        registerKit = val;
    }

    @Value("${spring.appsUrl}")
    public void setReset(String val) {reset = val;}

    @Value("${spring.backToHomeUrl}")
    public void setBackToHomeUrl(String val) {backToHomeUrl = val;}

}