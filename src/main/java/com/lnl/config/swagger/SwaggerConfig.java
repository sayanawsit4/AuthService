package com.lnl.config.swagger;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger.web.ApiKeyVehicle;
import springfox.documentation.swagger.web.SecurityConfiguration;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hibernate.validator.internal.util.CollectionHelper.newArrayList;
import static springfox.documentation.builders.PathSelectors.regex;

@Configuration
@EnableSwagger2
public class SwaggerConfig {

    private static final String lnl_SITE_URL = "https://www.lnl.com/";
    private static final String DEV = "Developers";
    private static final String AUTHV1_TITLE = "AuthService V1 APIs";
    private static final String AUTHV1_MESSAGE = "Supports the legacy client.";
    private static final String AUTHV1_GROUP_NAME = "AuthService-1.0";
    private static final String AUTHV2_GROUP_NAME = "AuthService-2.0";
    private static final String AUTHV2_TITLE = "AuthService V2 APIs";
    private static final String AUTHV2_MESSAGE = "Newer client should use this.More verbose message";
    private static final String CONTACT_EMAIL = "email";
    private static final String AUTHV1_VERSION = "1.0.0";
    private static final String AUTHV2_VERSION = "2.0.0";

    @Bean
    public Docket productApiV1() {
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName(AUTHV1_GROUP_NAME)
                .select()
                .apis(RequestHandlerSelectors.any())
                .paths(regex("/api/((?!v2).)*$"))
                .build()
                .securityContexts(Collections.singletonList(securityContext()))
                .securitySchemes(Arrays.asList(securitySchema(), apiKey(), apiCookieKey()))
                .apiInfo(apiInfo());
    }

    @Bean
    public Docket productApiV2() {
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName(AUTHV2_GROUP_NAME)
                .select()
                .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.ant("/api/v2.*/**"))
                .build()
                .securityContexts(Collections.singletonList(securityContext()))
                .securitySchemes(Arrays.asList(securitySchema(), apiKey(), apiCookieKey()))
                .apiInfo(apiInfov2());
    }

    @Bean
    public SecurityScheme apiKey() {
        return new ApiKey(HttpHeaders.AUTHORIZATION, "apiKey", "header");
    }

    @Bean
    public SecurityScheme apiCookieKey() {
        return new ApiKey(HttpHeaders.COOKIE, "apiKey", "cookie");
    }

    private OAuth securitySchema() {

        List<AuthorizationScope> authorizationScopeList = newArrayList();
        authorizationScopeList.add(new AuthorizationScope("read", "read all"));
        authorizationScopeList.add(new AuthorizationScope("write", "access all"));

        List<GrantType> grantTypes = newArrayList();
        GrantType passwordCredentialsGrant = new ResourceOwnerPasswordCredentialsGrant("http://localhost:7070/oauth/token");
        grantTypes.add(passwordCredentialsGrant);

        return new OAuth("oauth2", authorizationScopeList, grantTypes);
    }

    private SecurityContext securityContext() {
        return SecurityContext.builder().securityReferences(defaultAuth())
                .build();
    }


    private List<SecurityReference> defaultAuth() {

        final AuthorizationScope[] authorizationScopes = new AuthorizationScope[3];
        authorizationScopes[0] = new AuthorizationScope("read", "read all");
        authorizationScopes[1] = new AuthorizationScope("trust", "trust all");
        authorizationScopes[2] = new AuthorizationScope("write", "write all");

        return Collections.singletonList(new SecurityReference("oauth2", authorizationScopes));
    }

    @Bean
    public SecurityConfiguration security() {
        return new SecurityConfiguration
                ("client", "secret", "", "", "Bearer access token", ApiKeyVehicle.HEADER, HttpHeaders.AUTHORIZATION, "");
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title(AUTHV1_TITLE)
                .description(AUTHV1_MESSAGE)
                .termsOfServiceUrl(lnl_SITE_URL)
                .contact(new Contact(DEV, lnl_SITE_URL, CONTACT_EMAIL))
                .version(AUTHV1_VERSION)
                .build();
    }

    private ApiInfo apiInfov2() {
        return new ApiInfoBuilder()
                .title(AUTHV2_TITLE)
                .description(AUTHV2_MESSAGE)
                .termsOfServiceUrl(lnl_SITE_URL)
                .contact(new Contact(DEV, lnl_SITE_URL, CONTACT_EMAIL))
                .version(AUTHV2_VERSION)
                .build();
    }

}