package com.lnl.config.auth;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

public class CustomTokenEnhancer  extends  JwtAccessTokenConverter  {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,OAuth2Authentication authentication) {
        //Enable this fields carefully.Make sure the lnlprovider is expecting this fields or marked as optional.
        //otherwise we might get parse exception at client side and client needs to be modified as required.
        ((DefaultOAuth2AccessToken) accessToken).setScope(null);
        ((DefaultOAuth2AccessToken) accessToken).setExpiration(null);
        ((DefaultOAuth2AccessToken) accessToken).setRefreshToken(null);
        return accessToken;
    }

}