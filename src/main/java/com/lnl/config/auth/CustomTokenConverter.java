package com.lnl.config.auth;

import com.lnl.config.user.ExtendedUser;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.HashMap;
import java.util.Map;

public class CustomTokenConverter extends JwtAccessTokenConverter {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,OAuth2Authentication authentication) {
        ExtendedUser extendedUser = (ExtendedUser)authentication.getPrincipal();
        final Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("email123", extendedUser.getEmail().toLowerCase());
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
        accessToken = super.enhance(accessToken, authentication);
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(new HashMap<>());
        authentication = super.extractAuthentication(additionalInfo);
        authentication.setDetails(additionalInfo);
        ((DefaultOAuth2AccessToken) accessToken).setScope(null);
        ((DefaultOAuth2AccessToken) accessToken).setExpiration(null);
        ((DefaultOAuth2AccessToken) accessToken).setRefreshToken(null);
        return accessToken;
    }

}