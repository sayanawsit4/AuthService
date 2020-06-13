package com.lnl.service;

import com.sendgrid.Content;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.constants.Tokens;
import com.lnl.config.user.ExtendedUser;
import com.lnl.domain.OperationalAudit;
import com.lnl.repository.OpsAuditRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class TokenService {

    @Value("${jwt.certificate.store.file}")
    private org.springframework.core.io.Resource keystore;

    @Value("${jwt.certificate.store.password}")
    private String keystorePassword;

    @Value("${jwt.certificate.key.alias}")
    private String keyAlias;

    @Value("${jwt.certificate.key.password}")
    private String keyPassword;

    @Resource(name = "tokenServices")
    ConsumerTokenServices contokenServices;

    @Resource(name = "tokenStore")
    TokenStore tokenStore;

    @Autowired
    OpsAuditRepository opsAuditRepository;

    @Autowired
    JdbcClientDetailsService clientDetailsService;

    @Autowired
    SendGridEmailService sendGridEmailService;

    @Autowired
    private JdbcClientDetailsService clientsDetailsService;

    @Autowired
    private AuthorizationServerEndpointsConfiguration configuration;

    @Autowired
    private ExtendedUser extendedUserDefault;

    @Autowired
    private CacheManager cacheManager;

    public void revokeToken(OAuth2AccessToken accessToken, OAuth2AuthenticationDetails details) {

        if (accessToken.getScope().contains(Tokens.ONE_TIME.toString()) && accessToken.getScope().size() == 1)
            contokenServices.revokeToken(details.getTokenValue());
    }

    public void revokeAllToken(String email) {
        clientDetailsService.listClientDetails().forEach(s ->
                tokenStore.findTokensByClientIdAndUserName(s.getClientId(), email).forEach(tokenStore::removeAccessToken));
    }

    public Boolean checkClientId(String clientId) {
        Boolean checkClint;
        try {
            checkClint = Optional.ofNullable(clientsDetailsService.loadClientByClientId(clientId)).isPresent();
        } catch (Exception e) {
            checkClint = false;
        }
        return checkClint;
    }

    public void updateOperationalAudit(String trackId,
                                       String response,
                                       ExtendedUser extendedUser,
                                       String scope,
                                       String clientId) {
        OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
        u.setOpsPerformedBy(extendedUser.getEmail().toLowerCase());
        u.setScope(scope);
        u.setClientId(clientId);
        u.setResponse(response);
    }

    public OAuth2AccessToken createToken(Integer extendedValidity,
                                         ExtendedUser extUser,
                                         Tokens scope,
                                         String clientId) {

        OAuth2Authentication auth = createAuthenticationObject(extUser, scope, clientId);
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(configuration.getEndpointsConfigurer().getTokenStore());
        tokenServices.setSupportRefreshToken(false);
        tokenServices.setClientDetailsService(configuration.getEndpointsConfigurer().getClientDetailsService());
        tokenServices.setTokenEnhancer(configuration.getEndpointsConfigurer().getTokenEnhancer());
        tokenServices.setAccessTokenValiditySeconds(extendedValidity);
        tokenServices.createAccessToken(auth);
        return tokenServices.createAccessToken(auth);
    }

    public OAuth2Authentication createAuthenticationObject(Optional<String> extUser,
                                                           Tokens scope,
                                                           String clientId) {
        ExtendedUser ext = createDefaultExtendedObject(extUser);
        return createAuthenticationObject(ext, scope, clientId);
    }


    public OAuth2Authentication createAuthenticationObject(ExtendedUser ext,
                                                           Tokens scope,
                                                           String clientId) {
        Map<String, String> requestParameters = new HashMap<>();
        boolean approved = true;
        Set<String> responseTypes = new HashSet<>();
        responseTypes.add("code");
        OAuth2Request oauth2Request = new OAuth2Request(requestParameters, clientId, ext.getAuthorities(), approved, new HashSet<String>(Arrays.asList(scope.toString())), null, null, responseTypes, null);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(ext, "N/A", ext.getAuthorities());
        return new OAuth2Authentication(oauth2Request, authenticationToken);
    }

    // @CacheEvict(cacheNames="codes", key="#email",condition = "#email != null")
    public String genCode(String email) {
        Random r = new Random(System.currentTimeMillis());
        String code = Integer.toString((1 + r.nextInt(2)) * 10000 + r.nextInt(10000));
        Cache cache = cacheManager.getCache("codes");
        cache.put(email, code);
        return cache.get(email).get().toString();
    }


    public String validateCode(String code, String email, Boolean genCode) throws IOException {
        Cache cache = cacheManager.getCache("codes");
        Random r = new Random(System.currentTimeMillis());
        String newCode = Integer.toString((1 + r.nextInt(2)) * 10000 + r.nextInt(10000));
        String cacheCode = cache.get(email).get().toString();
        System.out.println("email" + email);
        System.out.println("code" + cache.get(email).get());
        System.out.println("code passed" + code);
        if (cache.get(email) != null && cacheCode.equals(code)) {
            cache.put(email, newCode);
            if(genCode) {
                Content content = new Content("text/plain", newCode);
                sendGridEmailService.sendEmail("donotreply@lnl.com", email, "Pass Code", content);
            }
            return newCode;
        } else {
            return "Wrong code";
        }
    }

    public void tokenServiceBuilder(OAuth2Authentication auth, Optional<String> email, Optional<String> responseObj, Optional<String> trackId) {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        OAuth2AccessToken accessToken = null;
        String scope = "NA";

        if (details != null) {
            accessToken = tokenStore.readAccessToken(details.getTokenValue());
            System.out.println("get scopes" + accessToken.getScope() + accessToken.getValue());
            if (accessToken.getScope() != null)
                scope = accessToken.getScope().stream().map(Object::toString).collect(Collectors.joining(","));
        } else
            scope = Tokens.AD_HOC_AUTH_SSO.toString(); //this would from hmac calls because those doest pass through Spring authentication

        //Revoke token if one-time
        try {
            revokeToken(accessToken, details);
        } catch (Exception e) {
            //should revoke silently
        }
        if (responseObj.map(s -> s.contains(MessageDTO.USER_DEACTIVATED.toString()) || s.contains(MessageDTO.EMAIL_UPDATED_SUCCESSFULLY.toString())).orElse(false) && email.isPresent()) {
            revokeAllToken(email.get());
        }

        if (responseObj.isPresent() && trackId.isPresent()) {

            if (responseObj.get().matches(".*\\d.*"))
                responseObj = responseObj.map(s -> s.substring(0, 4) + "****-****-****-****");
            updateOperationalAudit(trackId.get(), responseObj.get(), (ExtendedUser) auth.getPrincipal(), scope, auth.getOAuth2Request().getClientId());
        }
    }

    public ExtendedUser createDefaultExtendedObject(Optional<String> email) {
        String userName = email.orElse("anonymous");
        return new ExtendedUser(userName,
                "", true, true, true,
                true, Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")),
                userName,
                UUID.fromString("582a4263-3dfd-4bea-897c-88f7612bc165"),
                userName,
                userName);
    }

}