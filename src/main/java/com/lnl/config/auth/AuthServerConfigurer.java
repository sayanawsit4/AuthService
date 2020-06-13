package com.lnl.config.auth;

import com.lnl.config.user.UserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.security.KeyPair;


@Configuration
@EnableAuthorizationServer
@Order(6)
@Slf4j
public class AuthServerConfigurer extends AuthorizationServerConfigurerAdapter {

    @Value("${jwt.certificate.store.file}")
    private Resource keystore;

    @Value("${jwt.certificate.store.password}")
    private String keystorePassword;

    @Value("${jwt.certificate.key.alias}")
    private String keyAlias;

    @Value("${jwt.certificate.key.password}")
    private String keyPassword;

    @Value("${token.validity}")
    private Integer validity;

    @Value("${token.jwt}")
    private Boolean jwt;

    @Value("${spring.schema}")
    private String jdbcSchema;

    //AuthenticationManager is instantiate in WebSecurityConfiguration and is autowired here
    //Be sure to use the Qualifier so that it picks up the correct authentication manager bean.
    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    //instantiate in webSecurityConfig and autowired here.
    @Autowired
    private PasswordEncoder passwordEncoder;

    //this instatinted a custom user details service
    //user detail service forms the OAuth2Authentication object and holds user detail infromation
    //generally user detail service is loaded using loadbyuser name method
    //in our scenario we have overridden to use get by email id (have a look at the userDetailServiceImpl)
    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    //the datasource,in our case this is postgres
    @Bean
    @ConfigurationProperties(prefix = "spring.datasource")
    public DataSource oauthDataSource() {
        DataSourceBuilder dataSourceBuilder = DataSourceBuilder.create();
        DataSource datasource = dataSourceBuilder.build();
        if(datasource instanceof org.apache.tomcat.jdbc.pool.DataSource){
            ((org.apache.tomcat.jdbc.pool.DataSource) datasource).setInitSQL("SET search_path = "+jdbcSchema);
        }
        return datasource;
    }

    //Instantiates the client details service object
    //note that we are storing the client details in a database so we need this
    //other option could have been using in memory and config properties
    @Bean
    @Primary
    public JdbcClientDetailsService clientDetailsService() {
        return new JdbcClientDetailsService(oauthDataSource());
    }

    //The tokens are backed up in db.This intiatlized a customjbcstoken store
    //Note the reason we use custom jdbctoken store is because token_expiry is not a first class attriburte in jdbcstore.
    //check com.lnl.config.auth.CustomJdbcTokenStore
    @Bean
    public TokenStore tokenStore() {
        return new CustomJdbcTokenStore(oauthDataSource());
    }


    @Bean
    public ApprovalStore approvalStore() {
        return new JdbcApprovalStore(oauthDataSource());
    }

    //this stores the OAuthCodes
    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new JdbcAuthorizationCodeServices(oauthDataSource());
    }

    //Note:Clients can be registered in no. of ways.This is just one implementation.
    //we attach clientDetailsService here which is has been initialized earlier
    @Override
    @Primary
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService());
    }


    //this configure is the core of this class.Does the final binding for all the required endpoints of OAuth2.
    //Note the jwt boolean,we can switch to A JWT based token from configs.
    //authenticationManager bean also used to create a filter that checks for UsernamePasswordAuthentication and inject into HttpSecurity configuration
    //look in to com.lnl.config.web.WebSecurityConfigurer
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .approvalStore(approvalStore())
                .authorizationCodeServices(authorizationCodeServices())
                .tokenStore(tokenStore())
                //.tokenEnhancer(tokenEnhancer())
                .authenticationManager(authenticationManager) //this is required for password grant flow to work
                .tokenServices(tokenServices())
                .userDetailsService(userDetailsService());
        if (jwt) endpoints.accessTokenConverter(accessTokenConverter()); //this gives a JWT token

    }

    //allowFormAuthenticationForClients is requried to allow form based authorize requests.Currently lnl uses this flow
    //Also note we need to attach an passwordEncoder bean to it so that it can validate against the encrypted client credential secrets
    //checkTokenAccess is given isAuthenticated() which means only authenticated access is allowed to checktoken
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients()
                .passwordEncoder(passwordEncoder);
    }

    //This bean initialize the JWT token.It requires a keystore and p-p key pair
    //CustomTokenConverter does 2 important modifications here
    //It adds additonal information to the JWT token as required (for example: phone,email,location of user)
    //It also can modfiy the token return response and customize based on needs.For example we are currently interested in access_token only so
    // we are hiding scope,refresh_token information in the response token.Have look at com.lnl.config.auth.CustomTokenConverter
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                keystore, keystorePassword.toCharArray());
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(
                keyAlias, keyPassword.toCharArray());
        CustomTokenConverter tokenConverter = new CustomTokenConverter();
        tokenConverter.setKeyPair(keyPair);
        return tokenConverter;
    }

    // we are hiding scope,refresh_token information in the response token.Have look at com.lnl.config.auth.CustomTokenEnhancer for standard token
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new CustomTokenEnhancer();
    }

    //token service deals with the token store.
    //we modify the tokens before they been stored in the database with the additional customization we want on the tokens
    //we configure the token validity and refresh token
    //Note: Validity have the highest precedence in database(it will override any attempt to update it via DefaultTokenServices
    //So in order for application to derive token validity(based on request) set refresh_token_validity=0 in db
    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(false); //refresh token is not used as of now in lnl Oauth2 flow
        defaultTokenServices.setAccessTokenValiditySeconds(validity); //default validity is loaded from config
        if (jwt)
            defaultTokenServices.setTokenEnhancer(accessTokenConverter()); //set token enhancer to inject CustomTokenConverter for JWT
        else
            defaultTokenServices.setTokenEnhancer(tokenEnhancer()); //set token response using CustomTokenEnhancer

        return defaultTokenServices;
    }
}
