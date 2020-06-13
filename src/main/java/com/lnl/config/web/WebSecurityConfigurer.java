package com.lnl.config.web;

import com.lnl.config.auth.CustomJdbcTokenStore;
import com.lnl.config.filters.EventAuthenticationFailureHandler;
import com.lnl.config.filters.SimpleAuthenticationFilter;
import com.lnl.config.user.ExtendedUser;
import com.lnl.config.user.UserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.web.client.RestTemplate;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@EnableJdbcHttpSession
@Slf4j
@Order(16)
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Value("${spring.schema}")
    private String jdbcSchema;

    @Bean
    @Primary
    @ConfigurationProperties(prefix = "spring.datasource")
    public DataSource oauthDataSource() {
        DataSourceBuilder dataSourceBuilder = DataSourceBuilder.create();
        DataSource datasource = dataSourceBuilder.build();
        if(datasource instanceof org.apache.tomcat.jdbc.pool.DataSource){
            ((org.apache.tomcat.jdbc.pool.DataSource) datasource).setInitSQL("SET search_path = "+jdbcSchema);
        }
        return datasource;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Value("${spring.csrf.disabled}")
    private Boolean csrf;

    @Value("${xframe-headers.disabled}")
    private Boolean xHeader;

    //core configuration  to for  httpsecurity.
    //We have authenticationFilter which gets executed before the  UsernamePasswordAuthenticationFilter
    //we use this to keep track on the no failed of attempts and redirect back to login page
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(authenticationFilter(),
                UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/login", "/logout.do", "/webjars/**").permitAll()
                .antMatchers("/**").authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout.do"))
                .and()
                .userDetailsService(userDetailsService())
                .exceptionHandling().authenticationEntryPoint(new AuthenticationProcessingFilterEntryPoint("/login"));

        if (xHeader) http.headers().frameOptions().disable();
        if (csrf) http.csrf().disable();
    }

    //this bean keeps track of the login attempts that being made
    //also we have failureHandler to redirect failure to login page
    @Bean
    public SimpleAuthenticationFilter authenticationFilter() throws Exception {
        SimpleAuthenticationFilter filter = new SimpleAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManagerBean());
        filter.setAuthenticationFailureHandler(failureHandler());
        return filter;
    }

    //authentication Provider
    @Bean
    public AuthenticationProvider authProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler failureHandler() {
        EventAuthenticationFailureHandler failureHandler =
                new EventAuthenticationFailureHandler();
        failureHandler.setDefaultFailureUrl("/login?error=true");
        return failureHandler;
    }


    //these are the filter exclusion list
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/external/**", "/v*.*/getAccessTokenByEmail", "/tokens", "/webjars/**", "/resources/**", "/getjwttoken/**", "/authenticateSSO/**","/genCode/**","/validateCode/**");
    }

    @Bean
    @Override
    @Primary
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    @Override
    @Primary
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    //the authenticationMangerBuilder we need to inject our authentication provider here
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authProvider());
    }

    @Bean
    public TokenStore tokenStore() {
        return new CustomJdbcTokenStore(oauthDataSource());
    }

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.build();
    }

    @Bean
    public ExtendedUser extendedUserDefault() {
        return new ExtendedUser("anonymous",
                "", true, true, true,
                true, Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")),
                "anonymous",
                UUID.fromString("582a4263-3dfd-4bea-897c-88f7612bc165"),
                "anonymous",
                "");
    }
}