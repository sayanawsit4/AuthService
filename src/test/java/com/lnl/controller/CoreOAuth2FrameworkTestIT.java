package com.lnl.controller;

import com.lnl.AuthServer;
import com.lnl.config.constants.HttpDTO;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.constants.Tokens;
import com.lnl.config.utils.JsonUtil;
import com.lnl.config.utils.StringUtils;
import com.lnl.dto.ChangeUserActiveStatusRequest;
import com.lnl.dto.TokenRequest;
import com.lnl.dto.UserRequest;
import com.lnl.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONArray;
import org.apache.commons.codec.binary.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;

import java.lang.reflect.Array;
import java.time.Instant;
import java.util.*;

import static com.lnl.config.utils.StringUtils.getHmacKeys;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

@Slf4j
@RunWith(SpringRunner.class)
@TestPropertySource(locations = "classpath:application-test.properties")
@AutoConfigureMockMvc(secure = true)
@SpringBootTest(classes = {AuthServer.class})
@ActiveProfiles("test")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CoreOAuth2FrameworkTestIT {

    @TestConfiguration
    static class ContextConfiguration {

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }

    @Autowired
    private WebApplicationContext wac;

    @Autowired
    private MockMvc mvc;

    @Autowired
    private FilterChainProxy springSecurityFilterChain;

    @Autowired
    private TokenService tokenService;

    @Value("${token.validity}")
    private Integer validity;

    private MockMvc mockMvc;
    private static final String CLIENT_ID = "authserver";
    private static final String CLIENT_SECRET = "passwordforauthserver";
    private static final String CONTENT_TYPE = "application/json;charset=UTF-8";
    private static String token = "";
    private static String oneTimeToken = "";
    HttpHeaders headers = new HttpHeaders();
    private static String hmacKey = "";

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).addFilter(springSecurityFilterChain).build();
    }


    public String obtainAccessTokenThroughHmac(Optional<String> extension) throws Exception {

        String timeinmillis = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis() + "";
        TokenRequest tokenRequest = new TokenRequest("admin@lnl.com");
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set(HttpDTO.AUTH_DIGEST.toString(), getHmacKeys("/external/getAccessTokenByEmail", timeinmillis));
        headers.set(HttpDTO.AUTH_TIME.toString(), timeinmillis);

        MvcResult token = mvc.perform(post("/external/getAccessTokenByEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .param("client_id", CLIENT_ID)
                .param("expiry_extension", extension.orElse(""))
                .headers(headers)
                .content(JsonUtil.toJson(tokenRequest)))
                .andReturn();
        return token.getResponse().getContentAsString();
    }


    public void ChangeUserStatusTo(Boolean status) throws Exception {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("admin@lnl.com", status);
        oneTimeToken = obtainAccessTokenThroughHmac(Optional.empty());
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Authorization", "Bearer " + oneTimeToken);
        mvc.perform(post("/api/changeUserActiveStatus")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers)
                .content(JsonUtil.toJson(changeUserActiveStatusRequest)));
    }

    @Test
    public void method_a_obtainAccessToken() throws Exception {
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", "admin@lnl.com");
        params.add("password", "test");
        String base64ClientCredentials = new String(Base64.encodeBase64("authserver:passwordforauthserver".getBytes()));


        MvcResult mvc = mockMvc.perform(post("/oauth/token")
                .params(params)
                .header("Authorization", "Basic " + base64ClientCredentials)
                .accept("application/json;charset=UTF-8"))
                .andReturn();
        String resultString = mvc.getResponse().getContentAsString();
        JacksonJsonParser jsonParser = new JacksonJsonParser();
        token = jsonParser.parseMap(resultString).get("access_token").toString();
        assertThat(token).isNotEmpty();

    }

    @Test
    public void method_b_checkTokenEndpoint() throws Exception {
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("token", token);
        String base64ClientCredentials = new String(Base64.encodeBase64("authserver:passwordforauthserver".getBytes()));

        mockMvc.perform(post("/oauth/check_token")
                .params(params)
                .header("Authorization", "Basic " + base64ClientCredentials)
                .accept("application/json;charset=UTF-8"))
                .andExpect(content().string(containsString("user_name")));
    }

    @Test
    public void method_c_checkTokenEndpoint_GetTokenByEmail_Noextension() throws Exception {
        tokenService.revokeAllToken("admin@lnl.com");
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("token", obtainAccessTokenThroughHmac(Optional.empty()));
        Long executedAt = Instant.now().getEpochSecond();
        String base64ClientCredentials = new String(Base64.encodeBase64("authserver:passwordforauthserver".getBytes()));

        MvcResult mvc = mockMvc.perform(post("/oauth/check_token")
                .params(params)
                .header("Authorization", "Basic " + base64ClientCredentials)
                .accept("application/json;charset=UTF-8")).andReturn();
        String resultString = mvc.getResponse().getContentAsString();
        JacksonJsonParser jsonParser = new JacksonJsonParser();
        String exp = jsonParser.parseMap(resultString).get("exp").toString();
        System.out.println("exp" + exp + "executedAt" + executedAt + "validity" + validity);
        assertThat(Long.parseLong(exp) == (executedAt + validity)).isTrue();

    }

    @Test
    public void method_d_checkTokenEndpoint_GetTokenByEmail_extendByXtime() throws Exception {
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("token", obtainAccessTokenThroughHmac(Optional.of("123")));
        Long executedAt = Instant.now().getEpochSecond();
        String base64ClientCredentials = new String(Base64.encodeBase64("authserver:passwordforauthserver".getBytes()));

        MvcResult mvc = mockMvc.perform(post("/oauth/check_token")
                .params(params)
                .header("Authorization", "Basic " + base64ClientCredentials)
                .accept("application/json;charset=UTF-8")).andReturn();
        String resultString = mvc.getResponse().getContentAsString();
        JacksonJsonParser jsonParser = new JacksonJsonParser();
        String exp = jsonParser.parseMap(resultString).get("exp").toString();
        System.out.println("exp" + exp + "executedAt" + executedAt + "validity" + validity);
        assertThat(Long.parseLong(exp) == (executedAt + validity + 123)).isTrue();
    }

    @Test
    public void method_e_checkTokenEndpoint_GetTokenByEmail_InfiniteValidity() throws Exception {
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        oneTimeToken=obtainAccessTokenThroughHmac(Optional.of("0"));
        params.add("token", oneTimeToken);
        Long executedAt = Instant.now().getEpochSecond();
        String base64ClientCredentials = new String(Base64.encodeBase64("authserver:passwordforauthserver".getBytes()));

        MvcResult mvc = mockMvc.perform(post("/oauth/check_token")
                .params(params)
                .header("Authorization", "Basic " + base64ClientCredentials)
                .accept("application/json;charset=UTF-8")).andReturn();
        String resultString = mvc.getResponse().getContentAsString();
        JacksonJsonParser jsonParser = new JacksonJsonParser();

       // log.info(
        assertThat(Arrays.asList(jsonParser.parseMap(resultString).get("scope")).size()==1).isTrue();
        assertFalse(jsonParser.parseMap(resultString).containsKey("exp"));
    }

    @Test
    public void method_e_CheckInactiveUser_GetUserDetailService() throws Exception {
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", "sayan@lnl.com");
        params.add("password", "test");
        String base64ClientCredentials = new String(Base64.encodeBase64("authserver:passwordforauthserver".getBytes()));

        MvcResult mvc = mockMvc.perform(post("/oauth/token")
                .params(params)
                .header("Authorization", "Basic " + base64ClientCredentials)
                .accept("application/json;charset=UTF-8"))
                .andReturn();
        String resultString = mvc.getResponse().getContentAsString();
        JacksonJsonParser jsonParser = new JacksonJsonParser();
        System.out.println("resultString" + resultString);
        assertThat(jsonParser.parseMap(resultString).get("error_description").toString().contains("is not activated")).isTrue();
    }

    @Test
    public void method_f_GetTokenByEmail_WrongCredentials() throws Exception {
        String timeinmillis = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis() + "";
        TokenRequest tokenRequest = new TokenRequest("admin@lnl.com");
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set(HttpDTO.AUTH_DIGEST.toString(), getHmacKeys("/wrongUrl", timeinmillis));
        headers.set(HttpDTO.AUTH_TIME.toString(), timeinmillis);

        mvc.perform(post("/external/getAccessTokenByEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .param("client_id", CLIENT_ID)
                .headers(headers)
                .content(JsonUtil.toJson(tokenRequest)))
                .andExpect(content().string(containsString("Invalid")));
    }

    @Test
    public void method_g_GetTokenByEmail_ClientId_NotFound() throws Exception {
        String timeinmillis = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis() + "";
        TokenRequest tokenRequest = new TokenRequest("admin@lnl.com");
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set(HttpDTO.AUTH_DIGEST.toString(), getHmacKeys("/external/getAccessTokenByEmail", timeinmillis));
        headers.set(HttpDTO.AUTH_TIME.toString(), timeinmillis);

        mvc.perform(post("/external/getAccessTokenByEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .param("client_id", "notregistered123")
                .param("expiry_extension", "123")
                .headers(headers)
                .content(JsonUtil.toJson(tokenRequest)))
                .andExpect(content().string(containsString(MessageDTO.CLIENT_ID_NOT_FOUND.toString())));
    }

    @Test
    public void method_h_GetTokenByEmail_ONE_TIME_then_revoketoken() throws Exception {
        UserRequest userRequest = new UserRequest("testuat33115@gmail.com", "test", "test", "test", 1234567890L, "lnl");
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Authorization", "Bearer " + oneTimeToken);

        mvc.perform(post("/api/createUser")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers)
                .content(JsonUtil.toJson(userRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_CREATED_SUCCESSFULLY.toString())));

        mvc.perform(post("/api/user")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers))
                .andExpect(content().string(containsString(MessageDTO.INVALID_TOKEN.toString())));
    }

    @Test
    @Transactional
    public void method_i_whenUserDeactivated_RevokeAllTokens() throws Exception {
        ChangeUserActiveStatusRequest changeUserActiveStatusRequest = new ChangeUserActiveStatusRequest("admin@lnl.com", false);
        oneTimeToken=obtainAccessTokenThroughHmac(Optional.empty());

        log.info("encrypted values"+getHmacKeys("/external/createUser?client_id=6ab37b5500fe440bb6cf2f93f6f37140","1562327454202"));

        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Authorization", "Bearer " + oneTimeToken);

        log.info("oneTimeToken"+oneTimeToken);

        mvc.perform(post("/api/changeUserActiveStatus")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers)
                .content(JsonUtil.toJson(changeUserActiveStatusRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_DEACTIVATED.toString())));

        mvc.perform(post("/api/user")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers)
                .content(JsonUtil.toJson(changeUserActiveStatusRequest)))
                .andExpect(content().string(containsString(MessageDTO.INVALID_TOKEN.toString())));

//       ChangeUserStatusTo(true);
    }

    @After
    public void reset() throws Exception {
    }

}