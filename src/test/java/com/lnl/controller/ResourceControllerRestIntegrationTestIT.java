package com.lnl.controller;

import com.lnl.AuthServer;
import com.lnl.config.auth.CustomJdbcTokenStore;
import com.lnl.config.constants.HttpDTO;
import com.lnl.config.constants.MessageDTO;
import com.lnl.config.constants.Tokens;
import com.lnl.config.utils.JsonUtil;
import com.lnl.config.utils.StringUtils;
import com.lnl.domain.User;
import com.lnl.dto.TokenRequest;
import com.lnl.dto.UserRequest;
import com.lnl.repository.TokenRepository;
import com.lnl.repository.UserRepository;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.Calendar;
import java.util.Collection;
import java.util.List;
import java.util.TimeZone;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {AuthServer.class})
@TestPropertySource(locations = "classpath:application-test.properties")
@AutoConfigureMockMvc(secure = false)
@ActiveProfiles("test")
//@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ResourceControllerRestIntegrationTestIT {

    private static final String CLIENT_ID = "authserver";
    private static String hmacKey = "";

    @Autowired
    private MockMvc mvc;

    @Resource(name = "tokenStore")
    private CustomJdbcTokenStore customJdbcTokenStore;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenRepository tokenRepository;

    TestRestTemplate restTemplate = new TestRestTemplate();
    HttpHeaders headers = new HttpHeaders();

    @Before
    public void obtainAccessTokenThroughHmac() throws Exception {

        String timeinmillis = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis() + "";
        TokenRequest tokenRequest = new TokenRequest("admin@lnl.com");
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set(HttpDTO.AUTH_DIGEST.toString(), StringUtils.getHmacKeys("/external/getAccessTokenByEmail", timeinmillis));
        headers.set(HttpDTO.AUTH_TIME.toString(), timeinmillis);

        MvcResult token = mvc.perform(post("/external/getAccessTokenByEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .param("client_id", CLIENT_ID)
                .headers(headers)
                .content(JsonUtil.toJson(tokenRequest)))
                .andReturn();
        hmacKey = token.getResponse().getContentAsString();
    }

    @Test
    //@Ignore
    public void whenValidInput_thenCreateUser() throws IOException, Exception {
        UserRequest userRequest = new UserRequest("testuat33115@gmail.com", "test", "test", "test", 1234567890L, "lnl");

        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Authorization", "Bearer " + hmacKey);

        mvc.perform(post("/api/createUser")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers)
                .content(JsonUtil.toJson(userRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_CREATED_SUCCESSFULLY.toString())));

        List<User> found = userRepository.findAll();
        assertThat(found).extracting(User::getEmail).contains(userRequest.getEmail().toLowerCase());
    }

    @Test
    //@Ignore
    public void whenUserAlreadyExists_thenDontPersist() throws IOException, Exception {
        UserRequest userRequest = new UserRequest("admin@lnl.com", "test", "test", "test", 1234567890L, "lnl");
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Authorization", "Bearer " + hmacKey);

        mvc.perform(post("/api/createUser")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers)
                .content(JsonUtil.toJson(userRequest)))
                .andExpect(content().string(containsString(MessageDTO.USER_EXISTS.toString())));

        //also assert that duplicate record not getting created
        List<User> found = userRepository.findAll();
        assertThat(found).extracting(User::getEmail).containsOnlyOnce(userRequest.getEmail().toLowerCase());
    }

    @Test
    //@Ignore
    public void whenInvalidToken_thenDontPersist() throws IOException, Exception {
        UserRequest userRequest = new UserRequest("admin123@lnl.com", "test", "test", "test", 1234567890L, "lnl");
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Authorization", "Bearer " + "123-455-345-124");

        mvc.perform(post("/api/createUser")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers)
                .content(JsonUtil.toJson(userRequest)))
                .andExpect(content().string(containsString(MessageDTO.INVALID_TOKEN.toString())));

        //also assert that token got created and type adhoc
        List<User> found = userRepository.findAll();
        assertThat(found).extracting(User::getEmail).doesNotContain(userRequest.getEmail().toLowerCase());
    }


    //token service tests
    @Test
    public void whenGetAccessTokenByEmail_withValidClient_thenProduceAdhocToken() throws IOException, Exception {
        TokenRequest tokenRequest = new TokenRequest("admin@lnl.com");
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        MvcResult res = mvc.perform(post("/external/getAccessTokenByEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .param("client_id", CLIENT_ID)
                .headers(headers)
                .content(JsonUtil.toJson(tokenRequest)))
                .andReturn();

        String stringToken = res.getResponse().getContentAsString();

        Collection<OAuth2AccessToken> found = customJdbcTokenStore.findTokensByClientId(CLIENT_ID);
        OAuth2Authentication test = customJdbcTokenStore.readAuthentication(stringToken);
        //assert that token generate is persists
        assertThat(found).extracting(OAuth2AccessToken::getValue).contains(stringToken);
        //assert that token generate is type adhoc
        assertThat(test.getOAuth2Request().getScope()).containsExactly(Tokens.AD_HOC.toString());
    }

    //attempt counter scenarios

    @Test
    //@Ignore
    public void recordInvalidAttempts() throws IOException, Exception {
        UserRequest userRequest = new UserRequest("admin123@lnl.com", "test", "test", "test", 1234567890L, "lnl");
        //headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        //headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        //headers.set("Authorization", "Bearer " + "123-455-345-124");


        //also assert that token got created and type adhoc
        List<User> found = userRepository.findAll();
        assertThat(found).extracting(User::getEmail).doesNotContain(userRequest.getEmail().toLowerCase());
    }

    @After
    public void resetDb() {
        //userRepository.deleteAll();
    }


}