package com.lnl.controller;

import com.lnl.AuthServer;
import com.lnl.config.constants.HttpDTO;
import com.lnl.config.utils.JsonUtil;
import com.lnl.dto.ChangeUserActiveStatusRequest;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.Resource;

import java.util.Optional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {AuthServer.class})
@TestPropertySource(locations = "classpath:application-test.properties")
@AutoConfigureMockMvc
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@ActiveProfiles("test")
public class LoginTestIT {

    private MockMvc mockMvc;

    @Resource
    private WebApplicationContext webApplicationContext;

    @Resource
    private FilterChainProxy springSecurityFilterChain;

    @Before
    public void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .apply(springSecurity())
                .build();
    }


    @Test
    @WithMockUser(value = "user2@lnl.com", password = "test")
    public void method_a_testUserLogin() throws Exception {
        mockMvc.perform(formLogin("/login")
                .user("user2@lnl.com")
                .password("test"))
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername("user2@lnl.com"));
    }

    @Test
    @WithMockUser(value = "user2@lnl.com", password = "test")
    public void method_b_testUserLogin_failed_1() throws Exception {
        RequestBuilder requestBuilder = post("/login")
                .param("username", "user2@lnl.com")
                .param("password", "test123");

        mockMvc.perform(formLogin("/login")
                .user("user2@lnl.com")
                .password("test123"))
                .andExpect(redirectedUrl("/login?error="+ HttpDTO.invalid_user_name_pwd.name()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(value = "user2@lnl.com", password = "test")
    public void method_c_testUserLogin_passed_1() throws Exception {
        mockMvc.perform(formLogin("/login")
                .user("user2@lnl.com")
                .password("test"))
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername("user2@lnl.com"));
    }

    @Test
    @WithMockUser(value = "user2@lnl.com", password = "test")
    public void method_d_testUserLogin_failed_2() throws Exception {
        mockMvc.perform(formLogin("/login")
                .user("user2@lnl.com")
                .password("test123"))
                .andExpect(redirectedUrl("/login?error="+ HttpDTO.invalid_user_name_pwd.name()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(value = "user2@lnl.com", password = "test")
    public void method_e_testUserLogin_failed_3() throws Exception {
        mockMvc.perform(formLogin("/login")
                .user("user2@lnl.com")
                .password("test123"))
                .andExpect(redirectedUrl("/login?error="+ HttpDTO.invalid_user_name_pwd.name()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(value = "user2@lnl.com", password = "test")
    public void method_f_testUserLogin_failed_4() throws Exception {
        mockMvc.perform(formLogin("/login")
                .user("user2@lnl.com")
                .password("test123"))
                .andExpect(redirectedUrl("/login?error="+ HttpDTO.account_locked_2.name()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(value = "user2@lnl.com", password = "test")
    public void method_g_testUserLogin_failed_5() throws Exception {
        mockMvc.perform(formLogin("/login")
                .user("user2@lnl.com")
                .password("test123"))
                .andExpect(redirectedUrl("/login?error="+HttpDTO.account_locked_2.name()))
                .andExpect(status().is3xxRedirection());
    }
}
