package com.lnl.controller;

import com.lnl.config.constants.HttpDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;

@Controller
@Slf4j
public class LoginController {

    @Autowired
    private JdbcClientDetailsService clientDetailsService;

    @Autowired
    private ApprovalStore approvalStore;

    @Autowired
    private TokenStore tokenStore;

    @Value("${spring.loginUrl}")
    private String redirectUrl;

    @GetMapping("/")
    public ModelAndView root(Map<String, Object> model, Principal principal) {
        List<Approval> approvals = clientDetailsService.listClientDetails().stream()
                .map(clientDetails -> approvalStore.getApprovals(principal.getName(), clientDetails.getClientId()))
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
        model.put("approvals", approvals);
        model.put("clientDetails", clientDetailsService.listClientDetails());
        return new ModelAndView("index", model);
    }

    @PostMapping(value = "/approval/revoke")
    public String revokApproval(@ModelAttribute Approval approval) {
        approvalStore.revokeApprovals(asList(approval));
        tokenStore.findTokensByClientIdAndUserName(approval.getClientId(), approval.getUserId())
                .forEach(tokenStore::removeAccessToken);
        return "redirect:/";
    }

    @GetMapping("/login")
    public String loginPage(Model model, @RequestParam(value = "error", required = false) Optional<String> errorCode,
                            @RequestParam(value = "hideClose", required = false) Optional<String> hideClose,
                            HttpServletRequest request) {
        log.info("inside login page:"+request.getQueryString());
        if (errorCode.isPresent()) {
            model.addAttribute("loginError", errorCode.get());
        }
        return "login";
    }

    @GetMapping(value = "/logout")
    public String logoutPage(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "redirect:"+redirectUrl;
    }
}