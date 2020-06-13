package com.lnl.controller;

import com.lnl.config.constants.Tokens;
import com.lnl.config.user.AuthorityPropertyEditor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

import static com.google.common.collect.Sets.newHashSet;
import static org.hibernate.validator.internal.util.CollectionHelper.newArrayList;

@Controller
@Slf4j
@RequestMapping("clients")
public class ClientsController {

    @Autowired
    private JdbcClientDetailsService clientsDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.registerCustomEditor(GrantedAuthority.class, new AuthorityPropertyEditor());
    }

    @GetMapping(value = "/form")
    @PreAuthorize("hasRole('ROLE_ADMIN')") //user need to have adequate role to view this
    public String showEditForm(@RequestParam(value = "client", required = false) String clientId, Model model) {

        ClientDetails clientDetails;
        clientDetails = Optional.ofNullable(clientId)
                .map(s -> clientsDetailsService.loadClientByClientId(s))
                .orElse(new BaseClientDetails());
        model.addAttribute("clientDetails", clientDetails);
        return "form";
    }


    @PostMapping(value = "/edit")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String editClient(
            @ModelAttribute BaseClientDetails clientDetails,
            @RequestParam(value = "newClient", required = false) Optional<String> newClient) {

        //for now set all client roles with all permissions
        Set<String> scopes = newHashSet();
        Arrays.stream(Tokens.values()).forEach(s -> scopes.add(s.toString()));
        clientDetails.setScope(scopes);

        //auto approve all scopes
        Collection<String> autoApproves = newArrayList();
        autoApproves.add("true");
        clientDetails.setAutoApproveScopes(autoApproves);

        if (newClient.isPresent())
            clientsDetailsService.addClientDetails(clientDetails);
        else
            clientsDetailsService.updateClientDetails(clientDetails);

        Optional.ofNullable(clientDetails.getClientSecret())
                .ifPresent(s -> {
                    log.info("pass" + passwordEncoder.encode(clientDetails.getClientSecret()));
                    log.info("pass" + clientDetails.getClientSecret());
                    clientsDetailsService.updateClientSecret(clientDetails.getClientId(), passwordEncoder.encode(clientDetails.getClientSecret()));
                });
        return "redirect:/";
    }

    @GetMapping(value = "/{client.clientId}/delete")
    public String deleteClient(@ModelAttribute BaseClientDetails clientDetails, @PathVariable("client.clientId") String id) {
        clientsDetailsService.removeClientDetails(id);
        return "redirect:/";
    }
}