package org.camunda.oauth2.plugin.filter;

import org.apache.commons.lang3.StringUtils;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.camunda.bpm.engine.rest.security.auth.impl.ContainerBasedAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class SpringSecurityAuthenticationProvider extends ContainerBasedAuthenticationProvider {

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request,
                                                         ProcessEngine engine) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

//        if (authentication == null) {
//            return AuthenticationResult.unsuccessful();
//        }

//        String name = authentication.getName();
//        if (name == null || name.isEmpty()) {
//            return AuthenticationResult.unsuccessful();
//        }

        // Extract user-name-attribute of the OAuth2 token
        if (!(authentication instanceof OAuth2AuthenticationToken) ||
                !(authentication.getPrincipal() instanceof OidcUser)) {

            return AuthenticationResult.unsuccessful();
        }
        String name = ((OidcUser)authentication.getPrincipal()).getName();
        if (StringUtils.isEmpty(name)) {
            return AuthenticationResult.unsuccessful();
        }

        AuthenticationResult authenticationResult = new AuthenticationResult(name, true);
        authenticationResult.setGroups(getUserGroups(authentication));

        return authenticationResult;
    }

    private List<String> getUserGroups(Authentication authentication){

        List<String> groupIds;

        groupIds = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(res -> res.substring(5)) // Strip "ROLE_"
                .collect(Collectors.toList());

        return groupIds;

    }

    private List<String> getUserGroups(String userId, ProcessEngine engine){
        List<String> groupIds = new ArrayList<>();
        // query groups using KeycloakIdentityProvider plugin
        engine.getIdentityService().createGroupQuery().groupMember(userId).list()
                .forEach( g -> groupIds.add(g.getId()));
        return groupIds;
    }
}
