/*
 * Copyright 2017 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.spring.example.controllers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.okta.sdk.client.Client;
import com.okta.sdk.resource.user.User;
import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import com.okta.spring.example.model.Tokens;
import net.minidev.json.JSONObject;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.*;

@Controller
public class LoginController {

    private static final String STATE = "state";
    private static final String NONCE = "nonce";
    private static final String SCOPES = "scopes";
    private static final String OKTA_BASE_URL = "oktaBaseUrl";
    private static final String OKTA_CLIENT_ID = "oktaClientId";
    private static final String REDIRECT_URI = "redirectUri";
    private static final String ISSUER_URI = "issuerUri";

    private final OktaOAuth2Properties oktaOAuth2Properties;

    private final OAuth2AuthorizedClientService authorizedClientService;

    private final OAuth2AuthorizedClientManager authorizedClientManager;

    public LoginController(OktaOAuth2Properties oktaOAuth2Properties,
                           OAuth2AuthorizedClientService authorizedClientService,
                           OAuth2AuthorizedClientManager authorizedClientManager) {
        this.oktaOAuth2Properties = oktaOAuth2Properties;
        this.authorizedClientService = authorizedClientService;
        this.authorizedClientManager = authorizedClientManager;
    }

    @GetMapping("/refresh")
    public String refresh(Authentication authentication) {
        OAuth2AuthorizeRequest authRequest = OAuth2AuthorizeRequest.withClientRegistrationId("okta")
                .principal(authentication)
                .build();

        authorizedClientManager.authorize(authRequest);
        return "redirect:/tokens";
    }

    @GetMapping("/tokens")
    public ModelAndView tokens(OAuth2AuthenticationToken authenticationToken, @AuthenticationPrincipal OidcUser authentication) {
        //TODO See if getting from /userinfo will make sense
        OAuth2AuthorizedClient authorizedClient = getAuthorizedClient(authenticationToken);
        Tokens tokenDetails = new Tokens();
        DateTimeFormatter formatter =
                DateTimeFormatter.ofLocalizedDateTime( FormatStyle.FULL )
                        .withLocale( Locale.CANADA )
                        .withZone( ZoneId.systemDefault() );

        tokenDetails.setIdToken(getDecodedToken(authentication.getIdToken().getTokenValue()));
        tokenDetails.setAccessToken(getDecodedToken(authorizedClient.getAccessToken().getTokenValue()));
        tokenDetails.setRefreshToken(authorizedClient.getRefreshToken().getTokenValue());
        tokenDetails.setRefreshTokenIssuedAt(
                formatter.format(authorizedClient.getRefreshToken().getIssuedAt()));

        return new ModelAndView("tokens", Collections.singletonMap("tokens", tokenDetails));
    }

    private String prettyPrintJson(String myString) {
        String result = null;
        try{
            ObjectMapper mapper = new ObjectMapper();
            Object json = mapper.readValue(myString, Object.class);
            result = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
        }catch(JsonProcessingException ex){
            throw new IllegalArgumentException(
                    String.format("Failed to prettify input string: %s", myString));
        }
        return result;
    }

    private String getDecodedToken(String tokenValue) {
        String[] parts = tokenValue.split("\\.");
        byte[] decodedBytes = Base64.getMimeDecoder().decode(parts[0]);
        String decodedToken = prettyPrintJson(new String(decodedBytes));

        if(parts.length>=2){
            decodedBytes = Base64.getMimeDecoder().decode(parts[1]);
            decodedToken = decodedToken + System.lineSeparator() + prettyPrintJson(new String(new String(decodedBytes)));
        }
        return decodedToken;
    }

    @GetMapping(value = "/signin")
    public ModelAndView login(HttpServletRequest request,
                              @RequestParam(name = "state", required = false) String state,
                              @RequestParam(name = "nonce") String nonce) throws MalformedURLException {

        // if we don't have the state parameter redirect
        if (state == null) {
            return new ModelAndView("redirect:" + oktaOAuth2Properties.getRedirectUri());
        }

        String issuer = oktaOAuth2Properties.getIssuer();
        // the widget needs the base url, just grab the root of the issuer
        String orgUrl = new URL(new URL(issuer), "/").toString();

        ModelAndView mav = new ModelAndView("login");
        mav.addObject(STATE, state);
        mav.addObject(NONCE, nonce);
        mav.addObject(SCOPES, oktaOAuth2Properties.getScopes());
        mav.addObject(OKTA_BASE_URL, orgUrl);
        mav.addObject(OKTA_CLIENT_ID, oktaOAuth2Properties.getClientId());
        // from ClientRegistration.redirectUriTemplate, if the template is change you must update this
        mav.addObject(REDIRECT_URI,
            request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() +
            request.getContextPath() + "/authorization-code/callback"
        );
        mav.addObject(ISSUER_URI, issuer);

        return mav;
    }

    @GetMapping("/post-logout")
    public String logout() {
        return "logout";
    }

    @GetMapping("/403")
    public String error403() {
        return "403";
    }

    private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authentication) {
        return this.authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
    }

}
