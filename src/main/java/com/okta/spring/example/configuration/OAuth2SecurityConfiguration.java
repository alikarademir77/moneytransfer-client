package com.okta.spring.example.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import java.time.Duration;

@Configuration
class OAuth2SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .exceptionHandling()
                .accessDeniedHandler((req, res, e) -> res.sendRedirect("/403"))

                .and().authorizeRequests()
                .antMatchers(HttpMethod.GET,"/", "/signin", "/signup", "/refresh", "/img/**").permitAll()
                .antMatchers(HttpMethod.POST,"/register").permitAll()
                .anyRequest().authenticated()

                // send the user back to the root page when they logout
                .and()
                .logout().logoutSuccessUrl("/")

                .and().oauth2Client()
                .and().oauth2Login()
                .redirectionEndpoint()
                .baseUri("/authorization-code/callback*");
    }


}

