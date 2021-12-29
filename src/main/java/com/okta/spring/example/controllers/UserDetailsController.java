package com.okta.spring.example.controllers;

import com.okta.sdk.client.Client;
import com.okta.sdk.resource.user.User;
import com.okta.spring.example.model.Transaction;
import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.ModelAndView;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Controller
public class UserDetailsController {

    private final Client oktaClient;
    private final OAuth2AuthorizedClientService authorizedClientService;

    public UserDetailsController(
            Client oktaClient,
            OAuth2AuthorizedClientService authorizedClientService) {
        this.oktaClient = oktaClient;
        this.authorizedClientService = authorizedClientService;
    }

    @PreAuthorize("hasAuthority('SCOPE_customer')")
    @GetMapping("/profile")
    public ModelAndView userDetails(@AuthenticationPrincipal OidcUser authentication) {
        //TODO See if getting from /userinfo will make sense
        User user = oktaClient.getUser(authentication.getName());
        return new ModelAndView("userProfile", Collections.singletonMap("details", user));
    }

    @PreAuthorize("hasAuthority('SCOPE_transaction')")
    @PostMapping("/transactions")
    public String createTransaction(@ModelAttribute Transaction newTransaction, OAuth2AuthenticationToken authentication) {
       log.info("Received new transaction: {}", newTransaction);
       String email = authentication.getName();
       newTransaction.setEmail(email);

        Transaction createdTransaction = webClient(authentication)
                .post()
                .uri(uriBuilder -> uriBuilder
                        .path("/transactions")
                        .build())
                .body(Mono.just(newTransaction), Transaction.class)                .retrieve()
                .bodyToMono(Transaction.class).block();

        log.info("For user {}, a new transaction (id={}) has been created!", createdTransaction.getEmail(), createdTransaction.getId());
        return "redirect:/transactions";
    }

    @PreAuthorize("hasAuthority('SCOPE_transaction')")
    @GetMapping("/transactions")
    public ModelAndView userTransactions(Model model, OAuth2AuthenticationToken authentication) {

        List<Transaction> transactions = Collections.emptyList();
        ParameterizedTypeReference<List<Transaction>> parameterizedTypeReference =
                new ParameterizedTypeReference<List<Transaction>>(){};

        String email = authentication.getName();
        transactions = webClient(authentication)
                .get()
                .uri(uriBuilder -> uriBuilder
                            .path("/transactions")
                            .queryParam("email", email)
                            .build())
                .retrieve()
                .bodyToMono(parameterizedTypeReference).block();

        Map<String, Object> modelData = new HashMap<>();
        modelData.put("transaction", new Transaction());
        modelData.put("transactions", transactions);

        return new ModelAndView("userTransactions", modelData);

    }

    private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authentication) {
        return this.authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
    }

    private WebClient webClient(OAuth2AuthenticationToken authentication){
        OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authentication);

        HttpClient httpClient = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                .responseTimeout(Duration.ofMillis(5000))
                .doOnConnected(conn ->
                        conn.addHandlerLast(new ReadTimeoutHandler(5000, TimeUnit.MILLISECONDS))
                                .addHandlerLast(new WriteTimeoutHandler(5000, TimeUnit.MILLISECONDS)));

        return WebClient.builder()
                .baseUrl("http://localhost:8081/resource-server/transfer/api/v1")
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(oauth2Credentials(authorizedClient))
                .build();
    }

    private ExchangeFilterFunction oauth2Credentials(OAuth2AuthorizedClient authorizedClient) {
        return ExchangeFilterFunction.ofRequestProcessor(
                clientRequest -> {
                    ClientRequest authorizedRequest = ClientRequest.from(clientRequest)
                            .header(HttpHeaders.AUTHORIZATION,
                                    "Bearer " + authorizedClient.getAccessToken().getTokenValue())
                            .build();
                    return Mono.just(authorizedRequest);
                });
    }

}
