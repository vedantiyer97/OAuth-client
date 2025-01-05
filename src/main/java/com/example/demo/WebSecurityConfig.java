package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.oauth2.core.user.OAuth2User;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity

public class WebSecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);


    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        CustomAuthorizationRequestResolver resolver = 
            new CustomAuthorizationRequestResolver(
                clientRegistrationRepository, 
                OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
            );
        
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/home").permitAll()
                .anyRequest().authenticated())
            .oauth2Login(oauth2 -> {
                oauth2.authorizationEndpoint()
                    .authorizationRequestResolver(resolver);
                oauth2.successHandler((request, response, authentication) -> {
                    // Extract tokens from OAuth2 authentication
                    OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
                    
                    // Get access token
                    OAuth2User oauth2User = oauth2Token.getPrincipal();
                    String clientRegistrationId = oauth2Token.getAuthorizedClientRegistrationId();
                    OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                        clientRegistrationId, 
                        oauth2Token.getName()
                    );
                    String accessToken = client.getAccessToken().getTokenValue();
                    
                    // If using OpenID Connect (OIDC), you can get the ID token
                    if (oauth2User instanceof OidcUser) {
                        OidcUser oidcUser = (OidcUser) oauth2User;
                        OidcIdToken idToken = oidcUser.getIdToken();
                        String idTokenValue = idToken.getTokenValue();
                        logger.info("ID Token: {}", idTokenValue);
                    }
                    
                    // Log or process the tokens as needed
                    logger.info("Access Token: {}", accessToken);
                    logger.info("User Attributes: {}", oauth2User.getAttributes());
                    
                    response.sendRedirect("/hello");
                });
                oauth2.failureHandler((request, response, exception) -> {
                    System.out.println("Authentication failed: " + exception.getMessage());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Authentication failed: " + exception.getMessage());
                });
            });
        return http.build();
    }

    private static class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
        private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;
        private static final Logger logger = LoggerFactory.getLogger(CustomAuthorizationRequestResolver.class);

        public CustomAuthorizationRequestResolver(
                ClientRegistrationRepository clientRegistrationRepository, 
                String authorizationRequestBaseUri) {
            this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, authorizationRequestBaseUri);
        }

        @Override
        public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
            OAuth2AuthorizationRequest authRequest = defaultResolver.resolve(request);
            return customizeAuthorizationRequest(authRequest);
        }

        @Override
        public OAuth2AuthorizationRequest resolve(
                HttpServletRequest request, String clientRegistrationId) {
            OAuth2AuthorizationRequest authRequest = defaultResolver.resolve(
                request, clientRegistrationId);
            return customizeAuthorizationRequest(authRequest);
        }

        private OAuth2AuthorizationRequest customizeAuthorizationRequest(
                OAuth2AuthorizationRequest request) {
            if (request == null) {
                return null;
            }
            return OAuth2AuthorizationRequest.from(request)
                .clientId("myClientID")
                .state(generateCustomState(request.getState()))
                .additionalParameters(params -> 
                    params.put("nonce", generateCustomNonce()))
                .build();
        }

        private String generateCustomState(String originalState) {
            // Preserve any validation tokens from the original state
            // and append our custom data
            return String.format("%s_%d_%s",
                originalState,
                System.currentTimeMillis(),
                java.util.UUID.randomUUID().toString());
        }

        private String generateCustomNonce() {
            return java.util.UUID.randomUUID().toString();
        }
    }
}