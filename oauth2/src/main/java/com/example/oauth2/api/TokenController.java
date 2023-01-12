package com.example.oauth2.api;


import com.example.oauth2.service.Token;
import com.example.oauth2.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
@RestController
public class TokenController {
    private final TokenService tokenService;

    @GetMapping("/token/expired")
    public String auth() {
        throw new RuntimeException();
    }

    @GetMapping("/hello-oauth2")
    public String home(@RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient authorizedClient ,HttpServletRequest request,HttpServletResponse response ) { // (1)

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        System.out.println("Access Token Value: " + accessToken.getTokenValue());
        System.out.println("Access Token Type: " + accessToken.getTokenType().getValue());
        System.out.println("Access Token Scopes: " + accessToken.getScopes());
        System.out.println("Access Token Issued At: " + accessToken.getIssuedAt());
        System.out.println("Access Token Expires At: " + accessToken.getExpiresAt());

        String token = request.getHeader("Auth");


        response.addHeader("Auth", accessToken.getTokenValue());
//        response.addHeader("Refresh", newToken.getRefreshToken());
        response.setContentType("application/json;charset=UTF-8");

        String email = tokenService.getUid(token);
        String name = tokenService.getUid(token);
        String picture = tokenService.getUid(token);
        Token newToken = tokenService.generateToken(email, name,picture,"USER");

        response.addHeader("Auth", newToken.getToken());
        response.addHeader("Refresh", newToken.getRefreshToken());
        response.setContentType("application/json;charset=UTF-8");


        return "hello-oauth2";
    }

    @GetMapping("/token/refresh")
    public String refreshAuth(HttpServletRequest request, HttpServletResponse response) {
        String token = request.getHeader("Refresh");

        if (token != null && tokenService.verifyToken(token)) {
            String email = tokenService.getUid(token);
            String name = tokenService.getUid(token);
            String picture = tokenService.getUid(token);
            Token newToken = tokenService.generateToken(email, name,picture,"USER");

            response.addHeader("Auth", newToken.getToken());
            response.addHeader("Refresh", newToken.getRefreshToken());
            response.setContentType("application/json;charset=UTF-8");

            return "HAPPY NEW TOKEN";
        }

        throw new RuntimeException();
    }
}
