package com.example.oauth2.config;

import com.example.oauth2.service.Token;
import com.example.oauth2.service.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;


@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final TokenService tokenService;
    private final UserRequestMapper userRequestMapper;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        log.info("로그인 성공 시작");
        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        UserDto userDto = userRequestMapper.toDto(oAuth2User);

        log.info("Principal에서 꺼낸 OAuth2User = {}", oAuth2User);
        // 최초 로그인이라면 회원가입 처리를 한다.
        log.info("유저 이메일", oAuth2User.getName()); //  이메일 뽑아옴, 이 상태에서 DB조회 후 이 이메일이 잇는지 검사

         String email;
         email = oAuth2User.getName();


        String targetUrl;
        log.info("토큰 발행 시작");

        Token token = tokenService.generateToken(userDto.getEmail(), userDto.getName(),userDto.getPicture(), "USER");
        log.info("{}", token);

        response.setHeader("token", token.getToken());
        response.setHeader("refreshToken", token.getRefreshToken());


        targetUrl = UriComponentsBuilder.fromUriString("/home")
                .queryParam("token", "token")
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);


    }

//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
//        UserDto userDto = userRequestMapper.toDto(oAuth2User);
//
//        Token token = tokenService.generateToken(userDto.getEmail(),  userDto.getName(), userDto.getPicture(), "USER");
//        log.info("{}", token);
//
//        writeTokenResponse(response, token);
//
//        log.info("Principal에서 꺼낸 OAuth2User = {}", oAuth2User);
//        // 최초 로그인이라면 회원가입 처리를 한다.
//        String targetUrl;
//        log.info("토큰 발행 시작");
//
//        targetUrl = UriComponentsBuilder.fromUriString("/home")
//                .queryParam("token", "token")
//                .build().toUriString();
//        getRedirectStrategy().sendRedirect(request, response, targetUrl);
//    }

    private void writeTokenResponse(HttpServletResponse response, Token token) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        response.addHeader("Auth", token.getToken());
        response.addHeader("Refresh", token.getRefreshToken());
        response.setContentType("application/json;charset=UTF-8");

        var writer = response.getWriter();
        writer.println(objectMapper.writeValueAsString(token));
        writer.flush();
    }

    private URI createUri(String accessToken,
                          String refreshToken,
                          String provider) {
        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("accessToken", accessToken);
        queryParams.add("refreshToken", refreshToken);

        return UriComponentsBuilder
                .newInstance()
                .scheme("http")
                .host("localhost")
                .port(8080)
                .path("/oauth/" + provider)
                .queryParams(queryParams)
                .build()
                .toUri();
    }
}