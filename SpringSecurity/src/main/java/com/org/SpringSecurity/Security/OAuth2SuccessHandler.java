package com.org.SpringSecurity.Security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.org.SpringSecurity.dto.LoginresponseDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {


    @Autowired
    private  AuthService authService;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("Hello in the OnAuth SCreen");
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String registrationId = token.getAuthorizedClientRegistrationId(); // from where login is done

        try {
            ResponseEntity<LoginresponseDto> loginresponseDto = authService.handleOAuthLoginRequest(oAuth2User, registrationId);
            response.setStatus(loginresponseDto.getStatusCode().value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(loginresponseDto.getBody()));

        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }

    }
}
