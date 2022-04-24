package me.kckwon.jsonwebtoken.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final String TOKEN_HEADER = "Authorization";
    private final String TOKEN_SCHEMA = "Bearer ";

    @Autowired
    TokenProvider tokenProvider;


    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) {
        final String token = tokenProvider.createToken(authentication);
        response.addHeader(TOKEN_HEADER, TOKEN_SCHEMA + token);
    }
}
