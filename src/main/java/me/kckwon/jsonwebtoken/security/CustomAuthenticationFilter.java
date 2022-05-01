package me.kckwon.jsonwebtoken.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import me.kckwon.jsonwebtoken.config.AppProperties;
import me.kckwon.jsonwebtoken.user.domain.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;


@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // We use auth manager to validate the user credentials
    private final AuthenticationManager authManager;
    private final TokenProvider tokenProvider;
    private final AppProperties appProperties;

    public CustomAuthenticationFilter(AuthenticationManager authManager, TokenProvider tokenProvider,
                                      AppProperties appProperties) {
        this.authManager = authManager;
        this.tokenProvider = tokenProvider;
        this.appProperties = appProperties;

        this.setRequiresAuthenticationRequestMatcher(
                new AntPathRequestMatcher(appProperties.getJwtToken().getLoginUri(), appProperties.getJwtToken().getLoginMethod()));
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            // 1. Get credentials from request
            User user = new ObjectMapper().readValue(request.getInputStream(), User.class);

            // 2. Create auth object (contains credentials) which will be used by auth manager
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    user.getName(), user.getPassword(), Collections.emptyList());
            setDetails(request, authRequest);

            // 3. Authentication manager authenticate the user, and use UserDetialsServiceImpl::loadUserByUsername() method to load the user.
            return authManager.authenticate(authRequest);

        } catch (IOException e) {
            throw new RuntimeException(e);
            // throw new BadRequestException("Invalid name or password");
        }
    }

    // Upon successful authentication, generate a token.
    // The 'auth' passed to successfulAuthentication() is the current authenticated user.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) {
        final String token = tokenProvider.createToken(authentication);
        response.addHeader(appProperties.getJwtToken().getHeader(), appProperties.getJwtToken().getSchema() + token);
    }
}
