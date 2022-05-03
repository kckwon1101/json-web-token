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

    private final AuthenticationManager authManager;
    private final TokenProvider tokenProvider;
    private final AppProperties appProperties;

    public CustomAuthenticationFilter(AuthenticationManager authManager, TokenProvider tokenProvider,
                                      AppProperties appProperties) {
        this.authManager = authManager;
        this.tokenProvider = tokenProvider;
        this.appProperties = appProperties;

        this.setRequiresAuthenticationRequestMatcher(
                new AntPathRequestMatcher(appProperties.getJwtToken().getLoginUri(),
                        appProperties.getJwtToken().getLoginMethod()));
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            log.info("로그인 시도");

            User user = new ObjectMapper().readValue(request.getInputStream(), User.class);

            // AuthenticationManager가 사용할 인증 객체 생성
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    user.getName(), user.getPassword(), Collections.emptyList());
            setDetails(request, authRequest);

            // AuthenticationManager를 따로 구성하지 않을 경우
            // WebSecurityConfigurerAdapter에서 기본적으로 제공하는 DaoAuthenticationProvider가 인증처리를 함.
            //   (UserDetailsService와 PasswordEncoder는 필요)
            return authManager.authenticate(authRequest);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) {
        final String token = tokenProvider.createToken(authentication);
        response.addHeader(appProperties.getJwtToken().getHeader(),
                appProperties.getJwtToken().getSchema() + " " + token);
    }
}
