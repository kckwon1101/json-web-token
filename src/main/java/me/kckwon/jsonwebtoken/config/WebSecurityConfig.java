package me.kckwon.jsonwebtoken.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.kckwon.jsonwebtoken.security.*;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService userDetailsService;
    private final TokenProvider tokenProvider;
    private final AppProperties appProperties;
    private final TokenAuthenticationFilter tokenAuthenticationFilter;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .exceptionHandling()
                .authenticationEntryPoint((req, res, e) -> res.sendError(HttpServletResponse.SC_UNAUTHORIZED))
            .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
            .and()
                .formLogin().disable()
                // addFilterBefore : security filter chain 중 특정 필터 이전에 별도 등록
                .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // addFilter : security filter chain 으로 구성된 필터를 상속받아 커스터마이징하여 대체
                // authenticationManager()은 WebSecurityConfigurerAdapter에서 기본으로 제공.
                // AuthenticationProvider를 직접 생성하여 authenticationManagerBuilder로 구성해도 되고,
                // AuthenticationManagerBuilder에
                //   AuthenticationProvider를 직접 생성하여 넘겨줘도 되고,
                //   UserDetailsService와 PasswordEncoder를 넘겨줘도 된다.
                .addFilter(new CustomAuthenticationFilter(authenticationManager(), tokenProvider, appProperties));
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder());
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) {
        authenticationManagerBuilder.authenticationProvider(customAuthenticationProvider());
    }
}
