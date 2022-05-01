package me.kckwon.jsonwebtoken.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private final JwtToken jwtToken = new JwtToken();

    @Getter
    @Setter
    public static class JwtToken {
        private String loginUri;
        private String loginMethod;
        private String header;
        private String schema;
        private long expiration;
        private String secret;
    }
}
