package me.kckwon.jsonwebtoken.security;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String TOKEN_HEADER = "Authorization";
    private static final String TOKEN_SCHEMA = "Bearer ";

    private static final String JWT_SECRET = "SECRET_KEY";
    private static final int JWT_EXPIRATION = 1000 * 3600 * 24 * 7;


    public String createToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION);

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setClaims(createClaims(userPrincipal))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .compact();
    }

    private static Map<String, Object> createClaims(UserPrincipal user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", user.getName());
        return claims;
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(JWT_SECRET)
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT Signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT Token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT Token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT Token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty");
        }
        return false;
    }
}
