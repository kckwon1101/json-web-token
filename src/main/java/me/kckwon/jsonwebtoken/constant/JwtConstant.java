package me.kckwon.jsonwebtoken.constant;

public interface JwtConstant {

    String LOGIN_URI = "/auth/login";
    String LOGIN_METHOD = "POST";

    String HEADER = "Authorization";
    String SCHEMA = "Bearer ";
    int EXPIRATION = 1000 * 3600 * 24 * 7;
}
