package com.example.demo.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils
{
    @Value("${jwt.tokenExpireTime}")
    private static int tokenExpireTime;

    //校验token是否正确
    public static void verify(String token, String username, String secret) throws Exception
    {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier verifier = JWT.require(algorithm)
                .withClaim("userName", username)
                .build();
        verifier.verify(token);

    }


    /**
     * 获得token中的信息无需secret解密也能获得
     *
     * @return token中包含的用户名
     */


    public static String getUsername(String token)
    {
        try
        {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("userName").asString();
        }
        catch (JWTDecodeException e)
        {
            e.printStackTrace();
            return null;
        }
    }


    /**
     * 生成签名,30min后过期
     *
     * @param username 用户名
     * @return 加密的token
     */


    public static String sign(String username, String secret)
    {
        try
        {
            Date date = new Date(System.currentTimeMillis() + (tokenExpireTime * 60 * 1000));
            Algorithm algorithm = Algorithm.HMAC256(secret);
            // 附带username信息
            return JWT.create()
                    .withClaim("userName", username)
                    .withExpiresAt(date)
                    .sign(algorithm);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

}