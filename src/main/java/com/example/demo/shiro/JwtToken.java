package com.example.demo.shiro;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * Created by Administrator on 2019/1/6.
 */
public class JwtToken implements AuthenticationToken
{
    // 密钥
    private String token;

    public JwtToken(String token)
    {
        this.token = token;
    }

    @Override
    public Object getPrincipal()
    {
        return token;
    }

    @Override
    public Object getCredentials()
    {
        return token;
    }
}
