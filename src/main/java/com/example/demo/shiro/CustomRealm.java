package com.example.demo.shiro;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.example.demo.domain.UserDo;
import com.example.demo.domain.UserDoRepository;
import com.example.demo.util.JwtUtils;
import com.example.demo.util.RedisUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Component
public class CustomRealm extends AuthorizingRealm
{

    private static final Logger log = LoggerFactory.getLogger(CustomRealm.class);
    @Autowired
    UserDoRepository userDoRepository;

    @Autowired
    RedisUtils redisUtils;

    @Override
    public boolean supports(AuthenticationToken token)
    {
        return token instanceof JwtToken;
    }


    /**
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection)
    {
        log.debug("user auth confirm.");
        String userName = JwtUtils.getUsername(principalCollection.toString());
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        UserDo userDo = userDoRepository.findByUserName(userName);
        String roles = userDo.getRoles();
        String[] split = roles.split(",");
        Set<String> roleSet = new HashSet<>(Arrays.asList(split));
        authorizationInfo.setRoles(roleSet);
        String permissions = userDo.getPermissions();
        String[] permissionArray = permissions.split(",");
        Set<String> permissionSet = new HashSet<>(Arrays.asList(permissionArray));
        authorizationInfo.setStringPermissions(permissionSet);
        return authorizationInfo;
    }

    /**
     * 获取身份验证信息,Shiro中，最终是通过 Realm 来获取应用程序中的用户、角色及权限信息的。
     *
     * @param authenticationToken 用户身份信息 token
     * @return 返回封装了用户信息的 AuthenticationInfo 实例
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException
    {
        log.debug("user authentication...");
        String token = (String) authenticationToken.getCredentials();
        String username = JwtUtils.getUsername(token);
        //先判断用户是否存在
        if (username == null)
        {
            throw new AuthenticationException("Token不合法(Token invalid.)！");
        }
        UserDo userDo = userDoRepository.findByUserName(username);
        if (userDo == null)
        {
            throw new UnknownAccountException("该帐号不存在！");
        }
        try
        {
            JwtUtils.verify(token, username, userDo.getPassword());
        }
        catch (Exception e)
        {
            if (e instanceof TokenExpiredException)
            {
                throw new AuthenticationException("Token已失效(Token expired.)！");
            }
            throw new AuthenticationException("Token不合法(Token invalids.)！");
        }
        return new SimpleAuthenticationInfo(token, token, userDo.getUserName());
    }
}
