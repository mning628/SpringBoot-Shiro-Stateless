package com.example.demo.shiro;

import com.example.demo.domain.UserDo;
import com.example.demo.domain.UserDoRepository;
import com.example.demo.util.CodeAndMsgEnum;
import com.example.demo.util.CommonConstant;
import com.example.demo.util.JwtUtils;
import com.example.demo.util.RedisUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class ShiroFilter extends BasicHttpAuthenticationFilter
{
    @Value("${jwt.anonymous.urls}")
    private String anonymousStr;


    @Autowired
    RedisUtils redisUtils;


    @Autowired
    UserDoRepository userDoRepository;

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception
    {
        String path = WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
        List<String> anonPaths = Arrays.asList(anonymousStr.split(","));
        //直接放开login
        if (anonPaths.contains(path))
        {
            return true;
        }

        AuthenticationToken token = this.createToken(request, response);
        if (token == null)
        {
            handler401(response, CodeAndMsgEnum.UNAUTHENTIC.getcode(), CodeAndMsgEnum.UNAUTHENTIC.getMsg());
            return false;
        }
        else
        {
            try
            {
                this.getSubject(request, response).login(token);
                return true;
            }
            catch (Exception e)
            {
                String message = e.getMessage();
                if (message.contains("incorrect"))
                {
                    handler401(response, CodeAndMsgEnum.UNAUTHENTIC.getcode(), message);
                    return false;
                }
                else if (message.contains("expired"))
                {
                    //尝试刷新token
                    if (this.refreshToken(request, response))
                    {
                        return true;
                    }
                    else
                    {
                        handler401(response, CodeAndMsgEnum.UNAUTHENTIC.getcode(), "token已过期,请重新登录");
                        return false;
                    }

                }
                handler401(response, CodeAndMsgEnum.UNAUTHENTIC.getcode(), message);
                return false;

            }
        }
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response)
    {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader("Authorization");
        if (StringUtils.isNotEmpty(token))
        {
            return new JwtToken(token);
        }
        return null;
    }

    /**
     * 支持跨域
     *
     * @param request
     * @param response
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception
    {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setHeader("Access-control-Allow-Origin", "*");
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", "Authorization,Origin,X-Requested-With,Content-Type,Accept");
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name()))
        {
            httpServletResponse.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(httpServletRequest, httpServletResponse);
    }


    /**
     * token有问题
     */
    private void handler401(ServletResponse response, int code, String msg)
    {
        try
        {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.setStatus(HttpStatus.OK.value());
            response.setContentType("application/json;charset=utf-8");
            httpResponse.getWriter().write("{\"code\":" + code + ", \"msg\":\"" + msg + "\"}");
        }
        catch (IOException e)
        {
            //TODO
        }
    }

    private boolean refreshToken(ServletRequest servletRequest, ServletResponse servletResponse)
    {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        String oldToken = request.getHeader("Authorization");
        String userName = JwtUtils.getUsername(oldToken);
        String key = CommonConstant.JWT_TOKEN + userName;
        String redisUserInfo = redisUtils.get(key);
        if (StringUtils.isNotEmpty(redisUserInfo) && oldToken.equals(redisUserInfo))
        {
            UserDo vo = userDoRepository.findByUserName(userName);
            String newTokenStr = JwtUtils.sign(vo.getUserName(), vo.getPassword());
            redisUtils.set(key, newTokenStr);
            redisUtils.expire(key, 30 * 60 * 1000);
            JwtToken jwtToken = new JwtToken(newTokenStr);
            SecurityUtils.getSubject().login(jwtToken);
            response.setHeader("Authorization", newTokenStr);
            return true;
        }
        return false;
    }


}
