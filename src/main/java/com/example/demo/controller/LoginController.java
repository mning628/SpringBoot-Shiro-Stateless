package com.example.demo.controller;

import com.example.demo.bean.ResultMap;
import com.example.demo.util.CommonConstant;
import com.example.demo.util.RedisUtils;
import com.example.demo.domain.UserDo;
import com.example.demo.domain.UserDoRepository;
import com.example.demo.util.JwtUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

@RestController
public class LoginController
{
    @Autowired
    private UserDoRepository userDoRepository;

    @Autowired
    RedisUtils redisUtils;

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public ResultMap logout(@RequestParam("userName") String username)
    {
        redisUtils.del(CommonConstant.JWT_TOKEN + username);
        return new ResultMap().success().message("成功注销！");
    }


    /**
     * 登陆
     *
     * @param username 用户名
     * @param password 密码
     */
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public ResultMap login(@RequestParam("userName") String username, @RequestParam("password") String password, HttpServletResponse response)
    {
        UserDo role = userDoRepository.findByUserName(username);
        if (role != null && role.getPassword().equals(password))
        {
            String tokenStr = JwtUtils.sign(username, password);
            redisUtils.set(CommonConstant.JWT_TOKEN + username, tokenStr);
            redisUtils.expire(CommonConstant.JWT_TOKEN + username, 30 * 60 * 1000);
            response.setHeader("Authorization", tokenStr);
            return new ResultMap().success().message("欢迎登陆");
        }
        else
        {
            return new ResultMap().fail().message("用户信息有误");
        }
    }
}