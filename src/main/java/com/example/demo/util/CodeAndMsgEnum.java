package com.example.demo.util;

/**
 * The enum Code and msg enum.
 */
public enum CodeAndMsgEnum
{

    /**
     * Unauthentic code and msg enum.
     */
    UNAUTHENTIC(100401, "无权访问，当前是匿名访问，请先登录！");


    private int code;

    private String msg;

    CodeAndMsgEnum(int code, String msg)
    {
        this.code = code;
        this.msg = msg;
    }


    /**
     * Gets .
     *
     * @return the
     */
    public int getcode()
    {
        return this.code;
    }

    /**
     * Gets msg.
     *
     * @return the msg
     */
    public String getMsg()
    {
        return this.msg;
    }
}
