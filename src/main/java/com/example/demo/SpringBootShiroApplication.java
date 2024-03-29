package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

@SpringBootApplication
public class SpringBootShiroApplication
{

    public static void main(String[] args)
    {
        SpringApplication.run(SpringBootShiroApplication.class, args);
    }

}
