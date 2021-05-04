package com.flame.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringBootSecurityJwtApplication {

	private static final Logger logger = LoggerFactory.getLogger(SpringBootSecurityJwtApplication.class);
	public static void main(String[] args) {
		logger.info("this is a info message");
		logger.warn("this is a warn message");
		logger.error("this is a error message");
		SpringApplication.run(SpringBootSecurityJwtApplication.class, args);
	}

}
