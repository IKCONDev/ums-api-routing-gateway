package com.ikn.tech;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class UmsApiRoutingGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(UmsApiRoutingGatewayApplication.class, args);
	}

}
