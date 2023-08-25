package com.ikn.tech.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
public class CorsWebConfiguration implements WebFluxConfigurer{
	
	 @Override
	    public void addCorsMappings(CorsRegistry registry) {
	        registry.addMapping("/**")
	                .allowCredentials(false)
	                .allowedHeaders("*")
	                .allowedMethods("*");
	    }

	    @Bean
	    public CorsWebFilter corsWebFilter() {
	        CorsConfiguration corsConfiguration = new CorsConfiguration();
	        corsConfiguration.setAllowCredentials(false);
	        corsConfiguration.addAllowedHeader("Access-Control-Allow-Headers");
	        corsConfiguration.addAllowedHeader("Access-Control-Allow-Origin");
	        corsConfiguration.addAllowedHeader("*");
	        corsConfiguration.addAllowedMethod("*");
	        corsConfiguration.addAllowedOrigin("http://localhost:4200");
	        //corsConfiguration.addExposedHeader(HttpHeaders.SET_COOKIE);
	        corsConfiguration.addExposedHeader("token");
	        corsConfiguration.addExposedHeader("userId");
	        corsConfiguration.addExposedHeader("userRole");
	        corsConfiguration.addExposedHeader("firstName");
	        corsConfiguration.addExposedHeader("lastName");
	        corsConfiguration.addExposedHeader("email");
	        corsConfiguration.addExposedHeader("twoFactorAuth");
	        UrlBasedCorsConfigurationSource corsConfigurationSource = new UrlBasedCorsConfigurationSource();
	        corsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
	        return new CorsWebFilter(corsConfigurationSource);
	    }

}
