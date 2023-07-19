package com.ikn.tech.gateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;
/*
 *This filter executes before a particular route or path or 
 *HTTP request is performed to check the authorization
 *In order to execute this filter first before any request it should
 *extend from AbstractGatewayFilterFactory
*/
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config>{

    @Autowired
    private Environment env;
    
    public AuthorizationHeaderFilter() {
	super(Config.class);
    }
    
    public static class Config{
	// put some config properties here for the filter if needed
    }

    //we can get HTTP request obeject / details from exchange object and from 
    // request object we can get HTTP authorization header
    
    //chain object is used to deletgate the flow to next filter in chain
    @Override
    public GatewayFilter apply(Config config) {
	
	return (exchange, chain)->{
	    ServerHttpRequest request =  exchange.getRequest();
	    if(!request.getHeaders().containsKey("Authorization")) {
	    	System.out.println("executed");
		return onError(exchange, "No Authorization Header", HttpStatus.UNAUTHORIZED);	
	    }
	   String authorizationHeader =  request.getHeaders().get("Authorization").get(0);
	   String jwtToken = authorizationHeader.replace("Bearer","");
	   
	   if(!isJwtValid(jwtToken)) {
	       return onError(exchange, "Not a valid JWT Token", HttpStatus.UNAUTHORIZED);	
	   }
	   return chain.filter(exchange);
	    };
    }
    
    private Mono<Void> onError(ServerWebExchange exchange, String errorMsg, HttpStatus httpStatus) {
	ServerHttpResponse response = exchange.getResponse();
	response.setStatusCode(httpStatus);
	return response.setComplete();
    }
    
    private boolean isJwtValid(String jwtToken) {
	boolean returnValue = true;
	//get subject
	String userId = null;
	String role = null;
	System.out.println("bearer executed");
	try {
	    userId= Jwts.parser()
			.setSigningKey(env.getProperty("token.secret"))
			.parseClaimsJws(jwtToken)
			.getBody()
			.getSubject();
	    System.out.println("authorization success");
	}//try
	catch (Exception e) {
		System.out.println("exception");
	   returnValue = false;
	   //response.setHeader("error",e.getMessage())
//	   Map<String, String> tokenData = new HashMap<String, String>();
//		tokenData.put("token", jwtToken);
//		response.setContentType("application/json");
//		new ObjectMapper().writeValue(response.getOutputStream(), tokenData);
	}
	if(userId == null || userId.isEmpty()){
	    returnValue = false;
	}  
	System.out.println(returnValue);
	return returnValue;
    }
   
}
