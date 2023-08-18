package com.ikn.tech.gateway;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

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
	   
	   Mono<Void> error = null;
	   if(!isTeamsAccessTokenValid(jwtToken)) {
		   error = onError(exchange, "Not a valid microsoft's access token", HttpStatus.UNAUTHORIZED);
	   }
	   else if(!isJwtValid(jwtToken)) {
	        error  = onError(exchange, "Not a valid JWT Token", HttpStatus.UNAUTHORIZED);	
	   }
	   if(error != null) {
		   return error;
	   }
	   return chain.filter(exchange);
	    };
    }
    
    private Mono<Void> onError(ServerWebExchange exchange, String errorMsg, HttpStatus httpStatus) {
	ServerHttpResponse response = exchange.getResponse();
	response.setStatusCode(httpStatus);
	return response.setComplete();
    }
    
    
    private boolean isTeamsAccessTokenValid(String accessToken) {
    	
        try {
            // Parse the JWT token
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            System.out.println("Token Claims: " + claims.toString());

            // Retrieve the JWKS endpoint URL
            URL jwksUrl = new URL("https://login.microsoftonline.com/07c65ba0-ad88-46c0-bee7-90912bc21e8e/discovery/keys");
            JWKSet jwkSet = JWKSet.load(jwksUrl);

            // Get the key that matches the key ID (kid) from the token header
            JWSHeader jwsHeader = signedJWT.getHeader();
            JWK jwk = jwkSet.getKeyByKeyId(jwsHeader.getKeyID());
            
            String tokenKeyID = jwsHeader.getKeyID();
            System.out.println("Token Key ID: " + tokenKeyID);
            String jwkKeyID = jwk.getKeyID();
            System.out.println("JWK Key ID: " + jwkKeyID);


            // Convert the JWK to an RSA public key
            RSAPublicKey rsaPublicKey = jwk.toRSAKey().toRSAPublicKey();
            System.out.println("RSA Public Key: " + rsaPublicKey);


            // Create a verifier with the RSA public key
            JWSVerifier jwsVerifier = new RSASSAVerifier(rsaPublicKey);
            System.out.println("JWS Verifier: " + jwsVerifier);


            // Verify the signature
            if (signedJWT.verify(jwsVerifier)) {
                System.out.println("Token signature verified");
                return true;
            } else {
            	    System.out.println("Token signature verification failed");
            	    System.out.println("Token Header: " + signedJWT.getHeader());
            	    System.out.println("Token Payload: " + signedJWT.getJWTClaimsSet());
                return false;
            }
        } catch (ParseException | JOSEException | IOException e) {
            System.out.println("Exception occurred during token verification: " + e.getMessage());
            return false;
        }
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
