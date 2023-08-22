package com.ikn.tech;

import java.security.PublicKey;
import java.util.Base64;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;



@SpringBootApplication
@EnableDiscoveryClient
public class UmsApiRoutingGatewayApplication {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(UmsApiRoutingGatewayApplication.class, args);
		
		/*
		String jwtToken = null;
		
		// Create an HttpClient instance
        HttpClient httpClient = HttpClients.createDefault();

        // Define the API endpoint URL
        String endpoint = "https://login.microsoftonline.com/common/discovery/keys";

        // Create an HttpGet request
        HttpGet httpGet = new HttpGet(endpoint);

        try {
            HttpResponse response = httpClient.execute(httpGet);
            String responseBody = EntityUtils.toString(response.getEntity());

            // Parse the JSON response
            JSONObject jsonObject = new JSONObject(responseBody);

            // Extract key-value pairs
            JSONArray keysArray = jsonObject.getJSONArray("keys");
            for (int i = 0; i < keysArray.length(); i++) {
                JSONObject keyObject = keysArray.getJSONObject(i);
                String kid = keyObject.getString("kid");
                String value = keyObject.toString(); // The whole key object as a string
                System.out.println("Key ID: " + kid);
                System.out.println("Key Value: " + value);
                System.out.println("----------------------------------");
                
            }
            DecodedJWT jwt = JWT.decode(jwtToken);
            
            String kid = jwt.getKeyId();
            
         // Iterate through JWKs and find matching key based on "kid"
            PublicKey publicKey = null;
            JSONArray keyArray = jsonObject.getJSONArray("keys");
            for (int i = 0; i < keysArray.length(); i++) {
                JSONObject keyObject = keysArray.getJSONObject(i);
                String jwkKid = keyObject.getString("kid");
                if (kid.equals(jwkKid)) {
                    String publicKeyPEM = keyObject.getString("x5c").getString(0);
                    publicKey = getPublicKeyFromPEM(publicKeyPEM);
                    break;
                }
            }
            java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update((jwt.getHeader() + "." + jwt.getPayload()).getBytes());

            boolean isSignatureValid = signature.verify(Base64.getUrlDecoder().decode(jwt.getSignature()));


        } catch (Exception e) {
            e.printStackTrace();
        }
        */
	}
}
