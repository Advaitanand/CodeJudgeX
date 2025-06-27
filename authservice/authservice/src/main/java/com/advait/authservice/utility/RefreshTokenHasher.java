package com.advait.authservice.utility;

import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class RefreshTokenHasher {
	
	@Value("${security.refreshTokenSecret}")
	private String refreshTokenSecretKey;

	public String hashRefreshToken(String token) {
    	try {
            SecretKeySpec keySpec = new SecretKeySpec(refreshTokenSecretKey.getBytes(), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keySpec);
            byte[] rawHmac = mac.doFinal(token.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash refresh token", e);
        }
    }
	
}
