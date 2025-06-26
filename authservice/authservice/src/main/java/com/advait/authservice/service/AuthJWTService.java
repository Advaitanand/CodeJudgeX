package com.advait.authservice.service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Service	
public class AuthJWTService {
	
	private final int EXPIRATION_TIME = 1000*60*30;
	
	@Autowired 
	private PrivateKey privateKey;
	
	@Autowired
	private PublicKey publicKey;
	
	public String generateToken(String username) {
		
		Map<String, Object> claims = new HashMap<>();
		
		return Jwts
			.builder()
			.claims()
			.add(claims)
			.subject(username)
			.issuedAt(new Date(System.currentTimeMillis()))
			.expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
			.and()
			.signWith(privateKey)
			.compact();
	}

	public String getUsernameFromJwtToken(String token) {
		
		return extractClaim(token,Claims::getSubject);
	}

	public boolean validateToken(String token, UserDetails userDetails) {
		final String userName = getUsernameFromJwtToken(token);
		return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	
	private boolean isTokenExpired(String token) {
		
		return extractExpirationDate(token).before(new Date());
	}

	public Date extractExpirationDate(String token) {
		return extractClaim(token,Claims::getExpiration);
	}

	private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
		final Claims claims = extractAllClaims(token);
		return claimResolver.apply(claims);
	}

	private Claims extractAllClaims(String token) {
		
		return (Claims) Jwts.parser() 
			    .verifyWith(publicKey)       
			    .build()                     
			    .parseSignedClaims(token)
			    .getPayload();
	}
}
