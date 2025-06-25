package com.advait.authservice.service;

import java.security.PublicKey;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.advait.authservice.exception.RedundantUsernameException;
import com.advait.authservice.model.Users;
import com.advait.authservice.repository.AuthRepository;

@Service
public class AuthService {
	
	@Autowired
	private BCryptPasswordEncoder encoder;
	
	@Autowired
	private AuthRepository repository;
	
	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private AuthJWTService jwtService;
	
	@Autowired
	private PublicKey publicKey;
	
	public String registerUsers(Users users) throws RedundantUsernameException {
		
		if(repository.existsByUsername(users.getUsername())) {
			throw new RedundantUsernameException("Username already exists");
		}
		
		users.setPassword(encoder.encode(users.getPassword()));
		repository.save(users);
		return "User registered successfully";
	}
	
	public String verify(Users user) {
		Authentication authenticated = authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
		if(authenticated.isAuthenticated()) {
			return jwtService.generateToken(user.getUsername());
		}
		
		return "failed";
	}

	public String getPublicKey() {
		String pemFormatted = "-----BEGIN PUBLIC KEY-----\n" +
				Base64.getEncoder().encodeToString(publicKey.getEncoded()).replaceAll("(.{64})", "$1\n") +
                "\n-----END PUBLIC KEY-----";
		return pemFormatted;
	} 
}
