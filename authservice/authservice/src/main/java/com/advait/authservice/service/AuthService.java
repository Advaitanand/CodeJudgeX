package com.advait.authservice.service;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.advait.authservice.dto.LoginResponse;
import com.advait.authservice.dto.LogoutRequest;
import com.advait.authservice.dto.RefreshTokenRequest;
import com.advait.authservice.dto.RefreshTokenResponse;
import com.advait.authservice.exception.InvalidRefreshTokenException;
import com.advait.authservice.exception.RedundantUsernameException;
import com.advait.authservice.exception.RefreshTokenExpiredException;
import com.advait.authservice.exception.UnauthorizedAccessException;
import com.advait.authservice.model.RefreshTokens;
import com.advait.authservice.model.Users;
import com.advait.authservice.repository.AuthRefreshTokenRepository;
import com.advait.authservice.repository.AuthUserRepository;
import com.advait.authservice.utility.RefreshTokenHasher;

@Service
public class AuthService {
	
	private final int REFRESH_TOKEN_EXPIRY = 60*60*24*15;
	
	@Autowired
	private BCryptPasswordEncoder encoder;
	
	@Autowired
	private AuthUserRepository authUserRepo;
	
	@Autowired
	private AuthRefreshTokenRepository authRefreshTokenRepo;
	
	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private AuthJWTService jwtService;
	
	@Autowired
	private PublicKey publicKey;
	
	@Autowired
	private RefreshTokenHasher refreshTokenHasher;
	
	public String registerUsers(Users users) throws RedundantUsernameException {
		
		if(authUserRepo.existsByUsername(users.getUsername())) {
			throw new RedundantUsernameException("Username already exists");
		}
		
		users.setPassword(encoder.encode(users.getPassword()));
		authUserRepo.save(users);
		return "User registered successfully";
	}
	
	public LoginResponse verify(Users user) {
		
		Authentication authenticated = authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
		LoginResponse response = new LoginResponse();
		if(authenticated.isAuthenticated()) {
			
			response.setAccessToken(jwtService.generateToken(user.getUsername()));
			response.setRefreshToken(generateRefreshToken());
			response.setAccessTokenExpiry(jwtService.extractExpirationDate(response.getAccessToken()));
			
			insertRefreshToken(response.getRefreshToken(), user.getUsername());
		
		}
		return response;
	}

	public String getPublicKey() {
		String pemFormatted = "-----BEGIN PUBLIC KEY-----\n" +
				Base64.getEncoder().encodeToString(publicKey.getEncoded()).replaceAll("(.{64})", "$1\n") +
                "\n-----END PUBLIC KEY-----";
		return pemFormatted;
	} 
	
	public String generateRefreshToken() {
		SecureRandom secureRandom = new SecureRandom();
		byte[] tokenBytes = new byte[64];
		secureRandom.nextBytes(tokenBytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
	}

	@Transactional
	public RefreshTokenResponse refresh(RefreshTokenRequest request) throws RefreshTokenExpiredException, InvalidRefreshTokenException {
		RefreshTokenResponse response = new RefreshTokenResponse();
		
		RefreshTokens refreshTokensFromDb = authRefreshTokenRepo.findByToken(refreshTokenHasher.hashRefreshToken(request.getRefreshToken()));
		if (refreshTokensFromDb == null) {
		    throw new InvalidRefreshTokenException("Invalid token");
		}
			
		if(refreshTokensFromDb.getExpiresAt().isBefore(Instant.now())) {
			throw new RefreshTokenExpiredException("Refresh token is expired");
		}
		
		authRefreshTokenRepo.delete(refreshTokensFromDb);
		
		response.setAccessToken(jwtService.generateToken(refreshTokensFromDb.getUsername()));
		response.setRefreshToken(generateRefreshToken());
		
		insertRefreshToken(response.getRefreshToken(), refreshTokensFromDb.getUsername());
		
		return response;
	}
	
	private void insertRefreshToken(String token, String username) {
		
		RefreshTokens refreshToken = new RefreshTokens();
		refreshToken.setGeneratedAt(Instant.now());
		refreshToken.setToken(refreshTokenHasher.hashRefreshToken(token));
		refreshToken.setUsername(username);
		refreshToken.setExpiresAt(Instant.now().plusSeconds(REFRESH_TOKEN_EXPIRY));
		
		authRefreshTokenRepo.save(refreshToken);
		
	}

	public void logout(LogoutRequest request) throws UnauthorizedAccessException {
		RefreshTokens token = authRefreshTokenRepo.findByToken(refreshTokenHasher.hashRefreshToken(request.getRefreshToken()));
		
		if(token==null) {
			return;
		}
		
		if(token.getUsername().equals(SecurityContextHolder.getContext().getAuthentication().getName())) {
			throw new UnauthorizedAccessException("Refresh Token does no belong to the current user");
		}
		
		authRefreshTokenRepo.delete(token);
	}
}
