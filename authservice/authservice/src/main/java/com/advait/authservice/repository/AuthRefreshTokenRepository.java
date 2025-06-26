package com.advait.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.advait.authservice.model.RefreshTokens;

@Repository
public interface AuthRefreshTokenRepository extends JpaRepository<RefreshTokens, Integer> {
	RefreshTokens findByUsername(String username);
	RefreshTokens findByToken(String token);
	void deleteByToken(String token);
	
	boolean existsByToken(String token);
}
