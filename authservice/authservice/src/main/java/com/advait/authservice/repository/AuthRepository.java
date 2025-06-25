package com.advait.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.advait.authservice.model.Users;

@Repository
public interface AuthRepository extends JpaRepository<Users, Integer>{
	Users findByUsername(String username);

	boolean existsByUsername(String username);
}
