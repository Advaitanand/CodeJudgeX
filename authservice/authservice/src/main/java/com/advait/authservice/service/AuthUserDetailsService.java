package com.advait.authservice.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.advait.authservice.model.UserPrincipal;
import com.advait.authservice.model.Users;
import com.advait.authservice.repository.AuthRepository;

@Service
public class AuthUserDetailsService implements UserDetailsService{
	
	@Autowired
	private AuthRepository repository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		Users user = repository.findByUsername(username);
		
		if(user == null) {
			System.out.println("User not found!");
			throw new UsernameNotFoundException(username + "not found!");
		}
		
		return new UserPrincipal(user);
	}
}
