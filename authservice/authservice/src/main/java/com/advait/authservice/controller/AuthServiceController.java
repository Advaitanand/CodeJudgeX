package com.advait.authservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.advait.authservice.dto.LoginRequestDto;
import com.advait.authservice.dto.RegisterRequestDto;
import com.advait.authservice.exception.RedundantUsernameException;
import com.advait.authservice.model.UserPrincipal;
import com.advait.authservice.model.Users;
import com.advait.authservice.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthServiceController {
	
	@Autowired
	private AuthService service;
	
	@GetMapping("/hello")
	public String hello(HttpServletRequest request) {
		var auth = SecurityContextHolder.getContext().getAuthentication();
	    if (auth != null && auth.getPrincipal() instanceof UserPrincipal user) {
	        return "Hello " + user.getUsername() + ", email: " + user.getEmail();
	    }
	    return "Hello Guest";
	}
	
	@PostMapping("/register")
	public String register(@Valid @RequestBody RegisterRequestDto registerRequest) throws RedundantUsernameException {
		Users user = new Users();
		user.setEmail(registerRequest.getEmail());
		user.setUsername(registerRequest.getUsername());
		user.setPassword(registerRequest.getPassword());
		return service.registerUsers(user);
	}
	
	@PostMapping("/login")
	public String login(@Valid @RequestBody LoginRequestDto loginRequest) {
		Users user = new Users();
		user.setUsername(loginRequest.getUsername());
		user.setPassword(loginRequest.getPassword());
		return service.verify(user);
	}
	
	@GetMapping("/public-key")
	public String getPublicKey() {
		return service.getPublicKey();
	}
}
