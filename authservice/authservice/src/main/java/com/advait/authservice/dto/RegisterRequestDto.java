package com.advait.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class RegisterRequestDto {
	@Pattern(regexp = "^[a-zA-Z0-9_]{3,30}$", message = "Username can only contain letters, numbers and underscores")
	@NotBlank(message = "Username cannot be empty")
	private String username;
	
	@Size(min = 6, message = "Password must be at least 6 characters")
	@NotBlank(message = "Password cannot be empty")
	private String password;
	
	@Email(message = "Invalid email format")
	@NotBlank(message = "Email is required")
	private String email;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}
}
