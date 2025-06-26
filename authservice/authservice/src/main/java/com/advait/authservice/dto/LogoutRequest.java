package com.advait.authservice.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotBlank;

public class LogoutRequest {
	
	@JsonProperty("refresh_token")
	@NotBlank(message = "Refresh token is required")
	private String refreshToken;

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}	
}
