package com.advait.authservice.exception;

public class RefreshTokenExpiredException extends Exception {

	private static final long serialVersionUID = 2415789272883664701L;
	
	public RefreshTokenExpiredException(String message) {
		super(message);
	}
	
}
