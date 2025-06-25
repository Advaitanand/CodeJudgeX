package com.advait.authservice.exception;

public class RedundantUsernameException extends Exception {
	
	private static final long serialVersionUID = 1364721938963141814L;
	
	public RedundantUsernameException(String message) {
		super(message);
	}
}
