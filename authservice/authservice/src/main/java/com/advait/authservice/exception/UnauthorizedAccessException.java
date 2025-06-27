package com.advait.authservice.exception;

public class UnauthorizedAccessException extends Exception {

	private static final long serialVersionUID = -7925979612547404933L;

	public UnauthorizedAccessException(String message) {
		super(message);
	}
	
}
