package com.advait.authservice.exception;

public class InvalidRefreshTokenException extends Exception {

	private static final long serialVersionUID = 7857749703511550143L;

	public InvalidRefreshTokenException(String message) {
		super(message);
	}
}
