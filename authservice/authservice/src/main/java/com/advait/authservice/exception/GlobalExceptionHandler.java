package com.advait.authservice.exception;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.jsonwebtoken.MalformedJwtException;

@RestControllerAdvice
public class GlobalExceptionHandler {
	
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String,String>> handleValidationExceptions(MethodArgumentNotValidException ex){
		Map<String,String> errors = new HashMap<>();
		ex.getBindingResult().getFieldErrors().forEach(error ->
	        errors.put(error.getField(), error.getDefaultMessage())
	    );
		return ResponseEntity.status(HttpStatusCode.valueOf(403)).body(errors);
	}
	
	
	@ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> handleExtraJsonProps(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body("Unexpected or unknown fields in request.");
    }
	
	
	@ExceptionHandler(Exception.class)
	public ResponseEntity<String> handleGenericException(Exception ex) {

		ex.printStackTrace();

	    // Return a safe generic error to the client
	    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	            .body("Something went wrong");
	}
	
	@ExceptionHandler(RedundantUsernameException.class)
	public ResponseEntity<String> redundantUsername(RedundantUsernameException ex){
		return ResponseEntity.badRequest().body(ex.getMessage());
	}
	
	@ExceptionHandler(BadCredentialsException.class)
	public ResponseEntity<String> badCredentials(BadCredentialsException ex){
		return ResponseEntity.status(HttpStatusCode.valueOf(401)).body("Bad Credentials");
	}
	
	@ExceptionHandler(MalformedJwtException.class)
	public ResponseEntity<String> malformedJWT(MalformedJwtException ex){
		return ResponseEntity.status(HttpStatusCode.valueOf(403)).body("User not authenticated");
	}
	
}
