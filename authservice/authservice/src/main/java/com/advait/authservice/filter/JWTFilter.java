package com.advait.authservice.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.advait.authservice.service.AuthJWTService;
import com.advait.authservice.service.AuthUserDetailsService;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTFilter extends OncePerRequestFilter{
	
	private final String BEARER_PREFIX = "Bearer ";
	
	@Autowired
	private AuthUserDetailsService userDetailsService;
	
	@Autowired
	private AuthJWTService authJwtService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String authHeader = request.getHeader("Authorization");
		
		if(authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
			filterChain.doFilter(request, response);
			return;
		}
		
		String token = authHeader.substring(BEARER_PREFIX.length());
		
		try {
			
			String username = authJwtService.getUsernameFromJwtToken(token);
			
			if(username == null || SecurityContextHolder.getContext().getAuthentication()==null) {
				
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				
				if(authJwtService.validateToken(token,userDetails)) {
					UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
					authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				    SecurityContextHolder.getContext().setAuthentication(authentication);
				}
				
			}else {
				throw new JwtException("Missing subject claim");
			}
		} catch (UsernameNotFoundException ex) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("User not found!");
            return;
		} catch (MalformedJwtException ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid JWT token");
            return;
        } catch (JwtException ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("JWT token validation failed");
            return;
        }
		
		filterChain.doFilter(request, response);
		
	}
	
}
