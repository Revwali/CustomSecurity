package com.example.security.SecurityProvider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.example.security.customAuthentication.CustomAuthentication;

import lombok.AllArgsConstructor;
//@Component

public class CustomAuthenticationProvider implements AuthenticationProvider {

	
	private String key;
	
	public CustomAuthenticationProvider(String key) {
		super();
		this.key = key;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// TODO Auto-generated method stub
		CustomAuthentication  auth = (CustomAuthentication) authentication;
		if(key.equals(auth.getKey())) {
			auth.setAuthenticated(true);
			return auth;
		}
		throw new BadCredentialsException("not authorized inavalid user");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		return CustomAuthentication.class.equals(authentication);
	}

}
