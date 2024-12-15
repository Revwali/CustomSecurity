package com.example.security.SecurityManager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.example.security.SecurityProvider.CustomAuthenticationProvider;

import lombok.AllArgsConstructor;

//@Component
//@AllArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {

//	@Autowired
	private String key;
	
	public CustomAuthenticationManager(String key) {
		super();
		this.key = key;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// TODO Auto-generated method stub
		CustomAuthenticationProvider provider = new CustomAuthenticationProvider(key);
		if(provider.supports(authentication.getClass())) {
			return provider.authenticate(authentication);
		}
		return authentication;
	}

}
