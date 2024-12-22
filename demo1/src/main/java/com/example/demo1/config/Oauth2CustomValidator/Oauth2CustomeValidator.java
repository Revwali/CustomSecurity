package com.example.demo1.config.Oauth2CustomValidator;

import java.util.function.Consumer;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public class Oauth2CustomeValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext>{

	@Override
	public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext t) {
		// TODO Auto-generated method stub
	RegisteredClient registeredClient =	t.getRegisteredClient();
	
		
	}

}
