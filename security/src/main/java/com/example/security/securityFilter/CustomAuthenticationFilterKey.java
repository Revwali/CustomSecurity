package com.example.security.securityFilter;

import java.io.IOException;

import org.apache.tomcat.websocket.AuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.security.SecurityManager.CustomAuthenticationManager;
import com.example.security.customAuthentication.CustomAuthentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
//@Component
//@AllArgsConstructor
public class CustomAuthenticationFilterKey extends OncePerRequestFilter {

	//@Autowired
	private String key;
	
	public CustomAuthenticationFilterKey(String key) {
		super();
		this.key = key;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException{
		var hkey = request.getHeader("key");
		if(hkey==null || hkey.equals("null")) {
			filterChain.doFilter(request, response);
		}
		else {
		CustomAuthenticationManager manager = new CustomAuthenticationManager(key);
		var auth = manager.authenticate(new CustomAuthentication(hkey,false));
		if(auth.isAuthenticated()) {
			SecurityContextHolder.getContext().setAuthentication(auth);
			filterChain.doFilter(request, response);
		}
		else response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		}
	}

}
