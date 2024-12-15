package com.example.security.MethodSecurityConditionEval;

import java.util.List;
import java.util.function.Predicate;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component 
public class TestPriavteGetPreAuthCond {

	public boolean name(List<String> list) {
		/*	var authorities = SecurityContextHolder.getContext().getAuthentication().getAuthorities().iterator();
			while(authorities.hasNext()) {
			if(authorities.next().toString().equals("read"))return true;
			}
				*/
		for(String s : list) System.out.println("insisde pre auth "+s);
		list.clear();
		
		return true;
	}
}
