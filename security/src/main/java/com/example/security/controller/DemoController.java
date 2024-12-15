package com.example.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
public class DemoController {

	@GetMapping("/private")
	public String getPrivate() {
		return "success";
	}
	@GetMapping("/public")
	public ModelAndView getMethodName() {
		
		var v = new ModelAndView();
		v.setViewName("home.html");
		return v;
	}
	
}
