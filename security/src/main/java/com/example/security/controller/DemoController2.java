package com.example.security.controller;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.security.MethodSecurityConditionEval.PostFilterPriavteGetCondition;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.websocket.server.PathParam;

@RestController
@RequestMapping("/test")
public class DemoController2 {
	@Autowired
	PostFilterPriavteGetCondition condition;

	@PostMapping("/priavte")
	public String getPriavte(@RequestParam(required = false) String d) {
		return "done";
	}

	@GetMapping("/priavte/")
	//@PreAuthorize("@testPriavteGetPreAuthCond.name(#list)")
	 //@PostFilter("filterObject.contains('1')")
	@PostFilter("@postFilterPriavteGetCondition.eval(filterObject)")
	public List<List<String>> getPublic(@RequestBody(required = false) List<List<String>> list) {
		return list.stream().map(c->c.stream().filter( s -> condition.eval(s)).collect(Collectors.toList())).collect(Collectors.toList());
	}
}
