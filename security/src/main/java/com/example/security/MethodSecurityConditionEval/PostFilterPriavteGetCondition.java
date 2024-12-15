package com.example.security.MethodSecurityConditionEval;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class PostFilterPriavteGetCondition {

	public boolean eval(String list) {
	return list.contains("1");
	}
}
