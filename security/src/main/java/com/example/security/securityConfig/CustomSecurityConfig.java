package com.example.security.securityConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.example.security.securityFilter.CustomAuthenticationFilterKey;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class CustomSecurityConfig {
	
	//@Autowired
	//private CustomAuthenticationFilterKey authenticationFilter;
	@Value("key")
	private String key;
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {
		 return security.httpBasic().and().csrf().disable()
		          .addFilterBefore(new CustomAuthenticationFilterKey(key), BasicAuthenticationFilter.class)
		        .authorizeHttpRequests().
		       requestMatchers(HttpMethod.GET, "/test/**").hasAuthority("read").
		        requestMatchers("/private").hasAuthority("write").
		        anyRequest().permitAll().and().exceptionHandling(
		                e -> e.authenticationEntryPoint(
		                        new LoginUrlAuthenticationEntryPoint("/login")
		                    )
		                )
		        .build();
		/*
		 * return security.authorizeRequests().requestMatchers("/public").permitAll().
		 * and().httpBasic().and().addFilterBefore(authenticationFilter,
		 * BasicAuthenticationFilter.class).
		 * authorizeRequests().anyRequest().authenticated().and() .formLogin().and().
		 * build();
		 */
	}
	
	@Bean
	public UserDetailsService getUserDetails() {
		var manager = new InMemoryUserDetailsManager();
		var u1 = User.withUsername("raju").password(getPasswordEncoder().encode("INDIA")).authorities("read","1").build();
		var u2 = User.withUsername("raj").password(getPasswordEncoder().encode("INDIA")).authorities("write","2").build();
		var u3 = User.withUsername("admin").password(getPasswordEncoder().encode("INDIA")).authorities("read","write").build();
		manager.createUser(u1);
		manager.createUser(u2);
		manager.createUser(u3);
		return manager;
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
