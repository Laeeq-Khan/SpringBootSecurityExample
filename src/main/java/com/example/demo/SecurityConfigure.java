package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AndRequestMatcher;

@EnableWebSecurity
public class SecurityConfigure extends WebSecurityConfigurerAdapter{

	@Override
	protected void configure(AuthenticationManagerBuilder auth ) {
		try {
			
			auth.inMemoryAuthentication()
			.withUser("laeeq")
			.password("123")
			.roles("USER")
			.and()
			.withUser("foo")
			.password("foo")
			.roles("ADMIN");
			
			
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println(e);
		}
	}
	
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	
	@Override
	public void configure(HttpSecurity http) {
		try {
			http.authorizeRequests()
			.antMatchers("/admin").hasRole("ADMIN")
			.antMatchers("/user").hasAnyRole("USER" , "ADMIN")
			.antMatchers("/").permitAll()
			.and().formLogin();
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
}
