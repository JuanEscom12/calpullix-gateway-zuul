package com.arjun.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private static final String LOGIN_PATH = "/calpullix/login/**";
	
	private static final String RESTART_PASSWORD_PATH = "/calpullix/restartpassword/**";
	
	private static final String CHANGE_PASSWORD_PATH = "/calpullix/change-password/**";
	
	private static final String REGISTER_USER_PATH = "/calpullix/register/user/**";
	
	private static final String EUREKA_PATH = "/eureka/**";
	
	private static final String ACTUATOR_PATH = "/actuator/**";
	
	private static final String PATH_BASIS_HYSTRIX = "/hystrix/**";
	
	private static final String WILDCART_PATH = "/**";
	
	private static final String SINGLE_WILDCART_PATH = "/*/";
	
	private static final int LENGTH_PASS_ENCODER = 12;
	
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
         http.cors().and().csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests()
                .antMatchers(LOGIN_PATH, 
                		REGISTER_USER_PATH, 
                		CHANGE_PASSWORD_PATH, 
                		RESTART_PASSWORD_PATH).permitAll()
                .anyRequest().authenticated();

        http.apply(new JwtTokenFilterConfigurer(jwtTokenProvider));
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
        		.antMatchers(SINGLE_WILDCART_PATH)
                .antMatchers(EUREKA_PATH)
                .antMatchers(ACTUATOR_PATH)
                .antMatchers(PATH_BASIS_HYSTRIX)
                .antMatchers(HttpMethod.OPTIONS, WILDCART_PATH);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(LENGTH_PASS_ENCODER);
    }

    @Bean
    public AuthenticationManager customAuthenticationManager() throws Exception {
        return authenticationManager();
    }
}
