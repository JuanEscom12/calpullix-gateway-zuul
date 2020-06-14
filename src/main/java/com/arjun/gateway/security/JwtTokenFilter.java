package com.arjun.gateway.security;

import com.arjun.gateway.exception.CustomException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;

import org.apache.commons.lang.BooleanUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtTokenFilter extends GenericFilterBean {
	
	private static final String LOGIN_PATH = "/calpullix/login";
	
	private static final String LOGIN_TOKEN_PATH = "/calpullix/login/token";
	
	private static final String RESTART_PASSWORD_PATH = "/calpullix/restartpassword";
	
	private static final String CHANGE_PASSWORD_PATH = "/calpullix/change-password";
	
	private static final String REGISTER_USER_PATH = "/calpullix/register/user";

	
    private JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException {
    	log.info(":: Filter {} ", req);
    	final String path = ((HttpServletRequest) req).getRequestURI();
    	if (path.equals(LOGIN_PATH) || path.equals(RESTART_PASSWORD_PATH) || 
    		path.equals(CHANGE_PASSWORD_PATH) || path.equals(REGISTER_USER_PATH) ||
    		path.equals(LOGIN_TOKEN_PATH)) {
    		filterChain.doFilter(req, res);
    		return;
    	}

        final HttpServletResponse response = (HttpServletResponse) res;
        final String token = jwtTokenProvider.resolveToken((HttpServletRequest) req);
        log.info(":: TOKEN {} {} ", token, ((HttpServletRequest) req).getRequestURI());
        if (BooleanUtils.negate(token == null)) {
        	
            try {
                jwtTokenProvider.validateToken(token) ;
            } catch (JwtException | IllegalArgumentException e) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"Invalid JWT token");
                throw new CustomException("Invalid JWT token",HttpStatus.UNAUTHORIZED);
            }
            
            final String userName = jwtTokenProvider.getUsernameFromToken(token);
            log.info(":: User Name Token {} ", userName);
            
            final Authentication auth = BooleanUtils.negate(token == null) ? jwtTokenProvider.getAuthentication(token) : null;
            //setting auth in the context.
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(req, res);
    }
    
    
}
