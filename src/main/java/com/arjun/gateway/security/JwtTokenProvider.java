package com.arjun.gateway.security;

import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.BooleanUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.arjun.gateway.bean.auth.MongoUserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


@Component
public class JwtTokenProvider {
	
    private static final String AUTH = "auth";
    
    private static final String BEARER_PREFIX = "Bearer ";
        
    @Value("${jwt.secret-key}")
    private String secretKey;
    
    private long validityInMilliseconds = 3600000;

    
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createToken(String username, List<String> roles) {
        final Claims claims = Jwts.claims().setSubject(username);
        claims.put(AUTH,roles);

        final Date validity = 
        		new Date(Calendar.getInstance().getTime().getTime() + validityInMilliseconds);

        String token =  Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();

        return token;
    }

 	public String getUsernameFromToken(String token) {
 		return getClaimFromToken(token, Claims::getSubject);
 	}

 	public Date getExpirationDateFromToken(String token) {
 		return getClaimFromToken(token, Claims::getExpiration);
 	}

 	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
 		final Claims claims = getAllClaimsFromToken(token);
 		return claimsResolver.apply(claims);
 	}

 	private Claims getAllClaimsFromToken(String token) {
 		return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
 	}
 	
    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7, bearerToken.length());
        } else if (BooleanUtils.negate(bearerToken == null)) {
            return bearerToken;
        }
        return null;
    }

    public boolean validateToken(String token) throws JwtException,IllegalArgumentException{
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return Boolean.TRUE;
    }
    
    public UserDetails getUserDetails(String token) {
        String userName =  getUsername(token);
        List<String> roleList = getRoleList(token);
        UserDetails userDetails = new MongoUserDetails(userName,roleList.toArray(new String[roleList.size()]));
        return userDetails;
    }
    
    @SuppressWarnings("unchecked")
	public List<String> getRoleList(String token) {
        return (List<String>) Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).
                getBody().get(AUTH);
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }
    
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = getUserDetails(token);
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

}
