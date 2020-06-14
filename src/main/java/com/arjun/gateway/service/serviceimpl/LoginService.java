package com.arjun.gateway.service.serviceimpl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import com.arjun.gateway.exception.CustomException;
import com.arjun.gateway.security.JwtTokenProvider;
import com.arjun.gateway.service.ILoginService;

@Service
public class LoginService implements ILoginService
{
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private AuthenticationManager authenticationManager;
    
//    @Autowired
//    private UserRepository userRepository;
    
//    @Autowired
//    private JwtTokenRepository jwtTokenRepository;

    @Override
    public String login(String username, String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username,
                    password));
            
//            User user = userRepository.findByEmail(username);
//            if (user == null || user.getRole() == null || user.getRole().isEmpty()) {
//                throw new CustomException("Invalid username or password.", HttpStatus.UNAUTHORIZED);
//            }
//            User user = new User();
            //NOTE: normally we dont need to add "ROLE_" prefix. Spring does automatically for us.
            //Since we are using custom token using JWT we should add ROLE_ prefix
//            String token =  jwtTokenProvider.createToken(username, user.getRole().stream()
//                    .map((Role role)-> "ROLE_"+role.getRole()).filter(Objects::nonNull).collect(Collectors.toList()));
            
            return "";

        } catch (AuthenticationException e) {
            throw new CustomException("Invalid username or password.", HttpStatus.UNAUTHORIZED);
        }
    }


    @Override
    public Boolean isValidToken(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    @Override
    public String createNewToken(String token) {
        String username = jwtTokenProvider.getUsername(token);
        List<String>roleList = jwtTokenProvider.getRoleList(token);
        String newToken =  jwtTokenProvider.createToken(username,roleList);
        return newToken;
    }
}