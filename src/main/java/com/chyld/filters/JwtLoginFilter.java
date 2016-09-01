package com.chyld.filters;

import com.chyld.dtos.AuthDto;
import com.chyld.utilities.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import com.chyld.entities.*;
import com.chyld.services.UserService;

public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final UserService userService;

    public JwtLoginFilter(UserService userService, String defaultFilterProcessesUrl, JwtUtil jwtUtil, UserDetailsService userDetailsService, AuthenticationManager authManager) {
        super(defaultFilterProcessesUrl);

        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        setAuthenticationManager(authManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        final AuthDto auth = new ObjectMapper().readValue(request.getInputStream(), AuthDto.class);
        final UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(auth.getUsername(), auth.getPassword());
        Authentication value = null;
        User ud = null;
        boolean isadmin = false;
        try {
            value = getAuthenticationManager().authenticate(authToken);
        } catch (AuthenticationException ae){
            System.err.println("AuthenticationException: " + ae.getMessage());
            ud = (User) userService.loadUserByUsername(auth.getUsername());

            if ( ud != null ) {
                if ( ud.getLoginAttempts() > 2 ) {
                    if ( !ud.isAdmin() ) {
                        ud.setEnabled(false);
                    } else {
                        ud.setLoginAttempts();
                    }
                } else {
                    ud.setLoginAttempts();
                    if( ud.getLoginAttempts() == 3 && !ud.isAdmin() ) {
                        ud.setEnabled(false);
                    }
                }
                userService.saveUser(ud);
            }


        }

        return value;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
        User authenticatedUser = (User) userDetailsService.loadUserByUsername(authResult.getName());
        String token = jwtUtil.generateToken(authenticatedUser);
        response.setHeader("Authorization", "Bearer " + token);
        SecurityContextHolder.getContext().setAuthentication(jwtUtil.tokenFromStringJwt(token));
    }
}
