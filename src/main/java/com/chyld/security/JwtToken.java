package com.chyld.security;

import io.jsonwebtoken.lang.Assert;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtToken implements Authentication {

    private final String username;
    private final Collection<? extends GrantedAuthority> roles;
    private final Integer userId;
    private boolean authenticated;

    public JwtToken(Integer userId, String username, Collection<? extends GrantedAuthority> authorities) {
        this.userId = userId;
        this.username = username;
        this.roles = authorities;
        this.authenticated = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {return roles;}

    @Override
    public Object getCredentials() {return null;}

    @Override
    public Object getDetails() {return null;}

    @Override
    public Object getPrincipal() {return true;}

    @Override
    public boolean isAuthenticated() {return authenticated;}

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {this.authenticated = isAuthenticated;}

    @Override
    public String getName() {return username;}
    public Integer getUserId() {return userId;}
}
