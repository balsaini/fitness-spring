package com.chyld.utilities;

import com.chyld.entities.Role;
import com.chyld.entities.User;
import com.chyld.security.JwtToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultJwtParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {
    private final String signingSecret;

    @Autowired
    public JwtUtil(@Value("${jwt.signing-secret}") String siginingSecret) {
        this.signingSecret = siginingSecret;
    }

    public String generateToken(User user) {
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put("user_id", user.getId());
        claims.put("roles", user.getRoles());

        LocalDate tenDaysFromNow = LocalDate.now().plusDays(10);
        Date expirationDate = DateUtil.toJavaDate(tenDaysFromNow);

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, signingSecret)
                .compact();
    }

    public JwtToken tokenFromStringJwt(String rawJwt) {
        DefaultJwtParser parser = ((DefaultJwtParser) Jwts.parser());
        parser.setSigningKey(signingSecret);

        Jws<Claims> jws = parser.parseClaimsJws(rawJwt);
        Claims claims = jws.getBody();
        Integer userId = (Integer)claims.get("user_id");
        String username = claims.getSubject();
        Collection<? extends GrantedAuthority> roles = (List<Role>)claims.get("roles");
        return new JwtToken(userId, username, roles);
    }
}
