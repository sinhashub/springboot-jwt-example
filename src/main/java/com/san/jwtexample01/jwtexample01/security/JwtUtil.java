package com.san.jwtexample01.jwtexample01.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Date;
//Handles everything related to JWT token generation, validation, and parsing.
@Component
public class JwtUtil {

    private final String SECRET = "mysecretkeymysecretkeymysecretkey123"; // at least 256-bit
    private final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour



    private final Key key = Keys.hmacShaKeyFor(SECRET.getBytes());

    // Creates a JWT token with subject (username), issue time, expiry, and signs it with a secret key.
    public String generateToken(String username){
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
// Extracts the username (subject) from the JWT token
    public String extractUsername(String token){
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getSubject();
    }
//Checks if the token is valid (not expired or tampered with).
// Why needed?
//JWT allows stateless authentication — users authenticate once, then use the token to access secure resources.
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

}
