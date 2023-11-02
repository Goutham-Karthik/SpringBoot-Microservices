package com.goutham.shopping.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String secretKey = "cdac5d8528e94b399e1638df46a5d6ba4a27d1148a4356549d39c77ab722b404";


    // this is used to extract the username from the claims
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // this is to extract one single claims from the all the other claims
    public <T>  T extractClaim(String token, Function<Claims,T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    // this is to extract all claims from the token
    private Claims extractAllClaims(String token){
        return Jwts.parser().setSigningKey(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getBody();
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }
    public String generateToken(Map<String, Object> extractClaims,
    UserDetails userDetails){

        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    // validate the token username and the token expiry matches
    public boolean isTokenValid(String token, UserDetails userDetails){
        return (extractUsername(token).equals(userDetails.getUsername()) && extractClaim(token, Claims::getExpiration).before(new Date()));
    }

    // this key is unique to a individual user ... which is used to verify that this is the user trying to access and  verify
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
