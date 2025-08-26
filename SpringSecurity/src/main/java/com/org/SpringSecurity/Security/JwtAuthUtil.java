package com.org.SpringSecurity.Security;

import com.org.SpringSecurity.Model.AuthProviderType;
import com.org.SpringSecurity.Model.Users;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Service
public class JwtAuthUtil {


    private final SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    private SecretKey getSecreteKey() {
        return secretKey;
    }

    public String generateToken(Users user) {
        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + (60*60*30)))
                .and()
                .signWith(getSecreteKey())
                .compact();
    }



    public String extractUserName(String token) {
        return  extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return  claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return  Jwts.parser()
                .verifyWith(getSecreteKey())
                .build().
                parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return  (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public  boolean isTokenExpired(String token){
            return extractExpiration(token).before(new Date());
    }
    public Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
    }

    public AuthProviderType getProviderTypeFromRegistrationId(String registrationId){
        return  switch(registrationId.toLowerCase()){
            case "google" -> AuthProviderType.GOOGLE;
            case "github" -> AuthProviderType.GITHUB;
            default -> throw new IllegalStateException("Unexpected value: " + registrationId.toLowerCase());
        };
    }

    public String determineProviderIdFromOAuth2User(OAuth2User oAuth2User, String registrationId) {
        String providerId = switch (registrationId.toLowerCase()){
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("id").toString();
            default -> {
                log.error("unable to determmine the oAuth2 provider {}", registrationId);
                throw new IllegalStateException("Unexpected value: " + registrationId.toLowerCase());
            }
        };
        if (providerId == null || providerId.isBlank()){
            log.error("unable to determine providerId for the provider :" , registrationId);
            throw new IllegalArgumentException("unable to determine the providerId for oAuth2.0 login");
        }
        return  providerId;
    }

    // to get the Username
    public String determineUsernameFromOAuth2User(OAuth2User oAuth2User, String registrationId, String providerId) {
        String email = oAuth2User.getAttribute("email");
        if(email != null && !email.isBlank()){
            return  email;
        }
        return switch (registrationId.toLowerCase()){
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("login");
            default -> providerId;
        };
    }
}
