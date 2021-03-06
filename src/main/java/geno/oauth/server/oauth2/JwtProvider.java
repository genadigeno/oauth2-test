package geno.oauth.server.oauth2;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import java.util.Date;

@Component
public class JwtProvider {

    @Value("${jwt.token.secret.key}")
    private String jwtSecret;

    @Value("${jwt.token.expiration}")
    private int jwtExpiration;

    public String generateJwtToken(Authentication authentication) {

        return Jwts.builder()
                .setSubject((authentication.getName()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpiration*1000))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public boolean validateJwtToken(String authToken, HttpServletResponse response) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            String username = getUserNameFromJwtToken(authToken);
            if (response != null && expiresIn15Secs(getExpiration(authToken))){
                String newToken = generateNewToken(username);
                response.setHeader("access_token", newToken);
            }

            return true;
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    public String getUserNameFromJwtToken(String token){
        String subject = "";
        try {
            subject = Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .parseClaimsJws(token)
                    .getBody().getSubject();
        }
        catch (ExpiredJwtException e){
            e.printStackTrace();
        }

        return subject;
    }

    private Date getExpiration(String token){
        Date expirationDate = null;
        try {
            expirationDate = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getExpiration();
        }
        catch (NullPointerException e){
            e.printStackTrace();
        }

        return expirationDate;
    }

    private boolean expiresIn15Secs(Date date){
        if (date == null){
            return true;
        }
        Date now = new Date();
        Long currentTimeStamp = now.getTime();
        Long tokenExpiration  = date.getTime();

        return (tokenExpiration - currentTimeStamp) < 60000;
    }

    private String generateNewToken(String whom){
        Date newExpirationDate = new Date((new Date()).getTime() + jwtExpiration*1000);
        String newToken = Jwts.builder().setSubject(whom)
                                        .setExpiration(newExpirationDate)
                                        .signWith(SignatureAlgorithm.HS512, jwtSecret)
                                        .compact();
        return newToken;
    }
}
