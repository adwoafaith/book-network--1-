package com.faith.book.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service

public class JwtService {
    private static final String SECRET_KEY = "zBlV93yCqGoVsp1c2o3XmOAGRup8Bbo1bbJXpIqnTnMZ4kluOszCapG5k+Mfayf4";

    public String extractUsername(String token) {
        //in other to extrat stuff from the token we need to include it in our dependencies
        // dependencies like (jjwt-api, jjwt-impl,jjwt-jackson ) all has a groupid of io.jsonwebtoken
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //generating a token from the user details itself without extracting claims
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
       return Jwts
               .builder()
               .setClaims(extraClaims)
               .setSubject(userDetails.getUsername())
               .setIssuedAt(new Date(System.currentTimeMillis()))
               .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
               .signWith(getSignInKey(), SignatureAlgorithm.HS256)
               .compact(); //compact will generate and return the token
    }

        //validate token
    public boolean isTokenvalid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //lets extract all the claims from the signature
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())  //signin key is used to create the signature  part of a jwt to verify that the sender of the jwt is who they claim they are
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
       byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
       return Keys.hmacShaKeyFor(keyBytes);
    }


}



//in other to get or decode the jwt we
//consist of 3part

//first part
//the header, payload and signature
// Header(2parts) -- the type of token(which is jwt) and the signin algorithm used(RSA)

//second part
//payload(claims)
//claims are statements related to the user typically who is requesting for what access
//example
///"sub":"kaa-ayi"
//name: "kaa-ayi configuaration"
//Authorities:[
//"Admin",
//"Manager"
//]

//There are 3 types of claims
//registered claims- a set of predefined claims which are not mandatory but recommended to provide a set of useful and repeatable
//claims some of the registered claims are ISSv or the issuer, the subject, exp
//private claims - they are custom claims created to share information between parties that agree using them
// public claims -- they are public by nature

//third part
//signature- it is used to verify the sender of the jwt is who they claim they are and to ensure that the message
//isn't changed along the way
