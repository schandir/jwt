package com.nathan.auth0;

import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JWTDecode {

    private static final String SECRET = "jake";
    private static final String ISSUER = "Nathan";
    private static final String SUBJECT = "My JWT Test";
    private static final long TOKEN_VALIDITY_IN_MILLIS = 500L;

    private static Algorithm algorithm;
    private static JWTVerifier verifier;

    public static void initialize() {
        algorithm = Algorithm.HMAC256(SECRET);

        verifier = JWT.require(algorithm)
          .withIssuer(ISSUER)
          .build();
    }

    private static String createJWT() {
        String jwtToken = JWT.create()
          .withIssuer(ISSUER)
          .withSubject(SUBJECT)
          .withIssuedAt(new Date())
          .withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_VALIDITY_IN_MILLIS))
          .sign(algorithm);

        return jwtToken;
    }

    private static DecodedJWT verifyJWT(String jwtToken) {
        try {
            DecodedJWT decodedJWT = verifier.verify(jwtToken);
            return decodedJWT;
        } catch (JWTVerificationException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    private static DecodedJWT decodedJWT(String jwtToken) {
        try {
            DecodedJWT decodedJWT = JWT.decode(jwtToken);
            return decodedJWT;
        } catch (JWTDecodeException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    private static boolean isJWTExpired(DecodedJWT decodedJWT) {
        Date expiresAt = decodedJWT.getExpiresAt();
        return expiresAt.before(new Date());
    }

    public static void main(String args[]) throws InterruptedException {

        initialize();

        String jwtToken = createJWT();
        //jwtToken = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJOYXRoYW4iLCJzdWIiOiJNeSBKV1QgVGVzdCIsIm5hbWUiOiJOYXRoYW4gQ2hhbmRpciIsInNjb3BlIjoiYWRtaW5zIiwiaWF0IjoxNDY2Nzk2ODIyLCJleHAiOjQ2MjI0NzA0MjJ9.u5qiIjtAX2U7TWTPlaXZvtIQxNG4OJv7YuRxoBCQprI";
        System.out.println("Created JWT : " + jwtToken);

        Thread.sleep(1000L);

        DecodedJWT decodedJWT = verifyJWT(jwtToken);
        if (decodedJWT == null) {
            System.out.println("JWT Verification Failed");
        }

        decodedJWT = decodedJWT(jwtToken);
        if (decodedJWT != null) {
            System.out.println("Token Issued At : " + decodedJWT.getIssuedAt());
            System.out.println("Token Expires At : " + decodedJWT.getExpiresAt());
            System.out.println("Subject : " + decodedJWT.getSubject());
            System.out.println("Header : " + decodedJWT.getHeader());
            System.out.println("Payload : " + decodedJWT.getPayload());
            System.out.println("Signature : " + decodedJWT.getSignature());
            System.out.println("Algorithm : " + decodedJWT.getAlgorithm());
            System.out.println("JWT Id : " + decodedJWT.getId());

            Boolean isExpired = isJWTExpired(decodedJWT);
            System.out.println("Is Expired : " + isExpired);
        }
    }

}
