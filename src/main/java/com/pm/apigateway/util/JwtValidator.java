package com.pm.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Read-only JWT validator for the API Gateway.
 * Only loads the RSA public key — no token generation capability.
 * Validates JWT signature, expiry, issuer, and audience.
 */
@Slf4j
@Component
public class JwtValidator {

    private final PublicKey publicKey;
    private final String issuer;
    private final String audience;

    public JwtValidator(
            @Value("${jwt.public-key-path}") String publicKeyPath,
            @Value("${jwt.issuer:auth-service}") String issuer,
            @Value("${jwt.audience:patient-management}") String audience
    ) {
        this.publicKey = loadPublicKey(publicKeyPath);
        this.issuer = issuer;
        this.audience = audience;
    }

    /**
     * Validates the JWT token and extracts its claims.
     *
     * @param token the JWT token string (without "Bearer " prefix)
     * @return the parsed claims if validation succeeds
     * @throws JwtException if validation fails for any reason
     */
    public Claims validateAndExtractClaims(String token) {
        try {
            Claims claims = Jwts.parser().verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (!issuer.equals(claims.getIssuer()) || !claims.getAudience().contains(audience)) {
                log.warn("JWT validation failed because issuer or audience did not match expected values");
                throw new JwtException("JWT token has invalid issuer or audience");
            }

            return claims;
        } catch (ExpiredJwtException eje) {
            log.warn("JWT validation failed because token is expired");
            throw new JwtException("JWT token is expired", eje);
        } catch (MalformedJwtException mje) {
            log.warn("JWT validation failed because token is malformed");
            throw new JwtException("JWT token is malformed", mje);
        } catch (SignatureException se) {
            log.warn("JWT validation failed because token signature is invalid");
            throw new JwtException("JWT token signature is invalid", se);
        } catch (JwtException je) {
            log.debug("JWT parsing or validation failed", je);
            throw new JwtException("Invalid JWT token", je);
        }
    }

    private PublicKey loadPublicKey(String path) {
        try {
            String keyContent = Files.readString(Path.of(path));
            String keyPem = keyContent
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(keyPem);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            log.info("Successfully loaded RSA public key from: {}", path);
            return factory.generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to load RSA public key from: " + path, e);
        }
    }
}
