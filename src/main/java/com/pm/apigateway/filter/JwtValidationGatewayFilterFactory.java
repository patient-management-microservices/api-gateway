package com.pm.apigateway.filter;

import com.pm.apigateway.util.JwtValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtValidationGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtValidationGatewayFilterFactory.Config> {

    private final JwtValidator jwtValidator;

    public JwtValidationGatewayFilterFactory(JwtValidator jwtValidator) {
        super(Config.class);
        this.jwtValidator = jwtValidator;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Request rejected: missing or malformed Authorization header");
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String token = authHeader.substring(7);

            try {
                Claims claims = jwtValidator.validateAndExtractClaims(token);

                String userId = claims.get("userId", String.class);
                String role = claims.get("role", String.class);
                String email = claims.getSubject();

                // RBAC: Check if a specific role is required for this route
                if (config.getRequiredRole() != null && !config.getRequiredRole().isBlank()) {
                    if (!config.getRequiredRole().equalsIgnoreCase(role)) {
                        log.warn("Access denied for userId={}, role={}, requiredRole={}",
                                userId, role, config.getRequiredRole());
                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        return exchange.getResponse().setComplete();
                    }
                }

                // Forward user claims as headers to downstream services
                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("X-User-Id", userId != null ? userId : "")
                        .header("X-User-Role", role != null ? role : "")
                        .header("X-User-Email", email != null ? email : "")
                        .build();

                log.debug("JWT validated successfully for userId={}, role={}", userId, role);
                return chain.filter(exchange.mutate().request(mutatedRequest).build());

            } catch (JwtException e) {
                log.warn("JWT validation failed: {}", e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        };
    }

    @Getter
    @Setter
    public static class Config {
        /**
         * Optional. If set, the filter will enforce that the JWT role claim
         * matches this value. Returns 403 Forbidden if the role does not match.
         */
        private String requiredRole;
    }
}
