package com.capco.gateway.security;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.stream.Collectors;

import static com.capco.gateway.application.AppConstant.CLIENT_TYPE_CLAIM;

@Slf4j
@Component
public class JwtToHeadersGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtToHeadersGatewayFilterFactory.Config> {

    public JwtToHeadersGatewayFilterFactory() {
        super(JwtToHeadersGatewayFilterFactory.Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) ->
                ReactiveSecurityContextHolder.getContext()
                        .mapNotNull(SecurityContext::getAuthentication)
                        .flatMap(authentication -> mutateExchangeWithAuth(exchange, chain, authentication, config));
    }

    private Mono<Void> mutateExchangeWithAuth(ServerWebExchange exchange,
                                              GatewayFilterChain chain,
                                              Authentication authentication,
                                              Config config) {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("Authentication is null or not authenticated. Skipping header mutation.");
            return chain.filter(exchange);
        }

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(req -> req.headers(headers -> {
                    addUserDetailsToHeaders(config, headers, authentication);
                    addRolesToHeaders(config, headers, authentication);
                    addClientTypeToHeaders(config, headers, authentication);
                })).build();
        return chain.filter(mutatedExchange);
    }

    private void addUserDetailsToHeaders(Config config, HttpHeaders headers, Authentication authentication) {
        if (config.isIncludeUsername()) {
            log.info("Adding user ID to headers: {}", authentication.getName());
            headers.set(config.getHeaderPrefix() + "Id", authentication.getName());
        }
    }

    private void addRolesToHeaders(Config config, HttpHeaders headers, Authentication authentication) {
        if (config.isIncludeRoles()) {
            log.info("Adding user roles to headers");
            String roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));
            headers.set(config.getHeaderPrefix() + "Roles", roles);
        }
    }

    private void addClientTypeToHeaders(Config config, HttpHeaders headers, Authentication authentication) {
        if (config.isIncludeClientType() && authentication instanceof JwtAuthenticationToken jwtAuth) {
            log.info("Adding user type to headers");
            Jwt jwt = jwtAuth.getToken();
            String clientTypeClaim = jwt.getClaimAsString(CLIENT_TYPE_CLAIM);
            headers.set(config.getHeaderPrefix() + "Type", clientTypeClaim);
        }
    }

    @Getter
    @Setter
    public static class Config {
        private boolean includeUsername = true;
        private boolean includeRoles = true;
        private boolean includeClientType = true;
        //    private boolean includeRawJwt = false;
        private String headerPrefix = "X-User-";
    }
}
