package com.capco.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static com.capco.gateway.application.AppConstant.ROLE_CLAIM;
import static com.capco.gateway.application.AppConstant.ROLE_PREFIX;

@Slf4j
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {


    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/auth/**").permitAll()
                        .anyExchange().authenticated()
                ).oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));

        return http.build();
    }

    private Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        JwtAuthenticationConverter delegate = new JwtAuthenticationConverter();
        delegate.setJwtGrantedAuthoritiesConverter(jwt -> {
            log.info("Converting JWT to Granted Authorities");
            log.info("JWT: {}", jwt.getClaims());
            Object rolesClaim = jwt.getClaims().get(ROLE_CLAIM);
            if (!(rolesClaim instanceof Collection<?> roles)) {
                return List.of();
            }
            return roles.stream()
                    .map(Object::toString)
                    .map(role -> role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toCollection(ArrayList::new));
        });
        return new ReactiveJwtAuthenticationConverterAdapter(delegate);
    }
}
