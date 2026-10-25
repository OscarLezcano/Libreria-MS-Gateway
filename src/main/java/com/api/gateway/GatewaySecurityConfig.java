package com.api.gateway;

import java.nio.charset.StandardCharsets;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.StringUtils;

import reactor.core.publisher.Mono;

@Configuration
public class GatewaySecurityConfig {

	@Bean
	SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
			ServerAuthenticationConverter cookieBearerTokenConverter,
			@Value("${gateway.security.public-paths}") String[] publicPaths) {
		return http
				.csrf(ServerHttpSecurity.CsrfSpec::disable)
				.authorizeExchange(exchange -> exchange
						.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						.pathMatchers(publicPaths).permitAll()
						.anyExchange().authenticated())
				.oauth2ResourceServer(resourceServer -> resourceServer
						.bearerTokenConverter(cookieBearerTokenConverter)
						.jwt(Customizer.withDefaults()))
				.build();
	}

	@Bean
	ServerAuthenticationConverter cookieBearerTokenConverter() {
		ServerBearerTokenAuthenticationConverter headerConverter = new ServerBearerTokenAuthenticationConverter();
		return exchange -> headerConverter.convert(exchange)
				.switchIfEmpty(Mono.defer(() -> {
					HttpCookie cookie = exchange.getRequest().getCookies().getFirst("token");
					if (cookie == null || !StringUtils.hasText(cookie.getValue())) {
						return Mono.empty();
					}
					return Mono.just((Authentication) new BearerTokenAuthenticationToken(cookie.getValue()));
				}));
	}

	@Bean
	ReactiveJwtDecoder jwtDecoder(@Value("${jwt.secret}") String secret) {
		return NimbusReactiveJwtDecoder.withSecretKey(
				new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA512"))
				.macAlgorithm(MacAlgorithm.HS512).build();
	}
}
