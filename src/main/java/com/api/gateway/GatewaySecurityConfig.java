package com.api.gateway;

import java.nio.charset.StandardCharsets;
import java.util.List;

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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import reactor.core.publisher.Mono;

@Configuration
public class GatewaySecurityConfig {

	@Bean
	SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
			ServerAuthenticationConverter cookieBearerTokenConverter,
			CorsConfigurationSource corsConfigurationSource,
			@Value("${gateway.security.public-paths}") String[] publicPaths,
			@Value("${gateway.security.public-get-paths}") String[] publicGetPaths) {
		return http
				.csrf(ServerHttpSecurity.CsrfSpec::disable)
				.cors(cors -> cors.configurationSource(corsConfigurationSource))
				.authorizeExchange(exchange -> exchange
						.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						.pathMatchers(HttpMethod.GET, publicGetPaths).permitAll()
						.pathMatchers(publicPaths).permitAll()
						.anyExchange().authenticated())
				.oauth2ResourceServer(resourceServer -> resourceServer
						.bearerTokenConverter(cookieBearerTokenConverter)
						.jwt(Customizer.withDefaults()))
				.build();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(List.of("http://localhost:3000"));
		configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(List.of("*"));
		configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
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
