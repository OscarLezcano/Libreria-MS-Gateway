package com.api.gateway;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class JwtForwardingFilter implements GlobalFilter, Ordered {

	private static final String TOKEN_COOKIE = "token";

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		if (exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION) != null) {
			return chain.filter(exchange);
		}

		HttpCookie tokenCookie = exchange.getRequest().getCookies().getFirst(TOKEN_COOKIE);
		if (tokenCookie == null || !StringUtils.hasText(tokenCookie.getValue())) {
			return chain.filter(exchange);
		}

		ServerWebExchange authenticatedExchange = exchange.mutate()
				.request(request -> request.headers(headers -> headers.setBearerAuth(tokenCookie.getValue())))
				.build();
		return chain.filter(authenticatedExchange);
	}

	@Override
	public int getOrder() {
		return Ordered.LOWEST_PRECEDENCE;
	}
}
