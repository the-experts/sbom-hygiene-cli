package nl.theexperts.sbom.collector.fetcher;

import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;

public final class BearerTokenFilter implements ClientRequestFilter {

    private final String token;

    public BearerTokenFilter(String token) {
        this.token = token;
    }

    @Override
    public void filter(ClientRequestContext ctx) {
        if (token != null && !token.isBlank()) {
            ctx.getHeaders().putSingle("Authorization", "token " + token);
        }
    }
}