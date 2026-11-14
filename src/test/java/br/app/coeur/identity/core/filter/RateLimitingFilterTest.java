package br.app.coeur.identity.core.filter;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class RateLimitingFilterTest {
    private final Clock clock = mock(Clock.class);
    private final Instant now = Instant.parse("2026-01-01T00:00:00Z");

    private MockHttpServletResponse request(RateLimitingFilter filter, String remote, String forwarded, String path) throws Exception {
        var request = new MockHttpServletRequest("GET", path);
        request.setRemoteAddr(remote);
        if (forwarded != null) request.addHeader("X-Forwarded-For", forwarded);
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> {});
        return response;
    }

    @Test
    void ignoresSpoofedForwardingHeadersAndReturnsProblemDetails() throws Exception {
        when(clock.instant()).thenReturn(now);
        var filter = new RateLimitingFilter("", clock);
        for (int i = 0; i < 30; i++) assertThat(request(filter, "10.0.0.1", "192.0.2." + i, "/api/test").getStatus()).isEqualTo(200);
        var limited = request(filter, "10.0.0.1", "192.0.2.100", "/api/test");
        assertThat(limited.getStatus()).isEqualTo(429);
        assertThat(limited.getContentType()).startsWith("application/problem+json");
        assertThat(limited.getHeader("Retry-After")).isEqualTo("60");
        assertThat(request(filter, "10.0.0.1", null, "/health").getStatus()).isEqualTo(200);
    }

    @Test
    void usesTheClosestUntrustedHopInsteadOfAnAttackerSuppliedPrefix() throws Exception {
        when(clock.instant()).thenReturn(now);
        var filter = new RateLimitingFilter("10.0.0.1,10.0.0.2", clock);
        for (int i = 0; i < 30; i++) request(filter, "10.0.0.1", "192.0.2." + i + ", 203.0.113.1, 10.0.0.2", "/api/test");
        assertThat(request(filter, "10.0.0.1", "192.0.2.99, 203.0.113.1, 10.0.0.2", "/api/test").getStatus()).isEqualTo(429);
        assertThat(request(filter, "10.0.0.1", "203.0.113.2", "/api/test").getStatus()).isEqualTo(200);
    }

    @Test
    void boundsMemoryAndReleasesIdleBuckets() throws Exception {
        when(clock.instant()).thenReturn(now);
        var filter = new RateLimitingFilter("", clock);
        for (int i = 0; i < 10_000; i++) request(filter, "client-" + i, null, "/api/test");
        assertThat(request(filter, "new-client", null, "/api/test").getStatus()).isEqualTo(429);
        when(clock.instant()).thenReturn(now.plusSeconds(301));
        assertThat(request(filter, "new-client", null, "/api/test").getStatus()).isEqualTo(200);
    }
}
