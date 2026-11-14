package br.app.coeur.identity.core.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Component
public class RateLimitingFilter implements Filter {

    private final Map<String, TokenBucket> ipBuckets = new ConcurrentHashMap<>();
    private static final long MAX_TOKENS = 30;
    private static final long REFILL_PERIOD_SECONDS = 60;
    private static final int MAX_BUCKETS = 10_000;
    private final Set<String> trustedProxies;
    private final Clock clock;
    private Instant nextCleanup = Instant.MIN;

    @org.springframework.beans.factory.annotation.Autowired
    public RateLimitingFilter(@Value("${app.rate-limit.trusted-proxies:}") String trustedProxies) {
        this(trustedProxies, Clock.systemUTC());
    }

    RateLimitingFilter(String trustedProxies, Clock clock) {
        this.clock = clock;
        this.trustedProxies = Arrays.stream(trustedProxies.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    }

    private synchronized TokenBucket bucketFor(String ip) {
        Instant now = clock.instant();
        if (!now.isBefore(nextCleanup)) {
            ipBuckets.entrySet().removeIf(entry -> entry.getValue().idleSince(now.minusSeconds(300)));
            nextCleanup = now.plusSeconds(60);
        }
        TokenBucket existing = ipBuckets.get(ip);
        if (existing != null) return existing;
        if (ipBuckets.size() >= MAX_BUCKETS) return null;
        TokenBucket created = new TokenBucket(MAX_TOKENS, REFILL_PERIOD_SECONDS, clock);
        ipBuckets.put(ip, created);
        return created;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (request instanceof HttpServletRequest httpRequest && response instanceof HttpServletResponse httpResponse) {
            String ip = getClientIp(httpRequest);

            if ("OPTIONS".equals(httpRequest.getMethod()) || "/health".equals(httpRequest.getRequestURI())
                    || "/actuator/health".equals(httpRequest.getRequestURI())
                    || ("GET".equals(httpRequest.getMethod()) && "/.well-known/jwks.json".equals(httpRequest.getRequestURI()))) {
                chain.doFilter(request, response);
                return;
            }
            TokenBucket bucket = bucketFor(ip);

            if (bucket == null || !bucket.tryConsume()) {
                log.warn("[RATE_LIMIT] Too many requests from {}", ip);

                httpResponse.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                httpResponse.setContentType("application/problem+json");
                httpResponse.setHeader("Retry-After", "60");
                httpResponse.setCharacterEncoding("UTF-8");
                httpResponse.getWriter().write("{\"type\":\"about:blank\",\"title\":\"Too Many Requests\",\"status\":429,\"detail\":\"Too many requests. Try again shortly.\"}");
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");

        if (xfHeader == null || xfHeader.length() > 1024 || !trustedProxies.contains(request.getRemoteAddr())) {
            return request.getRemoteAddr();
        }

        String[] hops = xfHeader.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].trim();
            if (!hop.matches("[0-9a-fA-F:.]{1,64}")) return request.getRemoteAddr();
            if (!trustedProxies.contains(hop)) return hop;
        }
        return request.getRemoteAddr();
    }

    private static class TokenBucket {
        private final long capacity;
        private final long refillPeriodSeconds;
        private double tokens;
        private Instant lastRefill;
        private final Clock clock;

        public TokenBucket(long capacity, long refillPeriodSeconds, Clock clock) {
            this.clock = clock;
            this.capacity = capacity;
            this.refillPeriodSeconds = refillPeriodSeconds;
            this.tokens = capacity;
            this.lastRefill = clock.instant();
        }

        public synchronized boolean tryConsume() {
            refill();
            if (tokens >= 1.0) {
                tokens -= 1.0;
                return true;
            }
            return false;
        }

        public synchronized boolean idleSince(Instant cutoff) {
            return lastRefill.isBefore(cutoff);
        }

        private void refill() {
            Instant now = clock.instant();
            double elapsedSeconds = Duration.between(lastRefill, now).toMillis() / 1000.0;
            double tokensToAdd = elapsedSeconds * ((double) capacity / refillPeriodSeconds);
            if (tokensToAdd > 0) {
                tokens = Math.min(capacity, tokens + tokensToAdd);
                lastRefill = now;
            }
        }
    }
}
