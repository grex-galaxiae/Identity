package br.app.coeur.identity.core.config.jwt;

import br.app.coeur.identity.modules.authentication.model.JwtSigningKey;
import br.app.coeur.identity.modules.authentication.service.JwtKeyService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeanUtils;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;

import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtKeyProviderTest {
    private final JwtKeyService service = mock(JwtKeyService.class);
    private final Clock clock = mock(Clock.class);
    private final Instant now = Instant.now();
    private JwtSigningKey key;

    @BeforeEach
    void setUp() throws Exception {
        key = key();
        when(clock.instant()).thenReturn(now);
        when(service.initialize()).thenReturn(key);
    }

    private JwtSigningKey key() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        var key = BeanUtils.instantiateClass(JwtSigningKey.class);
        key.replace(UUID.randomUUID(), Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()), now);
        return key;
    }

    private String token(JwtKeyProvider config) {
        var claims = JwtClaimsSet.builder().issuer("https://production.coeur.app.br").subject("user")
                .issuedAt(now).expiresAt(now.plusSeconds(900)).build();
        return config.jwtEncoder().encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    @Test
    void reusesPersistedKeysAcrossInstancesAndCachesThem() {
        var first = new JwtKeyProvider(service, clock, "https://production.coeur.app.br");
        var restarted = new JwtKeyProvider(service, clock, "https://production.coeur.app.br");
        String token = token(first);
        assertThat(restarted.jwtDecoder().decode(token).getSubject()).isEqualTo("user");
        assertThat(restarted.jwtDecoder().decode(token).getHeaders()).containsEntry("kid", key.getKeyId().toString());
        verify(service, never()).getActiveKey();
    }

    @Test
    void updatesOtherInstancesAfterCacheExpiry() throws Exception {
        var first = new JwtKeyProvider(service, clock, "https://production.coeur.app.br");
        var replica = new JwtKeyProvider(service, clock, "https://production.coeur.app.br");
        String oldToken = token(first);
        JwtSigningKey replacement = key();
        when(service.getActiveKey()).thenReturn(replacement);
        first.onKeyRotated(new JwtKeyService.KeyRotated(replacement.getKeyId()));
        String newToken = token(first);
        var firstDecoder = first.jwtDecoder();
        assertThatThrownBy(() -> firstDecoder.decode(oldToken)).isInstanceOf(JwtException.class);
        when(clock.instant()).thenReturn(now.plusSeconds(5));
        assertThat(replica.jwtDecoder().decode(newToken).getHeaders())
                .containsEntry("kid", replacement.getKeyId().toString());
        var replicaDecoder = replica.jwtDecoder();
        assertThatThrownBy(() -> replicaDecoder.decode(oldToken)).isInstanceOf(JwtException.class);
    }

    @Test
    void reloadsOnlyOncePerCacheIntervalWhenTheKeyHasNotChanged() {
        var config = new JwtKeyProvider(service, clock, "https://production.coeur.app.br");
        String token = token(config);
        when(service.getActiveKey()).thenReturn(key);
        when(clock.instant()).thenReturn(now.plusSeconds(5));
        config.jwtDecoder().decode(token);
        config.jwtDecoder().decode(token);
        token(config);
        verify(service, times(1)).getActiveKey();
    }

    @Test
    void rejectsMismatchedKeysStoredInTheDatabase() throws Exception {
        JwtSigningKey other = key();
        key.replace(key.getKeyId(), key.getPublicKey(), other.getPrivateKey(), now);
        assertThatThrownBy(() -> new JwtKeyProvider(service, clock, "https://production.coeur.app.br"))
                .hasRootCauseMessage("JWT keys in the database do not match.");
    }

    @Test
    void concurrentRequestsRefreshExpiredCacheOnlyOnce() throws Exception {
        var provider = new JwtKeyProvider(service, clock, "https://production.coeur.app.br");
        String token = token(provider);
        var decoder = provider.jwtDecoder();
        when(service.getActiveKey()).thenReturn(key);
        when(clock.instant()).thenReturn(now.plusSeconds(5));
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(8)) {
            var results = new ArrayList<Future<String>>();
            for (int i = 0; i < 16; i++) {
                results.add(executor.submit(() -> {
                    start.await();
                    return decoder.decode(token).getSubject();
                }));
            }
            start.countDown();
            for (var result : results) {
                assertThat(result.get(10, TimeUnit.SECONDS)).isEqualTo("user");
            }
        }
        verify(service, times(1)).getActiveKey();
    }

    @Test
    void developmentAndProductionRejectEachOthersTokensEvenWithTheSameKey() {
        var development = new JwtKeyProvider(service, clock, "https://development.coeur.app.br");
        var production = new JwtKeyProvider(service, clock, "https://production.coeur.app.br");
        for (String issuer : new String[]{"https://development.coeur.app.br", "https://production.coeur.app.br"}) {
            var claims = JwtClaimsSet.builder().issuer(issuer).subject("user")
                    .issuedAt(now).expiresAt(now.plusSeconds(900)).build();
            String token = development.jwtEncoder().encode(JwtEncoderParameters.from(claims)).getTokenValue();
            var expected = issuer.contains("development") ? development.jwtDecoder() : production.jwtDecoder();
            var other = issuer.contains("development") ? production.jwtDecoder() : development.jwtDecoder();
            assertThat(expected.decode(token).getSubject()).isEqualTo("user");
            assertThatThrownBy(() -> other.decode(token)).isInstanceOf(JwtException.class);
        }
    }
}
