package br.app.coeur.identity.modules.authentication;

import br.app.coeur.identity.modules.authentication.dto.request.LoginRequest;
import br.app.coeur.identity.modules.authentication.dto.request.RefreshTokenRequest;
import br.app.coeur.identity.modules.authentication.model.JwtSigningKey;
import br.app.coeur.identity.modules.authentication.repository.JwtSigningKeyRepository;
import br.app.coeur.identity.modules.authentication.service.AuthService;
import br.app.coeur.identity.modules.authentication.service.JwtKeyService;
import br.app.coeur.identity.modules.user.model.User;
import br.app.coeur.identity.modules.user.repository.UserRepository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class JwtKeyIntegrationTest {
    @Autowired JwtKeyService keys;
    @Autowired JwtSigningKeyRepository repository;
    @Autowired JdbcTemplate jdbc;
    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired AuthService auth;
    @Autowired PasswordEncoder passwords;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactions;
    @Autowired org.springframework.security.oauth2.jwt.JwtDecoder decoder;

    @Test
    void startupGeneratesOnePersistentPairAndDoesNotReplaceItOnInitialization() {
        JwtSigningKey first = repository.findById(1).orElseThrow();
        assertThat(first.getKeyId()).isNotNull();
        assertThat(first.getPrivateKey()).isNotBlank();
        assertThat(keys.initialize().getKeyId()).isEqualTo(first.getKeyId());
        assertThat(repository.count()).isEqualTo(1);
    }

    @Test
    void concurrentInitializationsReuseTheSameKey() throws Exception {
        jdbc.update("UPDATE jwt_signing_key SET key_id = NULL, public_key = NULL, private_key = NULL, rotated_at = NULL WHERE id = 1");
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            Callable<java.util.UUID> initialize = () -> { start.await(); return keys.initialize().getKeyId(); };
            var first = executor.submit(initialize);
            var second = executor.submit(initialize);
            start.countDown();
            assertThat(first.get(10, TimeUnit.SECONDS)).isEqualTo(second.get(10, TimeUnit.SECONDS));
        }
        assertThat(repository.count()).isEqualTo(1);
    }

    @Test
    void rotationRequiresAuthenticationAndNeverReturnsPrivateMaterial() throws Exception {
        mvc.perform(post("/api/v1/auth/keys")).andExpect(status().isUnauthorized());
        var user = users.save(User.register("keys@coeur.app", passwords.encode("secret123"), "Keys"));
        var tokens = auth.login(new LoginRequest(user.getEmail(), "secret123"));
        String oldId = repository.findById(1).orElseThrow().getKeyId().toString();
        mvc.perform(post("/api/v1/auth/keys").header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.keyId").isNotEmpty())
                .andExpect(jsonPath("$.algorithm").value("RS256"))
                .andExpect(jsonPath("$.createdAt").isNotEmpty())
                .andExpect(jsonPath("$.privateKey").doesNotExist())
                .andExpect(jsonPath("$.publicKey").doesNotExist());
        assertThat(repository.findById(1).orElseThrow().getKeyId().toString()).isNotEqualTo(oldId);
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isUnauthorized());
        var renewed = auth.refresh(new RefreshTokenRequest(tokens.refreshToken()));
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + renewed.accessToken()))
                .andExpect(status().isOk());
    }

    @Test
    void migrationAllowsOnlyOneSigningKeyRow() {
        var previous = repository.findById(1).orElseThrow().getKeyId();
        assertThatThrownBy(() -> jdbc.update("INSERT INTO jwt_signing_key (id) VALUES (2)"))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThat(repository.findById(1).orElseThrow().getKeyId()).isEqualTo(previous);
    }

    @Test
    void rolledBackRotationPreservesThePersistedAndCachedKey() {
        users.save(User.register("rollback@coeur.app", passwords.encode("secret123"), "Rollback"));
        var tokens = auth.login(new LoginRequest("rollback@coeur.app", "secret123"));
        var previous = repository.findById(1).orElseThrow().getKeyId();
        new org.springframework.transaction.support.TransactionTemplate(transactions).executeWithoutResult(status -> {
            keys.rotate();
            status.setRollbackOnly();
        });
        assertThat(repository.findById(1).orElseThrow().getKeyId()).isEqualTo(previous);
        assertThat(decoder.decode(tokens.accessToken()).getSubject()).isNotBlank();
    }
}
