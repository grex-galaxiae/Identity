package br.app.coeur.identity.modules.authentication.service;

import br.app.coeur.identity.modules.authentication.dto.response.JwtKeyResponse;
import br.app.coeur.identity.modules.authentication.model.JwtSigningKey;
import br.app.coeur.identity.modules.authentication.repository.JwtSigningKeyRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtKeyService {
    private final JwtSigningKeyRepository repository;
    private final ApplicationEventPublisher events;

    @Transactional
    public JwtSigningKey initialize() {
        JwtSigningKey key = lockedKey();
        if (key.getKeyId() == null) generatePair(key);
        return key;
    }

    @Transactional(readOnly = true)
    public JwtSigningKey getActiveKey() {
        return repository.findById(JwtSigningKey.SINGLETON_ID)
                .filter(key -> key.getKeyId() != null)
                .orElseThrow(() -> new IllegalStateException("JWT signing key is not initialized. Check Flyway migrations."));
    }

    @Transactional
    public JwtKeyResponse rotate() {
        JwtSigningKey key = lockedKey();
        generatePair(key);
        events.publishEvent(new KeyRotated(key.getKeyId()));
        return new JwtKeyResponse(key.getKeyId(), "RS256", key.getRotatedAt());
    }

    private JwtSigningKey lockedKey() {
        return repository.findForUpdate().orElseThrow(
                () -> new IllegalStateException("JWT signing key row is missing. Apply Flyway migration V2."));
    }

    private void generatePair(JwtSigningKey key) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var pair = generator.generateKeyPair();
            key.replace(
                    UUID.randomUUID(),
                    Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                    Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                    Instant.now()
            );
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to generate JWT signing key", e);
        }
    }

    public record KeyRotated(UUID keyId) {
    }
}
