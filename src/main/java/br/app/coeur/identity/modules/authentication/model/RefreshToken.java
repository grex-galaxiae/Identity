package br.app.coeur.identity.modules.authentication.model;

import br.app.coeur.identity.shared.model.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.UuidGenerator;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Getter
@Entity
@Table(name = "refresh_tokens")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken extends BaseEntity<UUID> {

    @Id
    @GeneratedValue
    @UuidGenerator
    private UUID id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked;

    private RefreshToken(String token, UUID userId, Instant expiryDate) {
        this.token = token;
        this.userId = userId;
        this.expiryDate = expiryDate;
        this.revoked = false;
    }

    public static RefreshToken issue(String token, UUID userId, Instant now, Duration validFor) {
        return new RefreshToken(token, userId, now.plus(validFor));
    }

    public boolean isExpired(Instant now) {
        return !expiryDate.isAfter(now);
    }

    public boolean isValid(Instant now) {
        return !revoked && !isExpired(now);
    }

    public void revoke() {
        this.revoked = true;
    }
}
