package br.app.coeur.identity.modules.authentication.model;

import br.app.coeur.identity.shared.model.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Getter
@Entity
@Table(name = "jwt_signing_key")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class JwtSigningKey extends BaseEntity<Integer> {
    public static final int SINGLETON_ID = 1;

    @Id
    private Integer id;

    @Column(name = "key_id")
    private UUID keyId;

    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    @Column(name = "private_key", columnDefinition = "TEXT")
    private String privateKey;

    @Column(name = "rotated_at")
    private Instant rotatedAt;

    public void replace(UUID keyId, String publicKey, String privateKey, Instant rotatedAt) {
        this.keyId = keyId;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.rotatedAt = rotatedAt;
    }
}
