package br.app.coeur.identity.modules.user.model;

import br.app.coeur.identity.shared.model.BaseEntity;
import br.app.coeur.identity.shared.util.ValidationUtils;

import jakarta.persistence.*;
import lombok.Getter;
import org.hibernate.annotations.UuidGenerator;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Getter
@Entity
@Table(name = "users")
public class User extends BaseEntity<UUID> {

    public static final String DEFAULT_ROLE = "ROLE_USER";
    public static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    @Id
    @GeneratedValue
    @UuidGenerator
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String roles;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "lock_expired_at")
    private Instant lockExpiredAt;

    protected User() {
    }

    private User(String email, String password, String name) {
        this.email = ValidationUtils.requireText(email, "Email is required.");
        this.password = ValidationUtils.requireText(password, "Password is required.");
        this.name = ValidationUtils.requireText(name, "Name is required.");
        this.roles = DEFAULT_ROLE;
    }

    public static User register(String email, String encodedPassword, String name) {
        return new User(email, encodedPassword, name);
    }

    public boolean isLocked(Instant now) {
        return lockExpiredAt != null && lockExpiredAt.isAfter(now);
    }

    public void registerFailedLogin(Instant now) {

        this.failedAttempts++;

        if (this.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            this.lockExpiredAt = now.plus(LOCK_DURATION);
        }
    }

    public void registerSuccessfulLogin() {
        this.failedAttempts = 0;
        this.lockExpiredAt = null;
    }

    public void changeEmail(String email) {
        this.email = ValidationUtils.requireText(email, "Email is required.");
    }

    public void rename(String name) {
        this.name = ValidationUtils.requireText(name, "Name is required.");
    }

    public void changeRoles(String roles) {
        this.roles = ValidationUtils.requireText(roles, "Roles are required.");
    }
}
