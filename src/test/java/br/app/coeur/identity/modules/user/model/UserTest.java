package br.app.coeur.identity.modules.user.model;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UserTest {

    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    private User newUser() {
        return User.register("john@coeur.app", "encoded", "John");
    }

    @Test
    void registerShouldCreateUserWithDefaultRoleAndNoFailedAttempts() {
        User user = newUser();

        assertThat(user.getEmail()).isEqualTo("john@coeur.app");
        assertThat(user.getPassword()).isEqualTo("encoded");
        assertThat(user.getName()).isEqualTo("John");
        assertThat(user.getRoles()).isEqualTo(User.DEFAULT_ROLE);
        assertThat(user.getFailedAttempts()).isZero();
        assertThat(user.getLockExpiredAt()).isNull();
        assertThat(user.isLocked(NOW)).isFalse();
    }

    @Test
    void registerShouldRejectBlankFields() {
        assertThatThrownBy(() -> User.register(" ", "encoded", "John"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Email is required.");
        assertThatThrownBy(() -> User.register("john@coeur.app", null, "John"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Password is required.");
        assertThatThrownBy(() -> User.register("john@coeur.app", "encoded", ""))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Name is required.");
    }

    @Test
    void failedLoginsBelowLimitShouldNotLockAccount() {
        User user = newUser();

        for (int i = 0; i < User.MAX_FAILED_ATTEMPTS - 1; i++) {
            user.registerFailedLogin(NOW);
        }

        assertThat(user.getFailedAttempts()).isEqualTo(User.MAX_FAILED_ATTEMPTS - 1);
        assertThat(user.isLocked(NOW)).isFalse();
    }

    @Test
    void reachingFailedLoginLimitShouldLockAccountForFifteenMinutes() {
        User user = newUser();

        for (int i = 0; i < User.MAX_FAILED_ATTEMPTS; i++) {
            user.registerFailedLogin(NOW);
        }

        assertThat(user.getLockExpiredAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(user.isLocked(NOW)).isTrue();
        assertThat(user.isLocked(NOW.plus(Duration.ofMinutes(14)))).isTrue();
        assertThat(user.isLocked(NOW.plus(Duration.ofMinutes(15)))).isFalse();
        assertThat(user.isLocked(NOW.plus(Duration.ofMinutes(16)))).isFalse();
    }

    @Test
    void successfulLoginShouldResetFailedAttemptsAndLock() {
        User user = newUser();
        for (int i = 0; i < User.MAX_FAILED_ATTEMPTS; i++) {
            user.registerFailedLogin(NOW);
        }

        user.registerSuccessfulLogin();

        assertThat(user.getFailedAttempts()).isZero();
        assertThat(user.getLockExpiredAt()).isNull();
        assertThat(user.isLocked(NOW)).isFalse();
    }

    @Test
    void changeEmailRenameAndChangeRolesShouldUpdateFields() {
        User user = newUser();

        user.changeEmail("new@coeur.app");
        user.rename("New Name");
        user.changeRoles("ROLE_ADMIN");

        assertThat(user.getEmail()).isEqualTo("new@coeur.app");
        assertThat(user.getName()).isEqualTo("New Name");
        assertThat(user.getRoles()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    void changesShouldRejectBlankValuesAndKeepPreviousState() {
        User user = newUser();

        assertThatThrownBy(() -> user.changeEmail(" ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> user.rename(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> user.changeRoles("")).isInstanceOf(IllegalArgumentException.class);

        assertThat(user.getEmail()).isEqualTo("john@coeur.app");
        assertThat(user.getName()).isEqualTo("John");
        assertThat(user.getRoles()).isEqualTo(User.DEFAULT_ROLE);
    }
}
