package br.app.coeur.identity.modules.authentication.service;

import br.app.coeur.identity.modules.authentication.dto.request.LoginRequest;
import br.app.coeur.identity.modules.authentication.dto.request.RefreshTokenRequest;
import br.app.coeur.identity.modules.authentication.dto.response.TokenResponse;
import br.app.coeur.identity.modules.authentication.model.RefreshToken;
import br.app.coeur.identity.modules.authentication.repository.RefreshTokenRepository;
import br.app.coeur.identity.modules.user.model.User;
import br.app.coeur.identity.modules.user.repository.UserRepository;
import br.app.coeur.identity.shared.exception.BusinessException;
import br.app.coeur.identity.shared.exception.ResourceNotFoundException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private TokenService tokenService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    private User user;

    @BeforeEach
    void setUp() {
        user = User.register("john@coeur.app", "encoded", "John");
        ReflectionTestUtils.setField(user, "id", USER_ID);
    }

    private void stubTokenGeneration() {
        when(tokenService.generateAccessToken(user)).thenReturn("access-token");
        when(tokenService.generateRefreshToken()).thenReturn("refresh-token");
        when(tokenService.getAccessTokenExpiresIn()).thenReturn(900L);
    }

    // ---------- login ----------

    @Test
    void loginShouldRevokeOldTokensAndIssueNewPair() {
        when(userRepository.findByEmail("john@coeur.app")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "encoded")).thenReturn(true);
        stubTokenGeneration();

        TokenResponse response = authService.login(new LoginRequest("john@coeur.app", "secret"));

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900L);

        verify(refreshTokenRepository).revokeAllByUserId(USER_ID);
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        assertThat(captor.getValue().getToken()).isEqualTo("refresh-token");
        assertThat(captor.getValue().getUserId()).isEqualTo(USER_ID);
        assertThat(captor.getValue().isValid(Instant.now())).isTrue();
    }

    @Test
    void loginShouldResetPreviousFailedAttempts() {
        user.registerFailedLogin(Instant.now());
        user.registerFailedLogin(Instant.now());
        when(userRepository.findByEmail("john@coeur.app")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "encoded")).thenReturn(true);
        stubTokenGeneration();

        authService.login(new LoginRequest("john@coeur.app", "secret"));

        assertThat(user.getFailedAttempts()).isZero();
    }

    @Test
    void loginShouldFailForUnknownEmail() {
        when(userRepository.findByEmail("ghost@coeur.app")).thenReturn(Optional.empty());
        LoginRequest request = new LoginRequest("ghost@coeur.app", "secret");

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BusinessException.class)
                .hasMessage("Invalid credentials.");

        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void loginShouldFailAndCountAttemptWhenPasswordIsWrong() {
        when(userRepository.findByEmail("john@coeur.app")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);
        LoginRequest request = new LoginRequest("john@coeur.app", "wrong");

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BusinessException.class)
                .hasMessage("Invalid credentials.");

        assertThat(user.getFailedAttempts()).isEqualTo(1);
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void loginShouldLockAccountOnFifthFailedAttempt() {
        for (int i = 0; i < User.MAX_FAILED_ATTEMPTS - 1; i++) {
            user.registerFailedLogin(Instant.now());
        }
        when(userRepository.findByEmail("john@coeur.app")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);
        LoginRequest request = new LoginRequest("john@coeur.app", "wrong");

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("locked");

        assertThat(user.isLocked(Instant.now())).isTrue();
    }

    @Test
    void loginShouldRejectLockedAccountWithoutCheckingPassword() {
        user.registerFailedLogin(Instant.now().minus(Duration.ofMinutes(1)));
        ReflectionTestUtils.setField(user, "lockExpiredAt", Instant.now().plus(Duration.ofMinutes(10)));
        when(userRepository.findByEmail("john@coeur.app")).thenReturn(Optional.of(user));
        LoginRequest request = new LoginRequest("john@coeur.app", "secret");

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("locked");

        verify(passwordEncoder, never()).matches(any(), any());
        verify(refreshTokenRepository, never()).save(any());
    }

    // ---------- refresh ----------

    @Test
    void refreshShouldRejectLockedUser() {
        RefreshToken token = RefreshToken.issue("locked-token", USER_ID, Instant.now(), Duration.ofDays(7));
        ReflectionTestUtils.setField(user, "lockExpiredAt", Instant.now().plusSeconds(60));
        when(refreshTokenRepository.findByToken("locked-token")).thenReturn(Optional.of(token));
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        assertThatThrownBy(() -> authService.refresh(new RefreshTokenRequest("locked-token")))
                .isInstanceOf(br.app.coeur.identity.modules.user.exception.UserBlockedException.class);
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void refreshShouldRotateTokens() {
        RefreshToken oldToken = RefreshToken.issue("old-token", USER_ID, Instant.now(), Duration.ofDays(7));
        when(refreshTokenRepository.findByToken("old-token")).thenReturn(Optional.of(oldToken));
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        stubTokenGeneration();

        TokenResponse response = authService.refresh(new RefreshTokenRequest("old-token"));

        assertThat(oldToken.isRevoked()).isTrue();
        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        assertThat(captor.getValue().getToken()).isEqualTo("refresh-token");
        assertThat(captor.getValue().getUserId()).isEqualTo(USER_ID);
    }

    @Test
    void refreshShouldFailWhenTokenDoesNotExist() {
        when(refreshTokenRepository.findByToken("unknown")).thenReturn(Optional.empty());
        RefreshTokenRequest request = new RefreshTokenRequest("unknown");

        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(BusinessException.class)
                .hasMessage("Refresh token is invalid, revoked, or expired.");
    }

    @Test
    void refreshShouldFailWhenTokenIsRevoked() {
        RefreshToken revoked = RefreshToken.issue("revoked-token", USER_ID, Instant.now(), Duration.ofDays(7));
        revoked.revoke();
        when(refreshTokenRepository.findByToken("revoked-token")).thenReturn(Optional.of(revoked));
        RefreshTokenRequest request = new RefreshTokenRequest("revoked-token");

        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(BusinessException.class)
                .hasMessage("Refresh token is invalid, revoked, or expired.");

        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void refreshShouldFailWhenTokenIsExpired() {
        RefreshToken expired = RefreshToken.issue("expired-token", USER_ID, Instant.now().minus(Duration.ofDays(10)), Duration.ofDays(7));
        when(refreshTokenRepository.findByToken("expired-token")).thenReturn(Optional.of(expired));
        RefreshTokenRequest request = new RefreshTokenRequest("expired-token");

        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(BusinessException.class)
                .hasMessage("Refresh token is invalid, revoked, or expired.");

        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void refreshShouldFailWhenUserNoLongerExists() {
        RefreshToken token = RefreshToken.issue("orphan-token", USER_ID, Instant.now(), Duration.ofDays(7));
        when(refreshTokenRepository.findByToken("orphan-token")).thenReturn(Optional.of(token));
        when(userRepository.findById(USER_ID)).thenReturn(Optional.empty());
        RefreshTokenRequest request = new RefreshTokenRequest("orphan-token");

        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("User not found.");

        assertThat(token.isRevoked()).isFalse();
    }
}
