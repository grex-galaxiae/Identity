package br.app.coeur.identity.modules.authentication.service;

import br.app.coeur.identity.modules.authentication.dto.request.LoginRequest;
import br.app.coeur.identity.modules.authentication.dto.request.RefreshTokenRequest;
import br.app.coeur.identity.modules.authentication.dto.response.TokenResponse;
import br.app.coeur.identity.modules.authentication.exception.InvalidCredentialsException;
import br.app.coeur.identity.modules.authentication.exception.InvalidRefreshTokenException;
import br.app.coeur.identity.modules.authentication.model.RefreshToken;
import br.app.coeur.identity.modules.authentication.repository.RefreshTokenRepository;
import br.app.coeur.identity.modules.user.exception.UserBlockedException;
import br.app.coeur.identity.modules.user.exception.UserNotFoundException;
import br.app.coeur.identity.modules.user.model.User;
import br.app.coeur.identity.modules.user.repository.UserRepository;
import br.app.coeur.identity.shared.exception.BusinessException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Duration REFRESH_TOKEN_VALIDITY = Duration.ofDays(7);

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    @Transactional(noRollbackFor = BusinessException.class)
    public TokenResponse login(LoginRequest request) {
        User user = verifyCredentials(
                request.email(),
                request.password()
        );

        refreshTokenRepository.revokeAllByUserId(user.getId());

        return issueTokens(user);
    }

    @Transactional
    public TokenResponse refresh(RefreshTokenRequest request) {
        RefreshToken oldToken = refreshTokenRepository.findByToken(request.refreshToken())
                .filter(token -> token.isValid(Instant.now()))
                .orElseThrow(InvalidRefreshTokenException::new);

        User user = userRepository.findById(oldToken.getUserId()).orElseThrow(
                UserNotFoundException::new
        );

        oldToken.revoke();

        if (user.isLocked(Instant.now())) {
            throw new UserBlockedException();
        }

        return issueTokens(user);
    }

    @Transactional
    public void logout(RefreshTokenRequest request) {
        refreshTokenRepository.findByToken(request.refreshToken()).ifPresent(RefreshToken::revoke);
    }

    private User verifyCredentials(String email, String rawPassword) {

        log.info("[LOGIN] Login attempt started for email: '{}'", email);

        User user = userRepository.findByEmail(email).orElseThrow(
                () -> {
                    log.warn("[LOGIN] Login failed: email '{}' is not registered in the system", email);
                    return new InvalidCredentialsException();
                });

        Instant now = Instant.now();

        if (user.isLocked(now)) {
            log.warn("[LOGIN] Login failed: account '{}' " +
                    "is temporarily locked until {}", email, user.getLockExpiredAt());
            throw new UserBlockedException();
        }

        if (passwordEncoder.matches(rawPassword, user.getPassword())) {
            log.info("[LOGIN] Login succeeded for user: '{}' (ID: {})", email, user.getId());
            user.registerSuccessfulLogin();
            return user;
        }

        user.registerFailedLogin(now);

        if (user.isLocked(now)) {
            log.error("[LOGIN] Login failed: incorrect password for email '{}'. " +
                    "Attempt limit reached! Account temporarily LOCKED until {}", email, user.getLockExpiredAt());
            throw new UserBlockedException();
        }

        log.warn("[LOGIN] Login failed: incorrect password for email '{}'. " +
                "Consecutive failed attempts: {}/{}", email, user.getFailedAttempts(), User.MAX_FAILED_ATTEMPTS);
        throw new InvalidCredentialsException();
    }

    private TokenResponse issueTokens(User user) {
        String accessToken = tokenService.generateAccessToken(user);
        String refreshTokenValue = tokenService.generateRefreshToken();

        refreshTokenRepository.save(
                RefreshToken.issue(
                        refreshTokenValue,
                        user.getId(),
                        Instant.now(),
                        REFRESH_TOKEN_VALIDITY
                )
        );

        return TokenResponse.bearer(
                accessToken,
                refreshTokenValue,
                tokenService.getAccessTokenExpiresIn()
        );
    }
}
