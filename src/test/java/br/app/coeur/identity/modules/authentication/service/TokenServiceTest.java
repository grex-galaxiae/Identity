package br.app.coeur.identity.modules.authentication.service;

import br.app.coeur.identity.modules.user.model.User;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private JwtEncoder jwtEncoder;

    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenService(jwtEncoder, "https://production.coeur.app.br");
    }

    @Test
    void generateAccessTokenShouldEncodeUserClaims() {
        User user = User.register("john@coeur.app", "encoded", "John");
        UUID userId = UUID.randomUUID();
        ReflectionTestUtils.setField(user, "id", userId);
        Jwt jwt = Jwt.withTokenValue("signed-jwt").header("alg", "RS256").subject(userId.toString()).build();
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        String token = tokenService.generateAccessToken(user);

        assertThat(token).isEqualTo("signed-jwt");

        ArgumentCaptor<JwtEncoderParameters> captor = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(jwtEncoder).encode(captor.capture());
        JwtClaimsSet claims = captor.getValue().getClaims();
        assertThat(claims.getSubject()).isEqualTo(userId.toString());
        assertThat(claims.getIssuer().toString()).isEqualTo("https://production.coeur.app.br");
        assertThat(claims.<String>getClaim("email")).isEqualTo("john@coeur.app");
        assertThat(claims.<String>getClaim("name")).isEqualTo("John");
        assertThat(claims.<String>getClaim("scope")).isEqualTo(User.DEFAULT_ROLE);
        assertThat(Duration.between(claims.getIssuedAt(), claims.getExpiresAt()))
                .isEqualTo(Duration.ofSeconds(tokenService.getAccessTokenExpiresIn()));
    }

    @Test
    void accessTokenShouldExpireInFifteenMinutes() {
        assertThat(tokenService.getAccessTokenExpiresIn()).isEqualTo(900L);
    }

    @Test
    void generateRefreshTokenShouldReturnUniqueUuids() {
        String first = tokenService.generateRefreshToken();
        String second = tokenService.generateRefreshToken();

        assertThat(UUID.fromString(first)).isNotNull();
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void usesTheIssuerConfiguredForTheDeployment() {
        var service = new TokenService(jwtEncoder, "https://development.coeur.app.br");
        User user = User.register("issuer@coeur.app", "encoded", "Issuer");
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(
                Jwt.withTokenValue("jwt").header("alg", "RS256").claim("sub", "user").build());
        service.generateAccessToken(user);
        var captor = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(jwtEncoder).encode(captor.capture());
        assertThat(captor.getValue().getClaims().getIssuer().toString()).isEqualTo("https://development.coeur.app.br");
    }
}
