package br.app.coeur.identity.modules.authentication.dto.request;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class AuthRequestValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    private static <T> Map<String, String> violations(T request) {
        Set<ConstraintViolation<T>> violations = validator.validate(request);
        return violations.stream().collect(Collectors.toMap(
                v -> v.getPropertyPath().toString(),
                ConstraintViolation::getMessage,
                (first, second) -> first
        ));
    }

    // ---------- LoginRequest ----------

    @Test
    void loginRequestShouldAcceptValidPayload() {
        assertThat(violations(new LoginRequest("john@coeur.app", "secret"))).isEmpty();
    }

    @Test
    void loginRequestShouldRejectMissingFields() {
        assertThat(violations(new LoginRequest(null, null)))
                .containsEntry("email", "Email is required.")
                .containsEntry("password", "Password is required.");
    }

    @Test
    void loginRequestShouldRejectInvalidEmail() {
        assertThat(violations(new LoginRequest("not-an-email", "secret")))
                .containsOnlyKeys("email")
                .containsEntry("email", "Invalid email.");
    }

    // ---------- RefreshTokenRequest ----------

    @Test
    void refreshTokenRequestShouldAcceptValidPayload() {
        assertThat(violations(new RefreshTokenRequest("some-token"))).isEmpty();
    }

    @Test
    void refreshTokenRequestShouldRejectBlankToken() {
        assertThat(violations(new RefreshTokenRequest(" ")))
                .containsEntry("refreshToken", "Refresh token is required.");
    }
}
