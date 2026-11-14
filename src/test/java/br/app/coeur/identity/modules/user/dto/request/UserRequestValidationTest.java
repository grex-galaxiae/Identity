package br.app.coeur.identity.modules.user.dto.request;

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

class UserRequestValidationTest {

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

    // ---------- RegisterUserRequest ----------

    @Test
    void registerRequestShouldAcceptValidPayload() {
        assertThat(violations(new RegisterUserRequest("john@coeur.app", "secret", "John"))).isEmpty();
    }

    @Test
    void registerRequestShouldRejectMissingFields() {
        assertThat(violations(new RegisterUserRequest(null, null, null)))
                .containsEntry("email", "Email is required.")
                .containsEntry("password", "Password is required.")
                .containsEntry("name", "Name is required.");
    }

    @Test
    void registerRequestShouldRejectBlankPassword() {
        assertThat(violations(new RegisterUserRequest("john@coeur.app", " ", "John")))
                .containsOnlyKeys("password")
                .containsEntry("password", "Password is required.");
    }

    @Test
    void registerRequestShouldRejectInvalidEmail() {
        assertThat(violations(new RegisterUserRequest("not-an-email", "secret", "John")))
                .containsOnlyKeys("email")
                .containsEntry("email", "Invalid email.");
    }

    @Test
    void registerRequestShouldRejectFieldsLongerThan100Characters() {
        String longText = "a".repeat(101);

        assertThat(violations(new RegisterUserRequest("john@coeur.app", longText, longText)))
                .containsOnlyKeys("password", "name");
    }

    // ---------- UpdateUserRequest ----------

    @Test
    void updateRequestShouldAcceptValidPayload() {
        assertThat(violations(new UpdateUserRequest("john@coeur.app", "John", "ROLE_ADMIN"))).isEmpty();
    }

    @Test
    void updateRequestShouldRejectMissingFields() {
        assertThat(violations(new UpdateUserRequest(null, null, null)))
                .containsEntry("email", "Email is required.")
                .containsEntry("name", "Name is required.")
                .containsEntry("roles", "Roles are required.");
    }

    @Test
    void updateRequestShouldRejectBlankFields() {
        assertThat(violations(new UpdateUserRequest(" ", " ", " ")))
                .containsOnlyKeys("email", "name", "roles");
    }

    @Test
    void updateRequestShouldRejectInvalidEmail() {
        assertThat(violations(new UpdateUserRequest("not-an-email", "John", "ROLE_USER")))
                .containsOnlyKeys("email")
                .containsEntry("email", "Invalid email.");
    }
}
