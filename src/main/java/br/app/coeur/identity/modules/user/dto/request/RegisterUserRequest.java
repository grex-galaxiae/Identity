package br.app.coeur.identity.modules.user.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterUserRequest(
        @NotBlank(message = "Email is required.")
        @Email(message = "Invalid email.")
        @Size(max = 100, message = "Email must be at most 100 characters.")
        String email,

        @NotBlank(message = "Password is required.")
        @Size(max = 100, message = "Password must be at most 100 characters.")
        String password,

        @NotBlank(message = "Name is required.")
        @Size(max = 100, message = "Name must be at most 100 characters.")
        String name) {
}
