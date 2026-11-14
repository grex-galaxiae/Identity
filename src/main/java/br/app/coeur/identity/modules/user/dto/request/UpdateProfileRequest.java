package br.app.coeur.identity.modules.user.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateProfileRequest(
        @NotBlank(message = "Email is required.") @Email(message = "Invalid email.")
        @Size(max = 100) String email,
        @NotBlank(message = "Name is required.") @Size(max = 100) String name) {
}
