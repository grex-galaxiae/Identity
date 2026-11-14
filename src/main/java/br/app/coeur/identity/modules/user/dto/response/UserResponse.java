package br.app.coeur.identity.modules.user.dto.response;

import br.app.coeur.identity.modules.user.model.User;

import java.util.UUID;

public record UserResponse(
        UUID id,
        String email,
        String name,
        String roles) {

    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getRoles()
        );
    }
}
