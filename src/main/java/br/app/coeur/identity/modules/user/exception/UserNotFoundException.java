package br.app.coeur.identity.modules.user.exception;

import br.app.coeur.identity.shared.exception.ResourceNotFoundException;

/** Indicates that the requested user does not exist. */
public class UserNotFoundException extends ResourceNotFoundException {

    public UserNotFoundException() {
        super("User not found.");
    }
}
