package br.app.coeur.identity.modules.user.exception;

import br.app.coeur.identity.shared.exception.ConflictException;

/** Indicates that the given email is already registered to another user. */
public class EmailAlreadyInUseException extends ConflictException {

    public EmailAlreadyInUseException() {
        super("Email is already in use.");
    }
}
