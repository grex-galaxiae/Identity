package br.app.coeur.identity.modules.authentication.exception;

import br.app.coeur.identity.shared.exception.BusinessException;

/** Indicates that the email or password given at login is invalid. */
public class InvalidCredentialsException extends BusinessException {

    public InvalidCredentialsException() {
        super("Invalid credentials.");
    }
}
