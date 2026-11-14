package br.app.coeur.identity.modules.user.exception;

import br.app.coeur.identity.shared.exception.BusinessException;

/** Indicates that the user's account is temporarily locked due to too many failed login attempts. */
public class UserBlockedException extends BusinessException {

    public UserBlockedException() {
        super("Account temporarily locked due to multiple failed attempts. Try again later.");
    }
}
