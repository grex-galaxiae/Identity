package br.app.coeur.identity.shared.exception;

/** Indicates that a resource was not found. */
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }
}
