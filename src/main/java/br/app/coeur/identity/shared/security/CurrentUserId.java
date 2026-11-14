package br.app.coeur.identity.shared.security;

import io.swagger.v3.oas.annotations.Parameter;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Injects the authenticated user's ID (JWT {@code sub} claim) into the parameter.
 * The parameter must be of type {@link java.util.UUID}.
 *
 * <p>Resolved by {@link CurrentUserIdArgumentResolver}.</p>
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Parameter(hidden = true) // does not appear as an input parameter in Swagger
public @interface CurrentUserId {
}
