package br.app.coeur.identity.modules.authentication.controller;

import br.app.coeur.identity.modules.authentication.dto.request.LoginRequest;
import br.app.coeur.identity.modules.authentication.dto.request.RefreshTokenRequest;
import br.app.coeur.identity.modules.authentication.dto.response.JwtKeyResponse;
import br.app.coeur.identity.modules.authentication.dto.response.TokenResponse;
import br.app.coeur.identity.modules.authentication.service.AuthService;
import br.app.coeur.identity.modules.authentication.service.JwtKeyService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Endpoints for login and token (JWT) renewal")
public class AuthController {

    private final AuthService authService;
    private final JwtKeyService jwtKeyService;

    @PostMapping("/keys")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Generate a new JWT signing key",
            description = "Requires authentication. Replaces the active key and invalidates existing access tokens. "
                    + "Only key metadata is returned; refresh tokens remain usable.")
    public JwtKeyResponse generateKeys() {
        return jwtKeyService.rotate();
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request);
    }

    @PostMapping("/login")
    @Operation(
            summary = "Log in",
            description = "Authenticates email/password and issues a token pair (JWT access token + refresh token)"
    )
    @ApiResponse(responseCode = "200", description = "Login successful")
    @ApiResponse(responseCode = "400", description = "Invalid credentials or account temporarily locked")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    @Operation(
            summary = "Refresh access token",
            description = "Validates the given refresh token, revokes it for rotation security, and issues new tokens"
    )
    @ApiResponse(responseCode = "200", description = "Refresh successful")
    @ApiResponse(responseCode = "400", description = "Invalid, expired, or already revoked refresh token")
    public TokenResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refresh(request);
    }
}
