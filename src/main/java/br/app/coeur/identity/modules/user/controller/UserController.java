package br.app.coeur.identity.modules.user.controller;

import br.app.coeur.identity.modules.user.dto.request.RegisterUserRequest;
import br.app.coeur.identity.modules.user.dto.request.UpdateProfileRequest;
import br.app.coeur.identity.modules.user.dto.request.UpdateUserRequest;
import br.app.coeur.identity.modules.user.dto.response.UserResponse;
import br.app.coeur.identity.modules.user.service.UserService;
import br.app.coeur.identity.shared.security.CurrentUserId;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "Users", description = "Endpoints for managing (CRUD) users in the system")
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Register a new user",
            description = "Creates a new regular user in the database. Requires JWT authentication."
    )
    @ApiResponse(responseCode = "201", description = "User registered successfully")
    @ApiResponse(responseCode = "400", description = "Email already in use or invalid payload")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    public UserResponse register(@Valid @RequestBody RegisterUserRequest request) {
        return userService.register(request);
    }

    @GetMapping("/me")
    @Operation(
            summary = "Get current user data",
            description = "Retrieves the profile details of the currently authenticated user from the JWT."
    )
    @ApiResponse(responseCode = "200", description = "Data retrieved successfully")
    @ApiResponse(responseCode = "401", description = "Unauthorized / missing or invalid JWT token")
    public UserResponse me(@CurrentUserId UUID userId) {
        return userService.findById(userId);
    }

    @GetMapping
    @Operation(
            summary = "List all users",
            description = "Returns a page with registered users. Requires JWT authentication."
    )
    @ApiResponse(responseCode = "200", description = "Page returned successfully")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    public Page<UserResponse> listAll(@PageableDefault(size = 20) Pageable pageable) {
        return userService.findAll(pageable);
    }

    @PutMapping("/me")
    @Operation(summary = "Update own profile", description = "Updates name and email without changing roles.")
    public UserResponse updateProfile(@CurrentUserId UUID userId,
                                      @Valid @RequestBody UpdateProfileRequest request) {
        return userService.updateProfile(userId, request);
    }

    @GetMapping("/{id}")
    @Operation(
            summary = "Find user by ID",
            description = "Returns the details of a specific user by their unique ID."
    )
    @ApiResponse(responseCode = "200", description = "User found successfully")
    @ApiResponse(responseCode = "400", description = "User not found")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    public UserResponse getById(@PathVariable UUID id) {
        return userService.findById(id);
    }

    @PutMapping("/{id}")
    @Operation(
            summary = "Update user data",
            description = "Modifies the email, name, and roles of an existing user."
    )
    @ApiResponse(responseCode = "200", description = "User updated successfully")
    @ApiResponse(responseCode = "400", description = "Invalid ID, email already in use, or inconsistent data")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    public UserResponse update(@PathVariable UUID id, @Valid @RequestBody UpdateUserRequest request) {
        return userService.update(id, request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
            summary = "Delete a user",
            description = "Physically removes a specific user's record by their unique ID."
    )
    @ApiResponse(responseCode = "204", description = "User deleted successfully")
    @ApiResponse(responseCode = "400", description = "User not found")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    public void delete(@PathVariable UUID id) {
        userService.delete(id);
    }
}
