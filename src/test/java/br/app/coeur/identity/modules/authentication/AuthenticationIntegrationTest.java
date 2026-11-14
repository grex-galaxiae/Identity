package br.app.coeur.identity.modules.authentication;

import br.app.coeur.identity.modules.authentication.dto.request.LoginRequest;
import br.app.coeur.identity.modules.authentication.dto.request.RefreshTokenRequest;
import br.app.coeur.identity.modules.authentication.service.TokenService;
import br.app.coeur.identity.modules.user.dto.request.RegisterUserRequest;
import br.app.coeur.identity.modules.user.dto.request.UpdateUserRequest;
import br.app.coeur.identity.modules.user.model.User;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class AuthenticationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private br.app.coeur.identity.modules.user.repository.UserRepository userRepository;

    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    // User registration is a protected endpoint, so the tests need a valid JWT to create users
    private String registrarAuthHeader;

    @BeforeEach
    void setUpRegistrarToken() {
        User registrar = User.register("registrar@coeur.app", "unused", "Registrar");
        ReflectionTestUtils.setField(registrar, "id", UUID.randomUUID());
        registrarAuthHeader = "Bearer " + tokenService.generateAccessToken(registrar);
    }

    @Test
    void shouldPerformFullAuthenticationLifecycle() throws Exception {
        // 1. Register a user
        RegisterUserRequest registerRequest = new RegisterUserRequest("test@coeur.app", "secret123", "John Doe");

        mockMvc.perform(post("/api/v1/users/register")
                        .header("Authorization", registrarAuthHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id", notNullValue()))
                .andExpect(jsonPath("$.email", is("test@coeur.app")))
                .andExpect(jsonPath("$.name", is("John Doe")))
                .andExpect(jsonPath("$.roles", is("ROLE_USER")));

        // 2. Try to access /api/v1/users/me without a token (should return 401 Unauthorized)
        mockMvc.perform(get("/api/v1/users/me"))
                .andExpect(status().isUnauthorized());

        // 3. Log in and obtain the token pair
        LoginRequest loginRequest = new LoginRequest("test@coeur.app", "secret123");

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", notNullValue()))
                .andExpect(jsonPath("$.tokenType", is("Bearer")))
                .andExpect(jsonPath("$.expiresIn", is(900)))
                .andReturn();

        String responseContent = loginResult.getResponse().getContentAsString();
        String accessToken = objectMapper.readTree(responseContent).get("accessToken").asText();
        String refreshToken = objectMapper.readTree(responseContent).get("refreshToken").asText();

        // 4. Access /api/v1/users/me using the access token (should return the user's data)
        mockMvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email", is("test@coeur.app")))
                .andExpect(jsonPath("$.name", is("John Doe")));

        // 5. Use the refresh token to obtain new tokens
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshToken);

        MvcResult refreshResult = mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", notNullValue()))
                .andExpect(jsonPath("$.tokenType", is("Bearer")))
                .andReturn();

        String newResponseContent = refreshResult.getResponse().getContentAsString();
        String newAccessToken = objectMapper.readTree(newResponseContent).get("accessToken").asText();

        // 6. Try to use the old refresh token again (should fail due to rotation/revocation)
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isBadRequest());

        // 7. Use the new access token to call the protected endpoint
        mockMvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + newAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email", is("test@coeur.app")));
    }

    @Test
    void shouldLockAccountAfterFiveFailedAttempts() throws Exception {
        // 1. Register user
        RegisterUserRequest registerRequest = new RegisterUserRequest("lock@coeur.app", "secret123", "Locked User");

        mockMvc.perform(post("/api/v1/users/register")
                        .header("Authorization", registrarAuthHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        // 2. Try to log in with the wrong password 4 times in a row (should not lock yet)
        LoginRequest wrongLoginRequest = new LoginRequest("lock@coeur.app", "wrongpassword");

        for (int i = 0; i < 4; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(wrongLoginRequest)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail", is("Invalid credentials.")));
        }

        // 3. The 5th failed attempt should trigger the temporary lock
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(wrongLoginRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail", containsString("locked")));

        // 4. Try to log in with the CORRECT password (should still be locked)
        LoginRequest correctLoginRequest = new LoginRequest("lock@coeur.app", "secret123");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(correctLoginRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail", containsString("locked")));
    }

    @Test
    void shouldPerformFullUserCrud() throws Exception {
        // 1. Register an admin and obtain a token to authorize the CRUD endpoints
        RegisterUserRequest adminRegister = new RegisterUserRequest("admin@coeur.app", "admin123", "Admin User");

        mockMvc.perform(post("/api/v1/users/register")
                        .header("Authorization", registrarAuthHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(adminRegister)))
                .andExpect(status().isCreated());

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("admin@coeur.app", "admin123"))))
                .andExpect(status().isOk())
                .andReturn();

        String token = objectMapper.readTree(loginResult.getResponse().getContentAsString()).get("accessToken").asText();
        String authHeader = "Bearer " + token;

        // 2. Create a new user via the CRUD endpoint (registering another user)
        RegisterUserRequest userRequest = new RegisterUserRequest("crud@coeur.app", "crud123", "Crud User");

        MvcResult createResult = mockMvc.perform(post("/api/v1/users/register")
                        .header("Authorization", authHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isCreated())
                .andReturn();

        String newUserId = objectMapper.readTree(createResult.getResponse().getContentAsString()).get("id").asText();

        // 3. Fetch user by ID
        mockMvc.perform(get("/api/v1/users/" + newUserId)
                        .header("Authorization", authHeader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email", is("crud@coeur.app")))
                .andExpect(jsonPath("$.name", is("Crud User")));

        // 4. List all users (paginated)
        mockMvc.perform(get("/api/v1/users")
                        .header("Authorization", authHeader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(greaterThanOrEqualTo(2))));

        // 5. Update user data
        UpdateUserRequest updateRequest = new UpdateUserRequest("crud_updated@coeur.app", "Crud User Updated", "ROLE_ADMIN");

        mockMvc.perform(put("/api/v1/users/" + newUserId)
                        .header("Authorization", authHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name", is("Crud User Updated")))
                .andExpect(jsonPath("$.email", is("crud_updated@coeur.app")))
                .andExpect(jsonPath("$.roles", is("ROLE_ADMIN")));

        // 6. Delete user by ID
        mockMvc.perform(delete("/api/v1/users/" + newUserId)
                        .header("Authorization", authHeader))
                .andExpect(status().isNoContent());

        // 7. Fetch the deleted user (should return 404 Not Found through our exception)
        mockMvc.perform(get("/api/v1/users/" + newUserId)
                        .header("Authorization", authHeader))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.detail", is("User not found.")));
    }

    @Test
    void shouldRejectInvalidPayloadsWithBadRequest() throws Exception {
        // 1. Registration with blank password and invalid email
        mockMvc.perform(post("/api/v1/users/register")
                        .header("Authorization", registrarAuthHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterUserRequest("invalid", " ", "John"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email", is("Invalid email.")))
                .andExpect(jsonPath("$.errors.password", is("Password is required.")));

        // 2. Login without a password
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("john@coeur.app", null))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password", is("Password is required.")));

        // 3. Refresh without a token
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RefreshTokenRequest(null))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.refreshToken", is("Refresh token is required.")));

        // 4. Update with missing fields (requires authentication)
        mockMvc.perform(post("/api/v1/users/register")
                        .header("Authorization", registrarAuthHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterUserRequest("valid@coeur.app", "secret123", "Valid User"))))
                .andExpect(status().isCreated());

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("valid@coeur.app", "secret123"))))
                .andExpect(status().isOk())
                .andReturn();

        String token = objectMapper.readTree(loginResult.getResponse().getContentAsString()).get("accessToken").asText();
        String userId = objectMapper.readTree(
                mockMvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + token))
                        .andReturn().getResponse().getContentAsString()
        ).get("id").asText();

        mockMvc.perform(put("/api/v1/users/" + userId)
                        .header("Authorization", registrarAuthHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateUserRequest(null, " ", null))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email", is("Email is required.")))
                .andExpect(jsonPath("$.errors.name", is("Name is required.")))
                .andExpect(jsonPath("$.errors.roles", is("Roles are required.")));
    }

    @Test
    void shouldRejectMalformedRequestsWithBadRequest() throws Exception {
        // 1. Broken JSON in the body
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\": \"john@coeur.app\", "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail", is("Missing or malformed request body.")));

        // 2. Non-numeric ID in the path (requires authentication)
        mockMvc.perform(post("/api/v1/users/register")
                        .header("Authorization", registrarAuthHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterUserRequest("path@coeur.app", "secret123", "Path User"))))
                .andExpect(status().isCreated());

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("path@coeur.app", "secret123"))))
                .andExpect(status().isOk())
                .andReturn();

        String token = objectMapper.readTree(loginResult.getResponse().getContentAsString()).get("accessToken").asText();

        mockMvc.perform(get("/api/v1/users/abc")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail", is("Parameter 'id' has an invalid value.")));
    }

    @Test
    void shouldTriggerRateLimitWhenRequestLimitExceeded() throws Exception {
        // The bucket refills while requests run; the exact capacity is covered with a fixed clock in unit tests.
        for (int i = 0; i < 100; i++) {
            var result = mockMvc.perform(get("/v3/api-docs"));
            if (result.andReturn().getResponse().getStatus() == 429) {
                result.andExpect(jsonPath("$.detail", containsString("Too many requests")));
                return;
            }
            result.andExpect(status().isOk());
        }
        org.junit.jupiter.api.Assertions.fail("Expected throttling during a burst of requests");
    }

    @Test
    void authenticatedUserCanListUsersAndUpdateOwnProfile() throws Exception {
        User user = userRepository.save(User.register("regular@coeur.app", "unused", "Regular"));
        String auth = "Bearer " + tokenService.generateAccessToken(user);
        mockMvc.perform(get("/api/v1/users").header("Authorization", auth)).andExpect(status().isOk());
        mockMvc.perform(put("/api/v1/users/me").header("Authorization", auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"regular@coeur.app\",\"name\":\"Updated\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.name", is("Updated")));
    }

    @Autowired
    private br.app.coeur.identity.modules.authentication.service.AuthService authService;

    @Autowired
    private br.app.coeur.identity.modules.authentication.repository.RefreshTokenRepository refreshTokenRepository;

    @Test
    void onlyOneConcurrentRefreshCanConsumeTheToken() throws Exception {
        User user = userRepository.save(User.register("concurrent@coeur.app", "unused", "Concurrent"));
        refreshTokenRepository.save(br.app.coeur.identity.modules.authentication.model.RefreshToken.issue(
                "concurrent-refresh", user.getId(), java.time.Instant.now(), java.time.Duration.ofDays(1)));
        var start = new java.util.concurrent.CountDownLatch(1);
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Boolean> attempt = () -> {
                start.await();
                try {
                    authService.refresh(new RefreshTokenRequest("concurrent-refresh"));
                    return true;
                } catch (br.app.coeur.identity.modules.authentication.exception.InvalidRefreshTokenException expected) {
                    return false;
                }
            };
            var first = executor.submit(attempt);
            var second = executor.submit(attempt);
            start.countDown();
            org.assertj.core.api.Assertions.assertThat(java.util.List.of(
                    first.get(10, java.util.concurrent.TimeUnit.SECONDS),
                    second.get(10, java.util.concurrent.TimeUnit.SECONDS))).containsExactlyInAnyOrder(true, false);
        }
    }

    @Test
    void logoutRevokesRefreshTokenAndIsIdempotent() throws Exception {
        User user = userRepository.save(User.register("logout@coeur.app", "unused", "Logout"));
        refreshTokenRepository.save(br.app.coeur.identity.modules.authentication.model.RefreshToken.issue(
                "logout-refresh", user.getId(), java.time.Instant.now(), java.time.Duration.ofDays(1)));
        String body = "{\"refreshToken\":\"logout-refresh\"}";
        for (int i = 0; i < 2; i++) {
            mockMvc.perform(post("/api/v1/auth/logout").contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isNoContent());
        }
        mockMvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
    }
}
