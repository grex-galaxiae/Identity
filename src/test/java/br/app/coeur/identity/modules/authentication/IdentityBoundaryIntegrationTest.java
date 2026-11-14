package br.app.coeur.identity.modules.authentication;

import br.app.coeur.identity.modules.authentication.service.AuthService;
import br.app.coeur.identity.modules.authentication.dto.request.LoginRequest;
import br.app.coeur.identity.modules.user.model.User;
import br.app.coeur.identity.modules.user.repository.UserRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IdentityBoundaryIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwords;
    @Autowired AuthService auth;

    @Test
    void publishesOnlyThePublicKeyAndItVerifiesIssuedAccessTokens() throws Exception {
        var user = users.save(User.register("jwks-boundary@coeur.app", passwords.encode("secret123"), "JWKS"));
        var tokens = auth.login(new LoginRequest(user.getEmail(), "secret123"));
        var response = mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist())
                .andReturn();
        RSAKey publicKey = (RSAKey) JWKSet.parse(response.getResponse().getContentAsString()).getKeys().getFirst();
        assertThat(publicKey.isPrivate()).isFalse();
        var decoded = NimbusJwtDecoder.withPublicKey(publicKey.toRSAPublicKey()).build().decode(tokens.accessToken());
        assertThat(decoded.getSubject()).isEqualTo(user.getId().toString());
        assertThat(decoded.getClaimAsString("iss")).isEqualTo("https://production.coeur.app.br");
        assertThat(decoded.getHeaders()).containsEntry("kid", publicKey.getKeyID());
    }

    @Test
    void refreshAndLogoutWorkEvenWithAnInvalidAccessTokenHeader() throws Exception {
        var user = users.save(User.register("refresh-boundary@coeur.app", passwords.encode("secret123"), "Refresh"));
        var login = mvc.perform(post("/api/v1/auth/login")
                        .header("Authorization", "Bearer expired-access-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"refresh-boundary@coeur.app\",\"password\":\"secret123\"}"))
                .andExpect(status().isOk()).andReturn();
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        String refresh = mapper.readTree(login.getResponse().getContentAsString()).get("refreshToken").asText();
        var result = mvc.perform(post("/api/v1/auth/refresh")
                        .header("Authorization", "Bearer expired-access-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isOk()).andReturn();
        String rotated = mapper.readTree(result.getResponse().getContentAsString()).get("refreshToken").asText();
        assertThat(rotated).isNotEqualTo(refresh);
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/auth/logout").header("Authorization", "Bearer expired-access-token")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"refreshToken\":\"" + rotated + "\"}"))
                .andExpect(status().isNoContent());
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + rotated + "\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + rotated))
                .andExpect(status().isUnauthorized());
    }
}