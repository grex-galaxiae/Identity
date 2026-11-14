package br.app.coeur.identity.modules.authentication;

import br.app.coeur.identity.modules.authentication.dto.request.LoginRequest;
import br.app.coeur.identity.modules.authentication.service.AuthService;
import br.app.coeur.identity.modules.user.model.User;
import br.app.coeur.identity.modules.user.repository.UserRepository;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "dev"})
class EnvironmentIssuerIntegrationTest {
    @Autowired AuthService auth;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtDecoder decoder;
    @Autowired JwtEncoder encoder;
    @Autowired MockMvc mvc;

    @Test
    void deploymentIssuerIsUsedForLoginAndProtectedRequests() throws Exception {
        var user = users.save(User.register("environment@coeur.app", passwords.encode("secret123"), "Environment"));
        var tokens = auth.login(new LoginRequest(user.getEmail(), "secret123"));
        assertThat(decoder.decode(tokens.accessToken()).getIssuer().toString())
                .isEqualTo("https://development.coeur.app.br");
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isOk());

        var now = Instant.now();
        var claims = JwtClaimsSet.builder().issuer("https://production.coeur.app.br")
                .subject(user.getId().toString()).issuedAt(now).expiresAt(now.plusSeconds(900)).build();
        String wrongEnvironment = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + wrongEnvironment))
                .andExpect(status().isUnauthorized());
    }
}