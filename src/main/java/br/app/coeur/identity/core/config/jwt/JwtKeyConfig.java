package br.app.coeur.identity.core.config.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

@Configuration
public class JwtKeyConfig {
    @Bean
    public JwtEncoder jwtEncoder(JwtKeyProvider provider) {
        return provider.jwtEncoder();
    }

    @Bean
    public JwtDecoder jwtDecoder(JwtKeyProvider provider) {
        return provider.jwtDecoder();
    }
}
