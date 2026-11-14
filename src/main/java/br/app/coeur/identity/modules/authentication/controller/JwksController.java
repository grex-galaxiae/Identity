package br.app.coeur.identity.modules.authentication.controller;

import br.app.coeur.identity.modules.authentication.service.JwtKeyService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JwksController {
    private final JwtKeyService keyService;

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> publicKeys() {
        var stored = keyService.getActiveKey();
        try {
            var publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(stored.getPublicKey())));
            RSAKey jwk = new RSAKey.Builder(publicKey)
                    .keyID(stored.getKeyId().toString())
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                    .body(new JWKSet(jwk).toJSONObject());
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to publish JWT verification key", exception);
        }
    }
}
