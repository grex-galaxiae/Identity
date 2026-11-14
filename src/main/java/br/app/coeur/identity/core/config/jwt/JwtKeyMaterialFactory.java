package br.app.coeur.identity.core.config.jwt;

import br.app.coeur.identity.modules.authentication.model.JwtSigningKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.security.oauth2.jwt.*;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

final class JwtKeyMaterialFactory {
    private final String issuer;

    JwtKeyMaterialFactory(String issuer) {
        this.issuer = issuer;
    }

    JwtKeyMaterial create(JwtSigningKey stored) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(stored.getPublicKey())));
            RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(stored.getPrivateKey())));
            validateKeyPair(publicKey, privateKey);
            RSAKey jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(stored.getKeyId().toString()).build();
            JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk)));
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
            decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
            return new JwtKeyMaterial(stored.getKeyId(), encoder, decoder);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load JWT signing key from the database", e);
        }
    }


    private void validateKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        byte[] challenge = new byte[]{1, 2, 3};
        signature.initSign(privateKey);
        signature.update(challenge);
        byte[] signed = signature.sign();
        signature.initVerify(publicKey);
        signature.update(challenge);
        if (!signature.verify(signed)) throw new IllegalStateException("JWT keys in the database do not match.");
    }
}
