package br.app.coeur.identity.modules.authentication.repository;

import br.app.coeur.identity.modules.authentication.model.JwtSigningKey;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface JwtSigningKeyRepository extends JpaRepository<JwtSigningKey, Integer> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT k FROM JwtSigningKey k WHERE k.id = 1")
    Optional<JwtSigningKey> findForUpdate();
}
