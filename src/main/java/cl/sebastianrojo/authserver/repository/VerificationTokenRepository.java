package cl.sebastianrojo.authserver.repository;

import cl.sebastianrojo.authserver.domain.entity.VerificationToken;
import cl.sebastianrojo.authserver.domain.entity.VerificationToken.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {

    Optional<VerificationToken> findByToken(String token);

    /**
     * Busca el último token válido (no usado y no expirado) de un tipo dado para un usuario.
     */
    @Query("""
        SELECT vt FROM VerificationToken vt
        WHERE vt.user.id = :userId
          AND vt.tokenType = :type
          AND vt.used = FALSE
          AND vt.expiresAt > :now
        ORDER BY vt.createdAt DESC
        LIMIT 1
        """)
    Optional<VerificationToken> findLatestValidToken(
        @Param("userId") UUID userId,
        @Param("type") TokenType type,
        @Param("now") Instant now
    );

    /**
     * Invalida todos los tokens anteriores del mismo tipo para evitar
     * que haya múltiples tokens válidos al mismo tiempo (reenvío de email).
     */
    @Modifying
    @Query("""
        UPDATE VerificationToken vt
        SET vt.used = TRUE, vt.usedAt = :now
        WHERE vt.user.id = :userId
          AND vt.tokenType = :type
          AND vt.used = FALSE
        """)
    int invalidatePreviousTokens(
        @Param("userId") UUID userId,
        @Param("type") TokenType type,
        @Param("now") Instant now
    );

    @Modifying
    @Query("DELETE FROM VerificationToken vt WHERE vt.expiresAt < :before")
    int deleteExpired(@Param("before") Instant before);
}