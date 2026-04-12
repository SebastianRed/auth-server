package cl.sebastianrojo.authserver.repository;

import cl.sebastianrojo.authserver.domain.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findAllByUserIdAndRevokedFalse(UUID userId);

    /**
     * Revocar todos los refresh tokens activos de un usuario.
     * Usado en logout global (ej: "cerrar sesión en todos los dispositivos").
     */
    @Modifying
    @Query("""
        UPDATE RefreshToken rt
        SET rt.revoked = TRUE,
            rt.revokedAt = :now,
            rt.revokeReason = :reason
        WHERE rt.user.id = :userId
          AND rt.revoked = FALSE
        """)
    int revokeAllByUserId(
        @Param("userId") UUID userId,
        @Param("now") Instant now,
        @Param("reason") String reason
    );

    /**
     * Limpieza periódica: eliminar tokens expirados y revocados.
     * Llamado por un @Scheduled task para no acumular basura en BD.
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :before OR rt.revoked = TRUE")
    int deleteExpiredAndRevoked(@Param("before") Instant before);

    long countByUserIdAndRevokedFalse(UUID userId);
}