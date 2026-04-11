package cl.sebastianrojo.authserver.repository;

import cl.sebastianrojo.authserver.domain.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Repositorio de usuarios.
 *
 * <p>Convención: los métodos que modifican datos van con {@code @Modifying}
 * y en el servicio deben estar dentro de una transacción activa.</p>
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByUsername(String username);

    /**
     * Actualización directa en BD (evita cargar la entidad solo para modificar un campo).
     */
    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginAt, u.failedLoginAttempts = 0, u.lockedUntil = NULL WHERE u.id = :userId")
    void updateSuccessfulLogin(@Param("userId") UUID userId, @Param("loginAt") Instant loginAt);

    @Modifying
    @Query("UPDATE User u SET u.emailVerified = TRUE, u.enabled = TRUE WHERE u.id = :userId")
    void markEmailAsVerified(@Param("userId") UUID userId);
}