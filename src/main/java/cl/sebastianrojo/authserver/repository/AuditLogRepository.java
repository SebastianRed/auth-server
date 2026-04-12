package cl.sebastianrojo.authserver.repository;

import cl.sebastianrojo.authserver.domain.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findByUserId(UUID userId, Pageable pageable);

    Page<AuditLog> findByEventType(String eventType, Pageable pageable);

    List<AuditLog> findByUserIdAndCreatedAtAfter(UUID userId, Instant after);

    List<AuditLog> findByIpAddressAndEventTypeAndCreatedAtAfter(
        String ipAddress,
        String eventType,
        Instant after
    );
}