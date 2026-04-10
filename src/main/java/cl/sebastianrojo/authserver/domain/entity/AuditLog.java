package cl.sebastianrojo.authserver.domain.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * Registro de auditoría de eventos de seguridad.
 *
 * <p>No extiende {@link BaseEntity} porque:
 * <ul>
 *   <li>Usa BIGSERIAL (auto-incremental) como PK para mejor performance
 *       en inserciones masivas de logs.</li>
 *   <li>No necesita {@code updated_at} (los logs son inmutables).</li>
 *   <li>No tiene UUID como PK (no necesita ser referenciado externamente).</li>
 * </ul>
 * </p>
 */
@Entity
@Table(name = "audit_logs")
public class AuditLog {

    public enum EventType {
        // Autenticación
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGIN_BLOCKED,
        LOGOUT,
        // Tokens
        TOKEN_REFRESHED,
        TOKEN_REVOKED,
        // Cuenta
        REGISTER,
        EMAIL_VERIFICATION_SENT,
        EMAIL_VERIFIED,
        PASSWORD_RESET_REQUESTED,
        PASSWORD_RESET_SUCCESS,
        // Admin
        USER_LOCKED,
        USER_UNLOCKED,
        ROLE_ASSIGNED,
        ROLE_REMOVED
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id;

    /**
     * Puede ser null si el evento es previo a la autenticación
     * (ej: intento de login con email inexistente).
     */
    @Column(name = "user_id", columnDefinition = "UUID")
    private UUID userId;

    @Column(name = "event_type", nullable = false, length = 100)
    private String eventType;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    /**
     * Contexto adicional en formato JSON.
     * Ej: {"username": "...", "reason": "MAX_ATTEMPTS_EXCEEDED"}
     */
    @Column(name = "details", columnDefinition = "TEXT")
    private String details;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
    }

    // ── Constructors ─────────────────────────────────────────────────

    protected AuditLog() {}

    private AuditLog(Builder builder) {
        this.userId = builder.userId;
        this.eventType = builder.eventType;
        this.ipAddress = builder.ipAddress;
        this.userAgent = builder.userAgent;
        this.details = builder.details;
    }

    // ── Getters ───────────────────────────────────────────────────────

    public Long getId() { return id; }
    public UUID getUserId() { return userId; }
    public String getEventType() { return eventType; }
    public String getIpAddress() { return ipAddress; }
    public String getUserAgent() { return userAgent; }
    public String getDetails() { return details; }
    public Instant getCreatedAt() { return createdAt; }

    // ── Builder ───────────────────────────────────────────────────────

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private UUID userId;
        private String eventType;
        private String ipAddress;
        private String userAgent;
        private String details;

        private Builder() {}

        public Builder userId(UUID userId) { this.userId = userId; return this; }
        public Builder eventType(EventType eventType) { this.eventType = eventType.name(); return this; }
        public Builder eventType(String eventType) { this.eventType = eventType; return this; }
        public Builder ipAddress(String ipAddress) { this.ipAddress = ipAddress; return this; }
        public Builder userAgent(String userAgent) { this.userAgent = userAgent; return this; }
        public Builder details(String details) { this.details = details; return this; }

        public AuditLog build() {
            return new AuditLog(this);
        }
    }
}