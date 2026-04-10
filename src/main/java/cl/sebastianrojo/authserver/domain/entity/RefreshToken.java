package cl.sebastianrojo.authserver.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Refresh Token persistido en base de datos.
 *
 * <p>Decisión de diseño: el refresh token es un UUID opaco (no un JWT).
 * Esto permite revocarlo instantáneamente en BD sin necesidad de blacklist.
 * El access token sí es un JWT stateless (se invalida al expirar).</p>
 *
 * <p>Un usuario puede tener múltiples refresh tokens activos
 * (soporte multi-dispositivo: móvil, web, desktop).</p>
 */
@Entity
@Table(name = "refresh_tokens")
public class RefreshToken extends BaseEntity {

    @Column(name = "token", nullable = false, unique = true, length = 512)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "device_id", length = 255)
    private String deviceId;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "issued_at", nullable = false, updatable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "revoked", nullable = false)
    private boolean revoked = false;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "revoke_reason", length = 100)
    private String revokeReason;

    // ── Constructors ─────────────────────────────────────────────────

    protected RefreshToken() {}

    private RefreshToken(Builder builder) {
        this.token = builder.token;
        this.user = builder.user;
        this.deviceId = builder.deviceId;
        this.userAgent = builder.userAgent;
        this.ipAddress = builder.ipAddress;
        this.issuedAt = Instant.now();
        this.expiresAt = builder.expiresAt;
    }

    // ── Métodos de dominio ────────────────────────────────────────

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return !revoked && !isExpired();
    }

    public void revoke(String reason) {
        this.revoked = true;
        this.revokedAt = Instant.now();
        this.revokeReason = reason;
    }

    // ── Getters ───────────────────────────────────────────────────────

    public String getToken() { return token; }
    public User getUser() { return user; }
    public String getDeviceId() { return deviceId; }
    public String getUserAgent() { return userAgent; }
    public String getIpAddress() { return ipAddress; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public Instant getRevokedAt() { return revokedAt; }
    public String getRevokeReason() { return revokeReason; }

    // ── Builder ───────────────────────────────────────────────────────

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String token;
        private User user;
        private String deviceId;
        private String userAgent;
        private String ipAddress;
        private Instant expiresAt;

        private Builder() {}

        public Builder token(String token) { this.token = token; return this; }
        public Builder user(User user) { this.user = user; return this; }
        public Builder deviceId(String deviceId) { this.deviceId = deviceId; return this; }
        public Builder userAgent(String userAgent) { this.userAgent = userAgent; return this; }
        public Builder ipAddress(String ipAddress) { this.ipAddress = ipAddress; return this; }
        public Builder expiresAt(Instant expiresAt) { this.expiresAt = expiresAt; return this; }

        public RefreshToken build() {
            return new RefreshToken(this);
        }
    }
}