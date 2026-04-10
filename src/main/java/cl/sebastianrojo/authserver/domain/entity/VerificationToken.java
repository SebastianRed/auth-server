package cl.sebastianrojo.authserver.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Token de uso único para flujos de verificación de email y reset de contraseña.
 *
 * <p>Diseño unificado con discriminador de tipo ({@link TokenType}) para evitar
 * duplicar tablas con la misma estructura. Cada token puede usarse exactamente
 * una vez ({@code used = true}) y tiene fecha de expiración.</p>
 */
@Entity
@Table(name = "verification_tokens")
public class VerificationToken extends BaseEntity {

    /**
     * Tipo de token. Mapea al ENUM PostgreSQL {@code verification_token_type}.
     */
    public enum TokenType {
        EMAIL_VERIFICATION,
        PASSWORD_RESET
    }

    @Column(name = "token", nullable = false, unique = true, length = 255)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "token_type", nullable = false, length = 50,
            columnDefinition = "verification_token_type")
    private TokenType tokenType;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "used", nullable = false)
    private boolean used = false;

    @Column(name = "used_at")
    private Instant usedAt;

    // ── Constructors ─────────────────────────────────────────────────

    protected VerificationToken() {}

    private VerificationToken(Builder builder) {
        this.token = builder.token;
        this.user = builder.user;
        this.tokenType = builder.tokenType;
        this.expiresAt = builder.expiresAt;
    }

    // ── Métodos de dominio ────────────────────────────────────────

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return !used && !isExpired();
    }

    /**
     * Marca el token como usado. Operación irreversible.
     */
    public void markAsUsed() {
        this.used = true;
        this.usedAt = Instant.now();
    }

    // ── Getters ───────────────────────────────────────────────────────

    public String getToken() { return token; }
    public User getUser() { return user; }
    public TokenType getTokenType() { return tokenType; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isUsed() { return used; }
    public Instant getUsedAt() { return usedAt; }

    // ── Builder ───────────────────────────────────────────────────────

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String token;
        private User user;
        private TokenType tokenType;
        private Instant expiresAt;

        private Builder() {}

        public Builder token(String token) { this.token = token; return this; }
        public Builder user(User user) { this.user = user; return this; }
        public Builder tokenType(TokenType tokenType) { this.tokenType = tokenType; return this; }
        public Builder expiresAt(Instant expiresAt) { this.expiresAt = expiresAt; return this; }

        public VerificationToken build() {
            return new VerificationToken(this);
        }
    }
}