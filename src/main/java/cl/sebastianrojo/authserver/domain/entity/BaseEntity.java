package cl.sebastianrojo.authserver.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Clase base para entidades con auditoría automática.
 *
 * <p>Usa {@code @MappedSuperclass} para que JPA no cree una tabla propia,
 * sino que hereda las columnas en cada entidad hija.</p>
 *
 * <p>Decisión: no usamos {@code @EntityListeners(AuditingEntityListener.class)}
 * de Spring Data para mantener la dependencia mínima y el control explícito
 * de las fechas mediante callbacks JPA estándar.</p>
 */
@MappedSuperclass
public abstract class BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false, columnDefinition = "UUID")
    private UUID id;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    protected void onCreate() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }

    // ── Getters ─────────────────────────────────────────────────────

    public UUID getId() {
        return id;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    // ── equals / hashCode basados en ID ─────────────────────────────
    // Patrón recomendado para entidades JPA con UUID

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof BaseEntity that)) return false;
        return id != null && Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        // Constante para entidades transientes (id == null)
        return id != null ? Objects.hash(id) : getClass().hashCode();
    }
}