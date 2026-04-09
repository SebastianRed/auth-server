package cl.sebastianrojo.authserver.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import org.springframework.security.core.GrantedAuthority;

import java.util.HashSet;
import java.util.Set;

/**
 * Rol del sistema. Implementa {@link GrantedAuthority} para integración
 * directa con Spring Security sin capas de adaptación adicionales.
 *
 * <p>Convención de nombres: {@code ROLE_USER}, {@code ROLE_ADMIN}, etc.
 * Spring Security espera el prefijo "ROLE_" en {@code hasRole()} checks.</p>
 */
@Entity
@Table(name = "roles")
public class Role extends BaseEntity implements GrantedAuthority {

    @Column(name = "name", nullable = false, unique = true, length = 50)
    private String name;

    @Column(name = "description", length = 255)
    private String description;

    /**
     * Relación inversa. No es el lado "dueño" — solo para navegación.
     * {@code mappedBy} apunta al campo en {@link User}.
     */
    @ManyToMany(mappedBy = "roles")
    private Set<User> users = new HashSet<>();

    // ── Constructors ────────────────────────────────────────────────

    protected Role() {
        // Constructor protegido requerido por JPA
    }

    public Role(String name, String description) {
        this.name = name;
        this.description = description;
    }

    // ── GrantedAuthority ────────────────────────────────────────────

    /**
     * Spring Security usa este método para evaluar permisos.
     * Retorna el nombre del rol (ej: "ROLE_ADMIN").
     */
    @Override
    public String getAuthority() {
        return name;
    }

    // ── Getters / Setters ────────────────────────────────────────────

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<User> getUsers() {
        return users;
    }

    @Override
    public String toString() {
        return "Role{name='" + name + "'}";
    }
}