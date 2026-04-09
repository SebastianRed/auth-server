package cl.sebastianrojo.authserver.domain.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Entidad principal del sistema de autenticación.
 *
 * <p>Implementa {@link UserDetails} para integración con Spring Security.
 * Esto permite que el servicio de UserDetailsService retorne directamente
 * la entidad sin necesidad de un adaptador intermedio.</p>
 *
 * <p>Los roles se cargan con EAGER por requerimiento de Spring Security
 * (necesita los authorities en el momento de autenticación). Se usa
 * {@code FetchType.EAGER} solo aquí donde está justificado técnicamente.</p>
 */
@Entity
@Table(name = "users")
public class User extends BaseEntity implements UserDetails {

    @Column(name = "email", nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "username", nullable = false, unique = true, length = 100)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "first_name", length = 100)
    private String firstName;

    @Column(name = "last_name", length = 100)
    private String lastName;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = false;

    @Column(name = "account_locked", nullable = false)
    private boolean accountLocked = false;

    @Column(name = "account_expired", nullable = false)
    private boolean accountExpired = false;

    @Column(name = "credentials_expired", nullable = false)
    private boolean credentialsExpired = false;

    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified = false;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts = 0;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    // ── Relaciones ──────────────────────────────────────────────────

    /**
     * EAGER justificado: Spring Security necesita los roles durante
     * la autenticación, que ocurre en el mismo contexto de transacción.
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<RefreshToken> refreshTokens = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<VerificationToken> verificationTokens = new HashSet<>();

    // ── Constructors ─────────────────────────────────────────────────

    protected User() {
        // Requerido por JPA
    }

    /**
     * Constructor de creación. El builder estático es la forma preferida
     * de instanciar un User desde el código de servicio.
     */
    private User(Builder builder) {
        this.email = builder.email;
        this.username = builder.username;
        this.passwordHash = builder.passwordHash;
        this.firstName = builder.firstName;
        this.lastName = builder.lastName;
        this.enabled = builder.enabled;
        this.roles = builder.roles;
    }

    // ── UserDetails (Spring Security) ─────────────────────────────

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    /**
     * Retorna el hash de la contraseña (nunca la contraseña en texto plano).
     */
    @Override
    public String getPassword() {
        return passwordHash;
    }

    /**
     * Username usado por Spring Security. Usamos el email como identificador
     * primario de autenticación (más único que username).
     */
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !accountExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        // Verificar también el tiempo de bloqueo temporal
        if (accountLocked) return false;
        if (lockedUntil != null && Instant.now().isBefore(lockedUntil)) return false;
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    // ── Métodos de dominio ────────────────────────────────────────

    /**
     * Incrementa el contador de intentos fallidos y bloquea
     * temporalmente si supera el máximo.
     */
    public void registerFailedLoginAttempt(int maxAttempts, long lockDurationSeconds) {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= maxAttempts) {
            this.lockedUntil = Instant.now().plusSeconds(lockDurationSeconds);
        }
    }

    /**
     * Resetea el contador de intentos fallidos tras un login exitoso.
     */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
    }

    public void addRole(Role role) {
        this.roles.add(role);
    }

    public void removeRole(Role role) {
        this.roles.remove(role);
    }

    public boolean hasRole(String roleName) {
        return roles.stream().anyMatch(r -> r.getName().equals(roleName));
    }

    // ── Getters / Setters ────────────────────────────────────────────

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDisplayUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFullName() {
        if (firstName == null && lastName == null) return username;
        if (firstName == null) return lastName;
        if (lastName == null) return firstName;
        return firstName + " " + lastName;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isAccountLocked() {
        return accountLocked;
    }

    public void setAccountLocked(boolean accountLocked) {
        this.accountLocked = accountLocked;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public Instant getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(Instant lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public Set<RefreshToken> getRefreshTokens() {
        return refreshTokens;
    }

    // ── Builder ───────────────────────────────────────────────────────

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String email;
        private String username;
        private String passwordHash;
        private String firstName;
        private String lastName;
        private boolean enabled = false;
        private Set<Role> roles = new HashSet<>();

        private Builder() {}

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder passwordHash(String passwordHash) {
            this.passwordHash = passwordHash;
            return this;
        }

        public Builder firstName(String firstName) {
            this.firstName = firstName;
            return this;
        }

        public Builder lastName(String lastName) {
            this.lastName = lastName;
            return this;
        }

        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public Builder roles(Set<Role> roles) {
            this.roles = roles;
            return this;
        }

        public User build() {
            return new User(this);
        }
    }

    @Override
    public String toString() {
        return "User{id=" + getId() + ", email='" + email + "', username='" + username + "'}";
    }
}