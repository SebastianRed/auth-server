package cl.sebastianrojo.authserver.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

/**
 * Propiedades custom del Auth Server.
 *
 * <p>Binding de las propiedades bajo el prefijo {@code auth} en application.yml.
 * Al usar records (Java 16+), el binding es inmutable y thread-safe por diseño.</p>
 *
 * <p>Registrado automáticamente via {@code @ConfigurationPropertiesScan}
 * en la clase principal de la aplicación.</p>
 */
@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
    JwtProperties jwt,
    SecurityProperties security,
    EmailProperties email
) {

    /**
     * Propiedades de JWT.
     *
     * @param secret               Clave secreta para firmar tokens (min 256 bits en prod)
     * @param accessTokenExpirationMs  Duración del access token en ms (default: 15 min)
     * @param refreshTokenExpirationMs Duración del refresh token en ms (default: 7 días)
     * @param issuer               Claim "iss" del JWT
     */
    public record JwtProperties(
        String secret,
        long accessTokenExpirationMs,
        long refreshTokenExpirationMs,
        String issuer
    ) {}

    /**
     * Propiedades de seguridad.
     *
     * @param bcryptStrength          Rounds de BCrypt (12 recomendado)
     * @param maxLoginAttempts        Intentos fallidos antes de rate limit
     * @param loginAttemptWindowSeconds Ventana de tiempo para max-login-attempts
     */
    public record SecurityProperties(
        int bcryptStrength,
        int maxLoginAttempts,
        long loginAttemptWindowSeconds
    ) {}

    /**
     * Propiedades de email.
     *
     * @param verificationTokenExpirationHours Validez del token de verificación de email
     * @param passwordResetTokenExpirationHours Validez del token de reset de contraseña
     * @param baseUrl URL base para links en emails
     * @param from Dirección de origen de los emails
     */
    public record EmailProperties(
        int verificationTokenExpirationHours,
        int passwordResetTokenExpirationHours,
        String baseUrl,
        String from
    ) {}
}