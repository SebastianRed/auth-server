package cl.sebastianrojo.authserver.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Excepciones de dominio del Auth Server.
 *
 * <p>Jerarquía de excepciones:</p>
 * <ul>
 *   <li>{@link AuthServerException} — base checked, no se usa directamente</li>
 *   <li>Subclases unchecked (RuntimeException) con {@code @ResponseStatus}
 *       para que el GlobalExceptionHandler mapee el HTTP status correcto.</li>
 * </ul>
 *
 * <p>Centralizar las excepciones en este archivo facilita el mantenimiento
 * y da una visión clara del modelo de errores del dominio.</p>
 */
public final class AuthServerException {

    private AuthServerException() {}

    // ── 400 Bad Request ───────────────────────────────────────────

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public static class PasswordMismatchException extends RuntimeException {
        public PasswordMismatchException() {
            super("Las contraseñas no coinciden.");
        }
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public static class InvalidTokenException extends RuntimeException {
        public InvalidTokenException(String message) {
            super(message);
        }

        public static InvalidTokenException expired() {
            return new InvalidTokenException("El token ha expirado.");
        }

        public static InvalidTokenException invalid() {
            return new InvalidTokenException("El token es inválido o ya fue utilizado.");
        }
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public static class WeakPasswordException extends RuntimeException {
        public WeakPasswordException(String message) {
            super(message);
        }
    }

    // ── 401 Unauthorized ─────────────────────────────────────────

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class InvalidCredentialsException extends RuntimeException {
        public InvalidCredentialsException() {
            // Mensaje genérico para no revelar si existe el usuario
            super("Credenciales inválidas.");
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class TokenRefreshException extends RuntimeException {
        public TokenRefreshException(String message) {
            super(message);
        }

        public static TokenRefreshException revoked() {
            return new TokenRefreshException("El refresh token ha sido revocado.");
        }

        public static TokenRefreshException expired() {
            return new TokenRefreshException("El refresh token ha expirado. Por favor inicia sesión nuevamente.");
        }

        public static TokenRefreshException notFound() {
            return new TokenRefreshException("Refresh token no encontrado.");
        }
    }

    // ── 403 Forbidden ─────────────────────────────────────────────

    @ResponseStatus(HttpStatus.FORBIDDEN)
    public static class AccountNotVerifiedException extends RuntimeException {
        public AccountNotVerifiedException() {
            super("La cuenta no ha sido verificada. Revisa tu email para verificar tu cuenta.");
        }
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    public static class AccountLockedException extends RuntimeException {
        public AccountLockedException() {
            super("La cuenta está bloqueada temporalmente por múltiples intentos fallidos.");
        }
    }

    // ── 404 Not Found ─────────────────────────────────────────────

    @ResponseStatus(HttpStatus.NOT_FOUND)
    public static class UserNotFoundException extends RuntimeException {
        public UserNotFoundException(String identifier) {
            super("Usuario no encontrado: " + identifier);
        }
    }

    // ── 409 Conflict ──────────────────────────────────────────────

    @ResponseStatus(HttpStatus.CONFLICT)
    public static class EmailAlreadyExistsException extends RuntimeException {
        public EmailAlreadyExistsException(String email) {
            super("El email ya está registrado: " + email);
        }
    }

    @ResponseStatus(HttpStatus.CONFLICT)
    public static class UsernameAlreadyExistsException extends RuntimeException {
        public UsernameAlreadyExistsException(String username) {
            super("El username ya está en uso: " + username);
        }
    }

    // ── 429 Too Many Requests ────────────────────────────────────

    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    public static class RateLimitExceededException extends RuntimeException {
        public RateLimitExceededException() {
            super("Demasiados intentos. Por favor espera antes de intentar nuevamente.");
        }
    }
}