package cl.sebastianrojo.authserver.dto.response;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * DTOs de salida. Records inmutables para garantizar consistencia
 * en las respuestas JSON de la API.
 */
public final class AuthResponse {

    private AuthResponse() {}

    // ── Token Response (login / refresh) ─────────────────────────

    /**
     * Respuesta estándar de login y refresh de tokens.
     *
     * @param accessToken  JWT de corta duración
     * @param refreshToken Token opaco de larga duración
     * @param tokenType    Siempre "Bearer"
     * @param expiresIn    Segundos hasta que expira el access token
     * @param user         Datos básicos del usuario autenticado
     */
    public record TokenPair(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        UserInfo user
    ) {
        public static TokenPair of(
            String accessToken,
            String refreshToken,
            long accessTokenExpirationMs,
            UserInfo user
        ) {
            return new TokenPair(
                accessToken,
                refreshToken,
                "Bearer",
                accessTokenExpirationMs / 1000,
                user
            );
        }
    }

    // ── User Info (incluido en TokenPair y en /users/me) ─────────

    public record UserInfo(
        UUID id,
        String email,
        String username,
        String firstName,
        String lastName,
        String fullName,
        List<String> roles,
        boolean emailVerified,
        Instant lastLoginAt
    ) {}

    // ── Mensaje simple ────────────────────────────────────────────

    public record Message(String message) {
        public static Message of(String message) {
            return new Message(message);
        }
    }

    // ── Error estándar ────────────────────────────────────────────

    public record ApiError(
        int status,
        String error,
        String message,
        String path,
        Instant timestamp,
        List<FieldError> fieldErrors
    ) {
        public record FieldError(String field, String message) {}

        public static ApiError of(int status, String error, String message, String path) {
            return new ApiError(status, error, message, path, Instant.now(), List.of());
        }

        public static ApiError withFieldErrors(
            int status,
            String error,
            String message,
            String path,
            List<FieldError> fieldErrors
        ) {
            return new ApiError(status, error, message, path, Instant.now(), fieldErrors);
        }
    }
}