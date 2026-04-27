package cl.sebastianrojo.authserver.security.jwt;

import io.jsonwebtoken.Claims;

/**
 * Resultado tipado de la validación de un JWT.
 *
 * <p>Usa el patrón sealed interface + records de Java para modelar
 * un resultado algebraico (valid/expired/invalid) sin excepciones
 * como flujo de control.</p>
 *
 * <p>Ejemplo de uso:</p>
 * <pre>{@code
 * JwtValidationResult result = jwtService.validateToken(token);
 * switch (result) {
 *     case JwtValidationResult.Valid v -> // usar v.claims()
 *     case JwtValidationResult.Expired e -> // retornar 401 con mensaje específico
 *     case JwtValidationResult.Invalid i -> // retornar 401 genérico
 * }
 * }</pre>
 */
public sealed interface JwtValidationResult
    permits JwtValidationResult.Valid,
            JwtValidationResult.Expired,
            JwtValidationResult.Invalid {

    boolean isValid();

    // ── Implementaciones ─────────────────────────────────────────────

    record Valid(Claims claims) implements JwtValidationResult {
        @Override
        public boolean isValid() {
            return true;
        }
    }

    record Expired() implements JwtValidationResult {
        @Override
        public boolean isValid() {
            return false;
        }
    }

    record Invalid(String reason) implements JwtValidationResult {
        @Override
        public boolean isValid() {
            return false;
        }
    }

    // ── Factory methods ───────────────────────────────────────────────

    static JwtValidationResult valid(Claims claims) {
        return new Valid(claims);
    }

    static JwtValidationResult expired() {
        return new Expired();
    }

    static JwtValidationResult invalid(String reason) {
        return new Invalid(reason);
    }
}