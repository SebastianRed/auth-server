package cl.sebastianrojo.authserver.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTOs de entrada para operaciones de autenticación.
 *
 * <p>Se usan records de Java (inmutables por defecto) con Bean Validation.
 * La validación se activa con {@code @Valid} en los controllers.</p>
 */
public final class AuthRequest {

    private AuthRequest() {}

    // ── Login ──────────────────────────────────────────────────────

    public record Login(
        @NotBlank(message = "El email es requerido")
        @Email(message = "Formato de email inválido")
        String email,

        @NotBlank(message = "La contraseña es requerida")
        String password
    ) {}

    // ── Registro ───────────────────────────────────────────────────

    public record Register(
        @NotBlank(message = "El email es requerido")
        @Email(message = "Formato de email inválido")
        @Size(max = 255, message = "El email no puede superar 255 caracteres")
        String email,

        @NotBlank(message = "El username es requerido")
        @Size(min = 3, max = 50, message = "El username debe tener entre 3 y 50 caracteres")
        String username,

        @NotBlank(message = "La contraseña es requerida")
        @Size(min = 8, max = 100, message = "La contraseña debe tener entre 8 y 100 caracteres")
        String password,

        @NotBlank(message = "La confirmación de contraseña es requerida")
        String confirmPassword,

        @Size(max = 100)
        String firstName,

        @Size(max = 100)
        String lastName
    ) {}

    // ── Refresh Token ──────────────────────────────────────────────

    public record Refresh(
        @NotBlank(message = "El refresh token es requerido")
        String refreshToken
    ) {}

    // ── Forgot Password ────────────────────────────────────────────

    public record ForgotPassword(
        @NotBlank(message = "El email es requerido")
        @Email(message = "Formato de email inválido")
        String email
    ) {}

    // ── Reset Password ─────────────────────────────────────────────

    public record ResetPassword(
        @NotBlank(message = "El token es requerido")
        String token,

        @NotBlank(message = "La nueva contraseña es requerida")
        @Size(min = 8, max = 100, message = "La contraseña debe tener entre 8 y 100 caracteres")
        String newPassword,

        @NotBlank(message = "La confirmación de contraseña es requerida")
        String confirmPassword
    ) {}

    // ── Logout ─────────────────────────────────────────────────────

    public record Logout(
        @NotBlank(message = "El refresh token es requerido")
        String refreshToken,

        boolean logoutAll   // true = cerrar todas las sesiones del usuario
    ) {}
}