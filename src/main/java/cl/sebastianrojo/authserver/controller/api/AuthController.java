package cl.sebastianrojo.authserver.controller.api;

import cl.sebastianrojo.authserver.domain.entity.User;
import cl.sebastianrojo.authserver.dto.request.AuthRequest;
import cl.sebastianrojo.authserver.dto.response.AuthResponse;
import cl.sebastianrojo.authserver.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller REST para operaciones de autenticación.
 *
 * <p>Base path: {@code /auth}</p>
 *
 * <p>Los endpoints de este controller están mapeados en el
 * {@code apiSecurityFilterChain} de SecurityConfig y son públicos
 * excepto {@code /auth/logout} que requiere autenticación.</p>
 */
@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "Endpoints de autenticación y gestión de tokens")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // ── POST /auth/register ────────────────────────────────────────

    @PostMapping("/register")
    @Operation(
        summary = "Registrar nuevo usuario",
        description = "Crea una nueva cuenta. Envía un email de verificación al completar."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Usuario registrado exitosamente"),
        @ApiResponse(responseCode = "400", description = "Datos de entrada inválidos"),
        @ApiResponse(responseCode = "409", description = "Email o username ya existe")
    })
    public ResponseEntity<AuthResponse.Message> register(
        @Valid @RequestBody AuthRequest.Register request,
        HttpServletRequest httpRequest
    ) {
        AuthResponse.Message response = authService.register(request, httpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ── POST /auth/login ───────────────────────────────────────────

    @PostMapping("/login")
    @Operation(
        summary = "Iniciar sesión",
        description = "Autentica al usuario y retorna access token + refresh token."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Login exitoso"),
        @ApiResponse(responseCode = "401", description = "Credenciales inválidas"),
        @ApiResponse(responseCode = "403", description = "Cuenta bloqueada o no verificada"),
        @ApiResponse(responseCode = "429", description = "Demasiados intentos")
    })
    public ResponseEntity<AuthResponse.TokenPair> login(
        @Valid @RequestBody AuthRequest.Login request,
        HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(authService.login(request, httpRequest));
    }

    // ── POST /auth/refresh ─────────────────────────────────────────

    @PostMapping("/refresh")
    @Operation(
        summary = "Renovar tokens",
        description = "Usa un refresh token válido para obtener nuevos access y refresh tokens. " +
                      "Implementa rotación: el refresh token usado queda invalidado."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Tokens renovados exitosamente"),
        @ApiResponse(responseCode = "401", description = "Refresh token inválido, expirado o revocado")
    })
    public ResponseEntity<AuthResponse.TokenPair> refresh(
        @Valid @RequestBody AuthRequest.Refresh request,
        HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(authService.refresh(request, httpRequest));
    }

    // ── POST /auth/logout ─────────────────────────────────────────

    @PostMapping("/logout")
    @Operation(
        summary = "Cerrar sesión",
        description = "Revoca el refresh token. Si logoutAll=true, cierra todas las sesiones."
    )
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Sesión cerrada"),
        @ApiResponse(responseCode = "401", description = "No autenticado")
    })
    public ResponseEntity<AuthResponse.Message> logout(
        @Valid @RequestBody AuthRequest.Logout request,
        @AuthenticationPrincipal User currentUser,
        HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(authService.logout(request, currentUser, httpRequest));
    }

    // ── GET /auth/verify-email ────────────────────────────────────

    @GetMapping("/verify-email")
    @Operation(
        summary = "Verificar email",
        description = "Verifica el email con el token recibido por correo."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Email verificado"),
        @ApiResponse(responseCode = "400", description = "Token inválido o expirado")
    })
    public ResponseEntity<AuthResponse.Message> verifyEmail(
        @RequestParam String token,
        HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(authService.verifyEmail(token, httpRequest));
    }

    // ── POST /auth/forgot-password ────────────────────────────────

    @PostMapping("/forgot-password")
    @Operation(
        summary = "Solicitar reset de contraseña",
        description = "Envía un email con enlace para resetear la contraseña. " +
                      "Siempre retorna 200 para evitar enumeración de usuarios."
    )
    public ResponseEntity<AuthResponse.Message> forgotPassword(
        @Valid @RequestBody AuthRequest.ForgotPassword request,
        HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(authService.forgotPassword(request, httpRequest));
    }

    // ── POST /auth/reset-password ─────────────────────────────────

    @PostMapping("/reset-password")
    @Operation(
        summary = "Resetear contraseña",
        description = "Establece una nueva contraseña usando el token recibido por email."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Contraseña actualizada"),
        @ApiResponse(responseCode = "400", description = "Token inválido, expirado o contraseñas no coinciden")
    })
    public ResponseEntity<AuthResponse.Message> resetPassword(
        @Valid @RequestBody AuthRequest.ResetPassword request,
        HttpServletRequest httpRequest
    ) {
        return ResponseEntity.ok(authService.resetPassword(request, httpRequest));
    }
}