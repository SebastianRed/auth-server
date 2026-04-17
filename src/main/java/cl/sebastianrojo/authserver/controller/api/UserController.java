package cl.sebastianrojo.authserver.controller.api;

import cl.sebastianrojo.authserver.domain.entity.User;
import cl.sebastianrojo.authserver.dto.response.AuthResponse;
import cl.sebastianrojo.authserver.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Controller REST para gestión de usuarios.
 *
 * <p>Usa {@code @PreAuthorize} para control de acceso a nivel de método,
 * complementando las reglas globales de SecurityConfig.</p>
 */
@RestController
@RequestMapping("/api/users")
@Tag(name = "Users", description = "Gestión de usuarios")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // ── GET /api/users/me ──────────────────────────────────────────

    @GetMapping("/me")
    @Operation(summary = "Obtener perfil propio", description = "Retorna los datos del usuario autenticado.")
    public ResponseEntity<AuthResponse.UserInfo> getMyProfile(
        @AuthenticationPrincipal User currentUser
    ) {
        return ResponseEntity.ok(userService.getUserInfo(currentUser));
    }

    // ── GET /api/users ─────────────────────────────────────────────

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Listar todos los usuarios (Admin)", description = "Requiere ROLE_ADMIN.")
    public ResponseEntity<Page<AuthResponse.UserInfo>> getAllUsers(
        @PageableDefault(size = 20, sort = "createdAt") Pageable pageable
    ) {
        return ResponseEntity.ok(userService.getAllUsers(pageable));
    }

    // ── GET /api/users/{id} ────────────────────────────────────────

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    @Operation(summary = "Obtener usuario por ID", description = "Admin puede ver cualquier usuario. Usuario normal solo el suyo.")
    public ResponseEntity<AuthResponse.UserInfo> getUserById(
        @PathVariable UUID id
    ) {
        return ResponseEntity.ok(userService.getUserById(id));
    }
}