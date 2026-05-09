package cl.sebastianrojo.authserver.controller.web;

import cl.sebastianrojo.authserver.dto.request.AuthRequest;
import cl.sebastianrojo.authserver.dto.response.AuthResponse;
import cl.sebastianrojo.authserver.exception.AuthServerException;
import cl.sebastianrojo.authserver.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Controller MVC para las vistas Thymeleaf de autenticación.
 *
 * <p>Diferencia clave con {@code AuthController} (REST):</p>
 * <ul>
 *   <li>Este controller retorna nombres de vistas (Strings) para Thymeleaf.</li>
 *   <li>Usa {@code RedirectAttributes} para mensajes flash (PRG pattern).</li>
 *   <li>Procesa errores como atributos del modelo, no como JSON.</li>
 * </ul>
 *
 * <p>Patrón PRG (Post-Redirect-Get): los formularios POST siempre redirigen
 * tras procesamiento para evitar reenvío accidental del formulario al refrescar.</p>
 */
@Controller
public class WebAuthController {

    private static final Logger log = LoggerFactory.getLogger(WebAuthController.class);

    private final AuthService authService;

    public WebAuthController(AuthService authService) {
        this.authService = authService;
    }

    // ── Login ──────────────────────────────────────────────────────

    /**
     * Spring Security maneja el POST /login internamente.
     * Este método solo sirve la vista GET.
     */
    @GetMapping("/login")
    public String loginPage() {
        return "auth/login";
    }

    // ── Registro ───────────────────────────────────────────────────

    @GetMapping("/register")
    public String registerPage(Model model) {
        model.addAttribute("registerForm", new AuthRequest.Register(
            "", "", "", "", "", ""
        ));
        return "auth/register";
    }

    @PostMapping("/register")
    public String processRegister(
        @Valid @ModelAttribute("registerForm") AuthRequest.Register form,
        BindingResult bindingResult,
        Model model,
        HttpServletRequest request,
        RedirectAttributes redirectAttributes
    ) {
        // Errores de Bean Validation
        if (bindingResult.hasErrors()) {
            model.addAttribute("registerForm", form);
            return "auth/register";
        }

        try {
            authService.register(form, request);
            // PRG: redirigir al login con flag de registro exitoso
            return "redirect:/login?registered";

        } catch (AuthServerException.EmailAlreadyExistsException ex) {
            model.addAttribute("errorMessage", "El email ya está registrado. ¿Olvidaste tu contraseña?");
            model.addAttribute("registerForm", form);
            return "auth/register";

        } catch (AuthServerException.UsernameAlreadyExistsException ex) {
            model.addAttribute("errorMessage", "El username ya está en uso. Elige otro.");
            model.addAttribute("registerForm", form);
            return "auth/register";

        } catch (AuthServerException.PasswordMismatchException ex) {
            model.addAttribute("errorMessage", "Las contraseñas no coinciden.");
            model.addAttribute("registerForm", form);
            return "auth/register";

        } catch (Exception ex) {
            log.error("Error inesperado en registro: {}", ex.getMessage(), ex);
            model.addAttribute("errorMessage", "Ocurrió un error inesperado. Por favor intenta nuevamente.");
            model.addAttribute("registerForm", form);
            return "auth/register";
        }
    }

    // ── Recuperación de contraseña ────────────────────────────────

    @GetMapping("/forgot-password")
    public String forgotPasswordPage() {
        return "auth/forgot-password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPassword(
        @RequestParam String email,
        Model model,
        HttpServletRequest request
    ) {
        // Crear el DTO con el email del parámetro
        AuthRequest.ForgotPassword forgotRequest = new AuthRequest.ForgotPassword(email);

        try {
            authService.forgotPassword(forgotRequest, request);
        } catch (Exception ex) {
            // Silenciar cualquier excepción para no revelar si el email existe
            log.debug("Error en forgot-password (silenciado): {}", ex.getMessage());
        }

        // Siempre mostrar el estado de "email enviado" independientemente del resultado
        model.addAttribute("emailSent", true);
        model.addAttribute("submittedEmail", email);
        return "auth/forgot-password";
    }

    // ── Reset de contraseña ────────────────────────────────────────

    @GetMapping("/reset-password")
    public String resetPasswordPage(
        @RequestParam(required = false) String token,
        Model model
    ) {
        if (token == null || token.isBlank()) {
            model.addAttribute("tokenInvalid", true);
        } else {
            model.addAttribute("token", token);
        }
        return "auth/reset-password";
    }

    @PostMapping("/reset-password")
    public String processResetPassword(
        @RequestParam String token,
        @RequestParam String newPassword,
        @RequestParam String confirmPassword,
        Model model,
        HttpServletRequest request
    ) {
        AuthRequest.ResetPassword resetRequest = new AuthRequest.ResetPassword(
            token, newPassword, confirmPassword
        );

        try {
            authService.resetPassword(resetRequest, request);
            model.addAttribute("resetSuccess", true);
            return "auth/reset-password";

        } catch (AuthServerException.PasswordMismatchException ex) {
            model.addAttribute("token", token);
            model.addAttribute("errorMessage", "Las contraseñas no coinciden.");
            return "auth/reset-password";

        } catch (AuthServerException.InvalidTokenException ex) {
            model.addAttribute("tokenInvalid", true);
            return "auth/reset-password";

        } catch (Exception ex) {
            log.error("Error en reset-password: {}", ex.getMessage());
            model.addAttribute("tokenInvalid", true);
            return "auth/reset-password";
        }
    }

    // ── Verificación de email ─────────────────────────────────────

    @GetMapping("/verify-email")
    public String verifyEmail(
        @RequestParam String token,
        RedirectAttributes redirectAttributes,
        HttpServletRequest request
    ) {
        try {
            authService.verifyEmail(token, request);
            redirectAttributes.addFlashAttribute(
                "successMessage", "✓ Email verificado. Ya puedes iniciar sesión."
            );
        } catch (Exception ex) {
            redirectAttributes.addFlashAttribute(
                "errorMessage", "El enlace de verificación es inválido o ha expirado."
            );
        }
        return "redirect:/login";
    }

    // ── Dashboard ─────────────────────────────────────────────────

    @GetMapping({"/", "/dashboard"})
    public String dashboard() {
        return "dashboard";
    }
}