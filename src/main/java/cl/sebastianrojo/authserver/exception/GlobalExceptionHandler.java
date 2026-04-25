package cl.sebastianrojo.authserver.exception;

import cl.sebastianrojo.authserver.dto.response.AuthResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

/**
 * Manejador global de excepciones para la API REST.
 *
 * <p>Captura excepciones de dominio y las convierte en respuestas JSON
 * con el formato {@link AuthResponse.ApiError} consistente en toda la API.</p>
 *
 * <p>{@code @RestControllerAdvice} aplica solo a controllers REST (no Thymeleaf),
 * que tienen su propio manejo de errores via páginas de error.</p>
 */
@RestControllerAdvice(basePackages = "cl.sebastianrojo.authserver.controller.api")
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ── Validación de DTOs ────────────────────────────────────────

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<AuthResponse.ApiError> handleValidationErrors(
        MethodArgumentNotValidException ex,
        HttpServletRequest request
    ) {
        List<AuthResponse.ApiError.FieldError> fieldErrors = ex.getBindingResult()
            .getFieldErrors()
            .stream()
            .map(err -> new AuthResponse.ApiError.FieldError(
                err.getField(),
                err.getDefaultMessage()
            ))
            .toList();

        return ResponseEntity
            .badRequest()
            .body(AuthResponse.ApiError.withFieldErrors(
                400, "Validation Error",
                "Los datos proporcionados contienen errores de validación.",
                request.getRequestURI(),
                fieldErrors
            ));
    }

    // ── Excepciones de dominio: 400 ───────────────────────────────

    @ExceptionHandler(AuthServerException.PasswordMismatchException.class)
    public ResponseEntity<AuthResponse.ApiError> handlePasswordMismatch(
        AuthServerException.PasswordMismatchException ex,
        HttpServletRequest request
    ) {
        return buildError(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }

    @ExceptionHandler(AuthServerException.InvalidTokenException.class)
    public ResponseEntity<AuthResponse.ApiError> handleInvalidToken(
        AuthServerException.InvalidTokenException ex,
        HttpServletRequest request
    ) {
        return buildError(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }

    // ── Excepciones de dominio: 401 ───────────────────────────────

    @ExceptionHandler({
        AuthServerException.InvalidCredentialsException.class,
        BadCredentialsException.class
    })
    public ResponseEntity<AuthResponse.ApiError> handleInvalidCredentials(
        RuntimeException ex,
        HttpServletRequest request
    ) {
        // No logear como error — es evento normal de seguridad
        return buildError(HttpStatus.UNAUTHORIZED, "Credenciales inválidas.", request);
    }

    @ExceptionHandler(AuthServerException.TokenRefreshException.class)
    public ResponseEntity<AuthResponse.ApiError> handleTokenRefresh(
        AuthServerException.TokenRefreshException ex,
        HttpServletRequest request
    ) {
        return buildError(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
    }

    // ── Excepciones de dominio: 403 ───────────────────────────────

    @ExceptionHandler({
        AuthServerException.AccountNotVerifiedException.class,
        DisabledException.class
    })
    public ResponseEntity<AuthResponse.ApiError> handleAccountNotVerified(
        RuntimeException ex,
        HttpServletRequest request
    ) {
        return buildError(HttpStatus.FORBIDDEN, ex.getMessage(), request);
    }

    @ExceptionHandler({
        AuthServerException.AccountLockedException.class,
        LockedException.class
    })
    public ResponseEntity<AuthResponse.ApiError> handleAccountLocked(
        RuntimeException ex,
        HttpServletRequest request
    ) {
        return buildError(HttpStatus.FORBIDDEN, ex.getMessage(), request);
    }

    // ── Excepciones de dominio: 404 ───────────────────────────────

    @ExceptionHandler(AuthServerException.UserNotFoundException.class)
    public ResponseEntity<AuthResponse.ApiError> handleUserNotFound(
        AuthServerException.UserNotFoundException ex,
        HttpServletRequest request
    ) {
        return buildError(HttpStatus.NOT_FOUND, ex.getMessage(), request);
    }

    // ── Excepciones de dominio: 409 ───────────────────────────────

    @ExceptionHandler({
        AuthServerException.EmailAlreadyExistsException.class,
        AuthServerException.UsernameAlreadyExistsException.class
    })
    public ResponseEntity<AuthResponse.ApiError> handleConflict(
        RuntimeException ex,
        HttpServletRequest request
    ) {
        return buildError(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    // ── 429 Too Many Requests ─────────────────────────────────────

    @ExceptionHandler(AuthServerException.RateLimitExceededException.class)
    public ResponseEntity<AuthResponse.ApiError> handleRateLimit(
        AuthServerException.RateLimitExceededException ex,
        HttpServletRequest request
    ) {
        return buildError(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage(), request);
    }

    // ── Fallback: 500 Internal Server Error ───────────────────────

    @ExceptionHandler(Exception.class)
    public ResponseEntity<AuthResponse.ApiError> handleGenericException(
        Exception ex,
        HttpServletRequest request
    ) {
        // Loguear el error completo para diagnóstico
        log.error("Error inesperado en {}: {}", request.getRequestURI(), ex.getMessage(), ex);

        // Nunca exponer el mensaje interno al cliente
        return buildError(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Ha ocurrido un error interno. Por favor contacta al soporte.",
            request
        );
    }

    // ── Utilidad ──────────────────────────────────────────────────

    private ResponseEntity<AuthResponse.ApiError> buildError(
        HttpStatus status,
        String message,
        HttpServletRequest request
    ) {
        return ResponseEntity
            .status(status)
            .body(AuthResponse.ApiError.of(
                status.value(),
                status.getReasonPhrase(),
                message,
                request.getRequestURI()
            ));
    }
}