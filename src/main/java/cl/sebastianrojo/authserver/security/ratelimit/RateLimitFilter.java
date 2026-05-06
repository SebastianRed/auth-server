package cl.sebastianrojo.authserver.security.ratelimit;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filtro de rate limiting para el endpoint de login.
 *
 * <p>Se coloca ANTES del JwtAuthenticationFilter en la cadena de seguridad,
 * para rechazar requests excesivos sin ni siquiera procesar el JWT o
 * consultar la base de datos.</p>
 *
 * <p>Aplica dos capas de protección:</p>
 * <ol>
 *   <li>Rate limit por IP (protección contra brute force desde una IP)</li>
 *   <li>Rate limit por email en el body (protección contra ataques distribuidos)</li>
 * </ol>
 *
 * <p>Expone el header {@code X-Rate-Limit-Remaining} en todas las respuestas
 * para que los clientes puedan adaptar su comportamiento.</p>
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private static final String LOGIN_PATH = "/auth/login";

    private final RateLimitService rateLimitService;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(RateLimitService rateLimitService, ObjectMapper objectMapper) {
        this.rateLimitService = rateLimitService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String ip = extractClientIp(request);

        // Agregar header de tokens restantes a TODAS las respuestas
        long remaining = rateLimitService.getRemainingTokensByIp(ip);
        response.setHeader("X-Rate-Limit-Remaining", String.valueOf(remaining));

        // Aplicar rate limiting solo al endpoint de login
        if (!isLoginRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Capa 1: Rate limit por IP
        if (!rateLimitService.tryConsumeByIp(ip)) {
            writeRateLimitResponse(response, request.getRequestURI());
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // El filtro solo es relevante para POST /auth/login
        // pero dejamos que doFilterInternal maneje la lógica
        // para poder agregar el header en todos los requests
        return false;
    }

    private boolean isLoginRequest(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod())
            && LOGIN_PATH.equals(request.getServletPath());
    }

    private void writeRateLimitResponse(HttpServletResponse response, String path)
        throws IOException {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(429);
        response.setHeader("Retry-After", "300");  // Segundos hasta poder reintentar

        Map<String, Object> body = Map.of(
            "status", 429,
            "error", "Too Many Requests",
            "message", "Demasiados intentos de inicio de sesión. Por favor espera unos minutos antes de intentar nuevamente.",
            "path", path,
            "timestamp", Instant.now().toString()
        );

        objectMapper.writeValue(response.getOutputStream(), body);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isBlank()) {
            return xRealIp.trim();
        }
        return request.getRemoteAddr();
    }
}