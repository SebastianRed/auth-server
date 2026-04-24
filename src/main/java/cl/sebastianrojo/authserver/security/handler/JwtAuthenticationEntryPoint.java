package cl.sebastianrojo.authserver.security.handler;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Manejador de requests no autenticados (HTTP 401 Unauthorized).
 *
 * <p>Se dispara cuando un request llega a un endpoint protegido sin
 * token JWT o con token inválido/expirado.</p>
 *
 * <p>Retorna una respuesta JSON consistente con el formato de error
 * estándar del sistema, en lugar del comportamiento default de
 * Spring Security que redirige a /login.</p>
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);

    private final ObjectMapper objectMapper;

    public JwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException authException
    ) throws IOException {

        log.debug("Acceso no autorizado a: {} | Razón: {}",
            request.getRequestURI(), authException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Map<String, Object> body = Map.of(
            "status", 401,
            "error", "Unauthorized",
            "message", "Autenticación requerida. Proporciona un token válido en el header Authorization.",
            "path", request.getRequestURI(),
            "timestamp", Instant.now().toString()
        );

        objectMapper.writeValue(response.getOutputStream(), body);
    }
}