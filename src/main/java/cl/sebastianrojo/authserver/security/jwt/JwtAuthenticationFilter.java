package cl.sebastianrojo.authserver.security.jwt;

import cl.sebastianrojo.authserver.security.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro de autenticación JWT que se ejecuta UNA vez por request.
 *
 * <p>Flujo:</p>
 * <ol>
 *   <li>Extrae el token del header {@code Authorization: Bearer <token>}</li>
 *   <li>Valida la firma y expiración del JWT</li>
 *   <li>Carga el UserDetails desde el claim {@code sub} (email)</li>
 *   <li>Establece el {@code SecurityContext} si todo es válido</li>
 * </ol>
 *
 * <p>Si hay cualquier error, se pasa al siguiente filtro sin autenticar.
 * Spring Security rechazará la request más adelante si el endpoint
 * requiere autenticación.</p>
 *
 * <p>Extiende {@link OncePerRequestFilter} para garantizar que no se
 * ejecute más de una vez por request (importante en algunas configuraciones
 * con dispatching interno de Servlet).</p>
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String AUTH_HEADER = "Authorization";

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   UserDetailsServiceImpl userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String token = extractTokenFromRequest(request);

        if (token == null) {
            // Sin token: continuar la cadena de filtros sin autenticar.
            // Los endpoints públicos pasarán; los protegidos serán rechazados
            // por el EntryPoint configurado en SecurityConfig.
            filterChain.doFilter(request, response);
            return;
        }

        // Solo procesar si no hay autenticación previa en el contexto
        // (evitar re-autenticar en el mismo request)
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            authenticateFromToken(token, request);
        } catch (Exception ex) {
            // Cualquier excepción inesperada: limpiar contexto y continuar
            log.error("Error inesperado en autenticación JWT: {}", ex.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private void authenticateFromToken(String token, HttpServletRequest request) {
        JwtValidationResult result = jwtService.validateToken(token);

        switch (result) {
            case JwtValidationResult.Valid valid -> {
                String email = valid.claims().getSubject();

                UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                // Verificar estado de la cuenta (enabled, locked, etc.)
                if (!userDetails.isEnabled()
                    || !userDetails.isAccountNonLocked()
                    || !userDetails.isAccountNonExpired()) {
                    log.debug("Cuenta deshabilitada/bloqueada para: {}", email);
                    return;
                }

                UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,                          // credentials: null post-autenticación
                        userDetails.getAuthorities()
                    );

                // Agregar detalles de la request (IP, session ID)
                authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("Usuario autenticado via JWT: {}", email);
            }

            case JwtValidationResult.Expired ignored ->
                log.debug("Intento de acceso con token expirado");

            case JwtValidationResult.Invalid invalid ->
                log.debug("Token JWT inválido: {}", invalid.reason());
        }
    }

    /**
     * Extrae el token del header Authorization.
     * Retorna null si el header no existe o no tiene el prefijo "Bearer ".
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String header = request.getHeader(AUTH_HEADER);
        if (StringUtils.hasText(header) && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    /**
     * Excluir rutas públicas del procesamiento del filtro para optimizar performance.
     * Los endpoints de auth no necesitan validación JWT (son el punto de entrada).
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/auth/login")
            || path.startsWith("/auth/register")
            || path.startsWith("/auth/verify-email")
            || path.startsWith("/auth/forgot-password")
            || path.startsWith("/actuator/health")
            || path.startsWith("/error");
    }
}