package cl.sebastianrojo.authserver.security.jwt;

import cl.sebastianrojo.authserver.config.properties.AuthProperties;
import cl.sebastianrojo.authserver.domain.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Servicio central para generación y validación de JWT.
 *
 * <p>Decisiones de diseño:</p>
 * <ul>
 *   <li>Algoritmo: <b>HS256</b> (HMAC-SHA256). Suficiente para un auth server
 *       centralizado donde la misma app firma y verifica. Para distribución
 *       entre microservicios independientes, usar RS256 (asimétrico).</li>
 *   <li>Claims incluidos en el access token: solo lo necesario (sub, roles, iss, iat, exp).
 *       Nunca datos sensibles (email, contraseña, etc.).</li>
 *   <li>El refresh token NO es un JWT sino un UUID opaco persistido en BD.
 *       Esto permite revocación instantánea sin blacklist.</li>
 * </ul>
 */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_USER_ID = "uid";
    private static final String CLAIM_USERNAME = "username";

    private final SecretKey signingKey;
    private final AuthProperties authProperties;

    public JwtService(AuthProperties authProperties) {
        this.authProperties = authProperties;
        // La clave debe tener al menos 256 bits para HS256.
        // Keys.hmacShaKeyFor lanza una excepción al inicio si la clave es débil.
        this.signingKey = Keys.hmacShaKeyFor(
            authProperties.jwt().secret().getBytes(StandardCharsets.UTF_8)
        );
        log.info("JwtService inicializado. Issuer: {}, Access TTL: {}ms",
            authProperties.jwt().issuer(),
            authProperties.jwt().accessTokenExpirationMs()
        );
    }

    // ── Generación ────────────────────────────────────────────────────

    /**
     * Genera un access token JWT para el usuario dado.
     *
     * <p>El subject ({@code sub}) es el email del usuario — identificador
     * único de negocio que no cambia. El ID interno se incluye como claim
     * adicional para evitar queries extra en cada validación.</p>
     *
     * @param user Usuario autenticado
     * @return JWT firmado como String
     */
    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(authProperties.jwt().accessTokenExpirationMs());

        List<String> roles = user.getAuthorities()
            .stream()
            .map(GrantedAuthority::getAuthority)
            .toList();

        return Jwts.builder()
            .subject(user.getEmail())
            .issuer(authProperties.jwt().issuer())
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiry))
            .id(UUID.randomUUID().toString())   // jti: evita replay en ventana corta
            .claims(Map.of(
                CLAIM_USER_ID, user.getId().toString(),
                CLAIM_USERNAME, user.getDisplayUsername(),
                CLAIM_ROLES, roles
            ))
            .signWith(signingKey)
            .compact();
    }

    // ── Validación ────────────────────────────────────────────────────

    /**
     * Valida el token y retorna el resultado de parsing.
     * Encapsula toda la lógica de excepción para que los callers
     * solo trabajen con {@link JwtValidationResult}.
     */
    public JwtValidationResult validateToken(String token) {
        try {
            Claims claims = parseClaims(token);
            return JwtValidationResult.valid(claims);
        } catch (ExpiredJwtException ex) {
            log.debug("Token JWT expirado: {}", ex.getMessage());
            return JwtValidationResult.expired();
        } catch (JwtException ex) {
            log.warn("Token JWT inválido: {}", ex.getMessage());
            return JwtValidationResult.invalid(ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.warn("Token JWT vacío o nulo");
            return JwtValidationResult.invalid("Token vacío o nulo");
        }
    }

    // ── Extracción de claims ──────────────────────────────────────────

    public String extractSubject(String token) {
        return parseClaims(token).getSubject();
    }

    public String extractUserId(String token) {
        return (String) parseClaims(token).get(CLAIM_USER_ID);
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Object roles = parseClaims(token).get(CLAIM_ROLES);
        if (roles instanceof List<?> list) {
            return list.stream().map(Object::toString).toList();
        }
        return List.of();
    }

    public Instant extractExpiration(String token) {
        return parseClaims(token).getExpiration().toInstant();
    }

    public long getAccessTokenExpirationMs() {
        return authProperties.jwt().accessTokenExpirationMs();
    }

    // ── Privados ──────────────────────────────────────────────────────

    private Claims parseClaims(String token) {
        return Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }
}