package cl.sebastianrojo.authserver.security.ratelimit;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import cl.sebastianrojo.authserver.config.properties.AuthProperties;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;

/**
 * Servicio de rate limiting basado en el algoritmo Token Bucket (Bucket4j).
 *
 * <p>Estrategia aplicada al endpoint de login:</p>
 * <ul>
 *   <li>Cada IP tiene su propio bucket con capacidad = maxLoginAttempts</li>
 *   <li>Se recarga 1 token cada (windowSeconds / maxAttempts) segundos,
 *       permitiendo exactamente maxAttempts por ventana de tiempo</li>
 *   <li>El store es en memoria (ConcurrentHashMap). En producción con múltiples
 *       instancias, reemplazar por Bucket4j + Redis o Hazelcast</li>
 * </ul>
 *
 * <p>Token Bucket vs Sliding Window: Token Bucket es más indulgente con bursts
 * legítimos y más eficiente en memoria. Sliding Window es más preciso pero
 * costoso. Para un auth server, Token Bucket es la elección correcta.</p>
 */
@Service
public class RateLimitService {

    private static final Logger log = LoggerFactory.getLogger(RateLimitService.class);

    // Store en memoria: IP -> Bucket
    // ConcurrentHashMap garantiza thread-safety sin bloqueos globales
    private final Map<String, Bucket> ipBuckets = new ConcurrentHashMap<>();

    // Store por email (segunda capa de protección)
    private final Map<String, Bucket> emailBuckets = new ConcurrentHashMap<>();

    private final AuthProperties authProperties;

    public RateLimitService(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    /**
     * Intenta consumir 1 token del bucket asociado a la IP.
     *
     * @param ipAddress IP del cliente
     * @return {@code true} si el request puede proceder, {@code false} si debe ser bloqueado
     */
    public boolean tryConsumeByIp(String ipAddress) {
        Bucket bucket = ipBuckets.computeIfAbsent(ipAddress, this::createLoginBucket);
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit alcanzado para IP: {}", ipAddress);
        }

        return allowed;
    }

    /**
     * Segunda capa: rate limiting por email.
     * Detecta ataques distribuidos desde múltiples IPs contra un mismo usuario.
     *
     * @param email Email del intento de login
     * @return {@code true} si el request puede proceder
     */
    public boolean tryConsumeByEmail(String email) {
        Bucket bucket = emailBuckets.computeIfAbsent(email, this::createLoginBucket);
        boolean allowed = bucket.tryConsume(1);

        if (!allowed) {
            log.warn("Rate limit por email alcanzado: {}", maskEmail(email));
        }

        return allowed;
    }

    /**
     * Tokens restantes para una IP (para incluir en header de respuesta).
     */
    public long getRemainingTokensByIp(String ipAddress) {
        Bucket bucket = ipBuckets.get(ipAddress);
        return bucket != null ? bucket.getAvailableTokens() : getMaxAttempts();
    }

    /**
     * Limpia los buckets expirados periódicamente.
     * Llamado desde un @Scheduled en TokenCleanupService.
     * Estrategia simple: limpiar los que tienen capacidad completa
     * (no han tenido actividad reciente).
     */
    public void cleanupFullBuckets() {
        long maxTokens = getMaxAttempts();

        int ipCleaned = cleanBuckets(ipBuckets, maxTokens);
        int emailCleaned = cleanBuckets(emailBuckets, maxTokens);

        if (ipCleaned > 0 || emailCleaned > 0) {
            log.debug("Limpieza de rate limit buckets: {} IP, {} email eliminados",
                ipCleaned, emailCleaned);
        }
    }

    // ── Privados ──────────────────────────────────────────────────────

    private Bucket createLoginBucket(String key) {
        long maxAttempts = getMaxAttempts();
        long windowSeconds = authProperties.security().loginAttemptWindowSeconds();

        // Refill greedy: recarga los tokens en intervalos fijos
        // Ejemplo: 5 intentos en 300 segundos = 1 token cada 60 segundos
        Bandwidth limit = Bandwidth.classic(
            maxAttempts,
            Refill.intervally(maxAttempts, Duration.ofSeconds(windowSeconds))
        );

        return Bucket.builder()
            .addLimit(limit)
            .build();
    }

    private long getMaxAttempts() {
        return authProperties.security().maxLoginAttempts();
    }

    private int cleanBuckets(Map<String, Bucket> buckets, long maxTokens) {
        int count = 0;
        for (Map.Entry<String, Bucket> entry : buckets.entrySet()) {
            if (entry.getValue().getAvailableTokens() >= maxTokens) {
                buckets.remove(entry.getKey());
                count++;
            }
        }
        return count;
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***";
        String[] parts = email.split("@");
        String local = parts[0];
        String masked = local.length() > 2
            ? local.charAt(0) + "***" + local.charAt(local.length() - 1)
            : "***";
        return masked + "@" + parts[1];
    }
}