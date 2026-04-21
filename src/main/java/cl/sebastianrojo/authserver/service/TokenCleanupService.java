package cl.sebastianrojo.authserver.service;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import cl.sebastianrojo.authserver.repository.RefreshTokenRepository;
import cl.sebastianrojo.authserver.repository.VerificationTokenRepository;

/**
 * Tarea programada para limpieza de tokens expirados y revocados.
 *
 * <p>Sin esta tarea, las tablas de tokens crecerían indefinidamente.
 * Se ejecuta de madrugada para no impactar el tráfico.</p>
 */
@Service
public class TokenCleanupService {

    private static final Logger log = LoggerFactory.getLogger(TokenCleanupService.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final VerificationTokenRepository verificationTokenRepository;

    public TokenCleanupService(
        RefreshTokenRepository refreshTokenRepository,
        VerificationTokenRepository verificationTokenRepository
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.verificationTokenRepository = verificationTokenRepository;
    }

    /**
     * Limpieza diaria a las 3:00 AM (hora del servidor).
     * Cron: segundo minuto hora día mes díaSemana
     */
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();

        int refreshDeleted = refreshTokenRepository.deleteExpiredAndRevoked(now);
        int verificationDeleted = verificationTokenRepository.deleteExpired(now);

        log.info("Limpieza de tokens completada. Refresh eliminados: {}, Verification eliminados: {}",
            refreshDeleted, verificationDeleted);
    }
}