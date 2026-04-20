package cl.sebastianrojo.authserver.service;

import cl.sebastianrojo.authserver.config.properties.AuthProperties;
import cl.sebastianrojo.authserver.domain.entity.AuditLog;
import cl.sebastianrojo.authserver.domain.entity.RefreshToken;
import cl.sebastianrojo.authserver.domain.entity.Role;
import cl.sebastianrojo.authserver.domain.entity.User;
import cl.sebastianrojo.authserver.domain.entity.VerificationToken;
import cl.sebastianrojo.authserver.dto.request.AuthRequest;
import cl.sebastianrojo.authserver.dto.response.AuthResponse;
import cl.sebastianrojo.authserver.exception.AuthServerException;
import cl.sebastianrojo.authserver.repository.AuditLogRepository;
import cl.sebastianrojo.authserver.repository.RefreshTokenRepository;
import cl.sebastianrojo.authserver.repository.RoleRepository;
import cl.sebastianrojo.authserver.repository.UserRepository;
import cl.sebastianrojo.authserver.repository.VerificationTokenRepository;
import cl.sebastianrojo.authserver.security.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Servicio de autenticación. Orquesta el flujo completo de:
 * login, registro, refresh de tokens, logout y recuperación de contraseña.
 *
 * <p>Principios aplicados:</p>
 * <ul>
 *   <li><b>Single Responsibility</b>: cada método hace exactamente una cosa.</li>
 *   <li><b>Transacciones explícitas</b>: cada operación que modifica BD
 *       está en su propia transacción. Los métodos de solo lectura usan
 *       {@code readOnly = true} para optimización.</li>
 *   <li><b>Auditoría</b>: todos los eventos de seguridad se registran.</li>
 * </ul>
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final AuditLogRepository auditLogRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final AuthProperties authProperties;

    public AuthService(
        UserRepository userRepository,
        RoleRepository roleRepository,
        RefreshTokenRepository refreshTokenRepository,
        VerificationTokenRepository verificationTokenRepository,
        AuditLogRepository auditLogRepository,
        JwtService jwtService,
        PasswordEncoder passwordEncoder,
        AuthenticationManager authenticationManager,
        EmailService emailService,
        AuthProperties authProperties
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.verificationTokenRepository = verificationTokenRepository;
        this.auditLogRepository = auditLogRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.emailService = emailService;
        this.authProperties = authProperties;
    }

    // ══════════════════════════════════════════════════════════════
    //  LOGIN
    // ══════════════════════════════════════════════════════════════

    /**
     * Autentica al usuario y emite un par de tokens (access + refresh).
     *
     * <p>Flujo:</p>
     * <ol>
     *   <li>Delegar autenticación al {@link AuthenticationManager} de Spring Security
     *       (valida credenciales, estado de cuenta, etc.)</li>
     *   <li>Registrar login exitoso (auditoría, reset intentos fallidos)</li>
     *   <li>Emitir access token JWT</li>
     *   <li>Crear y persistir refresh token opaco</li>
     * </ol>
     */
    @Transactional
    public AuthResponse.TokenPair login(
        AuthRequest.Login request,
        HttpServletRequest httpRequest
    ) {
        try {
            // Spring Security valida credenciales, enabled, locked, etc.
            var authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.email(),
                    request.password()
                )
            );

            User user = (User) authentication.getPrincipal();

            // Actualizar último login y resetear contador de fallos
            userRepository.updateSuccessfulLogin(user.getId(), Instant.now());

            // Emitir tokens
            String accessToken = jwtService.generateAccessToken(user);
            RefreshToken refreshToken = createRefreshToken(user, httpRequest);

            // Auditoría
            audit(AuditLog.EventType.LOGIN_SUCCESS, user.getId(),
                extractIp(httpRequest), extractUserAgent(httpRequest), null);

            log.info("Login exitoso para usuario: {}", user.getEmail());

            return AuthResponse.TokenPair.of(
                accessToken,
                refreshToken.getToken(),
                jwtService.getAccessTokenExpirationMs(),
                mapToUserInfo(user)
            );

        } catch (AuthenticationException ex) {
            // Registrar fallo — puede ser BadCredentials, DisabledException, LockedException
            handleFailedLogin(request.email(), httpRequest, ex);
            throw ex;  // Propagar para que GlobalExceptionHandler maneje el tipo específico
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  REGISTRO
    // ══════════════════════════════════════════════════════════════

    /**
     * Registra un nuevo usuario y envía el email de verificación.
     */
    @Transactional
    public AuthResponse.Message register(
        AuthRequest.Register request,
        HttpServletRequest httpRequest
    ) {
        // Validaciones de unicidad
        if (userRepository.existsByEmail(request.email())) {
            throw new AuthServerException.EmailAlreadyExistsException(request.email());
        }

        if (userRepository.existsByUsername(request.username())) {
            throw new AuthServerException.UsernameAlreadyExistsException(request.username());
        }

        // Validar que las contraseñas coincidan
        if (!request.password().equals(request.confirmPassword())) {
            throw new AuthServerException.PasswordMismatchException();
        }

        // Obtener rol por defecto
        Role userRole = roleRepository.findByName("ROLE_USER")
            .orElseThrow(() -> new IllegalStateException("Rol ROLE_USER no encontrado. Verificar migraciones de BD."));

        // Construir entidad usuario
        User user = User.builder()
            .email(request.email())
            .username(request.username())
            .passwordHash(passwordEncoder.encode(request.password()))
            .firstName(request.firstName())
            .lastName(request.lastName())
            .enabled(false)       // Se habilita al verificar email
            .roles(Set.of(userRole))
            .build();

        user = userRepository.save(user);

        // Crear y enviar token de verificación de email
        VerificationToken verificationToken = createVerificationToken(
            user,
            VerificationToken.TokenType.EMAIL_VERIFICATION
        );
        emailService.sendVerificationEmail(user, verificationToken.getToken());

        // Auditoría
        audit(AuditLog.EventType.REGISTER, user.getId(),
            extractIp(httpRequest), extractUserAgent(httpRequest), null);

        log.info("Usuario registrado: {}. Verificación de email enviada.", user.getEmail());

        return AuthResponse.Message.of(
            "Registro exitoso. Por favor revisa tu email para verificar tu cuenta."
        );
    }

    // ══════════════════════════════════════════════════════════════
    //  REFRESH TOKEN
    // ══════════════════════════════════════════════════════════════

    /**
     * Renueva el access token usando un refresh token válido.
     *
     * <p>Implementa <b>Refresh Token Rotation</b>: al usar un refresh token,
     * se revoca el anterior y se emite uno nuevo. Esto detecta
     * robos de token: si el token original ya fue rotado, al intentar
     * usarlo nuevamente se detecta y se revocan TODOS los tokens del usuario.</p>
     */
    @Transactional
    public AuthResponse.TokenPair refresh(
        AuthRequest.Refresh request,
        HttpServletRequest httpRequest
    ) {
        RefreshToken oldToken = refreshTokenRepository
            .findByToken(request.refreshToken())
            .orElseThrow(AuthServerException.TokenRefreshException::notFound);

        if (oldToken.isRevoked()) {
            // Token ya revocado — posible robo de token detectado
            // Revocar TODOS los tokens del usuario como medida de seguridad
            log.warn("⚠️ Refresh token revocado usado. Posible robo detectado. Usuario: {}",
                oldToken.getUser().getEmail());
            refreshTokenRepository.revokeAllByUserId(
                oldToken.getUser().getId(),
                Instant.now(),
                "SECURITY_REVOKE"
            );
            throw AuthServerException.TokenRefreshException.revoked();
        }

        if (oldToken.isExpired()) {
            oldToken.revoke("EXPIRED");
            refreshTokenRepository.save(oldToken);
            throw AuthServerException.TokenRefreshException.expired();
        }

        User user = oldToken.getUser();

        // Revocar el token anterior (rotación)
        oldToken.revoke("ROTATION");
        refreshTokenRepository.save(oldToken);

        // Emitir nuevos tokens
        String newAccessToken = jwtService.generateAccessToken(user);
        RefreshToken newRefreshToken = createRefreshToken(user, httpRequest);

        // Auditoría
        audit(AuditLog.EventType.TOKEN_REFRESHED, user.getId(),
            extractIp(httpRequest), extractUserAgent(httpRequest), null);

        return AuthResponse.TokenPair.of(
            newAccessToken,
            newRefreshToken.getToken(),
            jwtService.getAccessTokenExpirationMs(),
            mapToUserInfo(user)
        );
    }

    // ══════════════════════════════════════════════════════════════
    //  LOGOUT
    // ══════════════════════════════════════════════════════════════

    @Transactional
    public AuthResponse.Message logout(
        AuthRequest.Logout request,
        User currentUser,
        HttpServletRequest httpRequest
    ) {
        if (request.logoutAll()) {
            // Cerrar TODAS las sesiones del usuario
            int revoked = refreshTokenRepository.revokeAllByUserId(
                currentUser.getId(), Instant.now(), "LOGOUT"
            );
            log.info("Logout global para usuario: {}. Tokens revocados: {}",
                currentUser.getEmail(), revoked);
        } else {
            // Cerrar solo la sesión actual
            refreshTokenRepository.findByToken(request.refreshToken())
                .ifPresent(token -> {
                    token.revoke("LOGOUT");
                    refreshTokenRepository.save(token);
                });
        }

        audit(AuditLog.EventType.LOGOUT, currentUser.getId(),
            extractIp(httpRequest), extractUserAgent(httpRequest), null);

        return AuthResponse.Message.of("Sesión cerrada exitosamente.");
    }

    // ══════════════════════════════════════════════════════════════
    //  VERIFICACIÓN DE EMAIL
    // ══════════════════════════════════════════════════════════════

    @Transactional
    public AuthResponse.Message verifyEmail(String token, HttpServletRequest httpRequest) {
        VerificationToken verificationToken = verificationTokenRepository
            .findByToken(token)
            .orElseThrow(AuthServerException.InvalidTokenException::invalid);

        if (!verificationToken.isValid()) {
            throw verificationToken.isExpired()
                ? AuthServerException.InvalidTokenException.expired()
                : AuthServerException.InvalidTokenException.invalid();
        }

        if (verificationToken.getTokenType() != VerificationToken.TokenType.EMAIL_VERIFICATION) {
            throw AuthServerException.InvalidTokenException.invalid();
        }

        // Marcar token como usado y habilitar usuario
        verificationToken.markAsUsed();
        verificationTokenRepository.save(verificationToken);

        userRepository.markEmailAsVerified(verificationToken.getUser().getId());

        audit(AuditLog.EventType.EMAIL_VERIFIED, verificationToken.getUser().getId(),
            extractIp(httpRequest), null, null);

        return AuthResponse.Message.of("Email verificado exitosamente. Ya puedes iniciar sesión.");
    }

    // ══════════════════════════════════════════════════════════════
    //  RECUPERACIÓN DE CONTRASEÑA
    // ══════════════════════════════════════════════════════════════

    /**
     * Inicia el flujo de recuperación de contraseña.
     *
     * <p>Siempre retorna el mismo mensaje independientemente de si el email
     * existe o no — evita la enumeración de usuarios.</p>
     */
    @Transactional
    public AuthResponse.Message forgotPassword(
        AuthRequest.ForgotPassword request,
        HttpServletRequest httpRequest
    ) {
        String genericMessage = "Si el email está registrado, recibirás instrucciones para resetear tu contraseña.";

        userRepository.findByEmail(request.email()).ifPresent(user -> {
            // Invalidar tokens anteriores del mismo tipo
            verificationTokenRepository.invalidatePreviousTokens(
                user.getId(),
                VerificationToken.TokenType.PASSWORD_RESET,
                Instant.now()
            );

            VerificationToken resetToken = createVerificationToken(
                user,
                VerificationToken.TokenType.PASSWORD_RESET
            );

            emailService.sendPasswordResetEmail(user, resetToken.getToken());

            audit(AuditLog.EventType.PASSWORD_RESET_REQUESTED, user.getId(),
                extractIp(httpRequest), null, null);
        });

        return AuthResponse.Message.of(genericMessage);
    }

    @Transactional
    public AuthResponse.Message resetPassword(
        AuthRequest.ResetPassword request,
        HttpServletRequest httpRequest
    ) {
        if (!request.newPassword().equals(request.confirmPassword())) {
            throw new AuthServerException.PasswordMismatchException();
        }

        VerificationToken verificationToken = verificationTokenRepository
            .findByToken(request.token())
            .orElseThrow(AuthServerException.InvalidTokenException::invalid);

        if (!verificationToken.isValid()
            || verificationToken.getTokenType() != VerificationToken.TokenType.PASSWORD_RESET) {
            throw verificationToken.isExpired()
                ? AuthServerException.InvalidTokenException.expired()
                : AuthServerException.InvalidTokenException.invalid();
        }

        User user = verificationToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));

        // Marcar token como usado
        verificationToken.markAsUsed();
        verificationTokenRepository.save(verificationToken);

        // Revocar todos los refresh tokens (forzar re-login en todos los dispositivos)
        refreshTokenRepository.revokeAllByUserId(user.getId(), Instant.now(), "PASSWORD_RESET");

        userRepository.save(user);

        audit(AuditLog.EventType.PASSWORD_RESET_SUCCESS, user.getId(),
            extractIp(httpRequest), null, null);

        return AuthResponse.Message.of("Contraseña actualizada exitosamente. Por favor inicia sesión.");
    }

    // ══════════════════════════════════════════════════════════════
    //  MÉTODOS PRIVADOS
    // ══════════════════════════════════════════════════════════════

    private RefreshToken createRefreshToken(User user, HttpServletRequest httpRequest) {
        long expirationMs = authProperties.jwt().refreshTokenExpirationMs();

        RefreshToken token = RefreshToken.builder()
            .token(UUID.randomUUID().toString())
            .user(user)
            .expiresAt(Instant.now().plusMillis(expirationMs))
            .ipAddress(extractIp(httpRequest))
            .userAgent(extractUserAgent(httpRequest))
            .deviceId(httpRequest.getHeader("X-Device-ID"))
            .build();

        return refreshTokenRepository.save(token);
    }

    private VerificationToken createVerificationToken(
        User user,
        VerificationToken.TokenType type
    ) {
        long expirationHours = type == VerificationToken.TokenType.EMAIL_VERIFICATION
            ? authProperties.email().verificationTokenExpirationHours()
            : authProperties.email().passwordResetTokenExpirationHours();

        VerificationToken token = VerificationToken.builder()
            .token(UUID.randomUUID().toString())
            .user(user)
            .tokenType(type)
            .expiresAt(Instant.now().plusSeconds(expirationHours * 3600L))
            .build();

        return verificationTokenRepository.save(token);
    }

    private void handleFailedLogin(
        String email,
        HttpServletRequest httpRequest,
        AuthenticationException ex
    ) {
        log.debug("Login fallido para email: {} | Razón: {}", email, ex.getClass().getSimpleName());

        // Intentar encontrar el usuario para registrar el intento
        userRepository.findByEmail(email).ifPresent(user -> {
            user.registerFailedLoginAttempt(
                authProperties.security().maxLoginAttempts(),
                authProperties.security().loginAttemptWindowSeconds()
            );
            userRepository.save(user);
        });

        audit(AuditLog.EventType.LOGIN_FAILURE, null,
            extractIp(httpRequest), extractUserAgent(httpRequest),
            "{\"email\":\"" + email + "\"}"
        );
    }

    private void audit(
        AuditLog.EventType eventType,
        java.util.UUID userId,
        String ipAddress,
        String userAgent,
        String details
    ) {
        try {
            AuditLog log = AuditLog.builder()
                .eventType(eventType)
                .userId(userId)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .details(details)
                .build();
            auditLogRepository.save(log);
        } catch (Exception ex) {
            // La auditoría nunca debe romper el flujo principal
            log.error("Error al registrar auditoría: {}", ex.getMessage());
        }
    }

    private AuthResponse.UserInfo mapToUserInfo(User user) {
        return new AuthResponse.UserInfo(
            user.getId(),
            user.getEmail(),
            user.getDisplayUsername(),
            user.getFirstName(),
            user.getLastName(),
            user.getFullName(),
            user.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .toList(),
            user.isEmailVerified(),
            user.getLastLoginAt()
        );
    }

    private String extractIp(HttpServletRequest request) {
        // Considerar headers de proxy reverso
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isBlank()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    private String extractUserAgent(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        return ua != null && ua.length() > 500 ? ua.substring(0, 500) : ua;
    }
}