package cl.sebastianrojo.authserver.config;

import cl.sebastianrojo.authserver.config.properties.AuthProperties;
import cl.sebastianrojo.authserver.security.handler.CustomAccessDeniedHandler;
import cl.sebastianrojo.authserver.security.handler.JwtAuthenticationEntryPoint;
import cl.sebastianrojo.authserver.security.jwt.JwtAuthenticationFilter;
import cl.sebastianrojo.authserver.security.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Configuración central de Spring Security.
 *
 * <p>Arquitectura de seguridad:</p>
 * <ul>
 *   <li><b>Stateless</b>: sin sesiones HTTP. Toda la autenticación es via JWT.</li>
 *   <li><b>CSRF deshabilitado</b>: correcto para APIs REST stateless (CSRF solo aplica
 *       a flujos de formulario con sesión). Las vistas Thymeleaf que usan formularios
 *       POST están protegidas a través del SecurityFilterChain de MVC separado.</li>
 *   <li><b>@EnableMethodSecurity</b>: habilita {@code @PreAuthorize} y
 *       {@code @PostAuthorize} en controllers y servicios.</li>
 * </ul>
 *
 * <p>Dos SecurityFilterChains separados:</p>
 * <ol>
 *   <li>{@code apiSecurityFilterChain}: para {@code /api/**} — stateless, JWT, JSON</li>
 *   <li>{@code webSecurityFilterChain}: para vistas Thymeleaf — session, form login</li>
 * </ol>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final UserDetailsServiceImpl userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final AuthProperties authProperties;

    public SecurityConfig(
        UserDetailsServiceImpl userDetailsService,
        JwtAuthenticationFilter jwtAuthenticationFilter,
        JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
        CustomAccessDeniedHandler customAccessDeniedHandler,
        AuthProperties authProperties
    ) {
        this.userDetailsService = userDetailsService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
        this.authProperties = authProperties;
    }

    // ════════════════════════════════════════════════════════════════
    //  FILTER CHAIN 1: API REST (JWT, Stateless)
    //  Orden 1 (más específico, se evalúa primero)
    // ════════════════════════════════════════════════════════════════

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            // Solo aplica a rutas /api/** y /auth/**
            .securityMatcher("/api/**", "/auth/**")

            // ── Session: STATELESS (sin cookies de sesión)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // ── CSRF: deshabilitado para APIs REST stateless
            .csrf(AbstractHttpConfigurer::disable)

            // ── CORS: configurado en corsConfigurationSource()
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // ── Reglas de autorización por endpoint
            .authorizeHttpRequests(auth -> auth
                // Endpoints de autenticación: públicos
                .requestMatchers(
                    "/auth/login",
                    "/auth/register",
                    "/auth/refresh",
                    "/auth/verify-email",
                    "/auth/forgot-password",
                    "/auth/reset-password"
                ).permitAll()

                // Swagger/OpenAPI: público (en dev)
                .requestMatchers(
                    "/api-docs/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html"
                ).permitAll()

                // Actuator health: público
                .requestMatchers("/actuator/health").permitAll()

                // Admin endpoints: solo ROLE_ADMIN
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/users").hasRole("ADMIN")

                // Todo lo demás requiere autenticación
                .anyRequest().authenticated()
            )

            // ── Manejadores de error personalizados
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(customAccessDeniedHandler)
            )

            // ── Proveedor de autenticación
            .authenticationProvider(authenticationProvider())

            // ── Agregar filtro JWT antes del filtro estándar de username/password
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

            // ── Headers de seguridad
            .headers(headers -> headers
                .frameOptions(frame -> frame.sameOrigin())
                .xssProtection(xss -> xss.disable())      // CSP es más moderno
                .contentSecurityPolicy(csp ->
                    csp.policyDirectives("default-src 'self'; frame-ancestors 'none'")
                )
            );

        return http.build();
    }

    // ════════════════════════════════════════════════════════════════
    //  FILTER CHAIN 2: Vistas Web Thymeleaf (Session-based)
    //  Orden 2 (menos específico, aplica al resto)
    // ════════════════════════════════════════════════════════════════

    @Bean
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            // CSRF habilitado para vistas con formularios (protección real)
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/auth/**") // Los endpoints REST no necesitan CSRF
            )

            .authorizeHttpRequests(auth -> auth
                // Recursos estáticos: públicos
                .requestMatchers(
                    "/css/**", "/js/**", "/images/**",
                    "/webjars/**", "/favicon.ico"
                ).permitAll()

                // Vistas de auth: públicas
                .requestMatchers(
                    "/login", "/register",
                    "/forgot-password", "/reset-password",
                    "/verify-email", "/error"
                ).permitAll()

                // Todo lo demás requiere autenticación
                .anyRequest().authenticated()
            )

            // Form login para vistas Thymeleaf
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )

            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )

            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(3)             // Máximo 3 sesiones web simultáneas
                .maxSessionsPreventsLogin(false) // Expira la sesión más antigua (no bloquea el login)
            )

            .authenticationProvider(authenticationProvider());

        return http.build();
    }

    // ════════════════════════════════════════════════════════════════
    //  BEANS de seguridad
    // ════════════════════════════════════════════════════════════════

    /**
     * BCrypt con strength configurable (12 en producción).
     * Cada aumento de 1 duplica el tiempo de hashing.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(authProperties.security().bcryptStrength());
    }

    /**
     * DaoAuthenticationProvider: el proveedor estándar de Spring Security
     * que usa UserDetailsService + PasswordEncoder.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        // No revelar si el usuario existe o no (seguridad anti-enumeración)
        provider.setHideUserNotFoundExceptions(true);
        return provider;
    }

    /**
     * AuthenticationManager: necesario para el endpoint de login que lo
     * invoca directamente desde el AuthController.
     */
    @Bean
    public AuthenticationManager authenticationManager(
        AuthenticationConfiguration config
    ) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Configuración CORS para la API REST.
     *
     * <p>En producción, reemplazar "*" con los dominios de los clientes reales.
     * Nunca usar "*" con {@code allowCredentials(true)}.</p>
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // Orígenes permitidos (configurar por entorno)
        config.setAllowedOriginPatterns(List.of("*"));

        config.setAllowedMethods(List.of(
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));

        config.setAllowedHeaders(List.of(
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Accept",
            "Origin",
            "X-Device-ID"   // Para soporte multi-dispositivo
        ));

        config.setExposedHeaders(List.of(
            "Authorization",
            "X-Rate-Limit-Remaining"
        ));

        config.setAllowCredentials(false);   // true solo si orígenes son específicos
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        source.registerCorsConfiguration("/auth/**", config);
        return source;
    }
}