package cl.sebastianrojo.authserver.config;

import java.util.concurrent.Executor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

/**
 * Configuraciones de infraestructura: OpenAPI y AsyncExecutor.
 */
@Configuration
@EnableAsync
public class AppConfig {

    // ── OpenAPI / Swagger ────────────────────────────────────────────

    @Bean
    public OpenAPI authServerOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Auth Server API")
                .description("Servidor de autenticación centralizado con JWT y Refresh Tokens")
                .version("1.0.0")
                .contact(new Contact()
                    .name("Sebastián Rojo")
                    .url("https://github.com/sebastianrojo"))
                .license(new License().name("MIT"))
            )
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
            .components(new Components()
                .addSecuritySchemes("bearerAuth", new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
                    .description("Ingresa el JWT obtenido en /auth/login")
                )
            );
    }

    // ── Executor para @Async (emails) ────────────────────────────────

    @Bean(name = "emailTaskExecutor")
    public Executor emailTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(5);
        executor.setQueueCapacity(50);
        executor.setThreadNamePrefix("email-");
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();
        return executor;
    }
}