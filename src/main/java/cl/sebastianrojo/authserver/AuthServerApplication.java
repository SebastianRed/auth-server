package cl.sebastianrojo.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Punto de entrada del Auth Server.
 *
 * <p>Anotaciones relevantes:</p>
 * <ul>
 *   <li>{@code @SpringBootApplication}: componente scan + auto-config</li>
 *   <li>{@code @ConfigurationPropertiesScan}: registra todos los records
 *       anotados con {@code @ConfigurationProperties} en el paquete</li>
 *   <li>{@code @EnableScheduling}: activa tasks periódicos (limpieza de tokens)</li>
 * </ul>
 */
@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling
public class AuthServerApplication {
 
    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }
}