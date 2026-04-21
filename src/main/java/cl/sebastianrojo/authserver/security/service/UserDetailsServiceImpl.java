package cl.sebastianrojo.authserver.security.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import cl.sebastianrojo.authserver.repository.UserRepository;

/**
 * Implementación de {@link UserDetailsService} para Spring Security.
 *
 * <p>Spring Security llama a este servicio durante el proceso de autenticación
 * para cargar los datos del usuario por su "username" (en nuestro caso, email).</p>
 *
 * <p>{@code @Transactional(readOnly = true)} es importante aquí porque JPA
 * necesita una transacción activa para cargar las relaciones EAGER de roles
 * que están en la entidad User.</p>
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Carga usuario por email (usado como "username" en el sistema).
     *
     * @param email Email del usuario
     * @return UserDetails (nuestra entidad User implementa esta interfaz)
     * @throws UsernameNotFoundException si el email no existe en BD
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException(
                "Usuario no encontrado con email: " + email
            ));
    }
}