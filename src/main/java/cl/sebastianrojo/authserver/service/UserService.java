package cl.sebastianrojo.authserver.service;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import cl.sebastianrojo.authserver.domain.entity.User;
import cl.sebastianrojo.authserver.dto.response.AuthResponse;
import cl.sebastianrojo.authserver.exception.AuthServerException;
import cl.sebastianrojo.authserver.repository.UserRepository;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public AuthResponse.UserInfo getUserInfo(User user) {
        return mapToUserInfo(user);
    }

    @Transactional(readOnly = true)
    public AuthResponse.UserInfo getUserById(UUID id) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new AuthServerException.UserNotFoundException(id.toString()));
        return mapToUserInfo(user);
    }

    @Transactional(readOnly = true)
    public Page<AuthResponse.UserInfo> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(this::mapToUserInfo);
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
}