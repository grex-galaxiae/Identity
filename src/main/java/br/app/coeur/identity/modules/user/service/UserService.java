package br.app.coeur.identity.modules.user.service;

import br.app.coeur.identity.modules.user.dto.request.RegisterUserRequest;
import br.app.coeur.identity.modules.user.dto.request.UpdateProfileRequest;
import br.app.coeur.identity.modules.user.dto.request.UpdateUserRequest;
import br.app.coeur.identity.modules.user.dto.response.UserResponse;
import br.app.coeur.identity.modules.user.exception.EmailAlreadyInUseException;
import br.app.coeur.identity.modules.user.exception.UserNotFoundException;
import br.app.coeur.identity.modules.user.model.User;
import br.app.coeur.identity.modules.user.repository.UserRepository;

import lombok.AllArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@AllArgsConstructor()
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponse register(RegisterUserRequest request) {

        if (userRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyInUseException();
        }

        User user = User.register(
                request.email(),
                passwordEncoder.encode(request.password()),
                request.name()
        );

        return UserResponse.from(
                userRepository.save(user)
        );
    }

    @Transactional(readOnly = true)
    public UserResponse findById(UUID id) {
        return UserResponse.from(getUser(id));
    }

    @Transactional(readOnly = true)
    public Page<UserResponse> findAll(Pageable pageable) {
        return userRepository.findAll(pageable).map(UserResponse::from);
    }

    @Transactional
    public UserResponse update(UUID id, UpdateUserRequest request) {
        User user = getUser(id);

        if (!request.email().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.email())) {
                throw new EmailAlreadyInUseException();
            }
            user.changeEmail(request.email());
        }
        user.rename(request.name());

        user.changeRoles(request.roles());

        return UserResponse.from(user);
    }

    @Transactional
    public UserResponse updateProfile(UUID id, UpdateProfileRequest request) {
        User user = getUser(id);
        if (!request.email().equals(user.getEmail()) && userRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyInUseException();
        }
        user.changeEmail(request.email());
        user.rename(request.name());
        return UserResponse.from(user);
    }

    @Transactional
    public void delete(UUID id) {
        userRepository.delete(
                getUser(id)
        );
    }

    private User getUser(UUID id) {
        return userRepository.findById(id).orElseThrow(UserNotFoundException::new);
    }
}
