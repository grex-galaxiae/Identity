package br.app.coeur.identity.modules.user.service;

import br.app.coeur.identity.modules.user.dto.request.RegisterUserRequest;
import br.app.coeur.identity.modules.user.dto.request.UpdateUserRequest;
import br.app.coeur.identity.modules.user.dto.response.UserResponse;
import br.app.coeur.identity.modules.user.model.User;
import br.app.coeur.identity.modules.user.repository.UserRepository;
import br.app.coeur.identity.shared.exception.ConflictException;
import br.app.coeur.identity.shared.exception.ResourceNotFoundException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID NON_EXISTENT_ID = UUID.randomUUID();

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    private User existingUser() {
        User user = User.register("john@coeur.app", "encoded", "John");
        ReflectionTestUtils.setField(user, "id", USER_ID);
        return user;
    }

    @Test
    void registerShouldEncodePasswordAndPersistUserWithDefaultRole() {
        when(userRepository.existsByEmail("john@coeur.app")).thenReturn(false);
        when(passwordEncoder.encode("secret")).thenReturn("encoded");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserResponse response = userService.register(new RegisterUserRequest("john@coeur.app", "secret", "John"));

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getPassword()).isEqualTo("encoded");
        assertThat(response.email()).isEqualTo("john@coeur.app");
        assertThat(response.name()).isEqualTo("John");
        assertThat(response.roles()).isEqualTo(User.DEFAULT_ROLE);
    }

    @Test
    void registerShouldFailWhenEmailAlreadyInUse() {
        when(userRepository.existsByEmail("john@coeur.app")).thenReturn(true);
        RegisterUserRequest request = new RegisterUserRequest("john@coeur.app", "secret", "John");

        assertThatThrownBy(() -> userService.register(request))
                .isInstanceOf(ConflictException.class)
                .hasMessage("Email is already in use.");

        verify(userRepository, never()).save(any());
    }

    @Test
    void findByIdShouldReturnUser() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(existingUser()));

        UserResponse response = userService.findById(USER_ID);

        assertThat(response.id()).isEqualTo(USER_ID);
        assertThat(response.email()).isEqualTo("john@coeur.app");
    }

    @Test
    void findByIdShouldFailWhenUserDoesNotExist() {
        when(userRepository.findById(NON_EXISTENT_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.findById(NON_EXISTENT_ID))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("User not found.");
    }

    @Test
    void findAllShouldMapAllUsers() {
        Pageable pageable = PageRequest.of(0, 20);
        when(userRepository.findAll(pageable)).thenReturn(new org.springframework.data.domain.PageImpl<>(List.of(
                existingUser(), User.register("mary@coeur.app", "encoded", "Mary"))));

        Page<UserResponse> responses = userService.findAll(pageable);

        assertThat(responses.getContent()).extracting(UserResponse::email)
                .containsExactly("john@coeur.app", "mary@coeur.app");
    }

    @Test
    void updateShouldChangeEmailNameAndRoles() {
        User user = existingUser();
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(userRepository.existsByEmail("new@coeur.app")).thenReturn(false);

        UserResponse response = userService.update(USER_ID, new UpdateUserRequest("new@coeur.app", "New Name", "ROLE_ADMIN"));

        assertThat(response.email()).isEqualTo("new@coeur.app");
        assertThat(response.name()).isEqualTo("New Name");
        assertThat(response.roles()).isEqualTo("ROLE_ADMIN");
        assertThat(user.getEmail()).isEqualTo("new@coeur.app");
    }

    @Test
    void updateShouldNotCheckEmailUniquenessWhenEmailIsUnchanged() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(existingUser()));

        UserResponse response = userService.update(USER_ID, new UpdateUserRequest("john@coeur.app", "John Updated", User.DEFAULT_ROLE));

        verify(userRepository, never()).existsByEmail(any());
        assertThat(response.name()).isEqualTo("John Updated");
    }

    @Test
    void updateShouldFailWhenNewEmailIsAlreadyInUse() {
        User user = existingUser();
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(userRepository.existsByEmail("taken@coeur.app")).thenReturn(true);
        UpdateUserRequest request = new UpdateUserRequest("taken@coeur.app", "John", User.DEFAULT_ROLE);

        assertThatThrownBy(() -> userService.update(USER_ID, request))
                .isInstanceOf(ConflictException.class)
                .hasMessage("Email is already in use.");

        assertThat(user.getEmail()).isEqualTo("john@coeur.app");
    }

    @Test
    void updateShouldFailWhenUserDoesNotExist() {
        when(userRepository.findById(NON_EXISTENT_ID)).thenReturn(Optional.empty());
        UpdateUserRequest request = new UpdateUserRequest("a@b.c", "John", User.DEFAULT_ROLE);

        assertThatThrownBy(() -> userService.update(NON_EXISTENT_ID, request))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("User not found.");
    }

    @Test
    void deleteShouldRemoveExistingUser() {
        User user = existingUser();
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));

        userService.delete(USER_ID);

        verify(userRepository).delete(user);
    }

    @Test
    void deleteShouldFailWhenUserDoesNotExist() {
        when(userRepository.findById(NON_EXISTENT_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.delete(NON_EXISTENT_ID))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("User not found.");

        verify(userRepository, never()).delete(any());
    }
}
