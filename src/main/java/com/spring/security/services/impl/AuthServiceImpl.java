package com.spring.security.services.impl;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.persistence.repositories.UserRepository;
import com.spring.security.services.IAuthService;
import com.spring.security.services.IJWTUtilityService;
import com.spring.security.services.models.dtos.LoginDTO;
import com.spring.security.services.models.dtos.ResponseDTO;
import com.spring.security.services.models.validation.UserValidation;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@Service
public class AuthServiceImpl implements IAuthService {

  private final UserRepository userRepository;

  private final IJWTUtilityService jwtUtilityService;

  private final UserValidation userValidations;

    public AuthServiceImpl(UserRepository userRepository, JWTUtilityServiceImpl jwtUtilityService, UserValidation userValidations) {
        this.userRepository = userRepository;
        this.jwtUtilityService = jwtUtilityService;
        this.userValidations = userValidations;

    }

    @Override
    public HashMap<String, String> login(LoginDTO loginRequest) throws Exception {
        try {
            HashMap<String, String> jwt = new HashMap<>();
            Optional<UserEntity> user = userRepository.findByEmail(loginRequest.getEmail());

            if (user.isEmpty()) {
                jwt.put("error", "User not registered!");
                return jwt;
            }
            if (verifyPassword(loginRequest.getPassword(), user.get().getPassword())) {
                jwt.put("jwt", jwtUtilityService.generateJWT(user.get().getId()));
            } else {
                jwt.put("error", "Authentication failed");
            }
            return jwt;
        } catch (IllegalArgumentException e) {
            System.err.println("Error generating JWT: " + e.getMessage());
            throw new Exception("Error generating JWT", e);
        } catch (Exception e) {
            System.err.println("Unknown error: " + e.toString());
            throw new Exception("Unknown error", e);
        }
    }

    @Override
    public ResponseDTO register(UserEntity user) throws Exception {
        try {
            ResponseDTO response = userValidations.validate(user);

            if (response.getNumOfErrors() > 0) {
                return response;
            }

            // Verificar si ya existe por email
            if (userRepository.existsByEmail(user.getEmail())) {
                response.setNumOfErrors(1);
                response.setMessage("El correo ya está registrado.");
                return response;
            }

            // Encriptar la contraseña antes de guardar
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
            user.setPassword(encoder.encode(user.getPassword()));
            userRepository.save(user);

            response.setMessage("Usuario creado con éxito!");
            return response;
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }


    private boolean verifyPassword(String enteredPassword, String storedPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(enteredPassword, storedPassword);
    }
}
