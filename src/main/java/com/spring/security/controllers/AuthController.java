package com.spring.security.controllers;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.services.IAuthService;
import com.spring.security.services.models.dtos.LoginDTO;
import com.spring.security.services.models.dtos.ResponseDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
@RequestMapping("/auth")
public class AuthController {


    private final IAuthService authService;

    public AuthController(IAuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    private ResponseEntity<ResponseDTO> addUser(@RequestBody UserEntity user) throws Exception {
        return new ResponseEntity<>(authService.register(user), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    private ResponseEntity<HashMap<String, String>> login(@RequestBody LoginDTO loginRequest) throws Exception {
        HashMap<String, String> login = authService.login(loginRequest);
        if (login.containsKey("jwt")) {
            return new ResponseEntity<>(authService.login(loginRequest), HttpStatus.ACCEPTED);
        } else {
            return new ResponseEntity<>(authService.login(loginRequest), HttpStatus.UNAUTHORIZED);
        }
    }
}
