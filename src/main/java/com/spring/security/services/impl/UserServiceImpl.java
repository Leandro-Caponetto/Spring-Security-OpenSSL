package com.spring.security.services.impl;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.persistence.repositories.UserRepository;
import com.spring.security.services.IUserService;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements IUserService {


    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public List<UserEntity> findAllUsers(){
        return userRepository.findAll();
    }
}
