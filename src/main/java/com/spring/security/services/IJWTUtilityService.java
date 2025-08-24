package com.spring.security.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

public interface IJWTUtilityService {
    public String generateJWT(long userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException;

    public JWTClaimsSet parseJWT(String jwt) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException;
}
