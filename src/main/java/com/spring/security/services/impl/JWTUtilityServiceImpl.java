package com.spring.security.services.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.spring.security.services.IJWTUtilityService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

@Service
public class JWTUtilityServiceImpl implements IJWTUtilityService {

    @Value("classpath:jwtKeys/private_key.pem")
    private Resource privateKeyResource;

    @Value("classpath:jwtKeys/public_key.pem")
    private Resource publicKeyResource;

    @Override
    public String generateJWT(long userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        PrivateKey privateKey = loadPrivateKey(privateKeyResource);

        JWSSigner signer = new RSASSASigner(privateKey);

        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(String.valueOf(userId))
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 1400000)) // 1,400,000 ms ~ 23.3 min; ajustá si querés 1h = 3_600_000
                .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    @Override
    public JWTClaimsSet parseJWT(String jwt) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
        PublicKey publicKey = loadPublicKey(publicKeyResource);
        SignedJWT signedJWT = SignedJWT.parse(jwt);

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

        if (!signedJWT.verify(verifier)) {
            throw new JOSEException("JWT verification failed");
        }
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        if (claimsSet.getExpirationTime().before(new Date())) {
            throw new JOSEException("JWT has expired");
        }

        return claimsSet;
    }

    private PrivateKey loadPrivateKey(Resource resource) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = readAllBytes(resource);
        String pem = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(pem);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey loadPublicKey(Resource resource) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = readAllBytes(resource);
        String pem = new String(keyBytes, StandardCharsets.UTF_8).trim();

        // Caso normal: BEGIN PUBLIC KEY -> X.509 SubjectPublicKeyInfo
        if (pem.contains("-----BEGIN PUBLIC KEY-----")) {
            String publicKeyPEM = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            return keyFactory.generatePublic(keySpec);
        }

        // Fallback: si la clave viene como PKCS#1 -> "-----BEGIN RSA PUBLIC KEY-----"
        if (pem.contains("-----BEGIN RSA PUBLIC KEY-----")) {
            String publicKeyPEM = pem
                    .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                    .replace("-----END RSA PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
            return generatePublicKeyFromPKCS1(decoded);
        }

        // Si no tiene headers, intentamos tratar el blob como X.509
        try {
            byte[] decoded = Base64.getDecoder().decode(pem.replaceAll("\\s", ""));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            return keyFactory.generatePublic(keySpec);
        } catch (IllegalArgumentException | InvalidKeySpecException e) {
            throw new InvalidKeySpecException("Formato de clave pública no soportado. Usá X.509 (BEGIN PUBLIC KEY) o RSA PKCS#1 (BEGIN RSA PUBLIC KEY).", e);
        }
    }

    // Lee todo el Resource de forma segura (funciona dentro de JAR)
    private byte[] readAllBytes(Resource resource) throws IOException {
        try (InputStream is = resource.getInputStream()) {
            return is.readAllBytes();
        }
    }

    // Convierte PKCS#1 (ASN.1: SEQUENCE { modulus, exponent }) a PublicKey
    private PublicKey generatePublicKeyFromPKCS1(byte[] pkcs1Bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            // Parsear la estructura ASN.1 mínima para extraer dos INTEGER (modulus y exponent).
            ByteArrayInputStream in = new ByteArrayInputStream(pkcs1Bytes);
            int seq = in.read();
            if (seq != 0x30) { // SEQUENCE
                throw new InvalidKeySpecException("Formato PKCS#1 inválido, no comienza con SEQUENCE (0x30).");
            }
            int seqLen = readLength(in);

            // First INTEGER (modulus)
            int tag = in.read();
            if (tag != 0x02) throw new InvalidKeySpecException("Formato PKCS#1 inválido (no INTEGER para modulus).");
            int modLen = readLength(in);
            byte[] modBytes = new byte[modLen];
            if (in.read(modBytes) != modLen) throw new InvalidKeySpecException("Error leyendo modulus.");

            // Second INTEGER (exponent)
            tag = in.read();
            if (tag != 0x02) throw new InvalidKeySpecException("Formato PKCS#1 inválido (no INTEGER para exponent).");
            int expLen = readLength(in);
            byte[] expBytes = new byte[expLen];
            if (in.read(expBytes) != expLen) throw new InvalidKeySpecException("Error leyendo exponent.");

            BigInteger modulus = new BigInteger(1, modBytes);
            BigInteger exponent = new BigInteger(1, expBytes);

            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (IOException ex) {
            throw new InvalidKeySpecException("Error parseando PKCS#1", ex);
        }
    }

    // Lee longitud ASN.1 (short/long forms)
    private int readLength(ByteArrayInputStream in) throws IOException, InvalidKeySpecException {
        int length = in.read();
        if (length < 0) throw new IOException("Unexpected EOF while reading length");
        if ((length & 0x80) == 0) {
            return length;
        }
        int numBytes = length & 0x7F;
        if (numBytes > 4) throw new InvalidKeySpecException("Longitud ASN.1 demasiado grande");
        int val = 0;
        for (int i = 0; i < numBytes; i++) {
            int next = in.read();
            if (next < 0) throw new IOException("Unexpected EOF while reading length bytes");
            val = (val << 8) + next;
        }
        return val;
    }
}
