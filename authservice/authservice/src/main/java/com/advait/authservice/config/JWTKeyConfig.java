package com.advait.authservice.config;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import com.advait.authservice.utility.RSAKeyUtility;

@Configuration
public class JWTKeyConfig {
	@Value("${jwt.private-key-path}")
    private String privateKeyPath;

    @Value("${jwt.public-key-path}")
    private String publicKeyPath;

    private final ResourceLoader resourceLoader;

    public JWTKeyConfig(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public PrivateKey jwtPrivateKey() throws Exception {
        Resource resource = resourceLoader.getResource(privateKeyPath);
        try (InputStream is = resource.getInputStream()) {
            return RSAKeyUtility.loadPrivateKey(is);
        }
    }

    @Bean
    public PublicKey jwtPublicKey() throws Exception {
        Resource resource = resourceLoader.getResource(publicKeyPath);
        try (InputStream is = resource.getInputStream()) {
            return RSAKeyUtility.loadPublicKey(is);
        }
    }
}
