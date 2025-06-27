package com.advait.authservice.utility;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoKeyUtility {

    public static PrivateKey loadPrivateKey(Path path) throws Exception {
        String key = stripPem(Files.readString(path), "PRIVATE KEY");
        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }
    
    public static PublicKey loadPublicKey(Path path) throws Exception {
        String key = stripPem(Files.readString(path), "PUBLIC KEY");
        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
    
    public static PrivateKey loadPrivateKey(InputStream inputStream) throws Exception {
        String key = stripPem(new String(inputStream.readAllBytes()), "PRIVATE KEY");
        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public static PublicKey loadPublicKey(InputStream inputStream) throws Exception {
        String key = stripPem(new String(inputStream.readAllBytes()), "PUBLIC KEY");
        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static String stripPem(String pem, String type) {
        return pem.replace("-----BEGIN " + type + "-----", "")
                  .replace("-----END " + type + "-----", "")
                  .replaceAll("\\s", "");
    }
}
