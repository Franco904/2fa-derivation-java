package org.example.utils;

import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.Scrypt;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class KeyDerivationUtils {
    private static final int PBKDF2_ITERATION_COUNT = 1000;
    private static final int PBKDF2_KEY_LENGTH = 128;

    private static final int SCRYPT_COST_PARAM = 2048;
    private static final int SCRYPT_BLOCKSIZE = 8;
    private static final int SCRYPT_PARALLELIZATION_PARAM = 1;

    public static String getSaltForUser(String username) throws IOException {
        File file = new File(FileUtils.resourcesFolder, "users-salt.txt");
        FileUtils.createIfNotExists(file);

        String saltFromFile = FileUtils.getLine(file, username);
        String saltHex = saltFromFile != null ? saltFromFile.split("=")[1] : generateSalt(file, username);

        return saltHex;
    }

    private static String generateSalt(File file, String username) throws IOException {
        SecureRandom sr;
        try {
            sr = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SecureRandom algorithm not found", e);
        }

        byte[] saltBytes = new byte[16];
        sr.nextBytes(saltBytes);

        String saltHex = Hex.toHexString(saltBytes);
        FileUtils.putLine(file, username + "=" + saltHex);

        return saltHex;
    }

    public static String deriveWithPbkdf2(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        char[] key = password.toCharArray();

        PBEKeySpec keySpec = new PBEKeySpec(
                key,
                salt,
                PBKDF2_ITERATION_COUNT,
                PBKDF2_KEY_LENGTH
        );

        SecretKeyFactory pbKdf2;
        try {
            pbKdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BCFIPS");
        } catch (Exception e) {
            throw new NoSuchAlgorithmException("Algorithm not found", e);
        }

        byte[] derivedKey = pbKdf2.generateSecret(keySpec).getEncoded();
        return Hex.toHexString(derivedKey);
    }

    public static String deriveWithScrypt(String password, byte[] salt, int keySize) {
        char[] key = password.toCharArray();

        KDFCalculator<Scrypt.Parameters> scryptKdf
                = new Scrypt.KDFFactory()
                .createKDFCalculator(
                        Scrypt.ALGORITHM.using(
                                salt,
                                SCRYPT_COST_PARAM,
                                SCRYPT_BLOCKSIZE,
                                SCRYPT_PARALLELIZATION_PARAM,
                                Strings.toUTF8ByteArray(key)
                        )
                );

        byte[] derivedKeyBytes = new byte[keySize];
        scryptKdf.generateBytes(derivedKeyBytes);

        return Hex.toHexString(derivedKeyBytes);
    }
}
