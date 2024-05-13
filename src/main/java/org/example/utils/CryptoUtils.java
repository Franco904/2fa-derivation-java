package org.example.utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

public class CryptoUtils {
    private static final String ALGORITHM = "AES";
    private static final String BLOCK_MODE = "GCM";
    private static final String PADDING_SCHEME = "NoPadding";
    private static final String TRANSFORMATION = ALGORITHM + "/" + BLOCK_MODE + "/" + PADDING_SCHEME;
    private static final String PROVIDER = "BCFIPS";

    private static Cipher getEncrypter(SecretKey secretKey, AlgorithmParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return cipher;
    }

    private static Cipher getDecrypter(SecretKey secretKey, AlgorithmParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        return cipher;
    }

    public static SecretKey generateSecretKey(byte[] keyBytes) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);

        return keyFactory.generateSecret(keySpec);
    }

    public static IvParameterSpec generateIv(byte[] ivBytes) {
        return new IvParameterSpec(ivBytes);
    }

    public static String encrypt(String plaintext, SecretKey key, AlgorithmParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher encrypter = getEncrypter(key, iv);
        byte[] encryptedTextBytes = encrypter.doFinal(plaintext.getBytes());

        return Hex.encodeHexString(encryptedTextBytes);
    }

    public static String decrypt(String ciphertext, SecretKey key, AlgorithmParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, DecoderException {
        Cipher decrypter = getDecrypter(key, iv);

        byte[] decryptedTextBytes;
        try {
            decryptedTextBytes = decrypter.doFinal(Hex.decodeHex(ciphertext.toCharArray()));
        } catch (IllegalBlockSizeException | BadPaddingException | DecoderException e) {
            decryptedTextBytes = "IV não é o mesmo da cifragem".getBytes();
        }

        return new String(decryptedTextBytes);
    }
}
