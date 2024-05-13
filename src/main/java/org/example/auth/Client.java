package org.example.auth;

import org.apache.commons.codec.DecoderException;
import org.example.utils.CryptoUtils;
import org.example.utils.KeyDerivationUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class Client {
    private static final Scanner scanner = new Scanner(System.in);
    private static String sessionKey = "";

    public static ClientAuthData inputUsernamePassword() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Nome do usuário:");
        String username = scanner.nextLine().trim();

        System.out.println("Senha do usuário:");
        String password = scanner.nextLine().trim();

        String salt = KeyDerivationUtils.getSaltForUser(username);
        String pbkdf2Token = KeyDerivationUtils.deriveWithPbkdf2(password, salt.getBytes());

        return new ClientAuthData(username, pbkdf2Token, System.currentTimeMillis());
    }

    public static String input2FA() {
        System.out.println("Código 2FA:");
        return scanner.nextLine().trim();
    }

    public static void derivateTOTPtoSessionKey(String totp, ClientAuthData clientAuthData) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String salt = KeyDerivationUtils.getSaltForUser(clientAuthData.username());
        String totpKey = KeyDerivationUtils.deriveWithPbkdf2(totp, salt.getBytes());

        sessionKey = totpKey;
    }

    public static String inputMessageToServer(ClientAuthData clientAuthData) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        System.out.println("Mensagem:");
        String message = scanner.nextLine().trim();

        String salt = KeyDerivationUtils.getSaltForUser(clientAuthData.username());

        String scryptForIv = KeyDerivationUtils.deriveWithScrypt(clientAuthData.pbKdf2Token(), salt.getBytes(), 12); // GCM IV 96 bits
        IvParameterSpec iv = CryptoUtils.generateIv(scryptForIv.getBytes());

        if (sessionKey.isEmpty()) {
            throw new RuntimeException("Chave de sessão indisponível.");
        }
        SecretKey secretKey = CryptoUtils.generateSecretKey(sessionKey.getBytes());

        return CryptoUtils.encrypt(message, secretKey, iv);
    }

    public static void readServerResponse(String serverResponse, ClientAuthData clientAuthData) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, DecoderException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String salt = KeyDerivationUtils.getSaltForUser(clientAuthData.username());

        String scryptForIv = KeyDerivationUtils.deriveWithScrypt(clientAuthData.pbKdf2Token(), salt.getBytes(), 12); // GCM IV 96 bits
        IvParameterSpec iv = CryptoUtils.generateIv(scryptForIv.getBytes());

        if (sessionKey.isEmpty()) {
            throw new RuntimeException("Chave de sessão indisponível.");
        }
        SecretKey secretKey = CryptoUtils.generateSecretKey(sessionKey.getBytes());

        String decryptedMessage = CryptoUtils.decrypt(serverResponse, secretKey, iv);
        System.out.println("[ Cliente ] Recebeu a resposta do servidor: " + decryptedMessage);
    }

    public static boolean continueConversation() {
        System.out.println("Nova mensagem? (s/n):");
        String confirmation = scanner.nextLine().trim();

        return confirmation.equalsIgnoreCase("s");
    }
}
