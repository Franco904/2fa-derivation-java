package org.example.auth;

import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import org.example.utils.CryptoUtils;
import org.example.utils.FileUtils;
import org.example.utils.KeyDerivationUtils;
import org.example.utils.TwoFAUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Server {
    private static String sessionKey = "";

    public static void signUpClient(ClientAuthData clientAuthData) throws Exception {
        File file = new File(FileUtils.resourcesFolder, "registry.txt");
        FileUtils.createIfNotExists(file);

        if (FileUtils.hasLine(file, clientAuthData.username())) {
            throw new Exception("Usuário já registrado.");
        }

        String salt = KeyDerivationUtils.getSaltForUser(clientAuthData.username());
        String scryptToken = KeyDerivationUtils.deriveWithScrypt(clientAuthData.pbKdf2Token(), salt.getBytes(), 32);
        String scryptForKey = KeyDerivationUtils.deriveWithScrypt(clientAuthData.pbKdf2Token(), salt.getBytes(), 16); // AES KEY 128 bits
        String scryptForIv = KeyDerivationUtils.deriveWithScrypt(clientAuthData.pbKdf2Token(), salt.getBytes(), 12); // GCM IV 96 bits

        SecretKey secretKey = CryptoUtils.generateSecretKey(scryptForKey.getBytes());
        IvParameterSpec iv = CryptoUtils.generateIv(scryptForIv.getBytes());

        FileUtils.putLine(file, clientAuthData.username() + "=" + CryptoUtils.encrypt(scryptToken, secretKey, iv));
        System.out.println("Usuário registrado com sucesso. Timestamp: \n" + clientAuthData.timestamp());
    }

    public static String validateUsernamePassword(ClientAuthData clientAuthData) throws Exception {
        File file = new File(FileUtils.resourcesFolder, "registry.txt");
        FileUtils.createIfNotExists(file);

        String userRegistry = FileUtils.getLine(file, clientAuthData.username());

        if (userRegistry == null || !userRegistry.contains("=")) {
            throw new Exception("Usuário ou senha incorretos.");
        }

        String scryptTokenStored = userRegistry.split("=")[1];

        String salt = KeyDerivationUtils.getSaltForUser(clientAuthData.username());
        String scryptToken = KeyDerivationUtils.deriveWithScrypt(clientAuthData.pbKdf2Token(), salt.getBytes(), 32);
        String scryptForKey = KeyDerivationUtils.deriveWithScrypt(clientAuthData.pbKdf2Token(), salt.getBytes(), 16); // AES KEY 128 bits
        String scryptForIv = KeyDerivationUtils.deriveWithScrypt(clientAuthData.pbKdf2Token(), salt.getBytes(), 12); // GCM IV 96 bits

        SecretKey secretKey = CryptoUtils.generateSecretKey(scryptForKey.getBytes());
        IvParameterSpec iv = CryptoUtils.generateIv(scryptForIv.getBytes());

        String decryptedScryptToken = CryptoUtils.decrypt(scryptTokenStored, secretKey, iv);

        if (!scryptToken.equals(decryptedScryptToken)) {
            throw new Exception("Usuário ou senha incorretos.");
        }

        System.out.println("Usuário autenticado com sucesso. Timestamp: \n" + clientAuthData.timestamp());
        return decryptedScryptToken;
    }

    public static String create2FACode(String secret) throws IOException {
        String totpToken = TwoFAUtils.generateTotp(secret);
        BitMatrix qrCodeMatrix = TwoFAUtils.createQRCode("https://large-type.com/#" + totpToken);

        if (qrCodeMatrix == null) {
            throw new IOException("Não possível criar o QR Code.");
        }

        File file = new File(FileUtils.resourcesFolder, "qr_code.png");
        try (FileOutputStream stream = new FileOutputStream(file)) {
            MatrixToImageWriter.writeToStream(qrCodeMatrix, "png", stream);
        }

        return totpToken;
    }

    public static void validate2FACode(String clientTOTP, String originalTOTP) throws Exception {
        if (!clientTOTP.equals(originalTOTP)) {
            throw new Exception("Código 2FA incorreto.");
        }
    }

    public static void derivateTOTPtoSessionKey(String totp, ClientAuthData clientAuthData) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String salt = KeyDerivationUtils.getSaltForUser(clientAuthData.username());
        String totpKey = KeyDerivationUtils.deriveWithPbkdf2(totp, salt.getBytes());

        sessionKey = totpKey;
    }

    public static String receiveMessageAndReply(String message, ClientAuthData clientAuthData) throws Exception {
        String salt = KeyDerivationUtils.getSaltForUser(clientAuthData.username());

        String scryptForIv = KeyDerivationUtils.deriveWithScrypt(clientAuthData.pbKdf2Token(), salt.getBytes(), 12); // GCM IV 96 bits
        IvParameterSpec iv = CryptoUtils.generateIv(scryptForIv.getBytes());

        if (sessionKey.isEmpty()) {
            throw new Exception("Chave de sessão indisponível.");
        }

        SecretKey secretKey = CryptoUtils.generateSecretKey(sessionKey.getBytes());

        String decryptedMessage = CryptoUtils.decrypt(message, secretKey, iv);
        System.out.println("[ Servidor ] Recebeu a mensagem do cliente: " + decryptedMessage);

        String serverReply = "( OK ) Código da mensagem: " + message.hashCode();
        return CryptoUtils.encrypt(serverReply, secretKey, iv);
    }
}
