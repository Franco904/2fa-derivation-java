package org.example;

import com.google.zxing.common.BitMatrix;
import it.auties.qr.QrTerminal;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.example.auth.Client;
import org.example.auth.ClientAuthData;
import org.example.auth.Server;
import org.example.auth.ServerTwoFAData;

import java.security.Security;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        // Add BouncyCastle security provider so we can access its algorithms
        Security.addProvider(new BouncyCastleFipsProvider());

        while (true) {
            String appMode = getAppMode();
            switch (appMode) {
                case "1":
                    runUserSignUpMode();
                    break;
                case "2":
                    runAuthMode();
                    break;
                case "0":
                    return;
            }
        }
    }

    private static String getAppMode() {
        System.out.println("=====");
        System.out.println("Escolha um modo de uso:");
        System.out.println("[ 1 ] Cadastro de usuário");
        System.out.println("[ 2 ] Autenticação de usuário");
        System.out.println("[ 0 ] Sair");
        System.out.println("=====");

        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine().trim();
    }

    private static void runUserSignUpMode() {
        System.out.println("[ Cadastro de usuário ]\n");

        try {
            ClientAuthData clientAuthData = Client.inputUsernamePassword();

            Server.signUpClient(clientAuthData);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void runAuthMode() {
        System.out.println("[ Autenticação de usuário ]\n");

        try {
            // Username and password auth (first factor)
            ClientAuthData clientAuthData = Client.inputUsernamePassword();

            String password = Server.validateUsernamePassword(clientAuthData);

            // TOTP auth (second factor)
            ServerTwoFAData serverTwoFAData = Server.create2FACode(password);
            String serverTOTP = serverTwoFAData.totpToken();
            BitMatrix qrCodeMatrix = serverTwoFAData.qrCodeMatrix();

            QrTerminal.print(qrCodeMatrix, false);

            String clientTOTP = Client.input2FA();

            Server.validate2FACode(clientTOTP, serverTOTP);

            // Create same session key for both client & server from TOTP code
            Server.derivateTOTPtoSessionKey(serverTOTP, clientAuthData);
            Client.derivateTOTPtoSessionKey(clientTOTP, clientAuthData);

            executeMessagingMode(clientAuthData);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void executeMessagingMode(ClientAuthData clientAuthData) {
        while (true) {
            try {
                String clientMessage = Client.inputMessageToServer(clientAuthData);

                String serverResponse = Server.receiveMessageAndReply(clientMessage, clientAuthData);

                Client.readServerResponse(serverResponse, clientAuthData);

                if (!Client.continueConversation()) {
                    // Exit
                    break;
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
                break;
            }
        }
    }
}

