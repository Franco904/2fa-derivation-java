package org.example.auth;

import com.google.zxing.common.BitMatrix;

public record ServerTwoFAData(String totpToken, BitMatrix qrCodeMatrix) {
}
