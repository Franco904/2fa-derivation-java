package org.example.utils;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.common.BitMatrix;
import de.taimos.totp.TOTP;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

public class TwoFAUtils {
    private static final int QR_CODE_WIDTH = 24;
    private static final int QR_CODE_HEIGHT = 24;

    public static String generateTotp(String secret) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secret.getBytes());
        String hexKey = Hex.encodeHexString(bytes);

        return TOTP.getOTP(hexKey);
    }

    public static BitMatrix createQRCode(String content) {
        try {
            return new MultiFormatWriter().encode(
                    content, BarcodeFormat.QR_CODE,
                    QR_CODE_WIDTH, QR_CODE_HEIGHT
            );
        } catch (Exception e) {
            return null;
        }
    }
}
