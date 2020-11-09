package RSA;

import Helper.Helper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class RSAEncryptor {
    private static RSAEncryptor instance;
    private Cipher cipher;
    private RSAEncryptor() {
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        }
        catch (Exception ignored) {}
    }
    public static RSAEncryptor getInstance() {
        if (instance == null) {
            instance = new RSAEncryptor();
        }
        return instance;
    }

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public void registerKeyPrivate(String privateKey) {
        try {
            byte[] privateKeyBytes = Helper.hexStringToByteArray(privateKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));;
        }
        catch (Exception ignored) {}
    }
    public void registerKeyPublic(String publicKey) {
        try {
            byte[] publicKeyBytes = Helper.hexStringToByteArray(publicKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            this.publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        }
        catch (Exception ignored) {}
    }
    public void registerKeys(String privateKey, String publicKey) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            byte[] publicKeyBytes = Helper.hexStringToByteArray(publicKey);
            byte[] privateKeyBytes = Helper.hexStringToByteArray(privateKey);
            this.publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));;
        }
        catch (Exception ignored) {}
    }

    public String code(String msg) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] res = cipher.doFinal(msg.getBytes());
        return Helper.bytesToHex(res);
    }

    public String decode(String msg) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] msgBytes = Helper.hexStringToByteArray(msg);
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] res = cipher.doFinal(msgBytes);
        return new String(res, StandardCharsets.UTF_8);
    }
}
