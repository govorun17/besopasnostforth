package RSA;

import Helper.Helper;

import java.nio.charset.StandardCharsets;
import java.security.*;

public final class RSAKeyGen {
    private static RSAKeyGen instance;
    private RSAKeyGen() {
        generateNewKeys();
    }
    public static RSAKeyGen getInstance() {
        if (instance == null) {
            instance = new RSAKeyGen();
        }
        return instance;
    }

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public String getPrivateKey() {
        return Helper.bytesToHex(privateKey.getEncoded());
    }
    public String getPublicKey() {
        return Helper.bytesToHex(publicKey.getEncoded());
    }

    public void generateNewKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
        }
        catch (Exception ignore) {}
    }
}
