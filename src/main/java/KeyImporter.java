import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class KeyImporter {

    private static final String PEM_SSLEAY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----\n";
    private static final String PEM_SSLEAY_END = "-----END RSA PRIVATE KEY-----\n";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PrivateKey importPrivateKey(byte[] privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePrivate(spec);
    }

    public static PrivateKey importPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchProviderException {
        privateKey = privateKey.replace(PEM_SSLEAY_BEGIN, "").replace(PEM_SSLEAY_END, "");
        return importPrivateKey(DatatypeConverter.parseBase64Binary(privateKey));
    }

    public static PrivateKey importPrivateKey(File privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(privateKeyFile)));
        return importPrivateKey(pemReader.readPemObject().getContent());
    }

    /*
     * Heavily based on:
     * https://github.com/ragnar-johannsson/CloudStack/blob/master/utils/src/com/cloud/utils/crypt/RSAHelper.java
     */
    public static PublicKey importPublicKey(byte[] publicKey) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(publicKey));

        byte[] header = readElement(dis);
        String pubKeyFormat = new String(header);
        if (!pubKeyFormat.equals("ssh-rsa")) {
            throw new RuntimeException("Unsupported format");
        }

        byte[] publicExponent = readElement(dis);
        byte[] modulus = readElement(dis);

        KeySpec spec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePublic(spec);
    }

    public static PublicKey importPublicKey(String publicKey) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        return importPublicKey(DatatypeConverter.parseBase64Binary(publicKey.split(" ")[1]));
    }

    public static PublicKey importPublicKey(File publicKeyFile) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        return importPublicKey(new String(Files.readAllBytes(publicKeyFile.toPath()), StandardCharsets.UTF_8));
    }

    private static byte[] readElement(DataInput dis) throws IOException {
        int len = dis.readInt();
        byte[] buf = new byte[len];
        dis.readFully(buf);
        return buf;
    }
}
