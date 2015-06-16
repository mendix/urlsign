package com.mendix.cloud.urlsign;

import com.mendix.cloud.urlsign.exception.KeyImporterException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class KeyImporter {

    private static final String PEM_SSLEAY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----\n";
    private static final String PEM_SSLEAY_END = "-----END RSA PRIVATE KEY-----\n";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PrivateKey importPrivateKey(byte[] privateKey) throws KeyImporterException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            throw new KeyImporterException(e);
        }
    }

    public static PrivateKey importPrivateKey(String privateKey) throws KeyImporterException {
        try {
            privateKey = privateKey.replace(PEM_SSLEAY_BEGIN, "").replace(PEM_SSLEAY_END, "");
            return importPrivateKey(DatatypeConverter.parseBase64Binary(privateKey));
        } catch (Exception e) {
            throw new KeyImporterException(e);
        }
    }

    public static PrivateKey importPrivateKey(File privateKeyFile) throws KeyImporterException {
        try {
            PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(privateKeyFile)));
            return importPrivateKey(pemReader.readPemObject().getContent());
        } catch (Exception e) {
            throw new KeyImporterException("Error while reading PrivateKey.", e);
        }
    }

    /*
     * Heavily based on:
     * https://github.com/ragnar-johannsson/CloudStack/blob/master/utils/src/com/cloud/utils/crypt/RSAHelper.java
     */
    public static PublicKey importPublicKey(byte[] publicKey) throws KeyImporterException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(publicKey));

        byte[] header = readElement(dis);
        String pubKeyFormat = new String(header);
        if (!pubKeyFormat.equals("ssh-rsa")) {
            throw new KeyImporterException("Unsupported format used for PublicKey.");
        }

        byte[] publicExponent = readElement(dis);
        byte[] modulus = readElement(dis);

        KeySpec spec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new KeyImporterException(e);
        }
    }

    public static PublicKey importPublicKey(String publicKey) throws KeyImporterException {
        return importPublicKey(DatatypeConverter.parseBase64Binary(publicKey.split(" ")[1]));
    }

    public static PublicKey importPublicKey(File publicKeyFile) throws KeyImporterException {
        try {
            return importPublicKey(new String(Files.readAllBytes(publicKeyFile.toPath()), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new KeyImporterException(e);
        }
    }

    private static byte[] readElement(DataInput dis) throws KeyImporterException {
        try {
            int len = dis.readInt();
            byte[] buf = new byte[len];
            dis.readFully(buf);
            return buf;
        } catch (Exception e) {
            throw new KeyImporterException("Error while reading DataInput for PublicKey.", e);
        }
    }
}
