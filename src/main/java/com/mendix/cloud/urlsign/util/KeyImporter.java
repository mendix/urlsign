package com.mendix.cloud.urlsign.util;

import com.mendix.cloud.urlsign.exception.URLSignException;
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

    private KeyImporter(){
    }

    public static PrivateKey importPrivateKey(byte[] privateKey) throws URLSignException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePrivate(spec);
        } catch (NoSuchAlgorithmException e) {
            throw new URLSignException("No Such Algorithm.", e);
        } catch (NoSuchProviderException e) {
            throw new URLSignException("No Such Provider.", e);
        } catch (InvalidKeySpecException e) {
            throw new URLSignException("Invalid Key Specification.", e);
        }
    }

    public static PrivateKey importPrivateKey(String privateKey) throws URLSignException {
        String privateKeyTrimmed = privateKey.replace(PEM_SSLEAY_BEGIN, "").replace(PEM_SSLEAY_END, "");
        return importPrivateKey(DatatypeConverter.parseBase64Binary(privateKeyTrimmed));
    }

    public static PrivateKey importPrivateKey(File privateKeyFile) throws URLSignException {
        try {
            return readPrivateKey(privateKeyFile);
        } catch (IOException e) {
            throw new URLSignException("Error while closing PemReader.", e);
        }
    }

    private static PrivateKey readPrivateKey(File privateKeyFile) throws URLSignException, IOException {
        PemReader pemReader = null;
        try {
            pemReader = new PemReader(new InputStreamReader(new FileInputStream(privateKeyFile)));
            return importPrivateKey(pemReader.readPemObject().getContent());
        } catch (IOException e) {
            throw new URLSignException("Error while reading PrivateKey.", e);
        } finally {
            if(pemReader != null) {
                pemReader.close();
            }
        }
    }

    /*
     * Heavily based on:
     * https://github.com/ragnar-johannsson/CloudStack/blob/master/utils/src/com/cloud/utils/crypt/RSAHelper.java
     */
    public static PublicKey importPublicKey(byte[] publicKey) throws URLSignException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(publicKey));

        byte[] header = readElement(dis);
        String pubKeyFormat = new String(header);
        if (!"ssh-rsa".equals(pubKeyFormat)) {
            throw new URLSignException("Unsupported format used for PublicKey.");
        }

        byte[] publicExponent = readElement(dis);
        byte[] modulus = readElement(dis);

        KeySpec spec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePublic(spec);
        } catch (NoSuchAlgorithmException e) {
            throw new URLSignException("No Such Algorithm.", e);
        } catch (NoSuchProviderException e) {
            throw new URLSignException("No Such Provider.", e);
        } catch (InvalidKeySpecException e) {
            throw new URLSignException("Invalid Key Specification.", e);
        }
    }

    public static PublicKey importPublicKey(String publicKey) throws URLSignException {
        return importPublicKey(DatatypeConverter.parseBase64Binary(publicKey.split(" ")[1]));
    }

    public static PublicKey importPublicKey(File publicKeyFile) throws URLSignException {
        try {
            return importPublicKey(new String(Files.readAllBytes(publicKeyFile.toPath()), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new URLSignException("Error while reading PublicKey.", e);
        }
    }

    private static byte[] readElement(DataInput dis) throws URLSignException {
        try {
            int len = dis.readInt();
            byte[] buf = new byte[len];
            dis.readFully(buf);
            return buf;
        } catch (IOException e) {
            throw new URLSignException("Error while reading DataInput for PublicKey.", e);
        }
    }
}
