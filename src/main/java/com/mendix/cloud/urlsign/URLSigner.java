package com.mendix.cloud.urlsign;

import com.mendix.cloud.urlsign.exception.KeyImporterException;
import com.mendix.cloud.urlsign.exception.URLSignerException;
import org.apache.http.client.utils.URIBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

public class URLSigner {

    public static final String URL_EXPIRE = "expire";
    public static final String URL_SIGNATURE = "signature";

    private static PrivateKey key;
    private static Signature signature;

    public URLSigner(byte[] privateKey) throws KeyImporterException, URLSignerException {
        this(KeyImporter.importPrivateKey(privateKey));
    }

    public URLSigner(String privateKey) throws KeyImporterException, URLSignerException {
        this(KeyImporter.importPrivateKey(privateKey));
    }

    public URLSigner(File privateKeyFile) throws KeyImporterException, URLSignerException {
        this(KeyImporter.importPrivateKey(privateKeyFile));
    }

    private URLSigner(PrivateKey privateKey) throws URLSignerException {
        key = privateKey;

        try {
            signature = Signature.getInstance("SHA1withRSA/ISO9796-2", BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new URLSignerException("No Such Algorithm.", e);
        } catch (NoSuchProviderException e) {
            throw new URLSignerException("No Such Provider.", e);
        }
    }

    public URI sign(URI uri, int ttlInSeconds) throws URLSignerException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date timestampNow = new Date();
        Date timestampExpiry = new Date(timestampNow.getTime() + (TimeUnit.SECONDS.toMillis(ttlInSeconds)));

        String expiryValue = dateFormat.format(timestampExpiry);
        URIBuilder uriBuilder = new URIBuilder(uri);
        uriBuilder.addParameter(URL_EXPIRE, expiryValue);

        try {
            String uriToSign = uriBuilder.build().toString();
            byte[] signatureBytes = getSignature(uriToSign.getBytes(StandardCharsets.UTF_8.name()));
            String signatureValue = DatatypeConverter.printHexBinary(signatureBytes);
            uriBuilder.addParameter(URL_SIGNATURE, signatureValue);
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new URLSignerException("Error while building URI.", e);
        } catch (UnsupportedEncodingException e) {
            throw new URLSignerException("Error while signing URI.", e);
        }
    }

    public byte[] getSignature(byte[] message) throws URLSignerException {
        try {
            signature.initSign(key);
            signature.update(message);
            return signature.sign();
        } catch (InvalidKeyException e) {
            throw new URLSignerException("Invalid Key.", e);
        } catch (SignatureException e) {
            throw new URLSignerException("Invalid Signature.", e);
        }
    }
}
