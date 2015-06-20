package com.mendix.cloud.urlsign;

import com.mendix.cloud.urlsign.exception.KeyImporterException;
import com.mendix.cloud.urlsign.exception.URLSignerException;
import com.mendix.cloud.urlsign.util.URLUtils;
import org.apache.http.client.utils.URIBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

public class URLSigner {

    public static final String URL_EXPIRE = "expire";
    public static final String URL_SIGNATURE = "signature";
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");

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
        } catch (Exception e) {
            throw new URLSignerException(e);
        }
    }

    public URI sign(URI uri, int ttlInSeconds) throws URLSignerException {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date timestampNow = new Date();
        Date timestampExpiry = new Date(timestampNow.getTime() + (TimeUnit.SECONDS.toMillis(ttlInSeconds)));

        String expiryValue = dateFormat.format(timestampExpiry);
        URIBuilder uriBuilder = new URIBuilder(uri);
        uriBuilder.addParameter(URL_EXPIRE, expiryValue);

        try {
            String uriToSign = uriBuilder.build().toASCIIString();
            byte[] signature = getSignature(uriToSign.getBytes(StandardCharsets.UTF_8.name()));
            String signatureValue = DatatypeConverter.printBase64Binary(signature);
            String signatureValueEscaped = URLUtils.escapeBase64String(signatureValue);
            uriBuilder.addParameter(URL_SIGNATURE, signatureValueEscaped);
            return uriBuilder.build();
        } catch (Exception e) {
            throw new URLSignerException(e);
        }
    }

    public byte[] getSignature(byte[] message) throws URLSignerException {
        try {
            signature.initSign(key);
            signature.update(message);
            return signature.sign();
        } catch (Exception e) {
            throw new URLSignerException(e);
        }
    }
}
