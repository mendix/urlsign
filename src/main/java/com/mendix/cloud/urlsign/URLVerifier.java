package com.mendix.cloud.urlsign;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

public class URLVerifier {

    public static final String URL_EXPIRE = "expire";
    public static final String URL_SIGNATURE = "signature";
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");

    private static PublicKey key;
    private static Signature verify;

    public URLVerifier(byte[] publicKey) {
        this(KeyImporter.importPublicKey(publicKey));
    }

    public URLVerifier(String publicKey) {
        this(KeyImporter.importPublicKey(publicKey));
    }

    public URLVerifier(File publicKeyFile) {
        this(KeyImporter.importPublicKey(publicKeyFile));
    }

    private URLVerifier(PublicKey publicKey) {
        key = publicKey;

        try {
            verify = Signature.getInstance("SHA1withRSA/ISO9796-2", BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(URI uri) {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date timestampNow = new Date();

        URIBuilder uriBuilder = new URIBuilder(uri);
        List<NameValuePair> queryParams = uriBuilder.getQueryParams();
        NameValuePair expireNameValuePair = extractQueryParam(URL_EXPIRE, queryParams);

        try {
            Date timestampExpiry = dateFormat.parse(expireNameValuePair.getValue());

            boolean isExpired = timestampNow.after(timestampExpiry);
            if(isExpired) {
                return false;
            }

            NameValuePair signatureNameValuePair = extractQueryParam(URL_SIGNATURE, queryParams);
            queryParams.remove(signatureNameValuePair);
            uriBuilder.setParameters(queryParams);

            String uriToVerify = uriBuilder.build().toString();
            byte[] signature = DatatypeConverter.parseBase64Binary(signatureNameValuePair.getValue());
            return getVerification(uriToVerify.getBytes(), signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private NameValuePair extractQueryParam(String name, List<NameValuePair> queryParams) {
        for (NameValuePair nvp: queryParams) {
            if(nvp.getName().equals(name)) {
                return nvp;
            }
        }
        return null;
    }

    public boolean getVerification(byte[] message, byte[] signature) {
        try {
            verify.initVerify(key);
            verify.update(message);
            return verify.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
