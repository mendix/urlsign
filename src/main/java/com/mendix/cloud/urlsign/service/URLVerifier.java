package com.mendix.cloud.urlsign.service;

import com.mendix.cloud.urlsign.exception.URLSignException;
import com.mendix.cloud.urlsign.util.KeyImporter;
import com.mendix.cloud.urlsign.util.URLUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

public class URLVerifier {

    public static final String URL_EXPIRE = "expire";
    public static final String URL_SIGNATURE = "signature";

    private static PublicKey key;
    private static Signature verify;

    public URLVerifier(byte[] publicKey) throws URLSignException {
        this(KeyImporter.importPublicKey(publicKey));
    }

    public URLVerifier(String publicKey) throws URLSignException {
        this(KeyImporter.importPublicKey(publicKey));
    }

    public URLVerifier(File publicKeyFile) throws URLSignException {
        this(KeyImporter.importPublicKey(publicKeyFile));
    }

    private URLVerifier(PublicKey publicKey) throws URLSignException {
        key = publicKey;

        try {
            verify = Signature.getInstance("SHA1withRSA/ISO9796-2", BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new URLSignException("No Such Algorithm.", e);
        } catch (NoSuchProviderException e) {
            throw new URLSignException("No Such Provider.", e);
        }
    }

    public boolean verify(HttpServletRequest request) throws URLSignException {
        if(verifyGracefully(request)) {
            return true;
        } else {
            throw new URLSignException("URL Verification failed for URL: " + URLUtils.getFullURL(request));
        }
    }

    public boolean verify(URI uri) throws URLSignException {
        if(verifyGracefully(uri)) {
            return true;
        } else {
            throw new URLSignException("URL Verification failed for URL: " + uri.toString());
        }
    }

    public boolean verifyGracefully(HttpServletRequest request) throws URLSignException {
        try {
            URI uri = new URI(URLUtils.getFullURL(request));
            return verifyGracefully(uri);
        } catch (URISyntaxException e) {
            throw new URLSignException("Error while parsing URI.", e);
        }
    }

    public boolean verifyGracefully(URI uri) throws URLSignException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date timestampNow = new Date();

        URIBuilder uriBuilder = new URIBuilder(uri);
        List<NameValuePair> queryParams = uriBuilder.getQueryParams();
        NameValuePair expireNameValuePair = getNameValuePair(URL_EXPIRE, queryParams, uri);

        try {
            Date timestampExpiry = dateFormat.parse(expireNameValuePair.getValue());
            if (isTimestampExpired(timestampExpiry, timestampNow)) {
                return false;
            }

            NameValuePair signatureNameValuePair = getNameValuePair(URL_SIGNATURE, queryParams, uri);
            String uriToVerify = rebuildUriToVerify(uriBuilder, queryParams, signatureNameValuePair);

            return verifySignature(signatureNameValuePair, uriToVerify);
        } catch(ParseException e) {
            throw new URLSignException("Error while parsing timestamp.", e);
        } catch (URISyntaxException e) {
            throw new URLSignException("Error while parsing URI.", e);
        }
    }

    private static NameValuePair getNameValuePair(String name, List<NameValuePair> queryParams, URI uri) throws URLSignException {
        NameValuePair expireNameValuePair = extractQueryParam(name, queryParams);
        if(expireNameValuePair == null) {
            throw new URLSignException("Missing '" + name + "' query parameter in URL: " + uri.toString());
        }
        return expireNameValuePair;
    }

    private static boolean isTimestampExpired(Date timestampExpiry, Date timestampNow) {
        return timestampNow.after(timestampExpiry);
    }

    private static String rebuildUriToVerify(URIBuilder uriBuilder, List<NameValuePair> queryParams, NameValuePair signatureNameValuePair) throws URISyntaxException {
        queryParams.remove(signatureNameValuePair);
        uriBuilder.setParameters(queryParams);
        return uriBuilder.build().toString();
    }

    private boolean verifySignature(NameValuePair signatureNameValuePair, String uriToVerify) throws URLSignException {
        try {
            byte[] signature = DatatypeConverter.parseHexBinary(signatureNameValuePair.getValue());
            return getVerification(uriToVerify.getBytes(StandardCharsets.UTF_8.name()), signature);
        } catch (UnsupportedEncodingException e) {
            throw new URLSignException("Error while decoding signature.", e);
        }
    }

    public boolean getVerification(byte[] message, byte[] signature) throws URLSignException {
        try {
            verify.initVerify(key);
            verify.update(message);
            return verify.verify(signature);
        } catch (InvalidKeyException e) {
            throw new URLSignException("Invalid Key.", e);
        } catch (SignatureException e) {
            throw new URLSignException("Invalid Signature.", e);
        }
    }

    private static NameValuePair extractQueryParam(String name, List<NameValuePair> queryParams) {
        for (NameValuePair nvp: queryParams) {
            if(nvp.getName().equals(name)) {
                return nvp;
            }
        }
        return null;
    }
}
