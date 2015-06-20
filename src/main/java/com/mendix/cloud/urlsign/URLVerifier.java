package com.mendix.cloud.urlsign;

import com.mendix.cloud.urlsign.exception.KeyImporterException;
import com.mendix.cloud.urlsign.exception.URLVerifierException;
import com.mendix.cloud.urlsign.exception.functional.URLVerificationInvalidException;
import com.mendix.cloud.urlsign.util.URLUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
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

    public URLVerifier(byte[] publicKey) throws KeyImporterException, URLVerifierException {
        this(KeyImporter.importPublicKey(publicKey));
    }

    public URLVerifier(String publicKey) throws KeyImporterException, URLVerifierException {
        this(KeyImporter.importPublicKey(publicKey));
    }

    public URLVerifier(File publicKeyFile) throws KeyImporterException, URLVerifierException {
        this(KeyImporter.importPublicKey(publicKeyFile));
    }

    private URLVerifier(PublicKey publicKey) throws URLVerifierException {
        key = publicKey;

        try {
            verify = Signature.getInstance("SHA1withRSA/ISO9796-2", BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            throw new URLVerifierException(e);
        }
    }

    public boolean verify(HttpServletRequest request) throws URLVerifierException, URLVerificationInvalidException {
        if(verifyGracefully(request)) {
            return true;
        } else {
            throw new URLVerificationInvalidException("URL Verification failed for URL: " + URLUtils.getFullURL(request));
        }
    }

    public boolean verify(URI uri) throws URLVerifierException, URLVerificationInvalidException {
        if(verifyGracefully(uri)) {
            return true;
        } else {
            throw new URLVerificationInvalidException("URL Verification failed for URL: " + uri.toString());
        }
    }

    public boolean verifyGracefully(HttpServletRequest request) throws URLVerifierException {
        try {
            URI uri = new URI(URLUtils.getFullURL(request));
            return verifyGracefully(uri);
        } catch (Exception e) {
            throw new URLVerifierException(e);
        }
    }

    public boolean verifyGracefully(URI uri) throws URLVerifierException {
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

            String unescapedSignatureValue = URLUtils.unescapeBase64String(signatureNameValuePair.getValue());
            byte[] signature = DatatypeConverter.parseBase64Binary(unescapedSignatureValue);
            return getVerification(uriToVerify.getBytes(StandardCharsets.UTF_8.name()), signature);
        } catch (Exception e) {
            throw new URLVerifierException(e);
        }
    }

    public boolean getVerification(byte[] message, byte[] signature) throws URLVerifierException {
        try {
            verify.initVerify(key);
            verify.update(message);
            return verify.verify(signature);
        } catch (Exception e) {
            throw new URLVerifierException(e);
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
}
