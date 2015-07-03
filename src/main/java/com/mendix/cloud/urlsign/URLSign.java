package com.mendix.cloud.urlsign;

import com.mendix.cloud.urlsign.exception.KeyImporterException;
import com.mendix.cloud.urlsign.exception.URLSignerException;
import com.mendix.cloud.urlsign.exception.URLVerifierException;
import com.mendix.cloud.urlsign.exception.functional.URLVerificationInvalidException;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.net.URI;
import java.util.HashMap;

public class URLSign {

    public static final int DEFAULT_EXPIRE_TTL = 120;

    private URLSign() {}

    public static URI sign(String privateKey, URI uri, int ttlInSeconds) throws URLSignerException, KeyImporterException {
        return new URLSigner(privateKey).sign(uri, ttlInSeconds);
    }

    public static boolean verify(String publicKey, HttpServletRequest request) throws URLVerificationInvalidException, URLVerifierException, KeyImporterException {
        return new URLVerifier(publicKey).verify(request);
    }

}

