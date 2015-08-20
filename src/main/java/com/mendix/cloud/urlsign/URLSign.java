package com.mendix.cloud.urlsign;

import com.mendix.cloud.urlsign.exception.URLSignException;
import com.mendix.cloud.urlsign.service.URLSigner;
import com.mendix.cloud.urlsign.service.URLVerifier;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;

public class URLSign {

    public static final int DEFAULT_EXPIRE_TTL = 120;

    private URLSign() {
    }

    public static URI sign(String privateKey, URI uri, int ttlInSeconds) throws URLSignException {
        return new URLSigner(privateKey).sign(uri, ttlInSeconds);
    }

    public static boolean verify(String publicKey, HttpServletRequest request) throws URLSignException {
        return new URLVerifier(publicKey).verify(request);
    }

}

