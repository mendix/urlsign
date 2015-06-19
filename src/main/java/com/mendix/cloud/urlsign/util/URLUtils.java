package com.mendix.cloud.urlsign.util;

import com.mendix.cloud.urlsign.exception.URLVerifierException;

import javax.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class URLUtils {

    public static String getFullURL(HttpServletRequest request) throws URLVerifierException {
        StringBuffer requestURL = request.getRequestURL();
        String queryString = request.getQueryString();

        String fullUrl;
        if (queryString == null) {
            fullUrl = requestURL.toString();
        } else {
            fullUrl = requestURL.append('?').append(queryString).toString();
        }

        try {
            return URLDecoder.decode(fullUrl, StandardCharsets.UTF_8.toString());
        } catch (Exception e) {
            throw new URLVerifierException(e);
        }
    }
}
