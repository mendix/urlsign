package com.mendix.cloud.urlsign.util;

import com.mendix.cloud.urlsign.exception.URLSignException;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class URLUtils {

    private static final char[] chars1 = {'+', '=', '/'};
    private static final char[] chars2 = {'~', '-', '_'};

    private URLUtils() {
    }

    public static String getFullURL(HttpServletRequest request) throws URLSignException {
        StringBuffer requestURL = request.getRequestURL();
        String queryString = request.getQueryString();

        String fullUrl;
        if (queryString == null) {
            fullUrl = requestURL.toString();
        } else {
            fullUrl = requestURL.append('?').append(queryString).toString();
        }

        fullUrl = replaceURLSchemeIfNeeded(request, fullUrl);

        try {
            return URLDecoder.decode(fullUrl, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new URLSignException("Error while decoding full URL.", e);
        }
    }

    public static String replaceURLSchemeIfNeeded(HttpServletRequest request, String url) {
        String forwardedScheme = request.getHeader("X-Forwarded-Scheme");
        String forwardedProto = request.getHeader("X-Forwarded-Proto");

        String scheme = forwardedProto;
        if (forwardedScheme != null)
            scheme = forwardedScheme;

        if (scheme != null) {
            return url.replaceFirst("http://", scheme + "://");
        }
        return url;
    }

    public static String escapeBase64String(String str) {
        assert chars1.length == chars2.length;

        String escapedString = new String(str);
        for (int i = 0; i < chars1.length; i++) {
            escapedString = escapedString.replace(chars1[i], chars2[i]);
        }
        return escapedString;
    }

    public static String unescapeBase64String(String str) {
        assert chars1.length == chars2.length;

        String unescapedString = new String(str);
        for (int i = 0; i < chars1.length; i++) {
            unescapedString = unescapedString.replace(chars2[i], chars1[i]);
        }
        return unescapedString;
    }
}
