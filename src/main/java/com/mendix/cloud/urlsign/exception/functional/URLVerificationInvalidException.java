package com.mendix.cloud.urlsign.exception.functional;

public class URLVerificationInvalidException extends Exception
{
    public URLVerificationInvalidException(String message)
    {
        super(message);
    }

    public URLVerificationInvalidException(Throwable cause)
    {
        super(cause);
    }

    public URLVerificationInvalidException(String message, Throwable cause)
    {
        super(message, cause);
    }
}