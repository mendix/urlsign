package com.mendix.cloud.urlsign.exception;

public class URLVerifierException extends Exception
{
    public URLVerifierException()
    {
    }

    public URLVerifierException(String message)
    {
        super(message);
    }

    public URLVerifierException(Throwable cause)
    {
        super(cause);
    }

    public URLVerifierException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public URLVerifierException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}