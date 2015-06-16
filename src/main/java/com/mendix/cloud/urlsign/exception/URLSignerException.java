package com.mendix.cloud.urlsign.exception;

public class URLSignerException extends Exception
{
    public URLSignerException()
    {
    }

    public URLSignerException(String message)
    {
        super(message);
    }

    public URLSignerException(Throwable cause)
    {
        super(cause);
    }

    public URLSignerException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public URLSignerException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}