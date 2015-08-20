package com.mendix.cloud.urlsign.exception;

public class URLSignException extends Exception
{
    public URLSignException(String message)
    {
        super(message);
    }

    public URLSignException(Throwable cause)
    {
        super(cause);
    }

    public URLSignException(String message, Throwable cause)
    {
        super(message, cause);
    }
}