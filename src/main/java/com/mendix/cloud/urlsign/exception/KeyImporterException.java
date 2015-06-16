package com.mendix.cloud.urlsign.exception;

public class KeyImporterException extends Exception
{
    public KeyImporterException()
    {
    }

    public KeyImporterException(String message)
    {
        super(message);
    }

    public KeyImporterException(Throwable cause)
    {
        super(cause);
    }

    public KeyImporterException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public KeyImporterException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}