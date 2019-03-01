package com.eiqui.odoojson_rpc.exceptions;

/**
 * Created by uchar on 11/09/16.
 */
public class OdooLoginException extends Exception {

    private String message = null;

    public OdooLoginException() {
        super();
    }

    public OdooLoginException(String message) {
        super(message);
        this.message = message;
    }

    public OdooLoginException(Throwable cause) {
        super(cause);
    }

    @Override
    public String toString() {
        return message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
