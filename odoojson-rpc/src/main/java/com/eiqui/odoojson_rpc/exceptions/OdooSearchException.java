package com.eiqui.odoojson_rpc.exceptions;

/**
 * Created by uchar on 11/09/16.
 */
public class OdooSearchException extends Exception {

    private String message = null;

    public OdooSearchException() {
        super();
    }

    public OdooSearchException(String message) {
        super(message);
        this.message = message;
    }

    public OdooSearchException(Throwable cause) {
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
