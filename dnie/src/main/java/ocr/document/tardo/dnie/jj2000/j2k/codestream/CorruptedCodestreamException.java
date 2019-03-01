package jj2000.j2k.codestream;

import java.io.IOException;

public class CorruptedCodestreamException extends IOException {
    public CorruptedCodestreamException(String s) {
        super(s);
    }
}
