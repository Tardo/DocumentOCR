package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class DERSequenceGenerator extends DERGenerator {
    private final ByteArrayOutputStream _bOut = new ByteArrayOutputStream();

    public DERSequenceGenerator(OutputStream out) throws IOException {
        super(out);
    }

    public DERSequenceGenerator(OutputStream out, int tagNo, boolean isExplicit) throws IOException {
        super(out, tagNo, isExplicit);
    }

    public void addObject(DEREncodable object) throws IOException {
        object.getDERObject().encode(new DEROutputStream(this._bOut));
    }

    public OutputStream getRawOutputStream() {
        return this._bOut;
    }

    public void close() throws IOException {
        writeDEREncoded(48, this._bOut.toByteArray());
    }
}