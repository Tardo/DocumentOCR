package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class DERExternal extends ASN1Object {
    private ASN1Object dataValueDescriptor;
    private DERObjectIdentifier directReference;
    private int encoding;
    private DERObject externalContent;
    private DERInteger indirectReference;

    public DERExternal(ASN1EncodableVector vector) {
        int offset = 0;
        DERObject objFromVector = getObjFromVector(vector, 0);
        if (objFromVector instanceof DERObjectIdentifier) {
            this.directReference = (DERObjectIdentifier) objFromVector;
            offset = 0 + 1;
            objFromVector = getObjFromVector(vector, offset);
        }
        if (objFromVector instanceof DERInteger) {
            this.indirectReference = (DERInteger) objFromVector;
            offset++;
            objFromVector = getObjFromVector(vector, offset);
        }
        if (!(objFromVector instanceof DERTaggedObject)) {
            this.dataValueDescriptor = (ASN1Object) objFromVector;
            offset++;
            objFromVector = getObjFromVector(vector, offset);
        }
        if (vector.size() != offset + 1) {
            throw new IllegalArgumentException("input vector too large");
        } else if (objFromVector instanceof DERTaggedObject) {
            DERTaggedObject obj = (DERTaggedObject) objFromVector;
            setEncoding(obj.getTagNo());
            this.externalContent = obj.getObject();
        } else {
            throw new IllegalArgumentException("No tagged object found in vector. Structure doesn't seem to be of type External");
        }
    }

    private DERObject getObjFromVector(ASN1EncodableVector v, int index) {
        if (v.size() > index) {
            return v.get(index).getDERObject();
        }
        throw new IllegalArgumentException("too few objects in input vector");
    }

    public DERExternal(DERObjectIdentifier directReference, DERInteger indirectReference, ASN1Object dataValueDescriptor, DERTaggedObject externalData) {
        this(directReference, indirectReference, dataValueDescriptor, externalData.getTagNo(), externalData.getDERObject());
    }

    public DERExternal(DERObjectIdentifier directReference, DERInteger indirectReference, ASN1Object dataValueDescriptor, int encoding, DERObject externalData) {
        setDirectReference(directReference);
        setIndirectReference(indirectReference);
        setDataValueDescriptor(dataValueDescriptor);
        setEncoding(encoding);
        setExternalContent(externalData.getDERObject());
    }

    public int hashCode() {
        int ret = 0;
        if (this.directReference != null) {
            ret = this.directReference.hashCode();
        }
        if (this.indirectReference != null) {
            ret ^= this.indirectReference.hashCode();
        }
        if (this.dataValueDescriptor != null) {
            ret ^= this.dataValueDescriptor.hashCode();
        }
        return ret ^ this.externalContent.hashCode();
    }

    void encode(DEROutputStream out) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (this.directReference != null) {
            baos.write(this.directReference.getDEREncoded());
        }
        if (this.indirectReference != null) {
            baos.write(this.indirectReference.getDEREncoded());
        }
        if (this.dataValueDescriptor != null) {
            baos.write(this.dataValueDescriptor.getDEREncoded());
        }
        baos.write(new DERTaggedObject(this.encoding, this.externalContent).getDEREncoded());
        out.writeEncoded(32, 8, baos.toByteArray());
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof DERExternal)) {
            return false;
        }
        if (this == o) {
            return true;
        }
        DERExternal other = (DERExternal) o;
        if (this.directReference != null && (other.directReference == null || !other.directReference.equals(this.directReference))) {
            return false;
        }
        if (this.indirectReference != null && (other.indirectReference == null || !other.indirectReference.equals(this.indirectReference))) {
            return false;
        }
        if (this.dataValueDescriptor == null || (other.dataValueDescriptor != null && other.dataValueDescriptor.equals(this.dataValueDescriptor))) {
            return this.externalContent.equals(other.externalContent);
        }
        return false;
    }

    public ASN1Object getDataValueDescriptor() {
        return this.dataValueDescriptor;
    }

    public DERObjectIdentifier getDirectReference() {
        return this.directReference;
    }

    public int getEncoding() {
        return this.encoding;
    }

    public DERObject getExternalContent() {
        return this.externalContent;
    }

    public DERInteger getIndirectReference() {
        return this.indirectReference;
    }

    private void setDataValueDescriptor(ASN1Object dataValueDescriptor) {
        this.dataValueDescriptor = dataValueDescriptor;
    }

    private void setDirectReference(DERObjectIdentifier directReferemce) {
        this.directReference = directReferemce;
    }

    private void setEncoding(int encoding) {
        if (encoding < 0 || encoding > 2) {
            throw new IllegalArgumentException("invalid encoding value: " + encoding);
        }
        this.encoding = encoding;
    }

    private void setExternalContent(DERObject externalContent) {
        this.externalContent = externalContent;
    }

    private void setIndirectReference(DERInteger indirectReference) {
        this.indirectReference = indirectReference;
    }
}
