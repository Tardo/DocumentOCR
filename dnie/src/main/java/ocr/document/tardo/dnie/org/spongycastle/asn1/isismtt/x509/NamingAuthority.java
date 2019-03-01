package org.spongycastle.asn1.isismtt.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.spongycastle.asn1.x500.DirectoryString;

public class NamingAuthority extends ASN1Encodable {
    public static final DERObjectIdentifier id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern = new DERObjectIdentifier(ISISMTTObjectIdentifiers.id_isismtt_at_namingAuthorities + ".1");
    private DERObjectIdentifier namingAuthorityId;
    private DirectoryString namingAuthorityText;
    private String namingAuthorityUrl;

    public static NamingAuthority getInstance(Object obj) {
        if (obj == null || (obj instanceof NamingAuthority)) {
            return (NamingAuthority) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new NamingAuthority((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static NamingAuthority getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private NamingAuthority(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        DEREncodable o;
        Enumeration e = seq.getObjects();
        if (e.hasMoreElements()) {
            o = (DEREncodable) e.nextElement();
            if (o instanceof DERObjectIdentifier) {
                this.namingAuthorityId = (DERObjectIdentifier) o;
            } else if (o instanceof DERIA5String) {
                this.namingAuthorityUrl = DERIA5String.getInstance(o).getString();
            } else if (o instanceof ASN1String) {
                this.namingAuthorityText = DirectoryString.getInstance(o);
            } else {
                throw new IllegalArgumentException("Bad object encountered: " + o.getClass());
            }
        }
        if (e.hasMoreElements()) {
            o = (DEREncodable) e.nextElement();
            if (o instanceof DERIA5String) {
                this.namingAuthorityUrl = DERIA5String.getInstance(o).getString();
            } else if (o instanceof ASN1String) {
                this.namingAuthorityText = DirectoryString.getInstance(o);
            } else {
                throw new IllegalArgumentException("Bad object encountered: " + o.getClass());
            }
        }
        if (e.hasMoreElements()) {
            o = (DEREncodable) e.nextElement();
            if (o instanceof ASN1String) {
                this.namingAuthorityText = DirectoryString.getInstance(o);
                return;
            }
            throw new IllegalArgumentException("Bad object encountered: " + o.getClass());
        }
    }

    public DERObjectIdentifier getNamingAuthorityId() {
        return this.namingAuthorityId;
    }

    public DirectoryString getNamingAuthorityText() {
        return this.namingAuthorityText;
    }

    public String getNamingAuthorityUrl() {
        return this.namingAuthorityUrl;
    }

    public NamingAuthority(DERObjectIdentifier namingAuthorityId, String namingAuthorityUrl, DirectoryString namingAuthorityText) {
        this.namingAuthorityId = namingAuthorityId;
        this.namingAuthorityUrl = namingAuthorityUrl;
        this.namingAuthorityText = namingAuthorityText;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (this.namingAuthorityId != null) {
            vec.add(this.namingAuthorityId);
        }
        if (this.namingAuthorityUrl != null) {
            vec.add(new DERIA5String(this.namingAuthorityUrl, true));
        }
        if (this.namingAuthorityText != null) {
            vec.add(this.namingAuthorityText);
        }
        return new DERSequence(vec);
    }
}
