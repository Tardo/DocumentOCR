package org.bouncycastle.tsp;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.tsp.TimeStampResp;

public class TimeStampResponseGenerator {
    private Set acceptedAlgorithms;
    private Set acceptedExtensions;
    private Set acceptedPolicies;
    int failInfo;
    int status;
    ASN1EncodableVector statusStrings;
    private TimeStampTokenGenerator tokenGenerator;

    class FailInfo extends DERBitString {
        FailInfo(int i) {
            super(DERBitString.getBytes(i), DERBitString.getPadBits(i));
        }
    }

    public TimeStampResponseGenerator(TimeStampTokenGenerator timeStampTokenGenerator, Set set) {
        this(timeStampTokenGenerator, set, null, null);
    }

    public TimeStampResponseGenerator(TimeStampTokenGenerator timeStampTokenGenerator, Set set, Set set2) {
        this(timeStampTokenGenerator, set, set2, null);
    }

    public TimeStampResponseGenerator(TimeStampTokenGenerator timeStampTokenGenerator, Set set, Set set2, Set set3) {
        this.tokenGenerator = timeStampTokenGenerator;
        this.acceptedAlgorithms = convert(set);
        this.acceptedPolicies = convert(set2);
        this.acceptedExtensions = convert(set3);
        this.statusStrings = new ASN1EncodableVector();
    }

    private void addStatusString(String str) {
        this.statusStrings.add(new DERUTF8String(str));
    }

    private Set convert(Set set) {
        if (set == null) {
            return set;
        }
        Set hashSet = new HashSet(set.size());
        for (Object next : set) {
            if (next instanceof String) {
                hashSet.add(new ASN1ObjectIdentifier((String) next));
            } else {
                hashSet.add(next);
            }
        }
        return hashSet;
    }

    private PKIStatusInfo getPKIStatusInfo() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(new DERInteger((long) this.status));
        if (this.statusStrings.size() > 0) {
            aSN1EncodableVector.add(PKIFreeText.getInstance(new DERSequence(this.statusStrings)));
        }
        if (this.failInfo != 0) {
            aSN1EncodableVector.add(new FailInfo(this.failInfo));
        }
        return PKIStatusInfo.getInstance(new DERSequence(aSN1EncodableVector));
    }

    private void setFailInfoField(int i) {
        this.failInfo |= i;
    }

    public TimeStampResponse generate(TimeStampRequest timeStampRequest, BigInteger bigInteger, Date date) throws TSPException {
        try {
            return generateGrantedResponse(timeStampRequest, bigInteger, date, "Operation Okay");
        } catch (Exception e) {
            return generateRejectedResponse(e);
        }
    }

    public org.bouncycastle.tsp.TimeStampResponse generate(org.bouncycastle.tsp.TimeStampRequest r4, java.math.BigInteger r5, java.util.Date r6, java.lang.String r7) throws java.security.NoSuchAlgorithmException, java.security.NoSuchProviderException, org.bouncycastle.tsp.TSPException {
        /* JADX: method processing error */
/*
Error: jadx.core.utils.exceptions.JadxRuntimeException: Exception block dominator not found, method:org.bouncycastle.tsp.TimeStampResponseGenerator.generate(org.bouncycastle.tsp.TimeStampRequest, java.math.BigInteger, java.util.Date, java.lang.String):org.bouncycastle.tsp.TimeStampResponse. bs: [B:1:0x0002, B:12:0x0043]
	at jadx.core.dex.visitors.regions.ProcessTryCatchRegions.searchTryCatchDominators(ProcessTryCatchRegions.java:86)
	at jadx.core.dex.visitors.regions.ProcessTryCatchRegions.process(ProcessTryCatchRegions.java:45)
	at jadx.core.dex.visitors.regions.RegionMakerVisitor.postProcessRegions(RegionMakerVisitor.java:63)
	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:58)
	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:31)
	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:17)
	at jadx.core.ProcessClass.process(ProcessClass.java:34)
	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:282)
	at jadx.api.JavaClass.decompile(JavaClass.java:62)
	at jadx.api.JadxDecompiler.lambda$appendSourcesSave$0(JadxDecompiler.java:200)
	at jadx.api.JadxDecompiler$$Lambda$8/1122805102.run(Unknown Source)
*/
        /*
        r3 = this;
        if (r6 != 0) goto L_0x002e;
    L_0x0002:
        r0 = new org.bouncycastle.tsp.TSPValidationException;	 Catch:{ TSPValidationException -> 0x000c }
        r1 = "The time source is not available.";	 Catch:{ TSPValidationException -> 0x000c }
        r2 = 512; // 0x200 float:7.175E-43 double:2.53E-321;	 Catch:{ TSPValidationException -> 0x000c }
        r0.<init>(r1, r2);	 Catch:{ TSPValidationException -> 0x000c }
        throw r0;	 Catch:{ TSPValidationException -> 0x000c }
    L_0x000c:
        r0 = move-exception;
        r1 = 2;
        r3.status = r1;
        r1 = r0.getFailureCode();
        r3.setFailInfoField(r1);
        r0 = r0.getMessage();
        r3.addStatusString(r0);
        r1 = r3.getPKIStatusInfo();
        r0 = new org.bouncycastle.asn1.tsp.TimeStampResp;
        r2 = 0;
        r0.<init>(r1, r2);
    L_0x0028:
        r1 = new org.bouncycastle.tsp.TimeStampResponse;	 Catch:{ IOException -> 0x0072 }
        r1.<init>(r0);	 Catch:{ IOException -> 0x0072 }
        return r1;
    L_0x002e:
        r0 = r3.acceptedAlgorithms;	 Catch:{ TSPValidationException -> 0x000c }
        r1 = r3.acceptedPolicies;	 Catch:{ TSPValidationException -> 0x000c }
        r2 = r3.acceptedExtensions;	 Catch:{ TSPValidationException -> 0x000c }
        r4.validate(r0, r1, r2, r7);	 Catch:{ TSPValidationException -> 0x000c }
        r0 = 0;	 Catch:{ TSPValidationException -> 0x000c }
        r3.status = r0;	 Catch:{ TSPValidationException -> 0x000c }
        r0 = "Operation Okay";	 Catch:{ TSPValidationException -> 0x000c }
        r3.addStatusString(r0);	 Catch:{ TSPValidationException -> 0x000c }
        r1 = r3.getPKIStatusInfo();	 Catch:{ TSPValidationException -> 0x000c }
        r0 = new java.io.ByteArrayInputStream;	 Catch:{ IOException -> 0x0069 }
        r2 = r3.tokenGenerator;	 Catch:{ IOException -> 0x0069 }
        r2 = r2.generate(r4, r5, r6, r7);	 Catch:{ IOException -> 0x0069 }
        r2 = r2.toCMSSignedData();	 Catch:{ IOException -> 0x0069 }
        r2 = r2.getEncoded();	 Catch:{ IOException -> 0x0069 }
        r0.<init>(r2);	 Catch:{ IOException -> 0x0069 }
        r2 = new org.bouncycastle.asn1.ASN1InputStream;	 Catch:{ IOException -> 0x0069 }
        r2.<init>(r0);	 Catch:{ IOException -> 0x0069 }
        r0 = r2.readObject();	 Catch:{ IOException -> 0x0069 }
        r2 = org.bouncycastle.asn1.cms.ContentInfo.getInstance(r0);	 Catch:{ IOException -> 0x0069 }
        r0 = new org.bouncycastle.asn1.tsp.TimeStampResp;	 Catch:{ TSPValidationException -> 0x000c }
        r0.<init>(r1, r2);	 Catch:{ TSPValidationException -> 0x000c }
        goto L_0x0028;	 Catch:{ TSPValidationException -> 0x000c }
    L_0x0069:
        r0 = move-exception;	 Catch:{ TSPValidationException -> 0x000c }
        r1 = new org.bouncycastle.tsp.TSPException;	 Catch:{ TSPValidationException -> 0x000c }
        r2 = "Timestamp token received cannot be converted to ContentInfo";	 Catch:{ TSPValidationException -> 0x000c }
        r1.<init>(r2, r0);	 Catch:{ TSPValidationException -> 0x000c }
        throw r1;	 Catch:{ TSPValidationException -> 0x000c }
    L_0x0072:
        r0 = move-exception;
        r0 = new org.bouncycastle.tsp.TSPException;
        r1 = "created badly formatted response!";
        r0.<init>(r1);
        throw r0;
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tsp.TimeStampResponseGenerator.generate(org.bouncycastle.tsp.TimeStampRequest, java.math.BigInteger, java.util.Date, java.lang.String):org.bouncycastle.tsp.TimeStampResponse");
    }

    public TimeStampResponse generateFailResponse(int i, int i2, String str) throws TSPException {
        this.status = i;
        this.statusStrings = new ASN1EncodableVector();
        setFailInfoField(i2);
        if (str != null) {
            addStatusString(str);
        }
        try {
            return new TimeStampResponse(new TimeStampResp(getPKIStatusInfo(), null));
        } catch (IOException e) {
            throw new TSPException("created badly formatted response!");
        }
    }

    public TimeStampResponse generateGrantedResponse(TimeStampRequest timeStampRequest, BigInteger bigInteger, Date date) throws TSPException {
        return generateGrantedResponse(timeStampRequest, bigInteger, date, null);
    }

    public TimeStampResponse generateGrantedResponse(TimeStampRequest timeStampRequest, BigInteger bigInteger, Date date, String str) throws TSPException {
        if (date == null) {
            throw new TSPValidationException("The time source is not available.", 512);
        }
        timeStampRequest.validate(this.acceptedAlgorithms, this.acceptedPolicies, this.acceptedExtensions);
        this.status = 0;
        this.statusStrings = new ASN1EncodableVector();
        if (str != null) {
            addStatusString(str);
        }
        try {
            try {
                return new TimeStampResponse(new TimeStampResp(getPKIStatusInfo(), this.tokenGenerator.generate(timeStampRequest, bigInteger, date).toCMSSignedData().toASN1Structure()));
            } catch (IOException e) {
                throw new TSPException("created badly formatted response!");
            }
        } catch (TSPException e2) {
            throw e2;
        } catch (Throwable e3) {
            throw new TSPException("Timestamp token received cannot be converted to ContentInfo", e3);
        }
    }

    public TimeStampResponse generateRejectedResponse(Exception exception) throws TSPException {
        return exception instanceof TSPValidationException ? generateFailResponse(2, ((TSPValidationException) exception).getFailureCode(), exception.getMessage()) : generateFailResponse(2, 1073741824, exception.getMessage());
    }
}
