package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.DERObjectIdentifier;

public interface CMPObjectIdentifiers {
    public static final DERObjectIdentifier ct_encKeyWithID = new DERObjectIdentifier("1.2.840.113549.1.9.16.1.21");
    public static final DERObjectIdentifier dhBasedMac = new DERObjectIdentifier("1.2.840.113533.7.66.30");
    public static final DERObjectIdentifier it_caKeyUpdateInfo = new DERObjectIdentifier("1.3.6.1.5.5.7.4.5");
    public static final DERObjectIdentifier it_caProtEncCert = new DERObjectIdentifier("1.3.6.1.5.5.7.4.1");
    public static final DERObjectIdentifier it_confirmWaitTime = new DERObjectIdentifier("1.3.6.1.5.5.7.4.14");
    public static final DERObjectIdentifier it_currentCRL = new DERObjectIdentifier("1.3.6.1.5.5.7.4.6");
    public static final DERObjectIdentifier it_encKeyPairTypes = new DERObjectIdentifier("1.3.6.1.5.5.7.4.3");
    public static final DERObjectIdentifier it_implicitConfirm = new DERObjectIdentifier("1.3.6.1.5.5.7.4.13");
    public static final DERObjectIdentifier it_keyPairParamRep = new DERObjectIdentifier("1.3.6.1.5.5.7.4.11");
    public static final DERObjectIdentifier it_keyPairParamReq = new DERObjectIdentifier("1.3.6.1.5.5.7.4.10");
    public static final DERObjectIdentifier it_origPKIMessage = new DERObjectIdentifier("1.3.6.1.5.5.7.4.15");
    public static final DERObjectIdentifier it_preferredSymAlg = new DERObjectIdentifier("1.3.6.1.5.5.7.4.4");
    public static final DERObjectIdentifier it_revPassphrase = new DERObjectIdentifier("1.3.6.1.5.5.7.4.12");
    public static final DERObjectIdentifier it_signKeyPairTypes = new DERObjectIdentifier("1.3.6.1.5.5.7.4.2");
    public static final DERObjectIdentifier it_suppLangTags = new DERObjectIdentifier("1.3.6.1.5.5.7.4.16");
    public static final DERObjectIdentifier it_unsupportedOIDs = new DERObjectIdentifier("1.3.6.1.5.5.7.4.7");
    public static final DERObjectIdentifier passwordBasedMac = new DERObjectIdentifier("1.2.840.113533.7.66.13");
    public static final DERObjectIdentifier regCtrl_altCertTemplate = new DERObjectIdentifier("1.3.6.1.5.5.7.5.1.7");
    public static final DERObjectIdentifier regCtrl_authenticator = new DERObjectIdentifier("1.3.6.1.5.5.7.5.1.2");
    public static final DERObjectIdentifier regCtrl_oldCertID = new DERObjectIdentifier("1.3.6.1.5.5.7.5.1.5");
    public static final DERObjectIdentifier regCtrl_pkiArchiveOptions = new DERObjectIdentifier("1.3.6.1.5.5.7.5.1.4");
    public static final DERObjectIdentifier regCtrl_pkiPublicationInfo = new DERObjectIdentifier("1.3.6.1.5.5.7.5.1.3");
    public static final DERObjectIdentifier regCtrl_protocolEncrKey = new DERObjectIdentifier("1.3.6.1.5.5.7.5.1.6");
    public static final DERObjectIdentifier regCtrl_regToken = new DERObjectIdentifier("1.3.6.1.5.5.7.5.1.1");
    public static final DERObjectIdentifier regInfo_certReq = new DERObjectIdentifier("1.3.6.1.5.5.7.5.2.2");
    public static final DERObjectIdentifier regInfo_utf8Pairs = new DERObjectIdentifier("1.3.6.1.5.5.7.5.2.1");
}
