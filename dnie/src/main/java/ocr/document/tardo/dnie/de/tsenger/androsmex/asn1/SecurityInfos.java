package de.tsenger.androsmex.asn1;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;

public class SecurityInfos extends ASN1Encodable {
    List<CardInfoLocator> cardInfoLocatorList = new ArrayList(1);
    List<ChipAuthenticationDomainParameterInfo> chipAuthenticationDomainParameterInfoList = new ArrayList(3);
    List<ChipAuthenticationInfo> chipAuthenticationInfoList = new ArrayList(3);
    List<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfoList = new ArrayList(3);
    private byte[] encodedData = null;
    List<PaceDomainParameterInfo> paceDomainParameterInfoList = new ArrayList(3);
    List<PaceInfo> paceInfoList = new ArrayList(3);
    List<PrivilegedTerminalInfo> privilegedTerminalInfoList = new ArrayList(1);
    List<TerminalAuthenticationInfo> terminalAuthenticationInfoList = new ArrayList(3);

    public void decode(byte[] encodedData) throws IOException {
        this.encodedData = encodedData;
        ASN1Set securityInfos = (ASN1Set) ASN1Object.fromByteArray(encodedData);
        int anzahlObjekte = securityInfos.size();
        DERSequence[] securityInfo = new DERSequence[anzahlObjekte];
        for (int i = 0; i < anzahlObjekte; i++) {
            securityInfo[i] = (DERSequence) securityInfos.getObjectAt(i);
            DERObjectIdentifier oid = (DERObjectIdentifier) securityInfo[i].getObjectAt(0);
            switch (oid.toString().charAt(18)) {
                case '1':
                    this.chipAuthenticationPublicKeyInfoList.add(new ChipAuthenticationPublicKeyInfo(securityInfo[i]));
                    break;
                case '2':
                    this.terminalAuthenticationInfoList.add(new TerminalAuthenticationInfo(securityInfo[i]));
                    break;
                case '3':
                    if (oid.toString().length() != 23) {
                        this.chipAuthenticationDomainParameterInfoList.add(new ChipAuthenticationDomainParameterInfo(securityInfo[i]));
                        break;
                    } else {
                        this.chipAuthenticationInfoList.add(new ChipAuthenticationInfo(securityInfo[i]));
                        break;
                    }
                case '4':
                    if (oid.toString().length() != 23) {
                        this.paceDomainParameterInfoList.add(new PaceDomainParameterInfo(securityInfo[i]));
                        break;
                    } else {
                        this.paceInfoList.add(new PaceInfo(securityInfo[i]));
                        break;
                    }
                case '6':
                    this.cardInfoLocatorList.add(new CardInfoLocator(securityInfo[i]));
                    break;
                case '8':
                    this.privilegedTerminalInfoList.add(new PrivilegedTerminalInfo(securityInfo[i]));
                    break;
                default:
                    break;
            }
        }
    }

    public String toString() {
        String summary = "------------------\nSecurityInfos object contains\n" + this.terminalAuthenticationInfoList.size() + " TerminalAuthenticationInfo objects \n" + this.chipAuthenticationInfoList.size() + " ChipAuthenticationInfo objects \n" + this.chipAuthenticationDomainParameterInfoList.size() + " ChipAuthenticationDomainParameterInfo objects \n" + this.chipAuthenticationPublicKeyInfoList.size() + " ChipAuthenticationPublicKeyInfo objects \n" + this.paceInfoList.size() + " PaceInfo objects \n" + this.paceDomainParameterInfoList.size() + " PaceDomainParameterInfo objects \n" + this.cardInfoLocatorList.size() + " CardInfoLocator objects \n" + this.privilegedTerminalInfoList.size() + " PrivilegedTerminalInfo objects\n------------------\n";
        for (TerminalAuthenticationInfo item : this.terminalAuthenticationInfoList) {
            summary = summary + item.toString();
        }
        for (ChipAuthenticationInfo item2 : this.chipAuthenticationInfoList) {
            summary = summary + item2.toString();
        }
        for (ChipAuthenticationDomainParameterInfo item3 : this.chipAuthenticationDomainParameterInfoList) {
            summary = summary + item3.toString();
        }
        for (ChipAuthenticationPublicKeyInfo item4 : this.chipAuthenticationPublicKeyInfoList) {
            summary = summary + item4.toString();
        }
        for (PaceInfo item5 : this.paceInfoList) {
            summary = summary + item5.toString();
        }
        for (PaceDomainParameterInfo item6 : this.paceDomainParameterInfoList) {
            summary = summary + item6.toString();
        }
        for (CardInfoLocator item7 : this.cardInfoLocatorList) {
            summary = summary + item7.toString();
        }
        for (PrivilegedTerminalInfo item8 : this.privilegedTerminalInfoList) {
            summary = summary + item8.toString();
        }
        return summary;
    }

    public byte[] getBytes() {
        return this.encodedData;
    }

    public List<PaceInfo> getPaceInfoList() {
        return this.paceInfoList;
    }

    public List<TerminalAuthenticationInfo> getTerminalAuthenticationInfoList() {
        return this.terminalAuthenticationInfoList;
    }

    public List<ChipAuthenticationInfo> getChipAuthenticationInfoList() {
        return this.chipAuthenticationInfoList;
    }

    public List<CardInfoLocator> getCardInfoLocatorList() {
        return this.cardInfoLocatorList;
    }

    public List<ChipAuthenticationDomainParameterInfo> getChipAuthenticationDomainParameterInfoList() {
        return this.chipAuthenticationDomainParameterInfoList;
    }

    public List<PaceDomainParameterInfo> getPaceDomainParameterInfoList() {
        return this.paceDomainParameterInfoList;
    }

    public List<ChipAuthenticationPublicKeyInfo> getChipAuthenticationPublicKeyInfoList() {
        return this.chipAuthenticationPublicKeyInfoList;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (TerminalAuthenticationInfo item : this.terminalAuthenticationInfoList) {
            v.add(item);
        }
        for (ChipAuthenticationInfo item2 : this.chipAuthenticationInfoList) {
            v.add(item2);
        }
        for (ChipAuthenticationDomainParameterInfo item3 : this.chipAuthenticationDomainParameterInfoList) {
            v.add(item3);
        }
        for (ChipAuthenticationPublicKeyInfo item4 : this.chipAuthenticationPublicKeyInfoList) {
            v.add(item4);
        }
        for (PaceInfo item5 : this.paceInfoList) {
            v.add(item5);
        }
        for (PaceDomainParameterInfo item6 : this.paceDomainParameterInfoList) {
            v.add(item6);
        }
        for (CardInfoLocator item7 : this.cardInfoLocatorList) {
            v.add(item7);
        }
        for (PrivilegedTerminalInfo item8 : this.privilegedTerminalInfoList) {
            v.add(item8);
        }
        return new DERSet(v);
    }
}
