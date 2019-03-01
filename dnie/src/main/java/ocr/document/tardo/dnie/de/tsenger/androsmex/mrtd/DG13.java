package de.tsenger.androsmex.mrtd;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.util.ASN1Dump;

public class DG13 {
    public static final int ADDR_DIRECCION = 1;
    public static final int ADDR_LOCALIDAD = 2;
    public static final int ADDR_PROVINCIA = 3;
    private String actual_direccion = "";
    private String actual_poblacion = "";
    private String actual_provincia = "";
    private Date date = null;
    private String docNumber = "";
    private String expiration_date = "";
    private String nacim_date = "";
    private String nacim_poblacion = "";
    private String nacim_provincia = "";
    private String name = "";
    private String name_father = "";
    private String name_mother = "";
    private byte[] rawData;
    private SimpleDateFormat sdEUFullFormat = new SimpleDateFormat("ddMMyyyy");
    private SimpleDateFormat sdFormat = new SimpleDateFormat("yyMMdd");
    private SimpleDateFormat sdFullFormat = new SimpleDateFormat("yyyyMMdd");
    private String surname1 = "";
    private String surname2 = "";

    public DG13(byte[] rawBytes) {
        this.rawData = (byte[]) rawBytes.clone();
        try {
            DERObject obj = new ASN1InputStream(rawBytes).readObject();
            System.out.println(ASN1Dump.dumpAsString(obj));
            ASN1Dump.dumpAsString(obj);
            ASN1Sequence seq = (ASN1Sequence) ((DERApplicationSpecific) obj).getObject();
            seq.getObjectAt(0).toString();
            this.surname1 = seq.getObjectAt(0).toString();
            this.surname2 = seq.getObjectAt(1).toString();
            this.name = seq.getObjectAt(2).toString();
            this.docNumber = seq.getObjectAt(3).toString();
            this.nacim_date = seq.getObjectAt(4).toString();
            this.nacim_poblacion = seq.getObjectAt(9).toString();
            this.nacim_provincia = seq.getObjectAt(10).toString();
            this.expiration_date = seq.getObjectAt(6).toString();
            this.name_father = seq.getObjectAt(11).toString().substring(0, seq.getObjectAt(11).toString().indexOf("/") - 1);
            this.name_mother = seq.getObjectAt(11).toString().substring(seq.getObjectAt(11).toString().indexOf("/") + 2, seq.getObjectAt(11).toString().length());
            this.actual_direccion = seq.getObjectAt(12).toString();
            this.actual_poblacion = seq.getObjectAt(13).toString();
            this.actual_provincia = seq.getObjectAt(15).toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getName() {
        return this.name;
    }

    public String getSurName1() {
        return this.surname1;
    }

    public String getSurName2() {
        return this.surname2;
    }

    public String getPersonalNumber() {
        return this.docNumber;
    }

    public String getExpirationDate() {
        try {
            this.date = this.sdEUFullFormat.parse(this.expiration_date.replace(" ", ""));
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return DateFormat.getDateInstance(2).format(this.date);
    }

    public byte[] getBytes() {
        return this.rawData;
    }

    public String getFatherName() {
        return this.name_father;
    }

    public String getMotherName() {
        return this.name_mother;
    }

    public String getBirthDate() {
        try {
            this.date = this.sdEUFullFormat.parse(this.nacim_date.replace(" ", ""));
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return DateFormat.getDateInstance(2).format(this.date);
    }

    public String getBirthPopulation() {
        return this.nacim_poblacion;
    }

    public String getBirthProvince() {
        return this.nacim_provincia;
    }

    public String getActualAddress() {
        return this.actual_direccion;
    }

    public String getActualPopulation() {
        return this.actual_poblacion;
    }

    public String getActualProvince() {
        return this.actual_provincia;
    }
}
