package de.tsenger.androsmex.data;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import java.text.SimpleDateFormat;
import java.util.Date;

public class BACSpecDO implements Parcelable {
    public static final Creator<BACSpecDO> CREATOR = new C00661();
    public static final String EXTRA_BAC = "EXTRA_BAC";
    public static final String EXTRA_BAC_COL = "EXTRA_BAC_COL";
    public static final SimpleDateFormat SDF = new SimpleDateFormat("yyMMdd");
    private String dateOfBirth;
    private String dateOfExpiry;
    private String documentNumber;

    /* renamed from: de.tsenger.androsmex.data.BACSpecDO$1 */
    static class C00661 implements Creator<BACSpecDO> {
        C00661() {
        }

        public BACSpecDO createFromParcel(Parcel in) {
            return new BACSpecDO(in);
        }

        public BACSpecDO[] newArray(int size) {
            return new BACSpecDO[size];
        }
    }

    public BACSpecDO(String documentNumber, String dateOfBirth, String dateOfExpiry) {
        this.documentNumber = documentNumber.trim();
        this.dateOfBirth = dateOfBirth;
        this.dateOfExpiry = dateOfExpiry;
    }

    public BACSpecDO(String documentNumber, Date dateOfBirth, Date dateOfExpiry) {
        this(documentNumber, SDF.format(dateOfBirth), SDF.format(dateOfExpiry));
    }

    public String getDocumentNumber() {
        return this.documentNumber;
    }

    public String getDateOfBirth() {
        return this.dateOfBirth;
    }

    public String getDateOfExpiry() {
        return this.dateOfExpiry;
    }

    public String toString() {
        return this.documentNumber + ", " + this.dateOfBirth + ", " + this.dateOfExpiry;
    }

    public boolean equals(Object o) {
        boolean z = true;
        if (o == null || !o.getClass().equals(getClass())) {
            return false;
        }
        if (o == this) {
            return true;
        }
        BACSpecDO previous = (BACSpecDO) o;
        if (!(this.documentNumber.equals(previous.documentNumber) && this.dateOfBirth.equals(previous.dateOfBirth) && this.dateOfExpiry.equals(previous.dateOfExpiry))) {
            z = false;
        }
        return z;
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel out, int flags) {
        out.writeString(this.documentNumber);
        out.writeString(this.dateOfBirth);
        out.writeString(this.dateOfExpiry);
    }

    private BACSpecDO(Parcel in) {
        this.documentNumber = in.readString();
        this.dateOfBirth = in.readString();
        this.dateOfExpiry = in.readString();
    }
}
