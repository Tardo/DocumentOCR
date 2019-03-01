package de.tsenger.androsmex.data;

import android.graphics.Bitmap;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;

public class PassportDO implements Parcelable {
    public static final Creator<PassportDO> CREATOR = new C00681();
    public static final String EXTRA_PASSPORTDO = "EXTRA_PASSPORTDO";
    private String dateOfBirth;
    private String dateOfExpiry;
    private String documentCode;
    private String documentNumber;
    private Bitmap face;
    private String gender;
    private String issuingState;
    private String nationality;
    private String personalNumber;
    private String primaryIdentifier;
    private String[] secondaryIdentifiers;

    /* renamed from: de.tsenger.androsmex.data.PassportDO$1 */
    static class C00681 implements Creator<PassportDO> {
        C00681() {
        }

        public PassportDO createFromParcel(Parcel in) {
            return new PassportDO(in);
        }

        public PassportDO[] newArray(int size) {
            return new PassportDO[size];
        }
    }

    public Bitmap getFace() {
        return this.face;
    }

    public void setFace(Bitmap face) {
        this.face = face;
    }

    public String getDocumentCode() {
        return this.documentCode;
    }

    public void setDocumentCode(String documentCode) {
        this.documentCode = documentCode;
    }

    public String getIssuingState() {
        return this.issuingState;
    }

    public void setIssuingState(String issuingState) {
        this.issuingState = issuingState;
    }

    public String getPrimaryIdentifier() {
        return this.primaryIdentifier;
    }

    public void setPrimaryIdentifier(String primaryIdentifier) {
        this.primaryIdentifier = primaryIdentifier;
    }

    public String[] getSecondaryIdentifiers() {
        return this.secondaryIdentifiers;
    }

    public void setSecondaryIdentifiers(String[] secondaryIdentifiers) {
        this.secondaryIdentifiers = secondaryIdentifiers;
    }

    public String getNationality() {
        return this.nationality;
    }

    public void setNationality(String nationality) {
        this.nationality = nationality;
    }

    public String getDocumentNumber() {
        return this.documentNumber;
    }

    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }

    public String getPersonalNumber() {
        return this.personalNumber;
    }

    public void setPersonalNumber(String personalNumber) {
        this.personalNumber = personalNumber;
    }

    public String getDateOfBirth() {
        return this.dateOfBirth;
    }

    public void setDateOfBirth(String dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public String getGender() {
        return this.gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public String getDateOfExpiry() {
        return this.dateOfExpiry;
    }

    public void setDateOfExpiry(String dateOfExpiry) {
        this.dateOfExpiry = dateOfExpiry;
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel out, int flags) {
        out.writeString(this.documentCode);
        out.writeString(this.issuingState);
        out.writeString(this.primaryIdentifier);
        out.writeInt(this.secondaryIdentifiers.length);
        out.writeStringArray(this.secondaryIdentifiers);
        out.writeString(this.nationality);
        out.writeString(this.documentNumber);
        out.writeString(this.personalNumber);
        out.writeString(this.dateOfBirth);
        out.writeString(this.gender);
        out.writeString(this.dateOfExpiry);
        out.writeParcelable(this.face, flags);
    }

    private PassportDO(Parcel in) {
        this.documentCode = in.readString();
        this.issuingState = in.readString();
        this.primaryIdentifier = in.readString();
        this.secondaryIdentifiers = new String[in.readInt()];
        in.readStringArray(this.secondaryIdentifiers);
        this.nationality = in.readString();
        this.documentNumber = in.readString();
        this.personalNumber = in.readString();
        this.dateOfBirth = in.readString();
        this.gender = in.readString();
        this.dateOfExpiry = in.readString();
        this.face = (Bitmap) in.readParcelable(null);
    }
}
