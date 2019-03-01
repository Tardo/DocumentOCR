package de.tsenger.androsmex.data;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;

public class CANSpecDO implements Parcelable {
    public static final Creator<CANSpecDO> CREATOR = new C00671();
    public static final String EXTRA_CAN = "EXTRA_CAN";
    public static final String EXTRA_CAN_COL = "EXTRA_CAN_COL";
    private String canNumber;
    private String userName;
    private String userNif;

    /* renamed from: de.tsenger.androsmex.data.CANSpecDO$1 */
    static class C00671 implements Creator<CANSpecDO> {
        C00671() {
        }

        public CANSpecDO createFromParcel(Parcel in) {
            return new CANSpecDO(in);
        }

        public CANSpecDO[] newArray(int size) {
            return new CANSpecDO[size];
        }
    }

    public CANSpecDO(String canNumber, String userName, String userNif) {
        String can6digitos = canNumber.trim();
        while (can6digitos.length() < 6) {
            can6digitos = "0" + can6digitos;
        }
        this.canNumber = can6digitos;
        this.userName = userName.trim();
        this.userNif = userNif.trim();
    }

    public String getCanNumber() {
        return this.canNumber;
    }

    public String getUserName() {
        return this.userName;
    }

    public String getUserNif() {
        return this.userNif;
    }

    public String toString() {
        return "CAN: " + this.canNumber + ", " + this.userName + ", " + this.userNif;
    }

    public boolean equals(Object o) {
        if (o == null || !o.getClass().equals(getClass())) {
            return false;
        }
        if (o == this) {
            return true;
        }
        return this.canNumber.equals(((CANSpecDO) o).canNumber);
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel out, int flags) {
        out.writeString(this.canNumber);
        out.writeString(this.userName);
        out.writeString(this.userNif);
    }

    private CANSpecDO(Parcel in) {
        this.canNumber = in.readString();
        this.userName = in.readString();
        this.userNif = in.readString();
    }
}
