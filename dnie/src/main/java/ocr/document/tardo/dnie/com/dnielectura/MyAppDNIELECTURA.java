package com.dnielectura;

import android.app.Application;
import de.tsenger.androsmex.data.CANSpecDO;

public class MyAppDNIELECTURA extends Application {
    public boolean m_started;
    private CANSpecDO selectedCAN;

    public void setCAN(CANSpecDO can) {
        this.selectedCAN = can;
    }

    public CANSpecDO getCAN() {
        return this.selectedCAN;
    }

    public boolean isStarted() {
        return this.m_started;
    }

    public void setStarted(boolean state) {
        this.m_started = state;
    }
}
