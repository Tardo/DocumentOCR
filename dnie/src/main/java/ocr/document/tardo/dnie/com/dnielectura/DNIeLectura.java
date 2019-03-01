package com.dnielectura;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.Toast;

public class DNIeLectura extends Activity {
    public static final String SETTING_READ_DG1 = "read_DG_1";
    public static final String SETTING_READ_DG11 = "read_DG_11";
    public static final String SETTING_READ_DG13 = "read_DG_13";
    public static final String SETTING_READ_DG2 = "read_DG_2";
    public static final String SETTING_READ_DG7 = "read_DG_7";
    private boolean doubleBackToExitPressedOnce = false;

    /* renamed from: com.dnielectura.DNIeLectura$1 */
    class C00121 implements Runnable {
        C00121() {
        }

        public void run() {
            DNIeLectura.this.doubleBackToExitPressedOnce = false;
        }
    }

    public void ExecuteOption1(View view) {
        startActivityForResult(new Intent(this, DataConfiguration.class), 1);
    }

    public void ExecuteOption2(View view) {
        startActivityForResult(new Intent(this, DNIeHelp.class), 1);
    }

    public void ExecuteOption3(View view) {
        startActivityForResult(new Intent(this, DNIeCanSelection.class), 1);
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        setContentView(C0041R.layout.main);
        ((MyAppDNIELECTURA) getApplicationContext()).setStarted(true);
    }

    public void onBackPressed() {
        if (this.doubleBackToExitPressedOnce) {
            moveTaskToBack(true);
            return;
        }
        this.doubleBackToExitPressedOnce = true;
        Toast.makeText(this, "Pulse de nuevo VOLVER para salir...", 0).show();
        new Handler().postDelayed(new C00121(), 2000);
    }
}
