package com.dnielectura;

import android.app.Activity;
import android.app.AlertDialog.Builder;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.os.Handler;
import android.os.Process;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class DNIeReader extends Activity {
    public static final String ACTION_READ = "ACTION_READ";
    private static NfcAdapter myNfcAdapter = null;
    final Runnable askForEnablingNFC = new C00151();
    private Context myContext;
    final Handler myHandler = new Handler();

    /* renamed from: com.dnielectura.DNIeReader$1 */
    class C00151 implements Runnable {

        /* renamed from: com.dnielectura.DNIeReader$1$1 */
        class C00131 implements OnClickListener {
            C00131() {
            }

            public void onClick(DialogInterface dialog, int id) {
                DNIeReader.this.startActivity(new Intent("android.settings.NFC_SETTINGS"));
            }
        }

        /* renamed from: com.dnielectura.DNIeReader$1$2 */
        class C00142 implements OnClickListener {
            C00142() {
            }

            public void onClick(DialogInterface dialog, int id) {
                dialog.cancel();
                DNIeReader.this.onBackPressed();
                DNIeReader.this.finish();
            }
        }

        C00151() {
        }

        public void run() {
            Builder alertDialogBuilder = new Builder(DNIeReader.this.myContext);
            alertDialogBuilder.setMessage(DNIeReader.this.getString(C0041R.string.nfc_disabled)).setCancelable(false).setPositiveButton(DNIeReader.this.getString(C0041R.string.nfc_configuration), new C00131());
            alertDialogBuilder.setNegativeButton(DNIeReader.this.getString(C0041R.string.psswd_dialog_cancel), new C00142());
            alertDialogBuilder.create().show();
        }
    }

    /* renamed from: com.dnielectura.DNIeReader$2 */
    class C00162 implements View.OnClickListener {
        C00162() {
        }

        public void onClick(View v) {
            DNIeReader.this.onBackPressed();
        }
    }

    /* renamed from: com.dnielectura.DNIeReader$3 */
    class C00173 implements View.OnClickListener {
        C00173() {
        }

        public void onClick(View v) {
            DNIeReader.this.startActivityForResult(new Intent(DNIeReader.this, DataConfiguration.class), 1);
        }
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        setContentView(C0041R.layout.dnie_00);
        this.myContext = this;
        myNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (((MyAppDNIELECTURA) getApplicationContext()).isStarted()) {
            getApplicationContext().getPackageManager().setComponentEnabledSetting(new ComponentName(getApplicationContext(), NFCOperationsEnc.class), 1, 1);
            ((TextView) findViewById(C0041R.id.textoproceso)).setTypeface(Typeface.createFromAsset(getAssets(), "fonts/HelveticaNeue.ttf"));
            ((Button) findViewById(C0041R.id.butVolver)).setOnClickListener(new C00162());
            ((Button) findViewById(C0041R.id.butConfigurar)).setOnClickListener(new C00173());
            return;
        }
        getApplicationContext().getPackageManager().setComponentEnabledSetting(new ComponentName(getApplicationContext(), NFCOperationsEnc.class), 2, 0);
        Process.killProcess(Process.myPid());
        System.exit(0);
    }

    public void onResume() {
        super.onResume();
        if (!myNfcAdapter.isEnabled()) {
            this.myHandler.post(this.askForEnablingNFC);
        }
    }

    protected void onStart() {
        super.onStart();
        getApplicationContext().getPackageManager().setComponentEnabledSetting(new ComponentName(getApplicationContext(), NFCOperationsEnc.class), 1, 1);
    }

    protected void onStop() {
        super.onStop();
        getApplicationContext().getPackageManager().setComponentEnabledSetting(new ComponentName(getApplicationContext(), NFCOperationsEnc.class), 2, 1);
    }

    protected void onDestroy() {
        super.onDestroy();
        getApplicationContext().getPackageManager().setComponentEnabledSetting(new ComponentName(getApplicationContext(), NFCOperationsEnc.class), 2, 1);
    }
}
