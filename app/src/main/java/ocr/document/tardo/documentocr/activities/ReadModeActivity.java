/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.Toast;

import ocr.document.tardo.documentocr.R;

public class ReadModeActivity extends Activity implements OnClickListener {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_read_mode);

        final Button ButtonOCR = findViewById(R.id.btnOCR);
        final Button ButtonNFC = findViewById(R.id.btnNFC);
        final Button ButtonLogout = findViewById(R.id.btnCloseApp);
        final ImageButton ButtonInfo = findViewById(R.id.btnInfo);

        ButtonOCR.setAlpha(0.0f);
        ButtonOCR.setTranslationX(-100);
        ButtonOCR.animate().alpha(1.0f).translationX(0).setStartDelay(250);
        ButtonNFC.setAlpha(0.0f);
        ButtonNFC.setTranslationX(100);
        ButtonNFC.animate().alpha(1.0f).translationX(0).setStartDelay(250);
        ButtonLogout.setTranslationY(100);
        ButtonLogout.animate().alpha(1.0f).translationY(0).setStartDelay(250);

        ButtonOCR.setOnClickListener(this);
        ButtonNFC.setOnClickListener(this);
        ButtonLogout.setOnClickListener(this);
        ButtonInfo.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btnOCR) {
            PackageManager pm = getPackageManager();
            if (pm.hasSystemFeature(PackageManager.FEATURE_CAMERA)) {
                Intent intent = new Intent(ReadModeActivity.this, OCRBReaderActivity.class);
                startActivity(intent);
            } else {
                showToast(getString(R.string.error_no_camera));
            }
        }
        else if (v.getId() == R.id.btnNFC) {
            PackageManager pm = getPackageManager();

            if (pm.hasSystemFeature(PackageManager.FEATURE_NFC)) {
                try {
                    NfcManager manager = (NfcManager) getSystemService(NFC_SERVICE);
                    NfcAdapter adapter = manager.getDefaultAdapter();
                    if (null != adapter && adapter.isEnabled()) {
                        Intent intent = new Intent(ReadModeActivity.this, DNIeCANActivity.class);
                        startActivity(intent);
                    } else {
                        showToast(getString(R.string.error_disabled_nfc));
                    }
                } catch (NullPointerException e) {
                    showToast(getString(R.string.error_no_nfc));
                }
            } else {
                showToast(getString(R.string.error_no_nfc));
            }
        }
        else if (v.getId() == R.id.btnCloseApp) {
            Intent intent = new Intent(ReadModeActivity.this, LoginActivity.class);
            intent.putExtra(LoginActivity.PARAM_LOGOUT, true);
            startActivity(intent);
            finish();
        }
        else if (v.getId() == R.id.btnInfo) {
            Intent intent = new Intent(ReadModeActivity.this, InfoActivity.class);
            startActivity(intent);
        }
    }

    private void showToast(final String text) {
        final Activity activity = this;
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(activity, text, Toast.LENGTH_SHORT).show();
            }
        });
    }

}