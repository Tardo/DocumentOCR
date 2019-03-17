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

    private Button mBtnOCR;
    private Button mBtnNFC;
    private Button mBtnLogout;
    private ImageButton mBtnInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_read_mode);

        mBtnOCR = findViewById(R.id.btnOCR);
        mBtnNFC = findViewById(R.id.btnNFC);
        mBtnLogout = findViewById(R.id.btnCloseApp);
        mBtnInfo = findViewById(R.id.btnInfo);

        mBtnOCR.setAlpha(0.0f);
        mBtnOCR.setTranslationX(-100);
        mBtnOCR.animate().alpha(1.0f).translationX(0).setStartDelay(250);
        mBtnNFC.setAlpha(0.0f);
        mBtnNFC.setTranslationX(100);
        mBtnNFC.animate().alpha(1.0f).translationX(0).setStartDelay(250);
        mBtnLogout.setTranslationY(100);
        mBtnLogout.animate().alpha(1.0f).translationY(0).setStartDelay(250);

        mBtnOCR.setOnClickListener(this);
        mBtnNFC.setOnClickListener(this);
        mBtnLogout.setOnClickListener(this);
        mBtnInfo.setOnClickListener(this);
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
                NfcManager manager = (NfcManager) getSystemService(NFC_SERVICE);
                NfcAdapter adapter = manager.getDefaultAdapter();
                if (null != adapter && adapter.isEnabled()) {
                    Intent intent = new Intent(ReadModeActivity.this, DNIeCANActivity.class);
                    startActivity(intent);
                } else {
                    showToast(getString(R.string.error_disabled_nfc));
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
        if (activity != null) {
            activity.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(activity, text, Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

}