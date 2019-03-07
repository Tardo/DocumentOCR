/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.ImageButton;

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

        mBtnOCR.setOnClickListener(this);
        mBtnNFC.setOnClickListener(this);
        mBtnLogout.setOnClickListener(this);
        mBtnInfo.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btnOCR) {
            Intent intent = new Intent(ReadModeActivity.this, OCRBReaderActivity.class);
            startActivity(intent);
        }
        else if (v.getId() == R.id.btnNFC) {
            Intent intent = new Intent(ReadModeActivity.this, DNIeCANActivity.class);
            startActivity(intent);
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

}