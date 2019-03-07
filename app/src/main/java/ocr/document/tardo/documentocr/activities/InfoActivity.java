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

import ocr.document.tardo.documentocr.R;

public class InfoActivity extends Activity implements OnClickListener {

    private Button mBtnBack;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_info);

        mBtnBack = findViewById(R.id.btnBack);
        mBtnBack.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btnBack) {
            Intent intent = new Intent(InfoActivity.this, ReadModeActivity.class);
            startActivity(intent);
            finish();
        }
    }

}