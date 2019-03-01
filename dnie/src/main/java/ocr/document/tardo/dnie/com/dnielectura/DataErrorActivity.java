package com.dnielectura;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class DataErrorActivity extends Activity {
    private String mError;

    /* renamed from: com.dnielectura.DataErrorActivity$1 */
    class C00251 implements OnClickListener {
        C00251() {
        }

        public void onClick(View v) {
            DataErrorActivity.this.startActivity(new Intent(DataErrorActivity.this, DNIeCanSelection.class));
        }
    }

    /* renamed from: com.dnielectura.DataErrorActivity$2 */
    class C00262 implements OnClickListener {
        C00262() {
        }

        public void onClick(View v) {
            DataErrorActivity.this.startActivityForResult(new Intent(DataErrorActivity.this, DataConfiguration.class), 1);
        }
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        setContentView(C0041R.layout.data_error);
        Typeface typeface = Typeface.createFromAsset(getAssets(), "fonts/HelveticaNeue.ttf");
        ((TextView) findViewById(C0041R.id.result1)).setTypeface(typeface);
        ((TextView) findViewById(C0041R.id.resultinfo)).setTypeface(typeface);
        Bundle extras = getIntent().getExtras();
        if (extras != null) {
            this.mError = extras.getString("ERROR_MSG");
            ((TextView) findViewById(C0041R.id.resultinfo)).setText(this.mError);
        }
        ((Button) findViewById(C0041R.id.butVolver)).setOnClickListener(new C00251());
        ((Button) findViewById(C0041R.id.butConfigurar)).setOnClickListener(new C00262());
    }
}
