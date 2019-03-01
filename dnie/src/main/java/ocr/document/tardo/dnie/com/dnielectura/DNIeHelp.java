package com.dnielectura;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

public class DNIeHelp extends Activity {

    /* renamed from: com.dnielectura.DNIeHelp$1 */
    class C00101 implements OnClickListener {
        C00101() {
        }

        public void onClick(View v) {
            DNIeHelp.this.onBackPressed();
        }
    }

    /* renamed from: com.dnielectura.DNIeHelp$2 */
    class C00112 implements OnClickListener {
        C00112() {
        }

        public void onClick(View v) {
            DNIeHelp.this.startActivity(new Intent(DNIeHelp.this, DNIeCanSelection.class));
        }
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        setContentView(C0041R.layout.help);
        Typeface typeface = Typeface.createFromAsset(getAssets(), "fonts/HelveticaNeue.ttf");
        TableLayout miTabla = (TableLayout) findViewById(C0041R.id.help_table);
        int j = miTabla.getChildCount();
        for (int i = 0; i < j; i++) {
            View view = miTabla.getChildAt(i);
            if (view instanceof TableRow) {
                TableRow row = (TableRow) view;
                for (int idx = 0; idx < row.getChildCount(); idx++) {
                    View viewText = row.getChildAt(idx);
                    if (viewText instanceof TextView) {
                        ((TextView) viewText).setTypeface(typeface);
                    }
                }
            }
        }
        ((Button) findViewById(C0041R.id.butDataVolver)).setOnClickListener(new C00101());
        ((Button) findViewById(C0041R.id.butDataLeer)).setOnClickListener(new C00112());
    }
}
