/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.text.HtmlCompat;
import android.text.method.LinkMovementMethod;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

import ocr.document.tardo.documentocr.R;

public class InfoActivity extends Activity implements OnClickListener {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_info);

        final Button ButtonBack = findViewById(R.id.btnBack);
        ButtonBack.setOnClickListener(this);

        TextView linkAldaUE = findViewById(R.id.linkAldaUE);
        String linkText = "Visit <a href='https://www.aldahotels.es/ue/'>Alda Hotels</a> web page for more information";
        linkAldaUE.setText(HtmlCompat.fromHtml(linkText, HtmlCompat.FROM_HTML_MODE_LEGACY));
        linkAldaUE.setMovementMethod(LinkMovementMethod.getInstance());
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