/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 * Original code from https://www.dnielectronico.es/descargas/Apps/Android_DGPApp_LECTURA.rar
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.TextView;

import ocr.document.tardo.documentocr.R;

public class DNIeErrorActivity extends Activity {

	private String mError;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		this.requestWindowFeature(Window.FEATURE_NO_TITLE);
		setContentView(R.layout.activity_dnie_error);

		Bundle extras = getIntent().getExtras();
		if(extras != null) {
			mError = extras.getString("ERROR_MSG");
			TextView tvloc = findViewById(R.id.infoResult);
			tvloc.setText(mError);
		}

		Button btnNFCBack = (Button)findViewById(R.id.btnBack);
		btnNFCBack.setOnClickListener(new View.OnClickListener() {
			public void onClick(View v) {
			Intent intent = new Intent(DNIeErrorActivity.this, DNIeCANActivity.class);
			startActivity(intent);
			finish();
			}
		});
	}
}