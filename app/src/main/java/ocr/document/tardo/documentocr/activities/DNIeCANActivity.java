/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 * Original code from https://www.dnielectronico.es/descargas/Apps/Android_DGPApp_LECTURA.rar
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
*/
package ocr.document.tardo.documentocr.activities;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import de.tsenger.androsmex.data.CANSpecDO;
import ocr.document.tardo.documentocr.AppMain;
import ocr.document.tardo.documentocr.R;

public class DNIeCANActivity extends Activity implements OnClickListener {

	private static final int REQ_EDIT_NEW_CAN 	= 1;
	private static final int REQ_READ_PP 		= 3;

    private EditText mEditTextCAN;

	private Context mContext = null;

	
	@Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mContext = DNIeCANActivity.this;

        this.requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.activity_dnie_can);


        final Button btnSolicitar = findViewById(R.id.btnBack);
        btnSolicitar.setOnClickListener(new OnClickListener()
        {
            public void onClick(View v) {
				Intent intent = new Intent(DNIeCANActivity.this, ReadModeActivity.class);
				startActivity(intent);
            }
        });

        mEditTextCAN = findViewById(R.id.etCAN);
        final Button ButtonStartRead = findViewById(R.id.btnStartRead);
        ButtonStartRead.setOnClickListener(this);
    }

		
	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
		setIntent(data);

		final Bundle bundle = data.getExtras();
		if (requestCode == REQ_EDIT_NEW_CAN) {
			if (resultCode == RESULT_OK) {
				try {
					if (bundle != null) {
						final CANSpecDO can = data.getExtras().getParcelable(CANSpecDO.EXTRA_CAN);
						read(can);
					} else {
						toastIt("Error!");
					}
				} catch (NullPointerException e) {
					e.printStackTrace(); // TODO: It's an error, don't hide & forget it ¬¬
				}
			}
		}
		else if (requestCode == REQ_READ_PP) {
			if (resultCode == RESULT_OK && bundle != null)
			{
				Intent i = new Intent(this, DNIeReaderActivity.class).putExtras(bundle);
				startActivityForResult(i, 1);
			}
			else if (resultCode == RESULT_CANCELED || bundle == null)
				toastIt("Error!");
		}
	}

    @Override
    public void onClick(View view) {
        if (view.getId() == R.id.btnStartRead)
        {
            if (mEditTextCAN.getText().length() != 6) {
                Toast.makeText(mContext, R.string.help_can_len, Toast.LENGTH_LONG).show();
                return;
            }

            final CANSpecDO can = new CANSpecDO(mEditTextCAN.getText().toString(), "", "");
            read(can);
        }
    }
	
	private void read(CANSpecDO b) {
		((AppMain)getApplicationContext()).setCAN(b);

		initReader();
	}

	private void initReader() {
		Intent i = new Intent(DNIeCANActivity.this, DNIeReaderActivity.class);
		startActivityForResult(i, 1);
	}
	
	private void toastIt(String msg) {
		Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
	}

}