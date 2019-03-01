package de.tsenger.androsmex;

import android.app.Activity;
import android.widget.TextView;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

public class TextViewHandler extends Handler {
    private Activity activity = null;
    private TextView tView = null;

    public TextViewHandler(Activity activity, TextView tView) {
        this.activity = activity;
        this.tView = tView;
    }

    public void close() {
    }

    public void flush() {
    }

    public void publish(LogRecord arg0) {
        final LogRecord t1 = arg0;
        this.activity.runOnUiThread(new Runnable() {
            public void run() {
                TextViewHandler.this.tView.append(t1.getMessage() + "\n");
            }
        });
    }
}
