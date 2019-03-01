package de.tsenger.androsmex;

import android.app.Activity;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.text.TextWatcher;
import android.widget.Button;
import android.widget.TextView;
import de.tsenger.androsmex.asn1.PaceInfo;
import de.tsenger.androsmex.asn1.SecurityInfos;
import de.tsenger.androsmex.iso7816.FileAccess;
import de.tsenger.androsmex.pace.PaceOperator;
import de.tsenger.androsmex.tools.HexString;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AndroSmexStartseite extends Activity {
    private static final Logger asLogger = Logger.getLogger("AndroSmex");
    Button buttonStart = null;
    TextView ergebnisText = null;
    IsoDepCardHandler idch = null;
    SharedPreferences prefs = null;
    PaceOperator ptag = null;
    OnSharedPreferenceChangeListener spListener = null;
    TextWatcher tWatcher = null;

    private SecurityInfos getSecurityInfosFromCardAccess() {
        Exception e1;
        SecurityInfos si = null;
        try {
            byte[] efcaBytes = new FileAccess(this.idch).getFile(new byte[]{(byte) 1, (byte) 28});
            SecurityInfos si2 = new SecurityInfos();
            try {
                si2.decode(efcaBytes);
                asLogger.log(Level.FINE, "Content of EF.CardAccess:\n" + HexString.bufferToHex(efcaBytes));
                return si2;
            } catch (Exception e) {
                e1 = e;
                si = si2;
                asLogger.log(Level.WARNING, "getSecurityInfosFromCardAccess() throws exception", e1);
                return si;
            }
        } catch (Exception e2) {
            e1 = e2;
            asLogger.log(Level.WARNING, "getSecurityInfosFromCardAccess() throws exception", e1);
            return si;
        }
    }

    private void performPACE(String pin) {
        SecurityInfos si = getSecurityInfosFromCardAccess();
        this.ptag = new PaceOperator(this.idch, getApplicationContext());
        this.ptag.setAuthTemplate((PaceInfo) si.getPaceInfoList().get(0), pin, asLogger, this.prefs);
        asLogger.log(Level.INFO, "Start PACE");
        this.ptag.execute((Void[]) null);
    }
}
