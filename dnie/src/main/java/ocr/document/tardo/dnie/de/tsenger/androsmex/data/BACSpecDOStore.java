package de.tsenger.androsmex.data;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import java.util.Vector;

public class BACSpecDOStore {
    private static final String COL_DOB = "DOB";
    private static final String COL_DOC_NUM = "DOCNUM";
    private static final String COL_DOE = "DOE";
    private static final int DATABASE_VERSION = 1;
    private static final String DB_NAME = "mrtd.db";
    private static final String TABLE_BAC = "bac";
    private DatabaseHelper helper;

    private static class DatabaseHelper extends SQLiteOpenHelper {
        DatabaseHelper(Context context) {
            super(context, BACSpecDOStore.DB_NAME, null, 1);
        }

        public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE bac (DOCNUM STRING PRIMARY KEY,DOB STRING,DOE STRING);");
        }

        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            db.execSQL("DROP TABLE IF EXISTS bac");
            onCreate(db);
        }
    }

    public BACSpecDOStore(Context context) {
        this.helper = new DatabaseHelper(context);
    }

    private boolean has(String docNumber) {
        Cursor c = this.helper.getWritableDatabase().query(TABLE_BAC, null, "DOCNUM='" + docNumber + "'", null, null, null, null);
        int count = c.getCount();
        c.close();
        return count > 0;
    }

    public Vector<BACSpecDO> getAll() {
        Cursor c = this.helper.getWritableDatabase().query(TABLE_BAC, null, null, null, null, null, null);
        Vector<BACSpecDO> result = new Vector();
        if (c.getCount() > 0) {
            c.moveToFirst();
            do {
                result.add(new BACSpecDO(getDocumentNumber(c), getDateOfBirth(c), getDateOfExpiry(c)));
            } while (c.moveToNext());
        }
        c.close();
        return result;
    }

    private String getDocumentNumber(Cursor c) {
        return c.getString(c.getColumnIndex(COL_DOC_NUM));
    }

    private String getDateOfBirth(Cursor c) {
        return c.getString(c.getColumnIndex(COL_DOB));
    }

    private String getDateOfExpiry(Cursor c) {
        return c.getString(c.getColumnIndex(COL_DOE));
    }

    public void save(BACSpecDO b) {
        if (has(b.getDocumentNumber())) {
            update(b);
        } else {
            insert(b);
        }
    }

    private void insert(BACSpecDO b) {
        SQLiteDatabase db = this.helper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COL_DOC_NUM, b.getDocumentNumber());
        values.put(COL_DOB, b.getDateOfBirth());
        values.put(COL_DOE, b.getDateOfExpiry());
        db.insert(TABLE_BAC, null, values);
        db.close();
    }

    private void update(BACSpecDO b) {
        SQLiteDatabase db = this.helper.getWritableDatabase();
        String where = "DOCNUM='" + b.getDocumentNumber() + "'";
        ContentValues values = new ContentValues();
        values.put(COL_DOC_NUM, b.getDocumentNumber());
        values.put(COL_DOB, b.getDateOfBirth());
        values.put(COL_DOE, b.getDateOfExpiry());
        db.update(TABLE_BAC, values, where, null);
        db.close();
    }

    public void delete(BACSpecDO b) {
        SQLiteDatabase db = this.helper.getWritableDatabase();
        db.delete(TABLE_BAC, "DOCNUM='" + b.getDocumentNumber() + "'", null);
        db.close();
    }
}
