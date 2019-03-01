package es.inteco.labs.android.utils;

import android.os.Environment;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public final class FileUtils {
    private FileUtils() {
    }

    public static File writeDownloadFile(String prefix, String extension, InputStream dataStream) throws IOException {
        File dest = File.createTempFile(prefix, "." + extension, Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS));
        writeFile(dest, dataStream);
        return dest;
    }

    public static File writeToSDFile(String fileUrl, InputStream dataStream) throws IOException, FileNotFoundException {
        File dest = new File(Environment.getExternalStorageDirectory().getAbsolutePath() + File.separator + fileUrl);
        if (dest.exists()) {
            dest.delete();
        }
        writeFile(dest, dataStream);
        return dest;
    }

    public static File writeToSDFile(String fileUrl, byte[] data) throws IOException, FileNotFoundException {
        File dest = new File(Environment.getExternalStorageDirectory().getAbsolutePath() + File.separator + fileUrl);
        if (dest.exists()) {
            dest.delete();
        }
        writeFile(dest, data);
        return dest;
    }

    private static void writeFile(File outputFile, byte[] inputData) throws IOException {
        Throwable th;
        FileOutputStream fos = null;
        try {
            FileOutputStream fos2 = new FileOutputStream(outputFile);
            try {
                fos2.write(inputData);
                fos2.flush();
                fos2.close();
                if (fos2 != null) {
                    fos2.close();
                }
            } catch (Throwable th2) {
                th = th2;
                fos = fos2;
                if (fos != null) {
                    fos.close();
                }
                throw th;
            }
        } catch (Throwable th3) {
            th = th3;
            if (fos != null) {
                fos.close();
            }
            throw th;
        }
    }

    private static void writeFile(File outputFile, InputStream inputStreamData) throws IOException {
        Throwable th;
        byte[] bufferReader = new byte[512];
        FileOutputStream fos = null;
        try {
            FileOutputStream fos2 = new FileOutputStream(outputFile);
            try {
                int leidos = inputStreamData.read(bufferReader);
                while (leidos > -1) {
                    fos2.write(bufferReader, 0, leidos);
                    leidos = inputStreamData.read(bufferReader);
                }
                fos2.flush();
                if (fos2 != null) {
                    fos2.close();
                }
            } catch (Throwable th2) {
                th = th2;
                fos = fos2;
                if (fos != null) {
                    fos.close();
                }
                throw th;
            }
        } catch (Throwable th3) {
            th = th3;
            if (fos != null) {
                fos.close();
            }
            throw th;
        }
    }
}
