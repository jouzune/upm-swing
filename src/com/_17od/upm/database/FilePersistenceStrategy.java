package com._17od.upm.database;

import com._17od.upm.crypto.CryptoException;
import com._17od.upm.crypto.EncryptionService;

import java.io.*;

/**
 * Created by Dallin on 8/30/2017.
 */
public class FilePersistenceStrategy implements PersistenceStrategy
{
    private File databaseFile;
    public FilePersistenceStrategy(File databaseFile) {
        this.databaseFile = databaseFile;
    }

    @Override
    public byte[] load() throws IOException {
        InputStream is;
        try {
            is = new FileInputStream(databaseFile);
        } catch (IOException e) {
            throw new IOException("There was a problem with opening the file", e);
        }

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int) databaseFile.length()];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;

        try {
            while (offset < bytes.length
                    && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
                offset += numRead;
            }

            // Ensure all the bytes have been read in
            if (offset < bytes.length) {
                throw new IOException("Could not completely read file " + databaseFile.getName());
            }
        } finally {
            is.close();
        }

        return bytes;
    }

    @Override
    public void save(byte[] database, EncryptionService encryptionService) throws IOException, CryptoException {
        FileOutputStream fos = new FileOutputStream(databaseFile);
        fos.write(database);
        fos.close();
    }
}
