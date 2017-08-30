package com._17od.upm.database;

import com._17od.upm.crypto.CryptoException;
import com._17od.upm.crypto.EncryptionService;

import java.io.IOException;

/**
 * Created by Dallin on 8/30/2017.
 */
public interface PersistenceStrategy
{
    byte[] load() throws IOException;
    void save(byte[] database, EncryptionService encryptionService) throws IOException, CryptoException;
}
