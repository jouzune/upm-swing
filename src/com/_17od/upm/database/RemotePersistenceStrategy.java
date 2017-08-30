package com._17od.upm.database;

import com._17od.upm.crypto.CryptoException;
import com._17od.upm.crypto.EncryptionService;
import com._17od.upm.transport.RESTTransport;
import com._17od.upm.transport.TransportException;

import java.io.IOException;

/**
 * Created by Dallin on 8/30/2017.
 */
public class RemotePersistenceStrategy implements PersistenceStrategy
{
    String url, username, password;
    RESTTransport transport;
    public RemotePersistenceStrategy(String url, String username, String password) {
        this.url = url;
        this.username = username;
        this.password = password;
        transport = new RESTTransport();
    }
    @Override
    public byte[] load() throws IOException
    {
        try {
            return transport.get(url, username, password);
        } catch (TransportException e) {
            throw new IOException(e.getMessage());
        }
    }

    @Override
    public void save(byte[] database, EncryptionService encryptionService) throws IOException, CryptoException
    {
        System.out.println("-----------------------------------------------");
        System.out.println("ready to save to the database.");
        System.out.println("URL: " + url);
        System.out.println("Username: " + username);
        System.out.println("Password: " + password);
        try {
            transport.post(url, database, username, password);
        } catch (TransportException e) {
            throw new IOException(e.getMessage());
        }
        System.out.println();
    }
}
