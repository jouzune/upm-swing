/*
 * Universal Password Manager
 * Copyright (C) 2005-2013 Adrian Smith
 *
 * This file is part of Universal Password Manager.
 *
 * Universal Password Manager is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Universal Password Manager is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Universal Password Manager; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com._17od.upm.transport;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.*;
import org.apache.commons.httpclient.methods.multipart.FilePart;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.methods.multipart.Part;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;

import com._17od.upm.util.Preferences;


public class RESTTransport{

    private HttpClient client;


    public RESTTransport() {

        client = new HttpClient();

        Boolean acceptSelfSignedCerts =
                new Boolean(Preferences.get(
                        Preferences.ApplicationOptions.HTTPS_ACCEPT_SELFSIGNED_CERTS));
        if (acceptSelfSignedCerts.booleanValue()) {
            // Create a Protocol handler which contains a HTTPS socket factory
            // capable of accepting self signed and otherwise invalid certificates.
            Protocol httpsProtocol = new Protocol("https",
                    (ProtocolSocketFactory) new EasySSLProtocolSocketFactory(),
                    443);
            Protocol.registerProtocol("https", httpsProtocol);
        }

        //Get the proxy settings
        Boolean proxyEnabled = new Boolean(Preferences.get(Preferences.ApplicationOptions.HTTP_PROXY_ENABLED));
        if (proxyEnabled.booleanValue()) {
            String proxyHost = Preferences.get(Preferences.ApplicationOptions.HTTP_PROXY_HOST);
            String proxyPortStr = Preferences.get(Preferences.ApplicationOptions.HTTP_PROXY_PORT);
            String proxyUserName = Preferences.get(Preferences.ApplicationOptions.HTTP_PROXY_USERNAME);
            String proxyPassword = Preferences.get(Preferences.ApplicationOptions.HTTP_PROXY_PASSWORD);
            String decodedPassword = new String(Base64.decodeBase64(proxyPassword.getBytes()));

            if (isNotEmpty(proxyHost)) {
                int proxyPort = 0;
                if (isNotEmpty(proxyPortStr)) {
                    proxyPort = Integer.parseInt(proxyPortStr);
                    client.getHostConfiguration().setProxy(proxyHost, proxyPort);
                    if (isNotEmpty(proxyUserName) && isNotEmpty(proxyPassword)) {
                        client.getState().setProxyCredentials(AuthScope.ANY,
                                new UsernamePasswordCredentials(proxyUserName, decodedPassword));
                    }
                }
            }
        }

    }

    public void put(String targetLocation, byte[] data, String username, String password) throws TransportException
    {
        targetLocation = targetLocation + "/api/database";
        PutMethod put = new PutMethod(targetLocation);

        try {
            if (username == null) {
                throw new TransportException("No username");
            }
            if (password == null) {
                throw new TransportException("No password");
            }

            System.out.println("Data from put: " + new String(data));

            String usernameEncoded = "username=" + URLEncoder.encode(username, "UTF-8");
            String passwordEncoded = "password=" + URLEncoder.encode(password, "UTF-8");
            String databaseEncoded = "database=" + URLEncoder.encode(new String(data), "UTF-8");

            String str = String.format("%s&%s&%s", usernameEncoded, passwordEncoded, databaseEncoded);
            put.setRequestEntity(new StringRequestEntity(str, "application/x-www-urlencoded", "UTF-8"));
            int status = client.executeMethod(put);

            switch (status) {
                case HttpStatus.SC_CREATED:
                    break;
                case HttpStatus.SC_BAD_REQUEST:
                    throw new TransportException(put.getResponseBodyAsString());
                default: break;
            }

        } catch (FileNotFoundException e) {
            throw new TransportException(e);
        } catch (MalformedURLException e) {
            throw new TransportException(e);
        } catch (HttpException e) {
            throw new TransportException(e);
        } catch (IOException e) {
            throw new TransportException(e);
        } finally {
            put.releaseConnection();
        }
    }

    public void post(String targetLocation, byte[] data, String username, String password) throws TransportException {

        targetLocation = targetLocation + "/api/database";

        PostMethod post = new PostMethod(targetLocation);

        //This part is wrapped in a try/finally so that we can ensure
        //the connection to the HTTP server is always closed cleanly
        try {
            if (username == null) {
                throw new TransportException("No username");
            }
            if (password == null) {
                throw new TransportException("No password");
            }

            //Set the HTTP Basic authentication details
            post.addRequestHeader("Authorization", getBasicAuth(username, password));

            System.out.println("Data from post: " + new String(data));
            post.setRequestEntity(new StringRequestEntity(new String(data, "UTF-8")));

            int status = client.executeMethod(post);

            switch (status) {
                case HttpStatus.SC_CREATED:
                    break;
                case HttpStatus.SC_BAD_REQUEST:
                    throw new TransportException(post.getResponseBodyAsString());
                default: break;
            }

        } catch (FileNotFoundException e) {
            throw new TransportException(e);
        } catch (MalformedURLException e) {
            throw new TransportException(e);
        } catch (HttpException e) {
            throw new TransportException(e);
        } catch (IOException e) {
            throw new TransportException(e);
        } finally {
            post.releaseConnection();
        }
    }

    public byte[] get(String url, String fileName) throws TransportException {
        return get(url, fileName, null, null);
    }


    public byte[] get(String url, String fileName, String username, String password) throws TransportException {
        url = addTrailingSlash(url);
        return get(url + fileName, username, password);
    }


    public byte[] get(String url, String username, String password) throws TransportException {

        byte[] retVal = null;

        url += "/api/database";
        GetMethod method = new GetMethod(url);

        //This part is wrapped in a try/finally so that we can ensure
        //the connection to the HTTP server is always closed cleanly
        try {
            if (username == null) {
                throw new TransportException("No username");
            }
            if (password == null) {
                throw new TransportException("No password");
            }

            //Set the HTTP Basic authentication details
            method.setRequestHeader("Authorization", getBasicAuth(username, password));
            int status = client.executeMethod(method);

            switch (status) {
                case HttpStatus.SC_OK:
                    break;
                default: throw new TransportException(method.getResponseBodyAsString());
            }

            retVal = method.getResponseBody();
            System.out.println("retval string:" + new String(retVal));

        } catch (MalformedURLException e) {
            throw new TransportException(e);
        } catch (HttpException e) {
            throw new TransportException(e);
        } catch (IOException e) {
            throw new TransportException(e);
        } finally {
            method.releaseConnection();
        }

        return retVal;

    }


    public File getRemoteFile(String remoteLocation, String fileName) throws TransportException {
        return getRemoteFile(remoteLocation, fileName, null, null);
    }


    public File getRemoteFile(String remoteLocation) throws TransportException {
        return getRemoteFile(remoteLocation, null, null);
    }


    public File getRemoteFile(String remoteLocation, String fileName, String httpUsername, String httpPassword) throws TransportException {
        remoteLocation = addTrailingSlash(remoteLocation);
        return getRemoteFile(remoteLocation + fileName, httpUsername, httpPassword);
    }


    public File getRemoteFile(String remoteLocation, String httpUsername, String httpPassword) throws TransportException {
        try {
            byte[] remoteFile = get(remoteLocation, httpUsername, httpPassword);
            File downloadedFile = File.createTempFile("upm", null);
            FileOutputStream fos = new FileOutputStream(downloadedFile);
            fos.write(remoteFile);
            fos.close();
            return downloadedFile;
        } catch (IOException e) {
            throw new TransportException(e);
        }
    }


    public void delete(String targetLocation, String name, String username, String password) throws TransportException {

        targetLocation = addTrailingSlash(targetLocation) + "database";

        DeleteMethod delete = new DeleteMethod(targetLocation);

        //This part is wrapped in a try/finally so that we can ensure
        //the connection to the HTTP server is always closed cleanly
        try {

            if (username == null) {
                throw new TransportException("No username");
            }
            if (password == null) {
                throw new TransportException("No password");
            }

            //Set the HTTP Basic authentication details
            delete.addRequestHeader("Authorization", getBasicAuth(username, password));

            int status = client.executeMethod(delete);

            switch (status) {
                case HttpStatus.SC_OK:
                    break;
                default: throw new TransportException(delete.getResponseBodyAsString());
            }

        } catch (MalformedURLException e) {
            throw new TransportException(e);
        } catch (HttpException e) {
            throw new TransportException(e);
        } catch (IOException e) {
            throw new TransportException(e);
        } finally {
            delete.releaseConnection();
        }

    }


    public void delete(String targetLocation, String name) throws TransportException {
        delete(targetLocation, name, null, null);
    }

    private String addTrailingSlash(String url) {
        if (url.charAt(url.length() - 1) != '/') {
            url = url + '/';
        }
        return url;
    }


    private boolean isNotEmpty(String stringToCheck) {
        boolean retVal = false;
        if (stringToCheck != null && !stringToCheck.trim().equals("")) {
            retVal = true;
        }
        return retVal;
    }

    private String getBasicAuth(String username, String password) {
        String auth = username + ":" + password;
        byte[] basicEncoded = Base64.encodeBase64(auth.getBytes(Charset.forName("ISO-8859-1")));
        return String.format("Basic %s", new String(basicEncoded));
    }


//    public void put(String targetLocation, File file) throws TransportException {
//        put(targetLocation, file, null, null);
//    }

//    public static void save(String urlString, String username, String password, byte[] data)
//    {
//        HttpURLConnection connection = null;
//
//        urlString = "http://localhost:3000";
//        username = "hello";
//        password = "world";
//        data = "idkman".getBytes();
//        try {
//            //Create connection
//            URL url = new URL(urlString);
//            connection = (HttpURLConnection) url.openConnection();
//            connection.setRequestMethod("POST");
//            connection.setRequestProperty("Content-Type",
//                    "application/x-www-form-urlencoded");
//
//            connection.setRequestProperty("Content-Length",
//                    Integer.toString(data.length));
//            connection.setRequestProperty("Content-Language", "en-US");
//            connection.setRequestProperty("Authorization",
//                    username + ":" + password);
//
//            connection.setUseCaches(false);
//            connection.setDoOutput(true);
//
//            //Send request
//            DataOutputStream wr = new DataOutputStream (
//                    connection.getOutputStream());
//            wr.write(data);
//            wr.close();
//
//            //Get Response
//            InputStream is = connection.getInputStream();
//            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
//            StringBuilder response = new StringBuilder(); // or StringBuffer if Java version 5+
//            String line;
//            while ((line = rd.readLine()) != null) {
//                response.append(line);
//                response.append('\r');
//            }
//            rd.close();
//            System.out.println(response.toString());
//        } catch (Exception e) {
//            e.printStackTrace();
//        } finally {
//            if (connection != null) {
//                connection.disconnect();
//            }
//        }
//    }


//    public byte[] get(String url, String fileName) throws TransportException {
//        return get(url, fileName, null, null);
//    }
//
//
//    public byte[] get(String url, String fileName, String username, String password) throws TransportException {
//        url = addTrailingSlash(url);
//        return get(url + fileName, username, password);
//    }
//
//
//    public byte[] get(String url, String username, String password) throws TransportException {
//
//        byte[] retVal = null;
//
//        GetMethod method = new GetMethod(url);
//
//        //This part is wrapped in a try/finally so that we can ensure
//        //the connection to the HTTP server is always closed cleanly
//        try {
//            if (username == null) {
//                throw new TransportException("No username");
//            }
//            if (password == null) {
//                throw new TransportException("No password");
//            }
//
//            //Set the HTTP Basic authentication details
//            method.setRequestHeader("Authorization", getBasicAuth(username, password));
//            int status = client.executeMethod(method);
//
//            switch (status) {
//                case HttpStatus.SC_OK:
//                    break;
//                default: throw new TransportException(method.getResponseBodyAsString());
//            }
//
//            retVal = method.getResponseBody();
//
//        } catch (MalformedURLException e) {
//            throw new TransportException(e);
//        } catch (HttpException e) {
//            throw new TransportException(e);
//        } catch (IOException e) {
//            throw new TransportException(e);
//        } finally {
//            method.releaseConnection();
//        }
//
//        return retVal;
//
//    }
//
//
//    public File getRemoteFile(String remoteLocation, String fileName) throws TransportException {
//        return getRemoteFile(remoteLocation, fileName, null, null);
//    }
//
//
//    public File getRemoteFile(String remoteLocation) throws TransportException {
//        return getRemoteFile(remoteLocation, null, null);
//    }
//
//
//    public File getRemoteFile(String remoteLocation, String fileName, String httpUsername, String httpPassword) throws TransportException {
//        remoteLocation = addTrailingSlash(remoteLocation);
//        return getRemoteFile(remoteLocation + fileName, httpUsername, httpPassword);
//    }
//
//
//    public File getRemoteFile(String remoteLocation, String httpUsername, String httpPassword) throws TransportException {
//        try {
//            byte[] remoteFile = get(remoteLocation, httpUsername, httpPassword);
//            File downloadedFile = File.createTempFile("upm", null);
//            FileOutputStream fos = new FileOutputStream(downloadedFile);
//            fos.write(remoteFile);
//            fos.close();
//            return downloadedFile;
//        } catch (IOException e) {
//            throw new TransportException(e);
//        }
//    }
//
//
//    public void delete(String targetLocation, String name, String username, String password) throws TransportException {
//
//        targetLocation = addTrailingSlash(targetLocation) + "deletefile.php";
//
//        PostMethod post = new PostMethod(targetLocation);
//        post.addParameter("fileToDelete", name);
//
//        //This part is wrapped in a try/finally so that we can ensure
//        //the connection to the HTTP server is always closed cleanly
//        try {
//
//            //Set the authentication details
//            if (username != null) {
//                Credentials creds = new UsernamePasswordCredentials(new String(username), new String(password));
//                URL url = new URL(targetLocation);
//                AuthScope authScope = new AuthScope(url.getHost(), url.getPort());
//                client.getState().setCredentials(authScope, creds);
//                client.getParams().setAuthenticationPreemptive(true);
//            }
//
//            int status = client.executeMethod(post);
//            if (status != HttpStatus.SC_OK) {
//                throw new TransportException("There's been some kind of problem deleting a file on the HTTP server.\n\nThe HTTP error message is [" + HttpStatus.getStatusText(status) + "]");
//            }
//
//            if (!post.getResponseBodyAsString().equals("OK") ) {
//                throw new TransportException("There's been some kind of problem deleting a file to the HTTP server.\n\nThe error message is [" + post.getResponseBodyAsString() + "]");
//            }
//
//        } catch (MalformedURLException e) {
//            throw new TransportException(e);
//        } catch (HttpException e) {
//            throw new TransportException(e);
//        } catch (IOException e) {
//            throw new TransportException(e);
//        } finally {
//            post.releaseConnection();
//        }
//
//    }
//
//
//    public void delete(String targetLocation, String name) throws TransportException {
//        delete(targetLocation, name, null, null);
//    }

}
