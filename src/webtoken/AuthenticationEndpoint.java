package webtoken;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.util.Calendar;
import java.util.Date;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import com.sun.mail.util.BASE64EncoderStream;

import java.io.PrintWriter;

import java.net.URI;

import org.apache.commons.codec.binary.Base64;

import java.text.SimpleDateFormat;

import javax.crypto.Cipher;

import javax.crypto.KeyGenerator;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import javax.ws.rs.core.UriBuilder;

import org.json.JSONObject;

@SuppressWarnings("org.adfemg.audits.java.system-out-usage")
@Path("/authentication")
public class AuthenticationEndpoint
{
    private static final String DB_URL = "jdbc:mysql://52.7.121.162:3306/mpiweb20?autoReconnect=true&useSSL=false";
    private static final String user = "mpiweb20";
    private static final String pw = "mpiweb20";
    private Connection          conn = null;
    private PreparedStatement   stmt = null;

    private Cipher    ecipher;
    private Cipher    dcipher;
    
    @POST
    @Produces("application/json")
    @Consumes("application/x-www-form-urlencoded")
    public Response authenticateUser(@FormParam("username") String username, @FormParam("password") String password)
    {
        try
        {
            //System.out.println("Starting to Authenticate");
            // Authenticate the user using the credentials provided
            authenticate(username, password);

            System.out.println("Authentication Successful");
            // Issue a token for the user
            String token = issueToken(username);
           
            System.out.println("Token '" + token + "' Issued");

            // Return the token on the response header
            //return Response.ok(token).header("Authorization", "Bearer " + token).build();

            
            UriBuilder ub = UriBuilder.fromPath("../").path("postform.html").queryParam("token", token);
            URI uri = ub.build("postRedirect", "sendToken");
            return Response.temporaryRedirect(uri).build();
            
            //URI u = new URI("/" + token);
            //return Response.temporaryRedirect(u).build();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
    }

    private void authenticate(String username, String password) throws Exception
    {
        // Authenticate against a database, LDAP, file or whatever
        // Throw an Exception if the credentials are invalid

        // STEP 2: Register JDBC driver
        Class.forName("com.mysql.jdbc.Driver");

        // STEP 3: Open a connection
        conn = DriverManager.getConnection(DB_URL, user, pw);

        String sql = "Select login, password FROM sw_auth where login='" + username + "'";
        
        // STEP 4: Execute a query
        stmt = conn.prepareStatement(sql);

        ResultSet rs = stmt.executeQuery();
        if (rs.next())
        {
            //System.out.println("Recieved Result Set");
            String passwordDB = rs.getString("password");
            String sha1 = "";
            try
            {
                MessageDigest crypt = MessageDigest.getInstance("SHA-1");
                crypt.reset();
                crypt.update(password.getBytes("UTF-8"));
                sha1 = byteToHex(crypt.digest());
            }
            catch (NoSuchAlgorithmException e)
            {
                stmt.close();
                conn.close();
                e.printStackTrace();
            }
            if (sha1.equals(passwordDB))
            {
                //Need to generate token since authentication successful
                stmt.close();
                conn.close();
                System.out.println("Correct Credentials");
            }
            else
            {
                //Authentication failed - incorrect Password Entered
                System.out.println("Incorrect Credentials");
                stmt.close();
                conn.close();
                throw new InvalidLoginException("LOGIN FAILED - Incorrect Password!");
            }
        }
        else
        {
            //Authentication failed - incorrect Username Entered
            stmt.close();
            conn.close();
            throw new InvalidLoginException("LOGIN FAILED - Incorrect Username!");
        }
        return;
    }

    private String issueToken(String username) throws Exception
    {
        // Issue a token (can be a random String persisted to a database or a JWT token)
        // The issued token must be associated to a user
        // Return the issued token
        
        //JSONObject to be converted to token
        JSONObject token = new JSONObject();
        
        // Put username into JSONObject
        token.put("login", username);
        
        //Put Start and Expiration Date and time in Token
        Calendar c = Calendar.getInstance();
        Date     d = c.getTime();

        //Convert Date to correct format - mm/dd/yyyy hh:MM:ss
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy hh:mm:ss");

        String fDate = sdf.format(d);
        
        token.put("TokenIssued", fDate);
        
        c.setTime(d);
        c.add(Calendar.MINUTE,3); // expire token after 2 mins - for testing purposes - should be set to higher increment
        //c.add(Calendar.MILLISECOND, 20000); // expire token after X Milliseconds
        //c.add(Calendar.MINUTE, 5); // expire token after X Mins
        //c.add(Calendar.HOUR,12); // expire token after X Hours
        //c.add(Calendar.MONTH, 11); // expire token after X Months
        //c.add(Calendar.YEAR, 1); // expire token after X Years
        d = c.getTime();
        
        //Convert Date to correct format - mm/dd/yyyy hh:MM:ss
        sdf = new SimpleDateFormat("MM/dd/yyyy hh:mm:ss");
        
        fDate = sdf.format(d);

        token.put("TokenExpiration", fDate);

        //Encrypt and return token
        
        String encrypted;
        SecretKey key = null;
        try 
        {
            // generate secret key using DES algorithm
            if (key == null)
            {
                key = KeyGenerator.getInstance("DES").generateKey();
                //Save key to file - to be used later for decryption
                try
                {
                    PrintWriter writer = new PrintWriter("WebTokenData.txt", "UTF-8");
                    //encode Key before writing to file
                    String encodedKey = new String(Base64.encodeBase64(key.getEncoded()));
                    writer.println(encodedKey);
                    writer.close();
                }
                catch (Exception e)
                {
                    e.printStackTrace();;
                }
            }
            ecipher = Cipher.getInstance("DES");
            
            // initialize the ciphers with the given key
            ecipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = encrypt(token.toString());
        }
        catch (NoSuchAlgorithmException e) 
        {
            System.out.println("No Such Algorithm:" + e.getMessage());
            return null;
        }
        catch (NoSuchPaddingException e) 
        {
            System.out.println("No Such Padding:" + e.getMessage());
            return null;
        }  
        
        //encode encrypted string to be URL safe
        //System.out.println("ENCRYPTED TOKEN BEFORE ENCODING -> " + encrypted);
        
        String encodedToken = new String(Base64.encodeBase64(encrypted.getBytes()));
        //System.out.println("ENCRYPTED TOKEN AFTER ENCODING -> " + encodedToken);
        return encodedToken;
    }

    private static String byteToHex(final byte[] hash)
    {
        java.util.Formatter formatter = new java.util.Formatter();
        for (byte b : hash)
        {
            formatter.format("%02x", b);
        }
        String result = formatter.toString();
        formatter.close();
        return result;
    }

    public String encrypt(String str)
    {
        try
        {
            // encode the string into a sequence of bytes using the named charset
            // storing the result into a new byte array.
            byte[] utf8 = str.getBytes("UTF8");
            byte[] enc = ecipher.doFinal(utf8);
        
            // encode to base64
            enc = BASE64EncoderStream.encode(enc);
            return new String(enc);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }
}