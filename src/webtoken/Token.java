package webtoken;

import com.sun.mail.util.BASE64DecoderStream;

import java.io.BufferedReader;
import java.io.FileReader;

import java.text.SimpleDateFormat;

import org.apache.commons.codec.binary.Base64;

import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class Token
{
    private Cipher dcipher;

    private String tok;
    
    public Token(String token)
    {
        this.tok = token;
    }

    @SuppressWarnings("org.adfemg.audits.java.system-out-usage")
    public JSONObject validateToken() throws Exception
    {
        // Check if it was issued by the server and if it's not expired
        // Throw an Exception if the token is invalid
        String dToken = decryptToken(tok);

        JSONObject j = new JSONObject(dToken);

        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy hh:mm:ss"); //Use same date format for decryption to maintain consistency
        Date     d = sdf.parse(j.getString("TokenExpiration"));
        Calendar c = Calendar.getInstance();
        Date     now = c.getTime();
        String currentDateString = sdf.format(now);
        Date formattedNow = sdf.parse(currentDateString);
        
        if (formattedNow.before(d))
        {
            //System.out.println("TOKEN STILL VALID for user '" + (String) j.get("login") + "'!");
            j.put("TokenExpired", "false");
        }
        else if (formattedNow.after(d) || formattedNow.equals(d))
        {
            //System.out.println("TOKEN EXPIRED for user '" + (String) j.get("login") + "'!");
            j.put("TokenExpired", "true");
        }
        j.put("CurrentTime", currentDateString);

        return j;
    }

    private String decrypt(String str)
    {
        try
        {
            // decode with base64 to get bytes
            byte[] dec = BASE64DecoderStream.decode(str.getBytes());
            byte[] utf8 = dcipher.doFinal(dec);
            // create new string based on the specified charset
            return new String(utf8, "UTF8");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    private String decryptToken(String token) throws Exception
    {
        dcipher = Cipher.getInstance("DES");
        SecretKey key = null;
        if (key == null)
        {
            BufferedReader br = new BufferedReader(new FileReader("WebTokenData.txt"));
            try
            {
                StringBuilder sb = new StringBuilder();
                String        line = br.readLine();

                while (line != null)
                {
                    sb.append(line);
                    sb.append(System.lineSeparator());
                    line = br.readLine();
                }
                String s = sb.toString();
                byte[] decodedKey = Base64.decodeBase64(s.getBytes());
                key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
            }
            finally
            {
                br.close();
            }
        }
        dcipher.init(Cipher.DECRYPT_MODE, key);
        String decrypted = decrypt(token);
        return decrypted;
    }
}