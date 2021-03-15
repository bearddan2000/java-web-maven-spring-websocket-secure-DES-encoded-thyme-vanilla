package example.security;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.apache.commons.codec.binary.Base64;

public class DESPasswordEncoder extends org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
  implements PasswordEncoder {

    private Cipher encryptCipher = null;

    /**
     * Construct a new object which can be utilized to encrypt
     * and decrypt strings using the specified key
     * with a DES encryption algorithm.
     *
     * @param key The secret key used in the crypto operations.
     * @throws Exception If an error occurs.
     *
     */
    public DESPasswordEncoder(SecretKey key) throws Exception {
      super();
        encryptCipher = Cipher.getInstance("DES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
    }
    @Override
    public java.lang.String encode(java.lang.CharSequence rawPassword)
    {
      try {
        String res = encryptBase64(rawPassword.toString());
        return super.encode(res);//BCrypt.hashpw(res, BCrypt.gensalt());
      } catch(Exception e) {}
      return null;
    }
    @Override
    public boolean matches(java.lang.CharSequence rawPassword,
                       java.lang.String encodedPassword)
                       {
                           try {
                             String res = encryptBase64(rawPassword.toString());
                             return super.matches(res, encodedPassword);
                           } catch(Exception e) {}
                           return false;
                       }
    /**
     * Encrypt a string using DES encryption, and return the encrypted
     * string as a base64 encoded string.
     * @param unencryptedString The string to encrypt.
     * @return String The DES encrypted and base 64 encoded string.
     * @throws Exception If an error occurs.
     */
    private String encryptBase64 (String unencryptedString) throws Exception {
        // Encode the string into bytes using utf-8
        byte[] unencryptedByteArray = unencryptedString.getBytes("UTF8");

        // Encrypt
        byte[] encryptedBytes = encryptCipher.doFinal(unencryptedByteArray);

        // Encode bytes to base64 to get a string
        byte [] encodedBytes = Base64.encodeBase64(encryptedBytes);

        return new String(encodedBytes);
    }
}
