
import javax.crypto.*;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.InvalidKeySpecException;
import sun.misc.*;

public class cipher_me_this{


  public String encrypt(String data,String instance,byte[] keyValue) throws Exception{
    String encryptedData;
    Key key = new SecretKeySpec(keyValue, instance);
    Cipher c = Cipher.getInstance(instance);
    byte[] encVal;
    c.init(Cipher.ENCRYPT_MODE, key);
    encVal = c.doFinal(data.getBytes());
    encryptedData= new BASE64Encoder().encodeBuffer(encVal);
    return encryptedData;
  }

  public byte[] decrypt(String encryptedData, String instance,byte[] keyValue) throws Exception {
    Key key = new SecretKeySpec(keyValue, instance);
    Cipher c = Cipher.getInstance(instance);
    byte[] decodedValue,data;
    c.init(Cipher.DECRYPT_MODE, key);
    decodedValue = new BASE64Decoder().decodeBuffer(encryptedData);
    data = c.doFinal(decodedValue);
    return data;
  }

}
