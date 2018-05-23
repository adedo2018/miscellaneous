package symmetric;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * class to generate and use symmetric key with AES
 */
public class SymmetricKey {

  /**
   *
   * @param key that will be used to initialise the cipher
   * @return Cipher that will be used for encryption
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   */
    public static final Cipher generateEncryptingCipher(SecretKey key, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException,
                                                                           InvalidKeyException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

  /**
   *
   * @param key that will be used to initialise the cipher
   * @return Cipher that will be used for decryption
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   */
    public static final Cipher generateDecryptingCipher(SecretKey key, String algorithm) throws NoSuchAlgorithmException,
                                                                                                NoSuchPaddingException,
                                                                              InvalidKeyException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher;
    }

  /**
   *
   * @return SecretKey the actual symetric key based on AES
   * @throws NoSuchAlgorithmException
   */
  public static final SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException{

        KeyGenerator keygen = KeyGenerator.getInstance(algorithm);
        SecureRandom random = SecureRandom.getInstanceStrong();

        keygen.init(128, random);

        SecretKey original_key = keygen.generateKey();
        byte[] raw = original_key.getEncoded();

        SecretKey key = new SecretKeySpec(raw, algorithm);

        return key;

    }

  /**
   *
   * @param content the String that will be encrypted
   * @param encryptingCipher initialised cipher to be used for encryption
   * @return String the encrypted content
   */
    public static String encrypt(String content, Cipher encryptingCipher)
        throws UnsupportedEncodingException,
               IllegalBlockSizeException,
               BadPaddingException {

            byte[] byte_encode = content.getBytes("utf-8");
            byte[] byte_content = encryptingCipher.doFinal(byte_encode);

            String encrypted = new String(new BASE64Encoder().encode(byte_content));

            return encrypted;
    }

  /**
   *
   * @param encryptedContent the String that will be decrypted
   * @param decryptionCipher initialised cipher to be used for decryption
   * @return String the decrypted content
   */
    public static String decrypt(String encryptedContent, Cipher decryptionCipher)
        throws IllegalBlockSizeException,
               BadPaddingException,
               IOException{

            byte[] byte_content = new BASE64Decoder().decodeBuffer(encryptedContent);
            byte[] byte_decode = decryptionCipher.doFinal(byte_content);

            String decode = new String(byte_decode, "utf-8");

            return decode;
    }

    public static void main(String[] args)
        throws IllegalBlockSizeException,
               BadPaddingException,
               IOException,
               NoSuchAlgorithmException,
               NoSuchPaddingException,
               InvalidKeyException{

      String algorithm = "AES";

        SecretKey key = generateKey(algorithm);
        Cipher encryptCipher = generateEncryptingCipher(key, algorithm);
        Cipher decryptCipher = generateDecryptingCipher(key, algorithm);

        String encryptedContent = encrypt("fred at library", encryptCipher);
        String decryptedContent = decrypt(encryptedContent, decryptCipher);

        System.out.println( "Cipher provider : "+encryptCipher.getProvider().getName());

        System.out.println( "content : fred at library");

        System.out.println( "fred at library : " +  encrypt("fred at library", encryptCipher));
        System.out.println( "fred at library is same as " +  decrypt(encryptedContent, decryptCipher));

    }

}