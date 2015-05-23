package crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AES {
	private static byte[] currentIV;
	
	public static byte[] getCurrentIV() {
		return currentIV;
	}
	public static SecretKey generateKey(){		 
        KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {			
			e.printStackTrace();
		}
        keyGen.init(128);
        return keyGen.generateKey();
	}
	
	public static byte[] encrypt(byte[] data, SecretKey aesKey){
		 Cipher encryptCipher = null;
         try {
        	encryptCipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
			encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey);
			currentIV = encryptCipher.getIV();
		 } catch (InvalidKeyException e1) {			
			e1.printStackTrace();
		 } catch (NoSuchAlgorithmException e) {			
			e.printStackTrace();
		 } catch (NoSuchPaddingException e) {			
			e.printStackTrace();
		 }
         ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
         CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
         try {
			 cipherOutputStream.write(data);
			 cipherOutputStream.flush();
	         cipherOutputStream.close();
		 } catch (IOException e) {			
			e.printStackTrace();
		 }        
         return outputStream.toByteArray();
	}
	
	public static byte[] decrypt(byte[] data, SecretKey aesKey, IvParameterSpec ivParameterSpec){
		Cipher decryptCipher = null;     
        try {
        	decryptCipher = Cipher.getInstance("AES/OFB/PKCS5Padding"); 
			decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {			
			e.printStackTrace();
		}      
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        CipherInputStream cipherInputStream = new CipherInputStream(inStream, decryptCipher);
        byte[] buf = new byte[1024];
        int bytesRead;
        try {
			while ((bytesRead = cipherInputStream.read(buf)) >= 0) {
			    outputStream.write(buf, 0, bytesRead);
			}
			cipherInputStream.close();
		} catch (IOException e) {			
			e.printStackTrace();
		}
        return outputStream.toByteArray();
	}
}
