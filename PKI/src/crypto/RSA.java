package crypto;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {

	public static KeyPair generateKeyPair() {
		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		kpg.initialize(2048);
		return kpg.genKeyPair();
	}

	public static byte[] encrypt(byte[] data, PublicKey publicKey) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		byte[] cipherData = null;
		try {
			cipherData = cipher.doFinal(data);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return cipherData;
	}

	public static byte[] decrypt(byte[] data, PrivateKey privateKey) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		byte[] cipherData = null;
		try {
			cipherData = cipher.doFinal(data);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return cipherData;
	}

	public static byte[] sign(byte[] data, PrivateKey privateKey) {
		byte[] signed = null;
		try {
			Signature sig = Signature.getInstance("MD5WithRSA");
			sig.initSign(privateKey);
			sig.update(data);
			signed = sig.sign();
		} catch (SignatureException | NoSuchAlgorithmException
				| InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return signed;
	}

	public static boolean checkSignature(byte[] data, byte[] signature,
			PublicKey publicKey) {
		boolean out = false;
		try {
			Signature sig = Signature.getInstance("MD5WithRSA");
			sig.initVerify(publicKey);
			sig.update(data);
			out = sig.verify(signature);
		} catch (SignatureException | InvalidKeyException
				| NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return out;
	}
}
