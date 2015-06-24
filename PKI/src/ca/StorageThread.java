package ca;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class StorageThread extends Thread {

    private DataOutputStream dout;	
    private DataInputStream din;
    private PublicKey storagePublicKey;
	private BlockingQueue<X509Certificate> certQueue = new LinkedBlockingQueue<X509Certificate>();
	private CA ca;
	
	public StorageThread(Socket s, CA ca) throws IOException 
	{		
		din = new DataInputStream(s.getInputStream());
		dout = new DataOutputStream(s.getOutputStream());
		this.ca = ca;
	}
	
	public void storeCertificate(X509Certificate cert) {
		certQueue.add(cert);
	}
	
	private void exchangePublicKeys(){
		try {
		byte[] publicKeyBytes = ca.getPublicKey().getEncoded();
		dout.writeInt(publicKeyBytes.length);				
			dout.write(publicKeyBytes, 0, publicKeyBytes.length);
			System.out.println("CA passed public key to storage.");
			int len = din.readInt();
			publicKeyBytes = new byte[len];
			din.readFully(publicKeyBytes, 0, len);
				storagePublicKey = KeyFactory.getInstance("RSA")
						.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
				ca.setStoragePublicKey(storagePublicKey);
		} catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void run() {
		exchangePublicKeys();
		while(true) {
			X509Certificate cert = null;
			try {
				cert = certQueue.take();
			} catch (InterruptedException e1) {				
				e1.printStackTrace();
			}			
			byte[] encoded = null;
			byte[] signatureBytes = null;
			try {
				encoded = cert.getEncoded();
				Signature sig = Signature.getInstance(CA.SIGN_ALGORITHM);
			    sig.initSign(ca.getPrivateKey());
			    sig.update(encoded);
			    signatureBytes = sig.sign();
			} catch (CertificateEncodingException | InvalidKeyException 
					| NoSuchAlgorithmException | SignatureException e) {			
				e.printStackTrace();
			}
			try {
				dout.writeInt(signatureBytes.length);
				dout.write(signatureBytes, 0, signatureBytes.length);	
				dout.writeInt(encoded.length);
				dout.write(encoded, 0, encoded.length);	
			} catch (IOException e) {			
				e.printStackTrace();
			}
		}
	}	
}
