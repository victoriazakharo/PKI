package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class ClientThread extends Thread {
	private DataInputStream din;
	private DataOutputStream dout;
	private X509Certificate cert;
	private PrivateKey privateKey;
	
	public ClientThread(Socket s, X509Certificate cert, PrivateKey privateKey) {
		this.cert = cert;
		this.privateKey = privateKey;
		try {
			dout = new DataOutputStream(s.getOutputStream());
			din = new DataInputStream(s.getInputStream());
		} catch (IOException e) {			
			e.printStackTrace();
		}		
	}
	
	public void run() {
		
	}
	
	private void sendDataForAuthorization() {		
		try {
			Signature sign = Signature.getInstance("MD5WithRSA");
			int lengthCert = cert.getEncoded().length;
			byte[] encodedCert = cert.getEncoded();
			dout.writeInt(lengthCert);
			dout.write(encodedCert);
			
			sign.initSign(privateKey);
		    sign.update(encodedCert);
		    byte[] signature = sign.sign();
		    
		    dout.writeInt(signature.length);
			dout.write(signature, 0, signature.length);
			System.out.println("Signature written.");
			
		} catch (CertificateEncodingException | IOException | 
				InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {		
			e.printStackTrace();
		}		
	}
}
