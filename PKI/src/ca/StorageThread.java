package ca;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class StorageThread extends Thread {

    private DataOutputStream dout;	
	private BlockingQueue<X509Certificate> certQueue = new LinkedBlockingQueue<X509Certificate>();
	private CA ca;
	
	public StorageThread(Socket s, CA ca) throws IOException 
	{		
		dout = new DataOutputStream(s.getOutputStream());
		this.ca = ca;
	}
	
	public void storeCertificate(X509Certificate cert) {
		certQueue.add(cert);
	}
	
	public boolean hasCertificate(X509Certificate cert){
		return certQueue.contains(cert);
	}
	public void run() {
		System.out.println("StorageThread started.");
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
