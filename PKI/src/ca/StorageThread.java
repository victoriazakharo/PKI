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
import java.util.Queue;
import java.util.concurrent.SynchronousQueue;

public class StorageThread extends Thread {

    private DataOutputStream dout;	
	private Queue<X509Certificate> certQueue = new SynchronousQueue<X509Certificate>();
	private CA ca;
	
	public StorageThread(Socket s, CA ca) throws IOException 
	{		
		dout = new DataOutputStream(s.getOutputStream());
		this.ca = ca;
	}
	
	public void storeCertificate(X509Certificate cert) {
		certQueue.add(cert);
	}
	
	public void run() {
		X509Certificate cert = certQueue.remove();
		byte[] encoded = null;
		try {
			encoded = cert.getEncoded();
			Signature sig = Signature.getInstance(CA.SIGN_ALGORITHM);
		    sig.initSign(ca.getPrivateKey());
		    sig.update(encoded);		
		} catch (CertificateEncodingException | InvalidKeyException 
				| NoSuchAlgorithmException | SignatureException e) {			
			e.printStackTrace();
		}
		try {
			dout.writeInt(encoded.length);
			dout.write(encoded, 0, encoded.length);	
		} catch (IOException e) {			
			e.printStackTrace();
		}
	}
}
