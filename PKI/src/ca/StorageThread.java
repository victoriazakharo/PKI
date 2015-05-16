package ca;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Queue;
import java.util.concurrent.SynchronousQueue;

public class StorageThread extends Thread {

    private DataOutputStream dout;	
	private Queue<X509Certificate> certQueue = new SynchronousQueue<X509Certificate>();
	
	public StorageThread(Socket s) throws IOException 
	{		
		dout = new DataOutputStream(s.getOutputStream());
	}
	
	public void storeCertificate(X509Certificate cert) {
		certQueue.add(cert);
	}
	
	public void run() {
		X509Certificate cert = certQueue.remove();
		byte[] encoded = null;
		try {
			encoded = cert.getEncoded();
		} catch (CertificateEncodingException e) {			
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
