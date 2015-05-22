package storage;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class ClientThread extends Thread {
	 private DataOutputStream dout;	
	 private DataInputStream din;
	 private KeyStore keyStore;
	 
	 public ClientThread(Socket s, KeyStore keyStore) throws IOException 
	 {		
		dout = new DataOutputStream(s.getOutputStream());
		din = new DataInputStream(s.getInputStream());
		this.keyStore = keyStore;
	 }
	 
	 public void run() {
		try {
			String alias = din.readUTF();
			X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
			byte[] encoded = cert.getEncoded();
			dout.writeInt(encoded.length);
			dout.write(encoded, 0, encoded.length);	
		} catch (IOException | KeyStoreException | CertificateEncodingException e) {			
			e.printStackTrace();
		}
	 }
}
