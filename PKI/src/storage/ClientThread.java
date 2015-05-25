package storage;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
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
		String alias;	 
		try {
			while((alias = din.readUTF()) != null) {	
				System.out.println("Got request from client.");
				X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
				if(cert == null) {					
					dout.writeInt(0);
				} else {				
					dout.writeInt(1);				
				}
			}
		} catch (IOException | KeyStoreException e) {			
			e.printStackTrace();
		}		
	 }
}
