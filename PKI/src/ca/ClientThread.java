package ca;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;

import crypto.RSA;

public class ClientThread extends Thread {
	private DataInputStream din; 
	private DataOutputStream dout;
    private CA ca;
	
	public ClientThread(Socket s, CA ca) throws IOException 
	{		
		din = new DataInputStream(s.getInputStream()); 
		dout = new DataOutputStream(s.getOutputStream());
        this.ca = ca;
	}
	
	public void SaveKeyPair(KeyPair keyPair, String id) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		System.out.println(publicKey.toString());
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream("D://public" + id + ".key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream("D://private" + id + ".key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
	
	public void run() {
		String dn, certID;
		try {
			while((dn = din.readUTF()) != null) {	
				certID=din.readUTF();
				System.out.println("Approve user " + dn + " and give him certificate? (yes/no)");
				String answer = ca.getScanner().nextLine();			
				X509Certificate cert = null;
				KeyPair pair = null;
				if(answer.equals("yes")) {
					 pair = RSA.generateKeyPair();
					try {
						SaveKeyPair(pair, certID);						
					} catch (IOException e1) {					
						e1.printStackTrace();
					}
					cert = ca.createCertificate(pair.getPublic(), dn);			
					ca.writeCertificateToStorage(cert);	
					try {				
						FileOutputStream out = new FileOutputStream("D://cert" + certID + ".cer");			  
				        out.write(cert.getEncoded());				
				        out.close();
					} catch (IOException | CertificateEncodingException e) {			
						e.printStackTrace();
					}	
					dout.writeInt(client.Client.CERTIFICATE_WRITTEN);
				} else {
					dout.writeInt(client.Client.CERTIFICATE_DENIED);
				}
			}
		} catch (IOException e) {			
			e.printStackTrace();
		}
	}
}
