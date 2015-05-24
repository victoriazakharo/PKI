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
	private String dn;
	public ClientThread(Socket s, CA ca) throws IOException 
	{		
		din = new DataInputStream(s.getInputStream());
        dout = new DataOutputStream(s.getOutputStream());
        this.ca = ca;
	}
	
	public void SaveKeyPair(KeyPair keyPair) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		System.out.println(publicKey.toString());
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream("D://public" +23+".key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream("D://private" +23+".key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
	
	public void run() {
		String CN="", OU="", O="", L="", S="", C="";
		while(true) {
			dn = null; // distinguished name (CN=.., OU=.., O=.., L=.., ST=.., C=..)
			try {
				dn = din.readUTF();
				System.out.println("Approve user " + dn + " and give him certificate? (yes/no)");
			} catch (IOException e) {			
				e.printStackTrace();
			}
			String answer = ca.getScanner().nextLine();
			byte[] encodedCert = null;
			X509Certificate cert=null;
			KeyPair pair=null;
			if(answer.equals("yes")) {
				 pair = RSA.generateKeyPair();
				try {
					SaveKeyPair(pair);
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				cert = ca.createCertificate(pair.getPublic(), dn);			
				ca.writeCertificateToStorage(cert);
				
				try {
					
					encodedCert = cert.getEncoded();
				} catch (CertificateEncodingException e) {				
					e.printStackTrace();
				}
			}
			
			try {
				//Write centificate to file
				FileOutputStream out = new FileOutputStream("D://cert23.cer");
			    //BASE64Encoder encoder = new BASE64Encoder();
		        out.write(cert.getEncoded());
				//dout.writeInt(encodedCert.length);
				//if(encodedCert.length > 0) {
				//	dout.write(encodedCert, 0, encodedCert.length);	
				//}
			} catch (IOException | CertificateEncodingException e) {			
				e.printStackTrace();
			}	
		}
	}
}
