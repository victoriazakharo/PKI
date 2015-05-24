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
		FileOutputStream fos = new FileOutputStream("D://public" +12+".key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream("D://private" +12+".key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
	
	public void run() {
		String CN="", OU="", O="", L="", S="", C="";
		while(true) {
			dn = null; // distinguished name (CN=.., OU=.., O=.., L=.., ST=.., C=..)
			try {
				CN = din.readUTF();
				OU = din.readUTF();
				O = din.readUTF();
				L = din.readUTF();
				S = din.readUTF();
				C = din.readUTF();
				System.out.println("Approve user " + CN + " and give him certificate? (yes/no)");
			} catch (IOException e) {			
				e.printStackTrace();
			}
			String answer = ca.getScanner().nextLine();
			byte[] encodedCert = null;
			if(answer.equals("yes")) {
				KeyPair pair = RSA.generateKeyPair();
				try {
					SaveKeyPair(pair);
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				X509Certificate cert = ca.createCertificate(pair.getPublic(), CN, OU, O, L, S, C);
				ca.writeCertificateToStorage(cert);
				try {
					encodedCert = cert.getEncoded();
				} catch (CertificateEncodingException e) {				
					e.printStackTrace();
				}
			}
			try {
				//Write centificate to file
				//FileOutputStream out = new FileOutputStream("D://cert12.cer");
			    //BASE64Encoder encoder = new BASE64Encoder();
		        //out.write(caCert.getEncoded());
				dout.writeInt(encodedCert.length);
				if(encodedCert.length > 0) {
					dout.write(encodedCert, 0, encodedCert.length);	
				}
			} catch (IOException e) {			
				e.printStackTrace();
			}	
		}
	}
}
