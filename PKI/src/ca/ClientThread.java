package ca;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

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
	
	public void run() {
		String dn = null; // distinguished name (CN=.., OU=.., O=.., L=.., ST=.., C=..)
		try {
			dn = din.readUTF();
			System.out.println("Approve user " + dn + " and give him certificate? (yes/no)");
		} catch (IOException e) {			
			e.printStackTrace();
		}
		String answer = ca.getScanner().nextLine();
		byte[] encodedCert = null;
		if(answer.equals("yes")) {
			KeyPair pair = RSA.generateKeyPair();
			X509Certificate cert = ca.createCertificate(pair.getPublic(), dn);
			ca.writeCertificateToStorage(cert);
			try {
				encodedCert = cert.getEncoded();
			} catch (CertificateEncodingException e) {				
				e.printStackTrace();
			}
		}
		try {
			dout.writeInt(encodedCert.length);
			if(encodedCert.length > 0) {
				dout.write(encodedCert, 0, encodedCert.length);	
			}
		} catch (IOException e) {			
			e.printStackTrace();
		}
	}
}
