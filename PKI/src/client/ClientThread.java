package client;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ClientThread extends Thread {
	private DataInputStream din;
	private DataOutputStream dout;
	private X509Certificate cert;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Signature sign;
	private boolean authorizationResult;
	public ClientThread(Socket s, X509Certificate cert, PrivateKey privateKey) {
		this.cert = cert;
		this.authorizationResult=false;
		this.privateKey = privateKey;
		try {
			sign = Signature.getInstance("MD5WithRSA");
			dout = new DataOutputStream(s.getOutputStream());
			din = new DataInputStream(s.getInputStream());			
		} catch (IOException | NoSuchAlgorithmException e) {			
			e.printStackTrace();
		}		
	}
	
	public void run() {
		
		sendDataForAuthorization();
		System.out.println("ClientThread Started!!!!");
		clientWithServerSocketAuthorizationWork();
	}
	private void sendDataForAuthorization() {		
		try {
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
				InvalidKeyException | SignatureException e) {		
			e.printStackTrace();
		}		
	}

	public boolean secondClientAuthorization()
	{
		byte[] encodedCert;
		boolean checkContinuation=false;
		byte[] signature;
		try {
			int signLength=0;
			int length=din.readInt();
			encodedCert=new byte[length];
			din.read(encodedCert, 0, length);
			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(encodedCert);
			cert = (X509Certificate)certFactory.generateCertificate(in);

			signLength=din.readInt();
			signature=new byte[signLength];
			din.read(signature, 0, signLength);
			publicKey=cert.getPublicKey();
			System.out.println(publicKey.toString());
			sign.initVerify(publicKey);
			sign.update(cert.getEncoded());
			boolean result=sign.verify(signature);
			cert.checkValidity();
			if(result==true)
			{
				System.out.println("Certifacate is valid.");
				cert.checkValidity();
				checkContinuation=true;
				System.out.println("Certificate in use.");
			}
			else
			{
				System.out.println("Invalid certifacate.");
			}			
			
		} catch ( IOException | CertificateException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		return checkContinuation;
	}
		
	
	public void clientWithServerSocketAuthorizationWork(){
		boolean result=true, authorized=false;
		try
		{
			result=din.readBoolean();
			if(result)
			{
				authorized=secondClientAuthorization();
			}
			authorizationResult=authorized;
			dout.writeBoolean(authorized);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if(!authorized)
		{
			System.out.println("Authorization failed.");			
		}
		else
		{
			System.out.println("Authorized.");
		}
	}
}
