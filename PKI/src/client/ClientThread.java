package client;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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

import crypto.Shamir.Share;

public class ClientThread extends Thread {
	private DataInputStream din;
	private DataOutputStream dout;
	private X509Certificate cert;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Signature sign;
	private boolean authorizationResult;
	private int port;
	public ClientThread(Socket s, X509Certificate cert, PrivateKey privateKey) {
		this.cert = cert;
		this.authorizationResult=false;
		this.privateKey = privateKey;
		port = s.getLocalPort();
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
		try {
			int action = din.readInt();
			if(action == 1){
				String filename = din.readUTF();
				int x = din.readInt();
				String sum = din.readUTF();
				writeToFile(filename,x,sum);
			}
			if(action == 2){
				String filename = din.readUTF();
				Share share = readFromFile(filename);
				dout.writeInt(share.getX());
				dout.writeUTF(share.getSum().toString());
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	

	private static void clearFile(String filename) {
		try {
			Files.write(Paths.get(filename),
					(new String()).getBytes(),
					StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void writeToFile(String filename, int x, String sum) {
		try {
			if(readFromFile(filename)!=null)
				clearFile("resources\\clientComputers\\shares"+port+".txt");
			PrintWriter fileWriter = new PrintWriter(new BufferedWriter(
					new FileWriter("resources\\clientComputers\\shares"+port+".txt", true)));
			fileWriter.write(filename + " " + x + " " + sum+"\n");
			fileWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private Share readFromFile(String filename){
		Share share = null;
		try {
			BufferedReader fileReader = new BufferedReader(new FileReader(
					"resources\\clientComputers\\shares"+port+".txt"));
			String str;

			while ((str = fileReader.readLine()) != null) {
				if (str.substring(0, Integer.valueOf(str.indexOf(" "))).equals(
						filename)) {
					String[] parts = str.split(" ");
					share = new Share(Integer.valueOf(parts[1]),new BigInteger(parts[2]));
					break;
				}
			}
			fileReader.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return share;
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
