package client;

import java.io.BufferedReader;

import crypto.RSA;
import crypto.Shamir.Share;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
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
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.swing.JFrame;

public class ClientThread extends Thread {
	protected DataInputStream din, storageDin;
	protected DataOutputStream dout, storageDout;
	protected X509Certificate cert, anotherCert;
	protected PrivateKey privateKey;	
	protected Signature sign;
	protected Socket storageSocket; 
	public int  port;
	public String host;
	protected ClientFrame frame;
	public Boolean answerReady = false;
	public Integer answer=0;
	
	public ClientThread(Socket s, X509Certificate cert, PrivateKey privateKey) {
		this.cert = cert;		
		this.privateKey = privateKey;
		try {
			sign = Signature.getInstance("MD5WithRSA");
			dout = new DataOutputStream(s.getOutputStream());
			din = new DataInputStream(s.getInputStream());	
			port = s.getLocalPort();
			host = s.getLocalAddress().toString();
			storageSocket = new Socket(Client.STORAGE_HOST, Client.STORAGE_PORT);
			storageDin = new DataInputStream(storageSocket.getInputStream());
			storageDout =  new DataOutputStream(storageSocket.getOutputStream());
		} catch (IOException | NoSuchAlgorithmException e) {			
			e.printStackTrace();
		}		
	}
	
	protected void initFrame(String filename,String host,int port){
		frame = new ClientFrame(this,filename,host,port);
		frame.setVisible(true); 
	}
	
	public void setAnswerReady() {
		answerReady = true;
	}
	
	public void run() {	
		while(true) {
			int request = Client.EXIT;
			try {
				request = din.readInt();
			} catch (IOException e) {			
				e.printStackTrace();
			}
			if(request == Client.AUTHORIZE) {
				sendDataForAuthorization();				
				try {
					if(din.readBoolean()) {						
						dout.writeBoolean(secondClientAuthorization());
					}					
				} catch (IOException e) {					
					e.printStackTrace();
				}
				getHostAndPort();
				try {
					while((request = din.readInt()) != Client.BREAK_CLIENT) {
						//getHostAndPort();
						responseForRequest(request);
					}
				} catch (IOException e) {					
					e.printStackTrace();
				}
			}
		}		
	}
	
	protected void getHostAndPort() {}

	protected void responseForRequest(int request) {
		try {
			if(request == Client.SEND_SHARE){
				String filename = din.readUTF();
				int x = din.readInt();
				int length = din.readInt();
				byte[] read = new byte[length];
				din.read(read, 0, length);
				writeToFile(filename,x,new BigInteger(RSA.decrypt(read,privateKey)).toString());
			}
			if(request == Client.GET_SHARE){
				String filename = din.readUTF();
				String host = din.readUTF();
				int port = din.readInt();
				if(port == this.port /*&& host.equals(this.host)*/)
					sendingShare(1, filename);
				else
					initFrame(filename,host,port);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	protected void sendDataForAuthorization() {		
		try {			
			byte[] encodedCert = cert.getEncoded();
			dout.writeInt(encodedCert.length);
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
		try {			
			int length = din.readInt();
			byte[] encodedCert = new byte[length];
			din.read(encodedCert, 0, length);
			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(encodedCert);
			anotherCert = (X509Certificate)certFactory.generateCertificate(in);

			length = din.readInt();
			byte[] signature = new byte[length];
			din.read(signature, 0, length);			
			//System.out.println(publicKey.toString());
			sign.initVerify(anotherCert.getPublicKey());
			System.out.println(anotherCert.getPublicKey());
			sign.update(anotherCert.getEncoded());			
			if(sign.verify(signature)) {
				System.out.println("Signature from client is valid.");
				anotherCert.checkValidity();
				System.out.println("Sertificate is up to date.");
				storageDout.writeUTF(anotherCert.getSubjectDN().toString());
				if(storageDin.readInt() == 0) {
					System.out.println("Sertificate is withdrawn.");
					return false;
				} else {
					System.out.println("Sertificate is ok.");
					return true;
				}
				
			}
			else {
				System.out.println("Signature from client is invalid.");
				return false;
			}					
		} catch ( IOException | CertificateException | InvalidKeyException | SignatureException e) {			
			e.printStackTrace();
		}	
		return false;
	}	
	
	
	protected static void clearFile(String filename) {
		try {
			Files.write(Paths.get(filename),
					(new String()).getBytes(),
					StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	protected void writeToFile(String filename, int x, String sum) {
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
	
	public  Share readFromFile(String filename){
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
					//}
				}
			}
			fileReader.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return share;
	}
	
	public void sendingShare(int allow,String filename) throws IOException{
		dout.writeInt(allow);
		if(allow==1){
		Share share = readFromFile(filename);
		dout.writeInt(share.getX());
		byte[] send = RSA.encrypt(share.getSum().toByteArray(), anotherCert.getPublicKey());
		dout.writeInt(send.length);
		dout.write(send, 0, send.length);
		}
	}

}
