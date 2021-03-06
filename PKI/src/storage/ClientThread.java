package storage;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import crypto.RSA;

public class ClientThread extends Thread {
	 private DataOutputStream dout;	
	 private DataInputStream din;
	 private KeyStore keyStore;
	 private PrivateKey privateKey;
	 private Socket socket;
	 
	 public ClientThread(Socket s, KeyStore keyStore, PrivateKey privateKey) throws IOException 
	 {		
		this.socket=s;
		dout = new DataOutputStream(socket.getOutputStream());
		din = new DataInputStream(socket.getInputStream());
		this.privateKey = privateKey;
		this.keyStore = keyStore;
	 }
	 
	 public Socket getSocket(){
			return this.socket;
	}
	 public void run() {
		String alias;	 
		try {
			while((alias = din.readUTF()) != null) {	
				System.out.println("Got request from client.");
				X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
				Integer answer = 0;
				if(cert == null) {					
					answer=0;
					
				} else {				
					answer=1;				
				}
				
				dout.writeInt(answer);
				byte[] ans=new byte[8];
				ans[0]=answer.byteValue();
				byte[] sign = RSA.sign(ans,privateKey);
				dout.write(sign.length);
				dout.write(sign);
			}
		} 
		catch(SocketException ex){
			try {
				din.close();
				dout.close();
				socket.close();
				System.out.println("Client disconnected.");
				this.interrupt();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		catch (IOException | KeyStoreException e) {			
			e.printStackTrace();
		}		
	 }
}
