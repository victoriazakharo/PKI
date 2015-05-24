package client;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import client.ClientThread;

public class ServerThread extends Thread {	
	private ServerSocket socket;
	private X509Certificate cert;
	private PrivateKey privateKey;
	
	public ServerThread(ServerSocket socket, X509Certificate cert, PrivateKey privateKey) {
		this.socket = socket;
		this.cert = cert;
		this.privateKey = privateKey;
	}
	
	public void run() {
		while(true) {
	    	try {		
				ClientThread clientThread = new ClientThread(socket.accept(), cert, privateKey);
				clientThread.start();	
			} catch (IOException e) {			
				e.printStackTrace();
			}	
    	}
	}
}
