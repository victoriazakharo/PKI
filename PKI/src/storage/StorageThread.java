package storage;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.security.PrivateKey;

public class StorageThread extends Thread{
	private ServerSocket storageSocket;
	private KeyStore keyStore;
	private PrivateKey privateKey;
	
	public StorageThread(ServerSocket storageSocket, KeyStore keyStore, PrivateKey privateKey) {
		this.storageSocket = storageSocket;
		this.keyStore = keyStore;
		this.privateKey = privateKey;
	}
	
    public void run() {
    	while(true) {
	    	try {		
				ClientThread clientThread = new ClientThread(storageSocket.accept(), keyStore, privateKey);
				clientThread.start();	
			} catch (IOException e) {			
				e.printStackTrace();
			}	
    	}
    }
}
