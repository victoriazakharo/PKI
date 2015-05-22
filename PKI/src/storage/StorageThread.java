package storage;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.KeyStore;

public class StorageThread extends Thread{
	private ServerSocket storageSocket;
	private KeyStore keyStore;
	
	public StorageThread(ServerSocket storageSocket, KeyStore keyStore) {
		this.storageSocket = storageSocket;
		this.keyStore = keyStore;
	}
	
    public void run() {
    	while(true) {
	    	try {		
				ClientThread clientThread = new ClientThread(storageSocket.accept(), keyStore);
				clientThread.start();	
			} catch (IOException e) {			
				e.printStackTrace();
			}	
    	}
    }
}
