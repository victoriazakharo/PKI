package storage;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Random;
import java.util.Scanner;

public class Storage {
	private final int CA_PORT = 24,
					  CLIENT_PORT = 25;
	private Socket caSocket;     
	private ServerSocket storageSocket;
    private DataInputStream din;
    private KeyStore keyStore;
    private CertificateFactory certFactory;
    private PublicKey caPublicKey;
    private final String KEYSTORE_FILE = "cakeystore.jks",
		     CA_ALIAS = "selfsigned",
		     SIGN_ALGORITHM = "MD5WithRSA",
		     PASS_ALPHABETH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private Random rnd = new Random();
	private Scanner sc = new Scanner(System.in);	
    
    public Storage() {
    	try {
			certFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e1) {			
			e1.printStackTrace();
		}
    	initKeystorageAndCACert();
    	try {
    		storageSocket = new ServerSocket(CLIENT_PORT);
			setCASocket(InetAddress.getLocalHost().getHostAddress());
		} catch (UnknownHostException e) {			
			e.printStackTrace();
		} catch (IOException e) {			
			e.printStackTrace();
		}
    }
    
    private void initKeystorageAndCACert() {
    	System.out.println("Enter keystore password.");
		String keystorePass = sc.nextLine();
		FileInputStream input;
		try {
			input = new FileInputStream(KEYSTORE_FILE);
			keyStore = KeyStore.getInstance("JKS");
		    keyStore.load(input, keystorePass.toCharArray());
		    input.close();
		    java.security.cert.Certificate caCert = keyStore.getCertificate(CA_ALIAS);	
		    caPublicKey = caCert.getPublicKey();
		}  catch (FileNotFoundException | NoSuchAlgorithmException |
				KeyStoreException | CertificateException e) {			
			e.printStackTrace();
		} catch (IOException e) {			
			e.printStackTrace();
		}		
    }
    
    public void setCASocket(String host) throws UnknownHostException, IOException {       
        caSocket = new Socket(host, CA_PORT);           
        try {                   
            din = new DataInputStream(caSocket.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
	
    private char[] generateRandomPassword()
    {
    	int length = rnd.nextInt() % 20 + 5;
        char[] text = new char[length];
        for (int i = 0; i < length; i++)
        {
            text[i] = PASS_ALPHABETH.charAt(rnd.nextInt(PASS_ALPHABETH.length()));
        }
        return text;
    }
    
    private void start(){
    	StorageThread storageThread = new StorageThread(storageSocket, keyStore);	
    	storageThread.start();
	    while(true) {
	    	int len;
			try {
				len = din.readInt();
				byte[] signatureBytes = new byte[len];
				din.readFully(signatureBytes, 0, len); 
				len = din.readInt();
				byte[] certBytes = new byte[len];
		    	din.readFully(certBytes, 0, len); 
		    	
		    	Signature sig = Signature.getInstance(SIGN_ALGORITHM);
		    	sig.initVerify(caPublicKey);
		    	sig.update(signatureBytes);
		    	
		    	if(sig.verify(signatureBytes)) {
		    		InputStream in = new ByteArrayInputStream(certBytes);
		    		X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
		    		keyStore.setCertificateEntry(cert.getIssuerDN().toString(), cert);
		    		File keystoreFile = new File(KEYSTORE_FILE);
		    		FileOutputStream out = new FileOutputStream(keystoreFile);
		    	    keyStore.store(out, generateRandomPassword());
		    	    out.close();
		    	}
		    	
			} catch (IOException | NoSuchAlgorithmException | 
					InvalidKeyException | SignatureException |
					CertificateException | KeyStoreException e) {				
				e.printStackTrace();
				break;
			} 	    	
	    }
    }
    
    public static void main(String[] args) {
    	new Storage().start();
    }
}
