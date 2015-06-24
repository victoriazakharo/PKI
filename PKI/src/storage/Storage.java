package storage;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.Scanner;

import sun.security.x509.CertificateIssuerName;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class Storage {
	private final int CA_PORT = 24,
					  CLIENT_PORT = 640;
	private Socket caSocket;     
	private ServerSocket storageSocket;
    private DataInputStream din;
    private DataOutputStream dout;
    private KeyStore keyStore;
    private CertificateFactory certFactory;
    private PublicKey caPublicKey;
    private final String KEYSTORE_FILE = "storagekeystore.jks",
    		CAKEYSTORE_FILE = "cakeystore.jks",
		     CA_ALIAS = "selfsigned",
		    STORAGE_ALIAS = "selfsigned",
		     SIGN_ALGORITHM = "MD5WithRSA",
		     PASS_ALPHABETH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		     CA_HOST = "127.0.0.1";
    private Random rnd = new Random();
	private Scanner sc = new Scanner(System.in);	
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private X500Name issuer;
    
    public Storage() {
    	try {
			certFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e1) {			
			e1.printStackTrace();
		}
    	//initKeystorageAndCACert();
    	initPrivateInfoFromKeyStorage();
    	try {
    		storageSocket = new ServerSocket(CLIENT_PORT);
			setCASocket(CA_HOST);
		} catch (UnknownHostException e) {			
			e.printStackTrace();
		} catch (IOException e) {			
			e.printStackTrace();
		}
    }
    
    /*private void initKeystorageAndCACert() {
    	System.out.println("Enter keystore password.");
		String keystorePass = sc.nextLine();
		FileInputStream input;
		try {
			input = new FileInputStream(CAKEYSTORE_FILE);
			KeyStore keyStore = KeyStore.getInstance("JKS");
		    keyStore.load(input, keystorePass.toCharArray());
		    input.close();
		    Certificate caCert = keyStore.getCertificate(CA_ALIAS);	
		    caPublicKey = caCert.getPublicKey();
		}  catch (FileNotFoundException | NoSuchAlgorithmException |
				KeyStoreException | CertificateException e) {			
			e.printStackTrace();
		} catch (IOException e) {			
			e.printStackTrace();
		}		
    }*/
    
    
    private void exchangePublicKeys(){
    	try {
    	int len = din.readInt();
		byte[] publicKeyBytes = new byte[len];
		din.readFully(publicKeyBytes, 0, len);
			caPublicKey = KeyFactory.getInstance("RSA")
					.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
			
			publicKeyBytes = getPublicKey().getEncoded();
			dout.writeInt(publicKeyBytes.length);				
				dout.write(publicKeyBytes, 0, publicKeyBytes.length);
				System.out.println("Storage passed public key to CA.");
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public void setCASocket(String host) throws UnknownHostException, IOException {       
        caSocket = new Socket(host, CA_PORT);           
        try {                   
            din = new DataInputStream(caSocket.getInputStream());
            dout = new DataOutputStream(caSocket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
	
    private char[] generateRandomPassword()
    {
    	int length = rnd.nextInt(25) + 5;
        char[] text = new char[length];
        for (int i = 0; i < length; i++)
        {
            text[i] = PASS_ALPHABETH.charAt(rnd.nextInt(PASS_ALPHABETH.length()));
        }
        return text;
    }
    //read CAcertificate
    private void start(){
    	exchangePublicKeys();
    	StorageThread storageThread = new StorageThread(storageSocket, keyStore, privateKey);	
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
		    	sig.update(certBytes);
		    	
		    	if(sig.verify(signatureBytes)) {
		    		InputStream in = new ByteArrayInputStream(certBytes);
		    		X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
		    		keyStore.setCertificateEntry(cert.getSubjectDN().toString(), cert);
		    		File keystoreFile = new File(KEYSTORE_FILE);
		    		FileOutputStream out = new FileOutputStream(keystoreFile);
		    	    keyStore.store(out, "storagepassword".toCharArray());
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
    
    private void initPrivateInfoFromKeyStorage() {
		System.out.println("Enter keystore password.");
		String keystorePass = sc.nextLine();
		System.out.println("Enter storage password.");
		String caPass = sc.nextLine();
		try {
			FileInputStream input = new FileInputStream(KEYSTORE_FILE);
			keyStore = KeyStore.getInstance("JKS");
		    keyStore.load(input, keystorePass.toCharArray());
		    input.close();
		    privateKey = (PrivateKey) keyStore.getKey(CA_ALIAS, caPass.toCharArray());
		    java.security.cert.Certificate caCert = keyStore.getCertificate(STORAGE_ALIAS);
		    publicKey = caCert.getPublicKey();
		    byte[] encoded = caCert.getEncoded();
		    X509CertImpl caCertImpl = new X509CertImpl(encoded);
		    X509CertInfo caCertInfo = (X509CertInfo) caCertImpl.get(X509CertImpl.NAME + "."
		        + X509CertImpl.INFO);
		    issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "."
		        + CertificateIssuerName.DN_NAME);
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException
				| IOException | UnrecoverableKeyException e) {			
			e.printStackTrace();
		}	   
	}
    
    public PrivateKey getPrivateKey() {
		return privateKey;
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}

    
    public static void main(String[] args) {
    	new Storage().start();
    }
}
