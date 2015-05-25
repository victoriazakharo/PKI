package ca;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Scanner;
import java.math.BigInteger;
import java.net.ServerSocket;

import sun.security.x509.*;

public class CA {
	private X500Name issuer;
	private ServerSocket storageSocket, clientSocket;
	private StorageThread storageThread;
	private PrivateKey privateKey;	
	private KeyStore keyStore;
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public KeyStore getKeyStore()
	{
		return keyStore;
	}
	
	private Scanner sc = new Scanner(System.in);	
	public static String KEYSTORE_FILE = "cakeystore.jks",
					     CA_ALIAS = "selfsigned",
					     SIGN_ALGORITHM = "MD5WithRSA";
	
	private final int STORAGE_PORT = 24,
					  CLIENT_PORT = 23,
				      EXPIRE_DAYS = 360;	
	
	public CA() {		
		try {
			storageSocket = new ServerSocket(STORAGE_PORT);
			clientSocket = new ServerSocket(CLIENT_PORT);
		} catch (IOException e) {			
			e.printStackTrace();
			return;
		}			
		initPrivateInfoFromKeyStorage();		
	}
	
	public void start() {
		try {		
			storageThread = new StorageThread(storageSocket.accept(), this);
			storageThread.start();	
		} catch (IOException e) {			
			e.printStackTrace();
		}			
		while (true) 
		{		
			try {
				new ClientThread(clientSocket.accept(), this).start();
				System.out.println("Client connected.");
			} catch (IOException e) {				
				e.printStackTrace();
			}				
		}
	}
	
	public Scanner getScanner() {
		return sc;
	}	
	
	public void writeCertificateToStorage(X509Certificate cert) {
		storageThread.storeCertificate(cert);
		System.out.println("Sertificate written to StorageThread");
	}	
	
	public void writeCertificateToStorage(X509Certificate cert, String alias) {
		storageThread.storeCertificate(cert);
		try {
			keyStore.setCertificateEntry(alias, cert);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}	
	
	public boolean containsCertificate(X509Certificate cert) {
		return storageThread.hasCertificate(cert);
	}
	// self signed certificate was created with command "keytool -genkey
	// -keyalg RSA -alias selfsigned -keystore cakeystore.jks -storepass
	// capassword -validity 360 -keysize 2048"	
	private void initPrivateInfoFromKeyStorage() {
		System.out.println("Enter keystore password.");
		String keystorePass = sc.nextLine();
		System.out.println("Enter CA password.");
		String caPass = sc.nextLine();
		try {
			FileInputStream input = new FileInputStream(KEYSTORE_FILE);
			keyStore = KeyStore.getInstance("JKS");
		    keyStore.load(input, keystorePass.toCharArray());
		    input.close();
		    privateKey = (PrivateKey) keyStore.getKey(CA_ALIAS, caPass.toCharArray());
		    Certificate caCert = keyStore.getCertificate(CA_ALIAS);
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
	
	public X509Certificate createCertificate(PublicKey subjectKey, String dn) {
		X509CertImpl cert = null;
		if(subjectKey != null) {
			X500Name subject = null;
			  try {
				subject = new X500Name(dn);
			} catch (IOException e) {			
				e.printStackTrace();
			}
			X509CertInfo info = new X509CertInfo();
			Date from = new Date();
			Date to = new Date(from.getTime() + EXPIRE_DAYS * 86400000l);
			CertificateValidity interval = new CertificateValidity(from, to);
			BigInteger sn = new BigInteger(64, new SecureRandom());		  
			
			try {
			  info.set(X509CertInfo.VALIDITY, interval);
			  info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
			  info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subject));
			  info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
			  info.set(X509CertInfo.KEY, new CertificateX509Key(subjectKey));
			  info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
			  AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
			  info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
			 
			  // Sign the certificate to identify the algorithm that's used.
			  cert = new X509CertImpl(info);
			  cert.sign(privateKey, SIGN_ALGORITHM);
			 
			  // Update the algorithm and resign.
			  algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
			  info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
			  cert = new X509CertImpl(info);		  
			  cert.sign(privateKey, SIGN_ALGORITHM);		  
			} catch (CertificateException | IOException | InvalidKeyException |
					NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {			
				e.printStackTrace();
			}		 
		}
		return cert;
	}
	
	public static void main(String[] args) {
		new CA().start();
	}
}
