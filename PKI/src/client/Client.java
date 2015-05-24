package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

public class Client {
	protected final int CA_PORT = 23, STORAGE_PORT = 25;
	protected int clientPort;
	protected Scanner sc = new Scanner(System.in);
	protected Socket socket, caSocket, storageSocket; 
	protected ServerSocket serverSocket;
	protected DataInputStream din, caDin, storageDin;
	protected DataOutputStream dout, caDout, storageDout;
	protected final String CA_HOST = "127.0.0.1", STORAGE_HOST = "127.0.0.1";	
	protected X509Certificate cert;
	protected CertificateFactory certFactory;
	protected PrivateKey privateKey;	
	protected String distinguishedName, host;	
	
	public Client() {
		initServerSocket();
		try {
			certFactory = CertificateFactory.getInstance("X.509");			
			caSocket = new Socket(CA_HOST, CA_PORT);
			caDin = new DataInputStream(caSocket.getInputStream());
			caDout = new DataOutputStream(caSocket.getOutputStream());
			storageSocket = new Socket(STORAGE_HOST, STORAGE_PORT);
			storageDin = new DataInputStream(storageSocket.getInputStream());
			storageDout = new DataOutputStream(storageSocket.getOutputStream());
			distinguishedName = getDistinguishedName();
		} catch (IOException | CertificateException   e) {
			e.printStackTrace();
		}		
		askCertificate();
		ServerThread serverThread = new ServerThread(serverSocket, cert, privateKey);
		serverThread.start();
	}
	
	public void askCertificate() {		
		try {
			caDout.writeUTF(distinguishedName);
			int answer = caDin.readInt();
			if(answer == 1) {
				readCertificate();
				readPrivateKey();				
			} else {
				System.out.println("Certification request denied.");
			}
		} catch (IOException | CertificateException | InvalidKeySpecException |
				NoSuchAlgorithmException e) {			
			e.printStackTrace();
		}			
	}
	
	private void initServerSocket() {
		System.out.println("Enter host.");
		host = sc.nextLine();
		System.out.println("Enter port number.");
		clientPort = Integer.valueOf(sc.nextLine());
		try {
			serverSocket = new ServerSocket(clientPort);
		} catch (IOException e) {		
			e.printStackTrace();
		} 
	}	
	
	private void connectToClient() {
		System.out.println("Enter host.");
		String host = sc.nextLine();
		System.out.println("Enter port number.");
		int port = sc.nextInt();
		try {
			socket = new Socket(host, port);               	
	        dout = new DataOutputStream(socket.getOutputStream());
	        din = new DataInputStream(socket.getInputStream()); 
	        acceptDataForAuthorization();
		} catch (UnknownHostException e) {			
			e.printStackTrace();
		} catch (IOException e) {			
			e.printStackTrace();
		}
	}
	
	public void start() {
		// menu
	}
	
	private void acceptDataForAuthorization() {	
		try {
			Signature sign = Signature.getInstance("MD5WithRSA");			
			int length = din.readInt();
			byte[] encodedCert = new byte[length];
			din.read(encodedCert, 0, length);			
			InputStream in = new ByteArrayInputStream(encodedCert);
			cert = (X509Certificate)certFactory.generateCertificate(in);
			
			int signLength = din.readInt();
			byte[] signature = new byte[signLength];
				din.read(signature, 0, signLength);	
				//System.out.println(publicKey.toString());
				try {
					sign.initVerify(cert.getPublicKey());
					sign.update(cert.getEncoded());				
				} catch (InvalidKeyException | SignatureException e) {
					e.printStackTrace();
				}
				if(sign.verify(signature)) {
					System.out.println("Signature from client is valid.");
					cert.checkValidity();
					storageDout.writeUTF(distinguishedName);
					if(storageDin.readInt() == 0) {
						System.out.println("Sertificate is withdrawn.");
					} else {
						System.out.println("Sertificate is ok.");
					}
				}
				else {
					System.out.println("Signature from client is invalid.");
				}				
			
		} catch ( IOException | CertificateException | NoSuchAlgorithmException
				| SignatureException e) {			
			e.printStackTrace();
		}		
	}	
	
	public void readCertificate() throws IOException, CertificateException{	
		String id = String.format("%s %d",  host, clientPort);
		String file = String.format("D://cert%s.cer", id);
		FileInputStream fis = new FileInputStream(file);		  
		byte encodedCertificate[] = new byte[fis.available()];
		fis.read(encodedCertificate);
		ByteArrayInputStream bais = new ByteArrayInputStream(encodedCertificate); 
		cert = (X509Certificate)certFactory.generateCertificate(bais);
		fis.close();		 
	}
	
	public void readPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException{
		String id = String.format("%s %d",  host, clientPort);
		String file = String.format("D://private%s.key", id);
		File filePrivateKey = new File(file);
		FileInputStream fis = new FileInputStream(file);
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		privateKey = keyFactory.generatePrivate(privateKeySpec);
	}
	
	protected String getDistinguishedName() {
		String CN, OU, O, L, ST, C;		
		System.out.println("Enter your name.");
		CN = sc.nextLine();
		System.out.println("Enter your organization unit.");
		OU = sc.nextLine();
		System.out.println("Enter your organiztion name.");
		O = sc.nextLine();
		System.out.println("Enter your locality (city) name.");
		L = sc.nextLine();
		System.out.println("Enter your state name.");
		ST = sc.nextLine();	
		System.out.println("Enter your country name.");
		C = sc.nextLine();
		return String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", CN, OU, O, L, ST, C);
	}
	
	public static void main(String[] args) {
		Client client = new Client();	
		client.start();
	}
}
