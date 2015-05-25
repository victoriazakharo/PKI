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
	protected ServerSocket serverSocket, servSocket;
	protected DataInputStream din, caDin, storageDin;
	protected DataOutputStream dout, caDout, storageDout;
	protected final String CA_HOST = "127.0.0.1", STORAGE_HOST = "127.0.0.1";	
	protected X509Certificate cert;
	protected CertificateFactory certFactory;
	protected PrivateKey privateKey;	
	protected String distinguishedName, host, certName;
	protected PublicKey publicKey;
	protected Signature sign;	
	private boolean authorizationResult;
	
	public Client() {
		authorizationResult=false;
		initServerSocket();
		try {
			sign = Signature.getInstance("MD5WithRSA");
			certFactory = CertificateFactory.getInstance("X.509");			
			caSocket = new Socket(CA_HOST, CA_PORT);
			caDin = new DataInputStream(caSocket.getInputStream());
			caDout = new DataOutputStream(caSocket.getOutputStream());
			storageSocket = new Socket(STORAGE_HOST, STORAGE_PORT);
			storageDin = new DataInputStream(storageSocket.getInputStream());
			storageDout = new DataOutputStream(storageSocket.getOutputStream());
			distinguishedName = getDistinguishedName();
		} catch (IOException | CertificateException | NoSuchAlgorithmException   e) {
			e.printStackTrace();
		}		
		askCertificate();
		initiateThread();
	}
	
	protected void initiateThread() {
		ServerThread serverThread = new ServerThread(serverSocket, cert,
				privateKey);
		serverThread.start();
	}
	
	public void askCertificate() {		
		try {
			caDout.writeUTF(distinguishedName);
			caDout.writeUTF(certName);
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
		certName =String.format("%s %d",  host, clientPort);
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
			din = new DataInputStream(socket.getInputStream()); 
	        dout = new DataOutputStream(socket.getOutputStream());
	        //acceptDataForAuthorization();
		} catch (UnknownHostException e) {			
			e.printStackTrace();
		} catch (IOException e) {			
			e.printStackTrace();
		}
	}
	
	public void start() {
		/*System.out.println("Choose mode:\n 1-Create connection.\n 2-Attach to connection");
		int mode=sc.nextInt();
		if(mode==1)
		{
			try {
				socket = serverSocket.accept();
				din = new DataInputStream(socket.getInputStream());
				dout = new DataOutputStream(socket.getOutputStream());		
				System.out.println("ServerSocket connected.");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
				
			clientWithServerSocketAuthorizationWork();
			System.out.println("ServerSocket connected 2.");
		}
		if(mode==2)
		{
			connectToClient();
			clientWithSocketAuthorizationWork();
		}*/
		
		connectToClient();
		int menu = 1,access = 0;
		try {
			dout.writeUTF(socket.getInetAddress().getHostName());
			dout.writeInt(serverSocket.getLocalPort());
			while (menu == 1) {
				System.out.println("Input 0 - to exit, 1 - to get file");
				menu = sc.nextInt();
				String filename;
				dout.writeInt(menu);
				if (menu == 1) {
					System.out.println("Input filename");
					filename = sc.next();
					dout.writeUTF(filename);
					access = din.readInt();
					System.out.println("Access:"+access);
					if(access==0)
						continue;
					String content= new String(getBytesDecrypted());
					System.out.println(content);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	private byte[] getBytesDecrypted() {
		byte[] out=null;
		try {
		int length = din.readInt();
		out = new byte[length];
			din.read(out, 0, length);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return out;
	}
	
	public void clientWithServerSocketAuthorizationWork(){
		firstClientAuthorization(/*certName*/);
		boolean result=true, authorized=false;
		try
		{
			result=din.readBoolean();
			if(result){
				authorized=secondClientAuthorization();
			}
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
	
	public void clientWithSocketAuthorizationWork(){
		boolean checkResult=acceptDataForAuthorization(), authorized=false;
		try 
		{
			dout.writeBoolean(checkResult);
			if(checkResult)
			{
				System.out.println("Enter host.");
				host = sc.nextLine();
				System.out.println("Enter port number.");
				clientPort = Integer.valueOf(sc.nextLine());
				String certName =String.format("%s %d",  host, clientPort);
				firstClientAuthorization(/*certName*/);
			}
			authorized=din.readBoolean();
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		this.authorizationResult=authorized;
		if(!authorized)
		{
			System.out.println("Authorization failed.");			
		}
		else
		{
			System.out.println("Authorized.");
		}
	}
	
	public void firstClientAuthorization()
	{
		/*try 
		{
			//readCertificate(clientID);
			//readPrivateKey(clientID);
			publicKey=cert.getPublicKey();
		} 
		catch (CertificateException | IOException | InvalidKeySpecException | NoSuchAlgorithmException  e)
		{
			e.printStackTrace();
		}*/
		publicKey=cert.getPublicKey();
		//System.out.println(cert.getEncoded().length);
		byte[] encodedCert;
		try
		{
			int lengthCert=cert.getEncoded().length;
			encodedCert=cert.getEncoded();
			dout.writeInt(lengthCert);
			dout.write(encodedCert);
			
			sign.initSign(privateKey);
		    sign.update(encodedCert);
		    byte[] signature = sign.sign();
		    
		    dout.writeInt(signature.length);
		    dout.write(signature, 0, signature.length);
			
		}
		catch (CertificateEncodingException | IOException | InvalidKeyException | SignatureException e) 
		{
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
	
	private boolean acceptDataForAuthorization() {	
		boolean result=false;
		try {
						
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
			
		} catch ( IOException | CertificateException | SignatureException e) {			
			e.printStackTrace();
		}		
		return result;
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
