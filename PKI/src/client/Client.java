package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.Scanner;


public class Client {
	protected final int CA_PORT = 23, STORAGE_PORT = 25;
	protected int clientPort;
	protected Scanner sc = new Scanner(System.in);
	protected Socket socket, CASocket; 
	private ServerSocket serverSocket;
	private DataInputStream din, CAdin;
	private DataOutputStream dout, CAdout;
	protected CertificateFactory certFactory;
	protected X509Certificate cert;
	protected PrivateKey privateKey;
	protected PublicKey publicKey;
	private Signature sign;
	private int mode;
	private String distinguishedName;
	public Client() {
		try {
			sign=Signature.getInstance("MD5WithRSA");
			CASocket=new Socket("127.0.0.1", CA_PORT);
			CAdin = new DataInputStream(CASocket.getInputStream());
			CAdout = new DataOutputStream(CASocket.getOutputStream());
			distinguishedName=getDistinguishedName(CAdout);
		} catch (NoSuchAlgorithmException | IOException   e) {
			e.printStackTrace();
		}
		try {
			certFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e1) {			
			e1.printStackTrace();
		}
		//readCertificate();
		chooseMode();
		sc.next();
		/*try {
			setSocket(InetAddress.getLocalHost().getHostAddress());
		} catch (UnknownHostException e) {			
			e.printStackTrace();
		} catch (IOException e) {			
			e.printStackTrace();
		}*/
	}
	
	public void chooseMode()
	{
		this.mode=1;
		System.out.println("Choose mode:\n 1-Create connection.\n 2-Attach to connection");
		mode=sc.nextInt();
		System.out.println("Enter port number.");
		clientPort = sc.nextInt();
		if(mode!=1)
		{
			mode=2;
			try 
			{
				socket=new Socket("127.0.0.1", clientPort);
				din = new DataInputStream(socket.getInputStream());
				dout = new DataOutputStream(socket.getOutputStream());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println("Connected.");
			clientWithSocketAuthorizationWork();
		}
		else
		{
			try {
				serverSocket=new ServerSocket(clientPort);
				System.out.println("ServerSocket created.");
				socket=serverSocket.accept();
				System.out.println("Client connected.");
				din = new DataInputStream(socket.getInputStream());
				dout = new DataOutputStream(socket.getOutputStream());
				clientWithServerSocketAuthorizationWork();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
	}
	
	public void clientWithServerSocketAuthorizationWork(){
		System.out.println("Enter ID:");
		int clientID=sc.nextInt();
		try 
		{
			readCertificate(clientID);
			readPrivateKey(clientID);
			publicKey=cert.getPublicKey();
		} 
		catch (CertificateException | IOException | InvalidKeySpecException | NoSuchAlgorithmException  e)
		{
			e.printStackTrace();
		}
		
		byte[] encodedCert;
		try {
			int lengthCert=cert.getEncoded().length;
			encodedCert=cert.getEncoded();
			dout.writeInt(lengthCert);
			dout.write(encodedCert);
			
			sign.initSign(privateKey);
		    sign.update(encodedCert);
		    byte[] signature = sign.sign();
		    
		    dout.writeInt(signature.length);
			dout.write(signature, 0, signature.length);
			System.out.println("Signature written.");
			System.out.println(new String(signature));
			
		} catch (CertificateEncodingException | IOException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}
	
	
	public void clientWithSocketAuthorizationWork(){
		System.out.println("Enter ID:");
		int clientID=sc.nextInt();		
		byte[] encodedCert;
		byte[] signature;
		try {
			int signLength=0;
			int length=din.readInt();
			encodedCert=new byte[length];
			din.readFully(encodedCert, 0, length);
			cert=getCertificateFromByteArray(encodedCert);
			try
			{
				signLength=din.readInt();
				signature=new byte[signLength];
				din.read(signature, 0, signLength);
				//System.out.println(new String(signature));
				publicKey=cert.getPublicKey();
				readPublicKey(clientID);
				System.out.println(publicKey.toString());
				sign.initVerify(publicKey);
				sign.update(signature);
				boolean result=sign.verify(signature);
				if(result==true){
					System.out.println("Is valid.");
					cert.checkValidity();
					System.out.println("Certificate in use.");
				}
				else
				{
					System.out.println("Invalid.");
				}
				
			} catch (InvalidKeyException | SignatureException | InvalidKeySpecException | NoSuchAlgorithmException | CertificateExpiredException | CertificateNotYetValidException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		} catch ( IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}
	
	
	public X509Certificate getCertificateFromByteArray(byte[] bytes)
	{
		X509Certificate result=null;
		ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
		try 
		{
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			result=(X509Certificate)certFactory.generateCertificate(bais);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
		
	}
	public void readCertificate(int ID) throws IOException, CertificateException{
		FileInputStream fis = null;
		 ByteArrayInputStream bais = null;
		 fis = new FileInputStream("D://cert"+ID+".cer");
		  
		  // read the bytes
		  byte value[] = new byte[fis.available()];
		  fis.read(value);
		  bais = new ByteArrayInputStream(value);
		  
		  // get X509 certificate factory
		  CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		   
		  // certificate factory can now create the certificate 
		  cert=(X509Certificate)certFactory.generateCertificate(bais);
		  fis.close();
		 
	}
	
	public void readPrivateKey(int ID) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException{
		File filePrivateKey = new File("D://private"+ID+".key");
		FileInputStream fis = new FileInputStream("D://private"+ID+".key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		privateKey = keyFactory.generatePrivate(privateKeySpec);
		
	}
	
	public void readPublicKey(int ID) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException{
		File filePrivateKey = new File("D://public"+ID+".key");
		FileInputStream fis = new FileInputStream("D://public"+ID+".key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPrivateKey);
		publicKey = keyFactory.generatePublic(publicKeySpec);
		System.out.println(publicKey.toString());
		
	}
	
	public void setSocket(String host) throws UnknownHostException, IOException {       
    	socket = new Socket(host, clientPort);               	
        dout = new DataOutputStream(socket.getOutputStream());
        din = new DataInputStream(socket.getInputStream());       
    }
	
	protected String getDistinguishedName(DataOutputStream out) {
		String CN="", OU="", O="", L="", ST="", C="";
		try
		{
		System.out.println("Enter your name.");
		CN = sc.nextLine();
		out.writeUTF(CN);
		System.out.println("Enter your organization unit.");
		OU = sc.nextLine();
		out.writeUTF(OU);
		System.out.println("Enter your organiztion name.");
		O = sc.nextLine();
		out.writeUTF(O);
		System.out.println("Enter your locality (city) name.");
		L = sc.nextLine();
		out.writeUTF(L);
		System.out.println("Enter your state name.");
		ST = sc.nextLine();		
		out.writeUTF(ST);
		System.out.println("Enter your country name.");
		C = sc.nextLine();
		out.writeUTF(C);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String result=String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", CN, OU, O, L, ST, C);		
		
		return result;
	}
	
	public static void main(String[] args) {
		Client client = new Client();
		
	}
}
