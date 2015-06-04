package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import crypto.RSA;

public class Client {
	public static int CA_PORT = 23, STORAGE_PORT = 640;
	public static final int AUTHORIZE = 1, EXIT = 4, GET_FILE = 2, BREAK_CLIENT = 3,SEND_SHARE = 5, GET_SHARE = 6,
			CERTIFICATE_WRITTEN = -1, CERTIFICATE_DENIED = -2, SKIP = 0, ASK_CERTIFICATE = 7;
	protected int clientPort;
	protected Scanner sc = new Scanner(System.in);
	protected Socket socket, caSocket, storageSocket;
	protected ServerSocket serverSocket;
	protected DataInputStream din, caDin, storageDin;
	protected DataOutputStream dout, caDout, storageDout;
	public static final String CA_HOST = "127.0.0.1",
			STORAGE_HOST = "127.0.0.1";
	protected X509Certificate cert,anotherCert;
	protected CertificateFactory certFactory;
	protected PrivateKey privateKey;
	protected String distinguishedName, host, certName;
	protected Signature sign;
	protected PublicKey caPublicKey;

	public Client() {
		try {
			sign = Signature.getInstance("MD5WithRSA");
			certFactory = CertificateFactory.getInstance("X.509");
			storageSocket = new Socket(STORAGE_HOST, STORAGE_PORT);
			storageDin = new DataInputStream(storageSocket.getInputStream());
			storageDout = new DataOutputStream(storageSocket.getOutputStream());			
			initServerSocket();
			
			caSocket = new Socket(CA_HOST, CA_PORT);
			caDin = new DataInputStream(caSocket.getInputStream());
			caDout = new DataOutputStream(caSocket.getOutputStream());
			
			distinguishedName = getDistinguishedName();
		} catch (IOException | CertificateException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return;
		}
		askCertificate();
		initiateThread();
	}
	
	public Client(String host, String port) {
		try {
			sign = Signature.getInstance("MD5WithRSA");
			certFactory = CertificateFactory.getInstance("X.509");
			storageSocket = new Socket(STORAGE_HOST, STORAGE_PORT);
			storageDin = new DataInputStream(storageSocket.getInputStream());
			storageDout = new DataOutputStream(storageSocket.getOutputStream());			
			initServerSocket(host, port);
			
			caSocket = new Socket(CA_HOST, CA_PORT);
			caDin = new DataInputStream(caSocket.getInputStream());
			caDout = new DataOutputStream(caSocket.getOutputStream());
			
			//distinguishedName = getDistinguishedName();
		} catch (IOException | CertificateException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return;
		}
		//askCertificate();
		//initiateThread();
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
			if (answer == CERTIFICATE_WRITTEN) {
				int len = caDin.readInt();
				byte[] publicKeyBytes = new byte[len];
				caDin.readFully(publicKeyBytes, 0, len);
		    	caPublicKey = KeyFactory.getInstance("RSA")
		    			.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		    	X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
		    			publicKeyBytes);
		    	FileOutputStream fos = new FileOutputStream("D://publicCA" + certName + ".key");
				fos.write(x509EncodedKeySpec.getEncoded());
				fos.close();
		    	readCertificateAndPrivateKey();
			} else {
				System.out.println("Certification request denied.");
			}
		} catch (IOException | CertificateException | InvalidKeySpecException
				| NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
	}

	public void askCertificate(String path) {
		try {
			caDout.writeUTF(distinguishedName);
			caDout.writeUTF(certName);
			int answer = caDin.readInt();
			if (answer == CERTIFICATE_WRITTEN) {
				int len = caDin.readInt();
				byte[] publicKeyBytes = new byte[len];
				caDin.readFully(publicKeyBytes, 0, len);
		    	caPublicKey = KeyFactory.getInstance("RSA")
		    			.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		    	X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
		    			publicKeyBytes);
				FileOutputStream fos = new FileOutputStream("D://publicCA" + certName + ".key");
				fos.write(x509EncodedKeySpec.getEncoded());
				fos.close();
		    	readCertificateAndPrivateKey(path);
			} else {
				System.out.println("Certification request denied.");
			}
		} catch (IOException | CertificateException | InvalidKeySpecException
				| NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
	}
	
	protected void initServerSocket() {
		System.out.println("Enter host.");
		host = sc.nextLine();
		System.out.println("Enter port number.");
		clientPort = Integer.valueOf(sc.nextLine());
		certName = String.format("%s %d", host, clientPort);
		try {
			serverSocket = new ServerSocket(clientPort);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	protected void initServerSocket(String host, String port) {
		this.host = host;
		this.clientPort = Integer.valueOf(port);
		certName = String.format("%s %d", this.host, this.clientPort);
		try {
			serverSocket = new ServerSocket(clientPort);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	protected void connectToClient() {
		System.out.println("Enter host.");
		String host = sc.nextLine();
		System.out.println("Enter port number.");
		int port = Integer.valueOf(sc.nextLine());
		try {
			socket = new Socket(host, port);
			din = new DataInputStream(socket.getInputStream());
			dout = new DataOutputStream(socket.getOutputStream());
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	protected void connectToClient(String hostString, String portString) {
		String host = hostString;
		int port = Integer.valueOf(portString);
		try {
			socket = new Socket(host, port);
			din = new DataInputStream(socket.getInputStream());
			dout = new DataOutputStream(socket.getOutputStream());
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	protected String getFile(String filename)
	{
		int access=0;
		try {
			dout.writeInt(GET_FILE);
			//dout.writeUTF(host);
			//dout.writeInt(clientPort);
			//dout.writeInt(GET_FILE);
			dout.writeUTF(filename);
			access = din.readInt();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//System.out.println("Access:"+access);
		if(access==0)
			return "";
		String content= new String(getBytesDecrypted());
		return content;
	}
	
	protected void authorize() {
		boolean accepted = false, authorized = false;
		try {
			dout.writeInt(AUTHORIZE);
			accepted = acceptDataForAuthorization();
			dout.writeBoolean(accepted);
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (accepted) {
			firstClientAuthorization();
			try {
				authorized = din.readBoolean();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		System.out
				.println(authorized ? "Authorized." : "Authorization failed.");
	}

	protected boolean authorizeClient() {
		boolean accepted = false, authorized = false;
		try {
			dout.writeInt(AUTHORIZE);
			accepted = acceptDataForAuthorization();
			dout.writeBoolean(accepted);
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (accepted) {
			firstClientAuthorization();
			try {
				authorized = din.readBoolean();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return authorized;
	}
	protected void writeHostAndPort(){
		try {
			dout.writeUTF(host);
			dout.writeInt(clientPort);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
	public void start() {
		int choice = AUTHORIZE;
		String filename;
		int access = 0;
		while (choice != EXIT) {
			System.out.println(String.format(
					"Enter\n%d to attach to some other client\n%d to ask certificate\n%d to exit.",
					AUTHORIZE, ASK_CERTIFICATE, EXIT));
			choice = Integer.valueOf(sc.nextLine());
			if(choice == ASK_CERTIFICATE) {
				askCertificate();
			} else if(choice == SKIP){
				try {
					Thread.sleep(20000);
					continue;
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			if (choice == AUTHORIZE) {
				connectToClient();
				authorize();
				try {
					dout.writeUTF(host);
					dout.writeInt(clientPort);
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				while (choice != BREAK_CLIENT) {
					System.out.println(String.format(
							"Enter\n%d to break client\n%d to get file.",
							BREAK_CLIENT, GET_FILE));
					choice = sc.nextInt();
					// add your commands for sharing keys
					if(choice == SKIP){
						try {
							Thread.sleep(20000);
							continue;
						} catch (InterruptedException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					try {
						if (choice == GET_FILE) {
							dout.writeInt(GET_FILE);
							System.out.println("Input filename");
							filename = sc.next();
							dout.writeUTF(filename);
							access = din.readInt();
							System.out.println("Access:"+access);
							if(access==0)
								continue;
							String content= new String(getBytesDecrypted());
							System.out.println(content);
							// for Maria
						} else if (choice == BREAK_CLIENT) {
							dout.writeInt(BREAK_CLIENT);
						}
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
		}

	}
	
	
	protected byte[] getBytesDecrypted() {
		byte[] out=null;
		try {
			int length = din.readInt();
			byte[] read = new byte[length];
			din.read(read, 0, length);
			length = din.readInt();
			byte[] sign = new byte[length];
			din.read(sign, 0, length);
			
			if(RSA.checkSignature(read, sign, anotherCert.getPublicKey())) {
				System.out.println("Signature from client is valid.");
				anotherCert.checkValidity();
				System.out.println("Sertificate is up to date.");
				storageDout.writeUTF(anotherCert.getSubjectDN().toString());
				if(storageDin.readInt() == 0) {
					System.out.println("Sertificate is withdrawn.");
				} else {
					System.out.println("Sertificate is ok.");
					out = RSA.decrypt(read, privateKey);
				}
			}
			else {
				System.out.println("Signature from client is invalid.");
			}		
		} catch (IOException | CertificateExpiredException | CertificateNotYetValidException e) {
			e.printStackTrace();
		}
		return out;
	}

	public void firstClientAuthorization() {
		try {
			byte[] encodedCert = cert.getEncoded();
			dout.writeInt(encodedCert.length);
			dout.write(encodedCert);
			
			sign.initSign(privateKey);
			sign.update(encodedCert);
			byte[] signature = sign.sign();

			dout.writeInt(signature.length);
			dout.write(signature, 0, signature.length);
		} catch (CertificateEncodingException | IOException
				| InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
	}

	protected boolean acceptDataForAuthorization() {
		try {
			int length = din.readInt();
			byte[] encodedCert = new byte[length];
			din.read(encodedCert, 0, length);
			InputStream in = new ByteArrayInputStream(encodedCert);
			anotherCert = (X509Certificate) certFactory.generateCertificate(in);

			length = din.readInt();
			byte[] signature = new byte[length];
			din.read(signature, 0, length);
			// System.out.println(publicKey.toString());
			try {
				sign.initVerify(anotherCert.getPublicKey());
				sign.update(anotherCert.getEncoded());
			} catch (InvalidKeyException | SignatureException e) {
				e.printStackTrace();
			}
			if (sign.verify(signature)) {
				System.out.println("Signature from client is valid.");
				anotherCert.checkValidity();
				System.out.println("Sertificate is up to date.");
				storageDout.writeUTF(distinguishedName);							
				if (storageDin.readInt() == 0) {
					System.out.println("Sertificate is withdrawn.");
					return false;
				} else {
					System.out.println("Sertificate is ok.");
					return true;
				}
			} else {
				System.out.println("Signature from client is invalid.");
				return false;
			}

		} catch (IOException | CertificateException | SignatureException e) {
			e.printStackTrace();
		}
		return false;
	}

	public void readCertificateAndPrivateKey() throws IOException, CertificateException,
	NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		String id = String.format("%s %d", host, clientPort);
		System.out.println("Enter path to certificate ");
		String path = sc.nextLine();
		String certFilename = String.format("%scert%s.cer", path, id),
				keyFileName = String.format("%sprivate%s.key", path, id),
				signFileName = String.format("%ssign%s.key", path, id);
		FileInputStream fis = new FileInputStream(signFileName);
		byte signature[] = new byte[fis.available()];
		fis.read(signature);		
		fis.close();
		
		fis = new FileInputStream(String.format("D://publicCA" + certName + ".key"));
		byte publicKeyBytes[] = new byte[fis.available()];
		fis.read(publicKeyBytes);		
		fis.close();
		caPublicKey = KeyFactory.getInstance("RSA")
    			.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		
		sign.initVerify(caPublicKey);
		sign.update(distinguishedName.getBytes());
		if(sign.verify(signature)) {		
			fis = new FileInputStream(certFilename);
			byte encodedCertificate[] = new byte[fis.available()];
			fis.read(encodedCertificate);
			ByteArrayInputStream bais = new ByteArrayInputStream(encodedCertificate);
			cert = (X509Certificate) certFactory.generateCertificate(bais);
			fis.close();
			
			fis = new FileInputStream(keyFileName);
			byte[] encodedPrivateKey = new byte[(int)new File(keyFileName).length()];
			fis.read(encodedPrivateKey);
			fis.close();
	
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
					encodedPrivateKey);
			privateKey = keyFactory.generatePrivate(privateKeySpec);
		} else {
			System.out.println("Source not trusted. Private key and certificate are not received.");
		}
	}

	public void readCertificateAndPrivateKey(String path) throws IOException, CertificateException,
	NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		String id = String.format("%s %d", host, clientPort);
		String certFilename = String.format("%scert%s.cer", path, id),
				keyFileName = String.format("%sprivate%s.key", path, id),
				signFileName = String.format("%ssign%s.key", path, id);
		FileInputStream fis = new FileInputStream(signFileName);
		byte signature[] = new byte[fis.available()];
		fis.read(signature);		
		fis.close();
		fis = new FileInputStream(String.format("D://publicCA" + certName + ".key"));
		byte publicKeyBytes[] = new byte[fis.available()];
		fis.read(publicKeyBytes);		
		fis.close();
		caPublicKey = KeyFactory.getInstance("RSA")
    			.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		
		sign.initVerify(caPublicKey);
		sign.update(distinguishedName.getBytes());
		if(sign.verify(signature)) {		
			fis = new FileInputStream(certFilename);
			byte encodedCertificate[] = new byte[fis.available()];
			fis.read(encodedCertificate);
			ByteArrayInputStream bais = new ByteArrayInputStream(encodedCertificate);
			cert = (X509Certificate) certFactory.generateCertificate(bais);
			fis.close();
			
			fis = new FileInputStream(keyFileName);
			byte[] encodedPrivateKey = new byte[(int)new File(keyFileName).length()];
			fis.read(encodedPrivateKey);
			fis.close();
	
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
					encodedPrivateKey);
			privateKey = keyFactory.generatePrivate(privateKeySpec);
		} else {
			System.out.println("Source not trusted. Private key and certificate are not received.");
		}
	}

	protected String getDistinguishedName() {
		String CN, OU, O, L, ST, C;
		System.out.println("Enter your name.");
		CN = sc.nextLine();
		System.out.println("Enter your organization unit.");
		OU = sc.nextLine();
		System.out.println("Enter your organization name.");
		O = sc.nextLine();
		System.out.println("Enter your locality (city) name.");
		L = sc.nextLine();
		System.out.println("Enter your state name.");
		ST = sc.nextLine();
		System.out.println("Enter your country name.");
		C = sc.nextLine();
		return String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", CN, OU,
				O, L, ST, C);
	}

	protected void setDistinguishedName(String CN, String OU,String O,String L,String ST,String C) {
		this.distinguishedName= String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", CN, OU,
				O, L, ST, C);
	}
	
	public static void main(String[] args) {
		Client client = new Client();
		client.start();
	}
}
