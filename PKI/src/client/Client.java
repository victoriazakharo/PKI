package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;


public class Client {
	protected final int CA_PORT = 23, STORAGE_PORT = 25;
	protected int clientPort;
	protected Scanner sc = new Scanner(System.in);
	protected Socket socket; 
	protected DataInputStream din;
	protected DataOutputStream dout;
	protected CertificateFactory certFactory;
	protected X509Certificate cert;
	protected PrivateKey privateKey;
	
	public Client() {
		try {
			certFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e1) {			
			e1.printStackTrace();
		}
		System.out.println("Enter port number.");
		clientPort = sc.nextInt();
		/*try {
			setSocket(InetAddress.getLocalHost().getHostAddress());
		} catch (UnknownHostException e) {			
			e.printStackTrace();
		} catch (IOException e) {			
			e.printStackTrace();
		}*/
	}
	
	public void setSocket(String host) throws UnknownHostException, IOException {       
    	socket = new Socket(host, clientPort);               	
        dout = new DataOutputStream(socket.getOutputStream());
        din = new DataInputStream(socket.getInputStream());       
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
		
	}
}
