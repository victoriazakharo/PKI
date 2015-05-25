package resourceStorage;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import crypto.AES;
import crypto.RSA;
import crypto.Shamir;
import crypto.Shamir.Share;

public class ServerThread extends Thread{
	private DataInputStream din;
	private DataOutputStream dout;
	private X509Certificate thisCert;
	private PrivateKey privateKey;
	
	private HashMap<String, List<List<Integer>>> accessMap;
	private int clientResId;
	
	
	public ServerThread(Socket s, X509Certificate thisCert, PrivateKey privateKey, HashMap<String, List<List<Integer>>> accessMap){
		this.thisCert = thisCert;
		this.privateKey = privateKey;
		this.accessMap = accessMap;
		try {
			dout = new DataOutputStream(s.getOutputStream());
			din = new DataInputStream(s.getInputStream());
		} catch (IOException e) {			
			e.printStackTrace();
		}	
	}
	
	@Override
	public void run() {
		sendDataForAuthorization();
		//TODO get data for auth
		int menu = 1;
		try{
			getClientID(din.readUTF(),din.readInt());
		while (menu==1) {
			menu = din.readInt();
			if(menu == 1){
				sendFile();
			}
		}
		}catch(IOException e){
			e.printStackTrace();
		}
	}
	
	private void sendDataForAuthorization() {		
		try {
			int lengthCert = thisCert.getEncoded().length;
			byte[] encodedCert = thisCert.getEncoded();
			dout.writeInt(lengthCert);
			dout.write(encodedCert);
			
			byte[] signature = RSA.sign(encodedCert, privateKey);
		    
		    dout.writeInt(signature.length);
			dout.write(signature, 0, signature.length);
			System.out.println("Signature written.");
			
		} catch (CertificateEncodingException | IOException e) {		
			e.printStackTrace();
		}		
	}
	
	public void getClientID(String host, int port){
		try {
			BufferedReader fileReader = new BufferedReader(new FileReader(
					"resources\\clients.txt"));
			String str;
			while ((str = fileReader.readLine()) != null) {
				String[] parts = str.split(" ");
				if (parts[1].equals(host) && Integer.valueOf(parts[2]).equals(port)) {
					clientResId = Integer.valueOf(parts[0]);
					break;
				}
			}
			fileReader.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void sendFile() {
		try {
			String filename = din.readUTF();
			getAccessToFile(filename, clientResId);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void getAccessToFile(String filename, Integer clientId) {
		try {
			List<Integer> accessList = getAccessToFileList(filename, clientId);
			if (accessList == null || accessList.size() < 2) {
				dout.writeInt(0); //no access
				return;
			}
			int needed = accessList.get(0);
			byte[] message = null;
			if (needed == 1) {
				message = Files.readAllBytes(Paths.get("resources\\documents\\"
						+ filename));
			} else if (needed > 1) {
				message = decryptText(accessList, filename);
			}
			if(message == null){
				dout.writeInt(0); //no access
				return;
			}
			dout.writeInt(1); // getting access
			sendBytesEncrypted(clientId, message);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private byte[] decryptText(List<Integer> accessList, String filename) {
		try {
			BufferedReader fileReader = new BufferedReader(new FileReader(
					"resources\\encryptParameters.txt"));
			String str;
			int sign = 0;
			BigInteger prime = null, initVector = null;
			while ((str = fileReader.readLine()) != null) {
				if (str.substring(0, str.indexOf(" ")).equals(filename)) {
					String[] parts = str.split(" ");
					prime = new BigInteger(parts[1]);
					initVector = new BigInteger(parts[2]);
					sign = Integer.valueOf(parts[3]);
					break;
				}
			}
			int needed = accessList.get(0);
			Share[] shares = new Share[needed];
			for (int i = 1; i < needed+1/* accessList.size() */; i++)
				shares[i - 1] = getShare(accessList.get(i),filename);
			BigInteger secret = Shamir.join(shares, prime, needed);

			if (sign == -1) {
				BigInteger secr = BigInteger.ZERO.subtract(secret);
				secret = secr;
			}
			SecretKey aesKey = new SecretKeySpec(secret.toByteArray(), "AES");
			byte[] content = AES.decrypt(Files.readAllBytes(Paths
					.get("resources\\documents\\" + filename)), aesKey,
					new IvParameterSpec(initVector.toByteArray()));
			return content;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private Share getShare(Integer clientId,String filename) {
		Share share = null;
		Socket sock = ResourceStorage.connectToClient(clientId);
		try {
			DataInputStream dinStr = new DataInputStream(sock.getInputStream());
			DataOutputStream doutStr = new DataOutputStream(
					sock.getOutputStream());
			
			//TODO auth
			doutStr.writeInt(2);  //getShare
			doutStr.writeUTF(filename);
			int x = dinStr.readInt();
			BigInteger sum = new BigInteger(dinStr.readUTF());
			share = new Share(x, sum);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return share;
	}

	private void sendBytesEncrypted(Integer clientId, byte[] bs) {
		try {
			dout.writeInt(bs.length);
			dout.write(bs, 0, bs.length);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// TODO Cipher and sign

	}

	public List<Integer> getAccessToFileList(String filename, Integer clientId) {
		List<List<Integer>> accessLists = accessMap.get(filename);
		for (List<Integer> list : accessLists)
			for (int i = 1; i < list.size(); i++)
				if (list.get(i).equals(clientId))
					return list;
		return null;
	}

}
