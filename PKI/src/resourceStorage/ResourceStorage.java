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
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import crypto.AES;
import crypto.RSA;
import crypto.Shamir;
import crypto.Shamir.Share;
import client.Client;

public class ResourceStorage extends Client {
	
	private HashMap<String, List<List<Integer>>> accessMap;

	public ResourceStorage() {
		super();
	}
	
	@Override
	protected void initiateThread() {
		getAccessMap();
		System.out.println("Input 1 - to send shares for each file to owners, 0 - to skip this.");
		int send = sc.nextInt();
		if(send == 1){
			generateSecretsForFiles();
		}
		while(true) {
	    	try {		
				ServerThread serverThread = new ServerThread(serverSocket.accept(),cert,privateKey, accessMap,this);
				serverThread.start();	
			} catch (IOException e) {			
				e.printStackTrace();
			}	
    	}
	}
	
	protected boolean connectToClient(Integer clientId) {
		try {
			socket = getSocket(clientId);
			din = new DataInputStream(socket.getInputStream());
			dout = new DataOutputStream(socket.getOutputStream());
		} catch (UnknownHostException e) {
			return false;
		} catch (IOException e) {
			return false;
		}
		return true;
	}
	
	public boolean initiateNewClientConnection(Integer clientId){
		int choice = AUTHORIZE;
		if (choice == AUTHORIZE) {
			if(!connectToClient(clientId))
				return false;
			authorize();
		}
		return true;
	}

	
	private void getAccessMap() {
		try {
			BufferedReader accessReader = new BufferedReader(new FileReader(
					"resources//access.txt"));
			int index = 0;
			String str;
			accessMap = new HashMap<String, List<List<Integer>>>();
			int size;
			String filename;
			while ((str = accessReader.readLine()) != null) {
				size = str.length();
				filename = str.substring(0, str.indexOf(" "));
				Matcher m = Pattern.compile("\\(([^)]+)\\)").matcher(str);
				List<List<Integer>> list = new ArrayList<List<Integer>>();
				while (m.find()) {
					List<Integer> accessList = new ArrayList<>();
					String[] clientList = m.group(1).split(" ");
					for (String s : clientList)
						accessList.add(Integer.valueOf(s));
					list.add(accessList);
				}
				accessMap.put(filename, list);
			}
			accessReader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void generateSecretsForFiles() {
		Iterator it = accessMap.entrySet().iterator();
		String filename;
		clearFile("encryptParameters.txt");
		while (it.hasNext()) {
			Map.Entry pair = (Map.Entry) it.next();
			filename = (String) pair.getKey();
			for (List<Integer> list : (List<List<Integer>>) pair.getValue()) {
				if (list.get(0) > 1) {
					generateSecretForFile(list, filename);
				}
			}
		}
	}

	public Share[] generateSecretForFile(List<Integer> list, String filename) {
		SecretKey aesKey = AES.generateKey();
		int sign = 1;
		BigInteger secret = new BigInteger(aesKey.getEncoded());
		BigInteger prime = Shamir.generatePrime(secret);
		if (secret.compareTo(BigInteger.ZERO) == -1) {
			sign = -1;
			BigInteger secr = BigInteger.ZERO.subtract(secret);
			secret = secr;
		}

		Share[] shares = Shamir.split(secret, list.size() - 1, list.get(0),
				prime);
		for (int i = 1; i < list.size(); i++)
			sendShare(list.get(i), shares[i - 1],filename);
		encryptFile(filename, aesKey);
		writePrime(filename, prime, AES.getCurrentIV(), sign);
		return shares;
	}
	
	public static Socket getSocket(Integer clientId) throws UnknownHostException, IOException {
		Socket sock = null;
			BufferedReader fileReader = new BufferedReader(new FileReader(
					"resources\\clients.txt"));
			String str;
			int port = 0;
			String host = "";
			while ((str = fileReader.readLine()) != null) {
				if (Integer.valueOf(str.substring(0, Integer.valueOf(str.indexOf(" ")))).equals(
						clientId)) {
					String[] parts = str.split(" ");
					host = parts[1];
					port = Integer.valueOf(parts[2]);
					break;
				}
			}
			fileReader.close();
			sock = new Socket(host, port);
		return sock;
	}

	private void sendShare(Integer clientId, Share share,String filename) {
		try {
			initiateNewClientConnection(clientId);
			dout.writeInt(Client.SEND_SHARE);  //sendShare
			dout.writeUTF(filename);
			dout.writeInt(share.getX());
			byte[] send = RSA.encrypt(share.getSum().toByteArray(), anotherCert.getPublicKey());
			dout.writeInt(send.length);
			dout.write(send, 0, send.length);
		} catch (IOException e) {
			e.printStackTrace();
		}
		// TODO Cipher and Sign
	}
	
	public Share getShare(Integer clientId,String filename, Integer clientResId) {
		Share share = null;
		try {
			if(!initiateNewClientConnection(clientId))
				return null;
			dout.writeInt(Client.GET_SHARE);  //getShare
			dout.writeUTF(filename);
			dout.writeInt(clientResId);
			int allow = din.readInt();
			if(allow == 1){
			int x = din.readInt();
			int length = din.readInt();
			byte[] read = new byte[length];
			din.read(read, 0, length);
			BigInteger sum = new BigInteger(RSA.decrypt(read, privateKey));
			share = new Share(x, sum);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return share;
	}
	
	private static void clearFile(String filename) {
		try {
			Files.write(Paths.get("resources\\" + filename),
					(new String()).getBytes(),
					StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void writePrime(String filename, BigInteger prime, byte[] iv,
			int sign) {
		try {
			PrintWriter fileWriter = new PrintWriter(new BufferedWriter(
					new FileWriter("resources\\encryptParameters.txt", true)));
			fileWriter.write(filename + " " + prime + " " + new BigInteger(iv)
					+ " " + sign + "\n");
			fileWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void encryptFile(String filename, SecretKey aesKey) {
		try {
			byte[] content = Files.readAllBytes(Paths
					.get("resources\\documents\\" + filename));
			byte[] newContent = AES.encrypt(content, aesKey);
			Files.write(Paths.get("resources\\documents\\" + filename),
					newContent, StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void decryptFile(String filename, SecretKey aesKey,
			BigInteger initVector) {
		try {
			byte[] content = Files.readAllBytes(Paths
					.get("resources\\documents\\" + filename));
			byte[] newContent = AES.decrypt(content, aesKey,
					new IvParameterSpec(initVector.toByteArray()));
			Files.write(Paths.get("resources\\documents\\" + filename),
					newContent, StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	public static void main(String[] args) {
		ResourceStorage resourceStorage = new ResourceStorage();
	}

}
