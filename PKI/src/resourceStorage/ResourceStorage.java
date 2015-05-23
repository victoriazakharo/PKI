package resourceStorage;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import crypto.AES;
import crypto.Shamir;
import crypto.Shamir.Share;
import client.Client;

public class ResourceStorage  extends Client{
	public HashMap<String, List<List<Integer>>> accessMap;
	
	public ResourceStorage() {
		super();
		getAccessMap();
	}
	
	private void sendShare(Integer clientId, Share share){
		//TODO Cipher and Sign
	}
	
	public void generateSecretsForFiles(){
		Iterator it = accessMap.entrySet().iterator();
		String filename;
		clearFile("encryptParameters.txt");
		while (it.hasNext()) {
	        Map.Entry pair = (Map.Entry)it.next();
	        filename = (String) pair.getKey();
	        for(List<Integer> list : (List<List<Integer>>)pair.getValue()){
	        	if(list.get(0)>1){
	        		generateSecretForFile(list, filename);
	        	}
	        }
	    }
	}
	
	public Share[] generateSecretForFile(List<Integer> list, String filename){
		SecretKey aesKey = AES.generateKey();
		int sign = 1;
		BigInteger secret = new BigInteger(aesKey.getEncoded());
		BigInteger prime = Shamir.generatePrime(secret);
		if(secret.compareTo(BigInteger.ZERO)==-1){
			sign = -1;
			BigInteger secr = BigInteger.ZERO.subtract(secret);
			secret = secr;
		}
		
		Share[] shares = Shamir.split(secret,list.size()-1 , list.get(0), prime);
		for(int i = 1;i<list.size();i++)
			sendShare(list.get(i), shares[i-1]);
		encryptFile(filename, aesKey);
		writePrime(filename,prime,AES.getCurrentIV(),sign);
		return shares;
	}
	
	public void getAccessToFile(String filename, Integer clientId){
		try{
		List<Integer> accessList = getAccessToFileList(filename, clientId);
		if(accessList == null || accessList.size()<2){
			//TODO no access for that client
			return;
		}
		int needed = accessList.get(0);
		if(needed==1){
			sendBytesEncrypted(clientId,Files.readAllBytes(Paths.get("resources\\documents\\"
					+ filename)));
		}else if(needed >1){
			sendBytesEncrypted(clientId,decryptText(accessList,filename));
		}
		}catch(IOException e){
			e.printStackTrace();
		}
			
	}
	
	private byte[] decryptText(List<Integer> accessList, String filename) {
		try {
			BufferedReader fileReader = new BufferedReader(new FileReader(
					"resources\\encryptParameters.txt"));
			String str;
			int sign=0;
			BigInteger prime=null, initVector=null;
			while ((str=fileReader.readLine()) != null) {
				if(str.substring(0, str.indexOf(" ")).equals(filename)){
					String[] parts = str.split(" ");
					prime = new BigInteger(parts[1]);
					initVector = new BigInteger(parts[2]);
					sign = Integer.valueOf(parts[3]);
					break;
				}
			}
			int needed = accessList.get(0);
			Share[] shares = new Share[needed];
			for(int i = 1;i<needed/*accessList.size()*/;i++)
				shares[i-1] = getShare(accessList.get(i));
			BigInteger secret = Shamir.join(shares, prime, needed);
			
			if(sign==-1){
				BigInteger secr = BigInteger.ZERO.subtract(secret);
				secret=secr;
			}
			SecretKey aesKey = new SecretKeySpec(secret.toByteArray(), "AES");
			byte[] content = AES.decrypt(Files.readAllBytes(Paths.get("resources\\documents\\"+ filename)), aesKey,
					new IvParameterSpec(initVector.toByteArray()));
			return content;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private Share getShare(Integer clientId) {
		// TODO Getting share from client
		return null;
	}

	private void sendBytesEncrypted(Integer clientId, byte[] bs) {
		// TODO Cipher and sign
		
	}

	private static void clearFile(String filename){
		try {
			Files.write(Paths.get("resources\\"+filename), (new String()).getBytes() , StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void writePrime(String filename, BigInteger prime, byte[] iv,int sign) {
		try {
			PrintWriter fileWriter = new PrintWriter(new BufferedWriter(
					new FileWriter("resources\\encryptParameters.txt", true)));
			fileWriter.write(filename+" "+ prime + " " + new BigInteger(iv)+" "+sign+"\n");
			fileWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void encryptFile(String filename, SecretKey aesKey) {
		try {
			byte[] content = Files.readAllBytes(Paths.get("resources\\documents\\"
										+ filename));
			byte[] newContent = AES.encrypt(content, aesKey);
			Files.write(Paths.get("resources\\documents\\"
										+ filename), newContent, StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void decryptFile(String filename, SecretKey aesKey,BigInteger initVector) {
		try {
			byte[] content = Files.readAllBytes(Paths.get("resources\\documents\\"
										+ filename));
			byte[] newContent = AES.decrypt(content, aesKey, new IvParameterSpec(initVector.toByteArray()));
			Files.write(Paths.get("resources\\documents\\"
										+ filename), newContent, StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public List<Integer> getAccessToFileList(String filename, Integer clientId){
		List<List<Integer>> accessLists = accessMap.get(filename);
		for(List<Integer> list : accessLists)
			if(list.contains(clientId))
				return list;
		return null;
	}
	
	private void getAccessMap(){
		try{
		BufferedReader accessReader = new BufferedReader(new FileReader(
				"resources//access.txt"));
		int index=0;
		String str;
		accessMap = new HashMap<String, List<List<Integer>>>();
		int size;
		String filename;
		while ((str=accessReader.readLine()) != null) {
			size = str.length();
			filename = str.substring(0, str.indexOf(" "));
			Matcher m = Pattern.compile("\\(([^)]+)\\)").matcher(str);
			List<List<Integer>> list = new ArrayList<List<Integer>>();
		     while(m.find()) {
		    	 List<Integer> accessList= new ArrayList<>();
		    	 String[] clientList = m.group(1).split(" ");
		    	 for(String s :clientList)
		    		 accessList.add(Integer.valueOf(s));
		    	 list.add(accessList);
		     }
		     accessMap.put(filename, list);
		}
		accessReader.close();
		}catch(IOException e){
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		ResourceStorage resourceStorage = new ResourceStorage();
	}
	
}
