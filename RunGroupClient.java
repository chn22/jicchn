import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class RunGroupClient{
	static String groupServerAddress = "";
	static String fileServerAddress = "";
	static int groupServerPort = 8765;
	static int fileServerPort = 4321;
	static PublicKey groupServerKey = null;
	static PublicKey fileServerKey = null;
	private static SecretKey gSharedKey = null;
	private static SecretKey fSharedKey = null;
	static String fileServerName = null;
	
	public static final byte[] intToByteArray(int value) {
	    return new byte[] {
	            (byte)(value >>> 24),
	            (byte)(value >>> 16),
	            (byte)(value >>> 8),
	            (byte)value};
	}
	
	public static byte[] RSAEncrypt(byte[] bytes, PrivateKey key){
		byte[] encrypted = null;
		try{
			Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			encrypted = cipher.doFinal(bytes);
		} catch(Exception e){
			System.out.println(e);
		}
		return encrypted;
	}
	
	public static byte[] RSAEncrypt(byte[] bytes, PublicKey key){
		byte[] encrypted = null;
		try{
			Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			encrypted = cipher.doFinal(bytes);
		} catch(Exception e){
			System.out.println(e);
		}
		return encrypted;
	}
	
	public static byte[] RSADecrypt(byte[] bytes, PrivateKey key){
		byte[] decrypt = null; 
		try{
			Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, key);
			decrypt = cipher.doFinal(bytes);
		} catch(Exception e){
			System.out.println(e);
		}
		return decrypt;
	}
	
	public static byte[] RSADecrypt(byte[] bytes, PublicKey key){
		byte[] decrypt = null; 
		try{
			Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, key);
			decrypt = cipher.doFinal(bytes);
		} catch(Exception e){
			System.out.println(e);
		}
		return decrypt;
	}
	
	public static Envelope AESEncrypt(Envelope en, byte[] key){
		Envelope envelope = new Envelope("IV, Encryption");
		SecretKeySpec skeyspec = new SecretKeySpec(key, "AES");
		try{
			byte[] bytes = getBytes(en);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, skeyspec);
			envelope.addObject(cipher.getIV());
			envelope.addObject(cipher.doFinal(bytes));
		} catch(Exception e){
			System.out.println(e);
		}
		return envelope;
	}
	
	public static Envelope AESDecrypt(Envelope envelope, byte[] key){
		Envelope en = null;
		byte[] decrypt = null; 
		byte[] IV = (byte[]) envelope.getObjContents().get(0);
		byte[] encrypted = (byte[]) envelope.getObjContents().get(1);
		SecretKeySpec skeyspec = new SecretKeySpec(key, "AES");
		try{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, skeyspec, new IvParameterSpec(IV));
			decrypt = cipher.doFinal(encrypted);
			en = getEnvelope(decrypt);
		} catch(Exception e){
			System.out.println(e);
		}
		return en;
	}
	

	private static byte[] getBytes(Envelope e) throws java.io.IOException{
	      ByteArrayOutputStream bos = new ByteArrayOutputStream(); 
	      ObjectOutputStream oos = new ObjectOutputStream(bos); 
	      oos.writeObject(e);
	      oos.flush(); 
	      oos.close(); 
	      bos.close();
	      byte [] data = bos.toByteArray();
	      return data;
	  }
	
	private static Envelope getEnvelope(byte[] bytes) throws java.io.IOException, ClassNotFoundException{
		ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
		ObjectInputStream ois = new ObjectInputStream(bis);
		Envelope e= (Envelope) ois.readObject();
		ois.close();
		bis.close();
		return e;
	}
	
	public static byte[] merge(byte[] key, String username, String password){
		String up = username + "\n" + password;
		byte[] merge = new byte[key.length + up.getBytes().length];
		System.arraycopy(key,0,merge,0,key.length);
		System.arraycopy(up.getBytes(),0,merge,key.length,up.getBytes().length);
		return merge;
	}
		
	public static void main(String args[]){
		
		System.out.println("Please enter group server address > ");
		Scanner scan = new Scanner(System.in);
		groupServerAddress = scan.next();
		System.out.println("Please enter group server port > ");
		try{
			groupServerPort = scan.nextInt();
		}catch(Exception e){
			groupServerPort = 8765;
		}
		
		GroupClient groupClient = new GroupClient();
		FileClient fileClient = new FileClient();
		String input = null;
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		UserToken token = null;
		//connect to the group server
		if(groupClient.connect(groupServerAddress,groupServerPort)){
			System.out.println("connection success.");
			Security.addProvider(new BouncyCastleProvider());
			
			//print out server's public key fingerprint
			PublicKey publicKey = groupClient.getPublicKey();
			groupServerKey = publicKey;
			if(publicKey != null){
				byte[] pKey = publicKey.getEncoded();
				try{
					MessageDigest md = MessageDigest.getInstance("SHA-1", "BC");
					byte[] fingerPrint = md.digest(pKey);
					System.out.println("The server's rsa key fingerprint is :\n");
					
					//convert hashed public key into hexadecimal
					StringBuffer strbuf = new StringBuffer(fingerPrint.length * 2);
				    int i;
				    for (i = 0; i < fingerPrint.length; i++) {
				    	if (((int) fingerPrint[i] & 0xff) < 0x10)
				    		strbuf.append("0");
				    	strbuf.append(Long.toString((int) fingerPrint[i] & 0xff, 16));
				    }
					System.out.println(strbuf);
					System.out.println("Enter 'yes' to continue or 'no' to disconnect > ");
					input = in.readLine();
					if(!input.toLowerCase().equals("yes") && !input.toLowerCase().equals("y")){
						groupClient.disconnect();
						System.exit(0);
					}
				} catch(Exception e){
					System.out.println(e);
				}
			}
			else{
				System.out.println("Error in obtain server's key fingerprint");
			}
		}
		else{
			System.out.println("connection fail.");
			System.exit(1);
		}
		boolean FSConnected = false;
		boolean loginSuccess = false;
		
		try{
			
			
			while(!loginSuccess){
				System.out.println("Enter your username to login");
				System.out.print(" > ");
				String username = in.readLine();
				System.out.println("Enter your password to login");
				System.out.print(" > ");
				String password = in.readLine();
				KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
				kgen.init(128);
				gSharedKey = kgen.generateKey();
				byte[] mergedData = merge(gSharedKey.getEncoded(), username, password);
				byte[] encryptedLogin = RSAEncrypt(mergedData, groupServerKey);
				loginSuccess = groupClient.login(encryptedLogin, 128/8);
				if(loginSuccess){
					System.out.println("Login successful.");
				}
				else{
					System.out.println("Login fail.");
				}
			}
		}catch(Exception e){
			System.err.println(e);
		}
		
		//loop to wait for command
		do{
			token = groupClient.getToken(gSharedKey.getEncoded(), fileServerName);
			try{
				System.out.println("Enter command, or type \"DISCONNECT\" to disconnect from groupserver.");
				System.out.print(" > ");	
			    input = in.readLine();
			}
			catch(Exception e){
			   System.err.println(e);
			}
			
			if(input.toUpperCase().equals("CUSER")){
				System.out.println("Enter the username to create");
				System.out.print(" > ");	
				String username = null;
				try {
					username = in.readLine().toLowerCase();
				} catch (IOException e) {
					e.printStackTrace();
				}
				boolean result = groupClient.createUser(username, token, gSharedKey.getEncoded());
				if(result){
					System.out.println("success");
				}
				else{
					System.out.println("fail");
				}
			}
			else if(input.toUpperCase().equals("DUSER")){
				System.out.println("Enter the username to delete");
				System.out.print(" > ");	
				String username = null;
				try {
					username = in.readLine().toLowerCase();
				} catch (IOException e) {
					e.printStackTrace();
				}
				boolean result = groupClient.deleteUser(username, token, gSharedKey.getEncoded());
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("CGROUP")){
				System.out.println("Enter the groupname to create");
				System.out.print(" > ");	
				String groupname = null;
				try {
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					e.printStackTrace();
				}
				boolean result = groupClient.createGroup(groupname, token, gSharedKey.getEncoded());
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("DGROUP")){
				System.out.println("Enter the groupname to delete");
				System.out.print(" > ");	
				String groupname = null;
				try {
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					e.printStackTrace();
				}
				boolean result = groupClient.deleteGroup(groupname, token, gSharedKey.getEncoded());
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("LMEMBERS")){
				System.out.println("Enter the groupname");
				System.out.print(" > ");	
				String groupname = null;
				try {
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					e.printStackTrace();
				}
				List<String> result = groupClient.listMembers(groupname, token, gSharedKey.getEncoded());
				if(result != null){
					System.out.println("number of members: " + result.size());
					for(int i = 0; i < result.size(); i++){
						System.out.println(result.get(i));
					}
					
				}
				else System.out.println("is null");
			}
			else if(input.toUpperCase().equals("AUSERTOGROUP")){	
				String username = null;
				String groupname = null;
				try {
					System.out.println("Enter the username");
					System.out.print(" > ");
					username = in.readLine().toLowerCase();
					System.out.println("Enter the groupname");
					System.out.print(" > ");
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					e.printStackTrace();
				}
				boolean result = groupClient.addUserToGroup(username, groupname, token, gSharedKey.getEncoded());
				if(result){
					System.out.println("success");
				}
				else
				{
					System.out.println("Add user not success!");
				}
			}
			else if(input.toUpperCase().equals("RUSERFROMGROUP")){	
				String username = null;
				String groupname = null;
				try {
					System.out.println("Enter the username");
					System.out.print(" > ");
					username = in.readLine().toLowerCase();
					System.out.println("Enter the groupname");
					System.out.print(" > ");
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					e.printStackTrace();
				}
				boolean result = groupClient.deleteUserFromGroup(username, groupname, token, gSharedKey.getEncoded());
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("DISCONNECT")){
				if(FSConnected)
				{
					fileClient.disconnect(fSharedKey.getEncoded());
				}
				groupClient.disconnect(gSharedKey.getEncoded());
			}
			else if(input.toUpperCase().equals("FSCONNECT"))
			{
				if(!FSConnected)
				{
					System.out.println("Please enter file server address > ");
					fileServerAddress = scan.next();
					System.out.println("Please enter file server port > ");
					try{
						fileServerPort = scan.nextInt();
					}catch(Exception e){
						fileServerPort = 4321;
					}
					if(fileClient.connect(fileServerAddress,fileServerPort)){
						FSConnected = true;
						System.out.println("Connected to File Server Successfully");
						
						//get public key
						PublicKey publicKey = fileClient.getPublicKey();
						fileServerKey = publicKey;
						if(publicKey != null){
							byte[] pKey = publicKey.getEncoded();
							try{
								MessageDigest md = MessageDigest.getInstance("SHA-1", "BC");
								byte[] fingerPrint = md.digest(pKey);
								System.out.println("The server's rsa key fingerprint is :\n");
								//convert hashed public key into hexadecimal
								StringBuffer strbuf = new StringBuffer(fingerPrint.length * 2);
							    int i;
							    for (i = 0; i < fingerPrint.length; i++) {
							    	if (((int) fingerPrint[i] & 0xff) < 0x10)
							    		strbuf.append("0");
							    	strbuf.append(Long.toString((int) fingerPrint[i] & 0xff, 16));
							    }
								System.out.println(strbuf);
								System.out.println("Enter 'yes' to continue or 'no' to disconnect > ");
								input = in.readLine();
								if(!input.toLowerCase().equals("yes") && !input.toLowerCase().equals("y")){
									fileClient.disconnect(gSharedKey.getEncoded());
									FSConnected = false;
									System.out.println("Successfully disconnected from File Server");
								}
								
								//send challenge to file server
								KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
								kgen.init(128);
								fSharedKey = kgen.generateKey();
								Random r = new Random();
								int challenge = r.nextInt();
								byte[] fByte = fSharedKey.getEncoded();
								byte[] cByte = intToByteArray(challenge);
								
								byte[] merge = new byte[cByte.length + fByte.length];
								System.arraycopy(fByte,0,merge,0,fByte.length);
								System.arraycopy(cByte,0,merge,fByte.length,cByte.length);
								
								byte[] encryptedMerge = RSAEncrypt(merge, fileServerKey);
								//byte[] rChallenge = fileClient.challenge(encryptedMerge, 128/8);
								ArrayList<Object> arr = fileClient.challenge(encryptedMerge, 128/8);
								byte[] rChallenge = (byte[])arr.get(0);
								String serverName = (String)arr.get(1);
								
								if(Arrays.equals(rChallenge, cByte)){
									System.out.println("File Server challenge success. Connection success.");
									System.out.println("File Server Name: " + serverName);
									fileServerName = serverName;
								}
								else{
									fileClient.disconnect(gSharedKey.getEncoded());
									FSConnected = false;
									System.out.println("File Server challenge fail. Connection closed.");
								}
								
							} catch(Exception e){
								System.out.println(e);
							}
						}
						else{
							System.out.println("Error in obtain server's key fingerprint");
						}
					}
					else{
						System.out.println("Connection fail.");
					}
				}
				else
				{
					System.out.println("Already Connected to File Server");
				}
			}
			
			else if(input.toUpperCase().equals("FSDISCONNECT"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					fileClient.disconnect(fSharedKey.getEncoded());
					FSConnected = false;
					System.out.println("Successfully disconnected from File Server");
				}
			}
			else if(input.toUpperCase().equals("LISTFILES"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					List<String> filelist = fileClient.listFiles(token, fSharedKey.getEncoded());
					for(String filename : filelist)
					{
						System.out.println(filename);
					}
				}
			}
			else if(input.toUpperCase().equals("UPLOAD"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					String sourceFile = null;
					String destFile = null;
					String group = null;
					try {
						System.out.println("Enter the sourceFile");
						System.out.print(" > ");
						sourceFile = in.readLine().toLowerCase();
						System.out.println("Enter the name to be saved in File Server");
						System.out.print(" > ");
						destFile = in.readLine().toLowerCase();
						System.out.println("Enter the groupname");
						System.out.print(" > ");
						group = in.readLine().toLowerCase();
					} catch (IOException e) {
						e.printStackTrace();
					}
					boolean result = fileClient.upload(sourceFile, destFile, group, token, fSharedKey.getEncoded());
					if(result){
						System.out.println("Upload Success");
					}
					else
					{
						System.out.println("Upload Failed");
					}
				}
			}
			else if(input.toUpperCase().equals("DOWNLOAD"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					String sourceFile = null;
					String destFile = null;
					try {
						System.out.println("Enter the sourceFile");
						System.out.print(" > ");
						sourceFile = in.readLine().toLowerCase();
						System.out.println("Enter the name to be saved of the downloaded file");
						System.out.print(" > ");
						destFile = in.readLine().toLowerCase();
					} catch (IOException e) {
						e.printStackTrace();
					}
					boolean result = fileClient.download(sourceFile, destFile, token, fSharedKey.getEncoded());
					if(result){
						System.out.println("Download Success");
					}
					else
					{
						System.out.println("Download Failed");
					}
				}
			}
			else if(input.toUpperCase().equals("DELETE"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					String filename = null;
					try {
						System.out.println("Enter the filename to be deleted");
						System.out.print(" > ");
						filename = in.readLine().toLowerCase();
					} catch (IOException e) {
						e.printStackTrace();
					}
					boolean result = fileClient.delete(filename, token, fSharedKey.getEncoded());
					if(result){
						System.out.println("Delete Success");
					}
					else
					{
						System.out.println("Delete Failed");
					}
				}
			}
			else
			{
				System.out.println("Command not valid!");
			}
			
			
		}while(!input.toUpperCase().equals("DISCONNECT"));
		System.out.println("Successfully disconnect.");
	}
}
