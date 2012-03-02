import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class RunGroupClient{
	static String groupServerAddress = "";
	static String fileServerAddress = "";
	static int groupServerPort = 8765;
	static int fileServerPort = 4321;
	static PublicKey groupServerKey = null;
	
	private static Envelope AESEncrypt(byte[] bytes, SecretKey key){
		Envelope envelope = new Envelope("IV, Encryption");
		try{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			envelope.addObject(cipher.getIV());
			envelope.addObject(cipher.doFinal(bytes));
		} catch(Exception e){
			System.out.println(e);
		}
		return envelope;
	}
	
	private static byte[] AESDecrypt(Envelope envelope, SecretKey key){
		byte[] decrypt = null; 
		byte[] IV = (byte[]) envelope.getObjContents().get(0);
		byte[] encrypted = (byte[]) envelope.getObjContents().get(1);
		try{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
			decrypt = cipher.doFinal(encrypted);
		} catch(Exception e){
			System.out.println(e);
		}
		return decrypt;
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
		groupClient.connect(groupServerAddress,groupServerPort);
		boolean FSConnected = false;
		String usert = "";
		
		try{
			while(token == null){
				System.out.println("Enter your username");
				System.out.print(" > ");
				usert = in.readLine();
				token = groupClient.getToken(usert);
				if(token == null){
					System.out.println("not a valid user");
				}
			}
		}catch(Exception e){
			System.err.println(e);
		}
		
		//loop to wait for command
		do{
			token = groupClient.getToken(usert);
			try{
				System.out.println("Enter command, or type \"DISCONNECT\" to disconnect from groupserver.");
				System.out.print(" > ");	
			    input = in.readLine();
			}
			catch(Exception e){
			   System.err.println(e);
			}
			if(input.toUpperCase().equals("GPUBLIC")){
				PublicKey publicKey = groupClient.getPublicKey();
				groupServerKey = publicKey;
				if(publicKey != null){
					byte[] pKey = publicKey.getEncoded();
					try{
						Security.addProvider(new BouncyCastleProvider());
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
							input = "DISCONNECT";
						}
					} catch(Exception e){
						System.out.println(e);
					}
				}
				else{
					System.out.println("Error in obtain server's key fingerprint");
				}
			}
			
			if(input.toUpperCase().equals("CUSER")){
				System.out.println("Enter the username to create");
				System.out.print(" > ");	
				String username = null;
				try {
					username = in.readLine().toLowerCase();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.createUser(username, token);
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("DUSER")){
				System.out.println("Enter the username to delete");
				System.out.print(" > ");	
				String username = null;
				try {
					username = in.readLine().toLowerCase();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.deleteUser(username, token);
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
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.createGroup(groupname, token);
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
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.deleteGroup(groupname, token);
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
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				List<String> result = groupClient.listMembers(groupname, token);
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
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.addUserToGroup(username, groupname, token);
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
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.deleteUserFromGroup(username, groupname, token);
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("DISCONNECT")){
				if(FSConnected)
				{
					fileClient.disconnect();
				}
				groupClient.disconnect();
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
					fileClient.connect(fileServerAddress,fileServerPort);
					FSConnected = true;
					System.out.println("Connected to File Server Successfully");
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
					fileClient.disconnect();
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
					List<String> filelist = fileClient.listFiles(token);
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
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					boolean result = fileClient.upload(sourceFile, destFile, group, token);
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
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					boolean result = fileClient.download(sourceFile, destFile, token);
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
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					boolean result = fileClient.delete(filename, token);
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
		
	}
}
