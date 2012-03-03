/* FileClient provides all the client functionality regarding the file server */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileClient extends Client implements FileClientInterface {
	
	public PublicKey getPublicKey(){
		try
		{
			PublicKey publicKey = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return the public key.
			message = new Envelope("FSPUBLIC");
			output.writeObject(message);
			//Get the response from the server
			response = (Envelope)input.readObject();
			
			//Successful response
			if(response.getMessage().equals("OK"))
				
			{
				
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 1)
				{
					publicKey = (PublicKey)temp.get(0);
					if(publicKey != null)
					return publicKey;
				}
			}
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}
	
	public byte[] challenge(byte[] challenge, int keySize){
		Envelope env = new Envelope("CHALLENGE");
	    env.addObject(challenge);
	    env.addObject(keySize);
	    try {
			output.writeObject(env);
			Envelope e = (Envelope)input.readObject();
			byte[] challengeReturn = (byte[])e.getObjContents().get(0);
			return challengeReturn;
	    }catch(Exception e){
	    	e.printStackTrace();
	    }
		return null;
	}
	
	public boolean delete(String filename, UserToken token, byte[] sKey) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
	    try {
	    	Envelope message = AESEncrypt(env, sKey);
			output.writeObject(message);
		    env = (Envelope)input.readObject();
		    Envelope mess = AESDecrypt(env, sKey);
		    
			if (mess.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, mess.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token, byte[] sKey) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
					    Envelope message = AESEncrypt(env, sKey);
					    output.writeObject(message); 
					
					    Envelope mess = (Envelope)input.readObject();
					    env = AESDecrypt(mess, sKey);
						while (env.getMessage().compareTo("CHUNK")==0) { 
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								message = AESEncrypt(env, sKey);
								output.writeObject(message);
								mess = (Envelope)input.readObject();
								env = AESDecrypt(mess, sKey);
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								message = AESEncrypt(env, sKey);
								output.writeObject(message);
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token, byte[] sKey) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			 Envelope m = AESEncrypt(message, sKey);
			 output.writeObject(m); 
			 
			 e = (Envelope)input.readObject();
			 Envelope env = AESDecrypt(e, sKey);
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("OK"))
			 { 
				return (List<String>)env.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token, byte[] sKey) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 Envelope m = AESEncrypt(message, sKey);
			 output.writeObject(m);
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 Envelope mess = (Envelope)input.readObject();
			 env = AESDecrypt(mess, sKey);
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					
					message.addObject(buf);
					message.addObject(new Integer(n));
					m = AESEncrypt(message, sKey);
					output.writeObject(m);
					
					
					mess = (Envelope)input.readObject();
					env = AESDecrypt(mess, sKey);
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				m = AESEncrypt(message, sKey);
				output.writeObject(m);
				
				mess = (Envelope)input.readObject();
				env = AESDecrypt(mess, sKey);
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

	 public Envelope AESEncrypt(Envelope en, byte[] key){
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
	 
	 private static Envelope getEnvelope(byte[] bytes) throws java.io.IOException, ClassNotFoundException{
			ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
			ObjectInputStream ois = new ObjectInputStream(bis);
			Envelope e= (Envelope) ois.readObject();
			ois.close();
			bis.close();
			return e;
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
}

