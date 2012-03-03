/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileThread extends Thread
{
	private final Socket socket;
	private ArrayList<Date> timestamps = new ArrayList<Date>();
	private PublicKey gspublicKey;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private byte[] sharedKey;
	
	public FileThread(Socket _socket)
	{
		socket = _socket;
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;
			

			ObjectInputStream inStream;
			inStream = new ObjectInputStream(new FileInputStream("ALPHA.public"));
			gspublicKey = (PublicKey)inStream.readObject();
			inStream.close();

			Security.addProvider(new BouncyCastleProvider());
			
			//load public and private key pair
			inStream = new ObjectInputStream(new FileInputStream("FilePile" + ".public"));
			publicKey = (PublicKey)inStream.readObject();
			inStream.close();
			inStream = new ObjectInputStream(new FileInputStream("FilePile" + ".private"));
			privateKey = (PrivateKey)inStream.readObject();
			inStream.close();

			Envelope env = (Envelope)input.readObject();
			if(env.getMessage().equals("FSPUBLIC"))//Client requests server's public key
			{
				try{
					response = new Envelope("OK");
					response.addObject(publicKey);
					output.writeObject(response);
				}catch(Exception ex){
					System.err.println(ex);
				}
			}
			env = (Envelope)input.readObject();
			if(env.getMessage().equals("CHALLENGE"))//Client requests server's public key
			{
				try{
					response = new Envelope("OK");
					byte[] challenge = (byte[])env.getObjContents().get(0);
					byte[] deChallenge = RSADecrypt(challenge, privateKey);
					int keySize = (Integer)env.getObjContents().get(1);
					byte[] c = new byte[deChallenge.length - keySize];
					System.arraycopy(deChallenge, keySize, c, 0, c.length);
					response.addObject(c);
					output.writeObject(response);
				}catch(Exception ex){
					ex.printStackTrace();
				}
			}
			
			do
			{
				Envelope en = (Envelope)input.readObject();
				Envelope e = AESDecrypt(en, sharedKey);
				System.out.println("Request received: " + e.getMessage());
				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
				    /* TODO: Write this handler */
					if(e.getObjContents().size() < 1 || e.getObjContents().get(0) == null)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						UserToken yourToken = (UserToken)e.getObjContents().get(0); //Extract token 
						if(!checkToken(yourToken)){
							System.out.println("Token not valid");
							response = new Envelope("TOKEN_NOT_VALID");
						}
						else{
							response = new Envelope("OK");
							List<String> list = new ArrayList<String>();
							for(int i = 0; i < FileServer.fileList.getFiles().size(); i++)
							{
								for(int j = 0; j < yourToken.getGroups().size(); j++)
								{
									if(FileServer.fileList.getFiles().get(i).getGroup().equals(yourToken.getGroups().get(j)))
									{
										list.add(FileServer.fileList.getFiles().get(i).getPath());
									}
								}
							}
							response.addObject(list);
						}
					}
					output.writeObject(response);
				}
				else if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
							if(!checkToken(yourToken)){
								System.out.println("Token not valid");
								response = new Envelope("TOKEN_NOT_VALID");
							}
							else if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								output.writeObject(response);

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if(!checkToken(t)){
						System.out.println("Token not valid");
						e = new Envelope("TOKEN_NOT_VALID");
						output.writeObject(e);
					}
					else if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e);

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}


								e.addObject(buf);
								e.addObject(new Integer(n));

								output.writeObject(e);

								e = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								output.writeObject(e);

								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
							fis.close();
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if(!checkToken(t)){
						System.out.println("Token not valid");
						e = new Envelope("TOKEN_NOT_VALID");
						output.writeObject(e);
					}
					else if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{


							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					output.writeObject(e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	private byte[] getHash(String s){
		byte[] hashed = null;
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-1", "BC");
			hashed = md.digest(s.getBytes());
		} catch(Exception e){
			System.out.println(e);
		}
		return hashed;
	}
	
	public byte[] RSAEncrypt(byte[] bytes, PrivateKey key){
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
	
	public byte[] RSAEncrypt(byte[] bytes, PublicKey key){
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
	
	public byte[] RSADecrypt(byte[] bytes, PrivateKey key){
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
	
	public byte[] RSADecrypt(byte[] bytes, PublicKey key){
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
	
	private Envelope AESEncrypt(Envelope en, byte[] key){
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
	
	private Envelope AESDecrypt(Envelope envelope, byte[] key){
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
	
	private byte[] getBytes(Envelope e) throws java.io.IOException{
	      ByteArrayOutputStream bos = new ByteArrayOutputStream(); 
	      ObjectOutputStream oos = new ObjectOutputStream(bos); 
	      oos.writeObject(e);
	      oos.flush(); 
	      oos.close(); 
	      bos.close();
	      byte [] data = bos.toByteArray();
	      return data;
	  }
	
	private Envelope getEnvelope(byte[] bytes) throws java.io.IOException, ClassNotFoundException{
		ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
		ObjectInputStream ois = new ObjectInputStream(bis);
		Envelope e= (Envelope) ois.readObject();
		ois.close();
		bis.close();
		return e;
	}
	
	private void clearTimestamps(){
		Date now = new Date();
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(now);
		calendar.add(Calendar.MINUTE, -5);
		Date fiveAgo = calendar.getTime();
		for(int i = 0; i < timestamps.size(); i++){
			Date date = timestamps.get(i);
			if(date.compareTo(fiveAgo) < 0)
				timestamps.remove(i);
		}
	}
	
	private boolean checkTimestamp(Date d){
		Date now = new Date();
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(now);
		calendar.add(Calendar.MINUTE, -5);
		Date fiveAgo = calendar.getTime();
		System.out.println(now);
		System.out.println(fiveAgo);
		if(d.compareTo(fiveAgo) < 0)
			return false;
		for(Date date : timestamps){
			if(d.compareTo(date) == 0)
				return false;
		}
		timestamps.add(d);
		return true;
	}
	
	private boolean checkToken(UserToken token){
		String tokendata = token.getTokendata();
		byte[] hashed = getHash(tokendata);
		byte[] signed = token.getSignature();
		byte[] compare = RSADecrypt(signed, gspublicKey);
		return Arrays.equals(hashed,compare);
	}
}
