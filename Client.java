import java.net.Socket;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	public boolean connect(final String server, final int port) {
		System.out.println("attempting to connect...");
		
		/* TODO: Write this method */
		try{
			sock = new Socket(server, port);
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
		}catch(Exception e){
			return false;
			 //System.err.println("Error: " + e.getMessage());
			 //e.printStackTrace(System.err);
		}
		
		return true;
	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect(int counter)	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				message.setNumber(counter);
				output.writeObject(message);
				sock.close();
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
	
	public void disconnect(byte[] sKey, int counter)	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				message.setNumber(counter);
				message = AESEncrypt(message, sKey);
				output.writeObject(message);
				sock.close();
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
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
}
