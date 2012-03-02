/*
 * This class will generate an RSA key pair and 
 * store in "server.private" and "server.public" files
 * 
 * Run 
 * java GenerateKeyPair Server_Name
 * to generate "Server_Name.private" and "Server_Name.public"
 * 
 */

import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GenerateKeyPair {
	
	int keySize = 1024; 
	String publicFile = "";
	String privateFile = "";
	
	public GenerateKeyPair() throws Exception{
		this("unknown_server");
	}
	public GenerateKeyPair(String serverName) throws Exception{
		
		publicFile = serverName + ".public";
		privateFile = serverName + ".private";
		File file1 = new File(publicFile);
		File file2 = new File(privateFile);
		if(!file1.exists() && !file2.exists()){
			Security.addProvider(new BouncyCastleProvider());
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGenerator.initialize(keySize);
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			ObjectOutputStream outStream;
			outStream = new ObjectOutputStream(new FileOutputStream(publicFile));
			outStream.writeObject(publicKey);
			outStream = new ObjectOutputStream(new FileOutputStream(privateFile));
			outStream.writeObject(privateKey);
			outStream.close();
		}
	}
}
