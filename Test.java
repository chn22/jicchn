
public class Test {
	public static void main (String[] args){
		String s = "this is a string";
		byte[] b = s.getBytes();
		byte[] key = Crypt.generateAESKey(128);
		//byte[] b2 = Crypt.AESEncrypt(b, key);
		System.out.println(new String(Crypt.AESDecrypt(b, key)));
		
	}
}
