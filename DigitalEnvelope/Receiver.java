//package receiver;
/*
  Authors: Myke Walker, Justin Singleton

*/
import java.util.Arrays;
import java.util.Scanner;
import java.io.*;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.Key;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//import receiver.util.Utilities;

import java.security.SecureRandom;

public class Receiver {

	//class variables
	private static int BUFFER_SIZE = 32 * 1024;
	//AES stuff
	static byte[] encryptionKey;
	static byte[] secKey;
	static String IV = "AAAAAAAAAAAAAAAA";
	//needed files
	File xFilePub = new File("xPublic.key");
	File xFilePri = new File("xPrivate.key");
	File yFilePub = new File("yPublic.key");
	File yFilePri = new File("yPrivate.key");
	File sKeyFile = new File("Symmetric.key");
	File messFile = new File("message.kmk");
	
	public static void main(String[] args) {
		
		//Greet user 
		System.out.println("Welcome to message receiver!");
		Scanner sc = new Scanner(System.in);
		//get the name of the file to which we will send locally calculated hash value
		System.out.println("Enter name of message file");
		String outFile1 = sc.nextLine();
		//create Receiver object
		Receiver myRec = new Receiver();
		//first we must calculate the hash value for comparison
		//SHA256
		byte[] expectedHash = new byte[1];
		
		try{
			//call SHA256 calculation method
			//with name of file holding Ks//M//Ks
			expectedHash = readDataInFromFile("message.khmac");
			encryptionKey = readDataInFromFile("message.kmk");
					
		}catch(Exception e) {
			System.out.println("Local hash calculation exception");
			e.printStackTrace();
		}
		
		
		//RSA decryption portion
		try {
			//get receiver private key
			PrivateKey yPri = Receiver.readPrivKeyFromFile("yPrivate.key");
			//get encrypted message for decryption
			byte[] rsaCipher = Receiver.readDataInFromFile("kxy.rsacipher");
		        secKey = rsaDecrypt(yPri, rsaCipher);
			byte[] aesCipher = Receiver.readDataInFromFile("message.aescipher");
			byte[] kmk = decrypt(aesCipher);
			
			byte[] actualHash = md(kmk);
			System.out.println("Acutal Hash:" + Utilities.bytesToHex(actualHash));
			System.out.println("Expected Hash:" + Utilities.bytesToHex(expectedHash));
			System.out.println("Do hashes match?");
			
			doesItMatch(actualHash,expectedHash);
			
			System.out.println(new String(kmk));
			
		}catch(Exception e) {
			System.out.println("RSA decryption excption");
			e.printStackTrace();
		}
		
		
		

	}
	
	public static byte[] md(byte[] in) throws Exception {
		BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(in));
		    MessageDigest md = MessageDigest.getInstance("SHA-256");
		    DigestInputStream dis = new DigestInputStream(bis, md);
		    int i;
		    byte[] buffer = new byte[BUFFER_SIZE];
		    do {
		      i = dis.read(buffer, 0, BUFFER_SIZE);
		    } while (i == BUFFER_SIZE);
		    md = dis.getMessageDigest();
		    dis.close();

		    byte[] hash = md.digest();
		    return hash;
	}
	
		
	public static byte[] decrypt(byte[] cipherText) throws Exception{
	    //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
	    Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
	    //Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
	    SecretKeySpec key = new SecretKeySpec(secKey, "AES");
	    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
	    byte[] output = cipher.doFinal(cipherText);
	    
	    byte[] expected = readDataInFromFile("message.kmk");
	   // doesItMatch(output,expected);
	    
	    return output;
	    //return new String(cipher.doFinal(cipherText),"UTF-8");
	  }
	
	
	public static void doesItMatch(byte[] a, byte[] b) {
		
		if (a == null && b == null) 
			return;
		if (a == null || b == null) {
			System.out.println("Mismatch:Nulls");
		}
	    if (a.length != b.length) {
	    	System.out.println("ERROR:" + a.length + "/" + b.length);
	    	return;
	    }
	    
	    for (int i = 0; i < a.length; i++) {
	    	if (a[i] != b[i]) {
	    		System.out.println("Mismatch at "+ i);
	    		System.out.println(Arrays.toString(a));
	    		System.out.println(Arrays.toString(b));
	    		return;
	    	}
	    }
	    System.out.println("IT MATCHED!");
	    
		
	}
	//read key parameters from a file and generate the private key 
	public static PrivateKey readPrivKeyFromFile(String keyFileName) 
	      throws IOException {

	    InputStream in = 
	        Receiver.class.getResourceAsStream(keyFileName);
	    ObjectInputStream oin =
	        new ObjectInputStream(new BufferedInputStream(in));

	    try {
	      BigInteger m = (BigInteger) oin.readObject();
	      BigInteger e = (BigInteger) oin.readObject();

	      System.out.println("Read from " + keyFileName + ": modulus = " + 
	          m.toString() + ", exponent = " + e.toString() + "\n");

	      RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
	      KeyFactory factory = KeyFactory.getInstance("RSA");
	      PrivateKey key = factory.generatePrivate(keySpec);

	      return key;
	    } catch (Exception e) {
	      throw new RuntimeException("Spurious serialisation error", e);
	    } finally {
	      oin.close();
	    }
	  }
	  
	  public static PublicKey readPubKeyFromFile(String keyFileName) 
		      throws IOException {

		    InputStream in = 
		        Receiver.class.getResourceAsStream(keyFileName);
		    ObjectInputStream oin =
		        new ObjectInputStream(new BufferedInputStream(in));

		    try {
		      BigInteger m = (BigInteger) oin.readObject();
		      BigInteger e = (BigInteger) oin.readObject();

		      System.out.println("Read from " + keyFileName + ": modulus = " + 
		          m.toString() + ", exponent = " + e.toString() + "\n");

		      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
		      KeyFactory factory = KeyFactory.getInstance("RSA");
		      PublicKey key = factory.generatePublic(keySpec);

		      return key;
		    } catch (Exception e) {
		      throw new RuntimeException("Spurious serialisation error", e);
		    } finally {
		      oin.close();
		    }
	  }
	  
	  public static byte[] readDataInFromFile(String keyFileName) 
		      throws IOException {
			byte[] val = null;
			//byte[] checker = null;
		    try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyFileName))) {
		    	
			//int howManyBlocks = in.read(checker, 0, 16);
			val = getByteArray(in);
		    	System.out.println("Encrypted message bytes:" + val);
		    	return val;
		    } catch (IOException e) {
		       // System.out.println("Read Symmetric key from file exception");
		        e.printStackTrace();
		    }
		    
			return null;
	  }
	  
		public static byte[] rsaDecrypt(PrivateKey priKey, byte[] input) throws Exception {
		    SecureRandom random = new SecureRandom();
		    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		    
		    /* first, encryption & decryption via the paired keys */
		    cipher.init(Cipher.DECRYPT_MODE, priKey);

		    byte[] aesCipher = cipher.doFinal(input);
		    
		   /* byte[] expected = readDataInFromFile("message.aescipher");
		    if (aesCipher.length != expected.length) {
		    	System.out.println("ERROR:" + aesCipher.length + "/" + expected.length);
		    }
		    
		    for (int i = 0; i < aesCipher.length; i++) {
		    	if (aesCipher[i] != expected[i]) {
		    		System.out.println("mismatch at "+ i);
		    		break;
		    	}
		    }*/
		    
		    System.out.println(new String(aesCipher));

		    
		    return aesCipher;
		  
	  }


	public static byte[] getByteArray(BufferedInputStream bs) throws IOException {
		byte[] retBytes = new byte[16];
		int cntLine;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		do{
			cntLine = bs.read(retBytes);
			if(cntLine < 16 && cntLine > 0){
				retBytes = Arrays.copyOfRange(retBytes, 0, cntLine);
				bos.write(retBytes);
			}
			if(cntLine == 16){
				bos.write(retBytes);
			}

		}while( cntLine != - 1);
		byte[] byteFinal = bos.toByteArray();
		return byteFinal; 
	}
	
	public static class Utilities {
		private final  static char[] HEX_ARRAY = 
			"1234567890123456".toCharArray();
		public static String bytesToHex(byte[] bytes) {
			char[] hexChars = new char[bytes.length * 2];
			for(int j = 0; j < bytes.length; j++) {
				int v = bytes[j] & 0xFF;
				hexChars[j * 2] = HEX_ARRAY[v >>> 4];
				hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
			}
			return new String(hexChars);
			}
		}
}
	




