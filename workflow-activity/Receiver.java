package receiver;

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
import java.security.SecureRandom;

public class Receiver {

	//class variables
	private static int BUFFER_SIZE = 32 * 1024;
	//AES stuff
	static String encryptionKey = "0123456789abcdef";
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
		String hashLocal = "";
		try{
			//call SHA256 calculation method
			//with name of file holding Ks//M//Ks
			hashLocal = Receiver.md("message.kmk");
		}catch(Exception e) {
			System.out.println("Local hash calculation exception");
		}
		
		//RSA decryption portion
		try {
			//get receiver private key
			PrivateKey yPri = Receiver.readPrivKeyFromFile("yPrivate.key");
			//get encrypted message for decryption
			String anRsaDecrypt = Receiver.readDataInFromFile("kxy.rsacipher");
		}catch(Exception e) {
			System.out.println("RSA decryption excption");
		}
		
		
		

	}
	
	public static String md(String f) throws Exception {
			BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
		    MessageDigest md = MessageDigest.getInstance("SHA-256");
		    DigestInputStream in = new DigestInputStream(file, md);
		    int i;
		    byte[] buffer = new byte[BUFFER_SIZE];
		    do {
		      i = in.read(buffer, 0, BUFFER_SIZE);
		    } while (i == BUFFER_SIZE);
		    md = in.getMessageDigest();
		    in.close();

		    byte[] hash = md.digest();

		    System.out.println("digit digest (hash value):");
		    for (int k=0, j=0; k<hash.length; k++, j++) {
		      System.out.format("%2X ", new Byte(hash[k])) ;
		      if (j >= 15) {
		        System.out.println("");
		        j=-1;
		      }
		    }return "";
	}
	
		
	public static String decrypt(byte[] cipherText) throws Exception{
	    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
	    //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
	    //Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
	    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
	    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
	    return new String(cipher.doFinal(cipherText),"UTF-8");
	  }
	
	//read key parameters from a file and generate the private key 
	public static PrivateKey readPrivKeyFromFile(String keyFileName) 
	      throws IOException {

	    InputStream in = 
	        RSAConfidentiality.class.getResourceAsStream(keyFileName);
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
		        RSAConfidentiality.class.getResourceAsStream(keyFileName);
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
	  
	  public static String readDataInFromFile(String keyFileName) 
		      throws IOException {

		  StringBuilder contentBuilder = new StringBuilder();
		    try (BufferedReader br = new BufferedReader(new FileReader(keyFileName)))
		    {
		 
		        String sCurLine;
		        while ((sCurLine = br.readLine()) != null)
		        {
		            contentBuilder.append(sCurLine);
		        }
		    }
		    catch (IOException e)
		    {
		        System.out.println("Read Symmetric key from file exception");
		    }
		    return contentBuilder.toString();
	  }

}

