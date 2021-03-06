package receiver;
/*
 * Sender.java
 * 
 * Author: Justin Singleton
 * 
 */
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class Sender extends KeyedHash{
	
	//This class needs to carry out the task of the sender's side
	//of the digital envelope encryption system
	
	//Class variables
	KeyPair xKeys, yKeys;
	private static int BUFFER_SIZE = 32 * 1024;
	static String IV = "AAAAAAAAAAAAAAAA";
	
	static String plaintext = "test text 123456ABCDEF987654321"; 
	
	static String encryptionKey = "0123456789abcdef";
	String aesEncrypt = "";
	File xFilePub = new File("xPublic.key");
	File xFilePri = new File("xPrivate.key");
	File yFilePub = new File("yPublic.key");
	File yFilePri = new File("yPrivate.key");
	File sKeyFile = new File("Symmetric.key");
	
	
	public static void main(String[] args) {
		
		//Start instance of class Sender
		Sender mySend = new Sender();
		String myAESKey = "";
		//Scanner for user input
		Scanner sc = new Scanner(System.in);
		//greet user and get name of input file
		System.out.println("Welcome to sender program");
		System.out.println("Enter name of message input file");
		String mesStr = sc.nextLine();
		String keyFileName = "Symmetric.key";
		
		//first we need to make the Ks//M//Ks
		//byte[] symKey = null;
		byte[] messageKey = null;
		byte[] bSymKey = null;
		try {
			messageKey = Sender.readSymmetricKeyFromFile(mesStr);
			bSymKey = mySend.readBytesFromFile("Symmetric.key");
			
			System.out.println("Message = " + messageKey);
			String strSymKey = bSymKey.toString();
			System.out.println(strSymKey);
		}catch(Exception e) {
			System.out.println("Symmetric key read exception");
		}
		//compute SHA256
		byte[] AESBytes = null;
		try {
			//put together Ks//M//Ks
			AESBytes = bSymKey;
			Sender.byteWriter(AESBytes, "message.kmk");
			AESBytes = messageKey;
			Sender.byteAppender(AESBytes, "message.kmk");
			AESBytes = bSymKey;
			Sender.byteAppender(AESBytes, "message.kmk");
			//call hash function and write result to file
			String hashVal = Sender.md("message.kmk");
			AESBytes = hashVal.getBytes();
			Sender.byteWriter(AESBytes, "message.khmac");
			}catch(Exception e) {
			System.out.println("SHA256 Calculation Exception");
		}
		
		//Compute AES next
		byte[] myCipher = null;
		
		try {
			//get symmetric key from file
			String keyString = Sender.readStringFromFile("Symmetric.key");
			byte[] keyBytes = mySend.readBytesFromFile("Symmetric.key");
			byte[] hashedBytes = mySend.readBytesFromFile("message.khmac");		
			Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
			SecretKeySpec key = new SecretKeySpec(keyString.getBytes(StandardCharsets.UTF_8), "AES");
		    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
			myCipher = cipher.doFinal(hashedBytes);
			Sender.byteWriter(myCipher, "message.aescipher");
			
			//write byte array to file
			OutputStream os = new FileOutputStream("message.aescipher");
			os.write(myCipher);
			os.close();
		} catch(Exception e) {
			System.out.println("AES encryption exception");
		}
		
		//compute RSA encryption
		byte[] RSACipher = null;
		try {
			// get receivers public key
			PublicKey yPub = Sender.readPubKeyFromFile("yPublic.key");
			// encrypt RSA
			//RSACipher = Sender.rsaEncrypt(yPub, myCipher);
			//write byte array to file
			//OutputStream os = new FileOutputStream("kxy.rsacipher");
			//os.write(RSACipher);
			//os.close();
		
		}catch(Exception e) {
			System.out.println("RSA encryption exception");
		}
		sc.close();
	
	}
	
	// this is the method we use to generate SHA256 
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
	      System.out.format("%2X ", Byte.valueOf(hash[k])) ;
	      if (j >= 15) {
	        System.out.println("");
	        j=-1;
	      }
	    }
	    byteWriter( hash, "message.khmac");
	    System.out.println("");    
	    return new String(hash);
	}
	
	
	//AES encryption code
	public static byte[] encrypt() throws Exception {
	    //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
	    //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
	    Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
	    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
	    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
	    
	    return cipher.doFinal(plaintext.getBytes("UTF-8"));
	}
	  
	  //AES decryption code
	public static String decrypt(byte[] cipherText) throws Exception{
	    //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
	    //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
	    Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
	    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
	    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
	    return new String(cipher.doFinal(cipherText),"UTF-8");
	}
	  
	  //RSA code to read RSA private key from a .key file
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
	  
	  // code to read RSA public key from .key file
	  public static PublicKey readPubKeyFromFile(String keyFileName) 
		      throws IOException {

		    InputStream in = 
		        Sender.class.getResourceAsStream(keyFileName);
		    System.out.println("Input stream created");
		    ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
		    System.out.println("Object input stream created");

		    try {
		      BigInteger m = (BigInteger) oin.readObject();
		      BigInteger e = (BigInteger) oin.readObject();

		      System.out.println("Read from " + keyFileName + ": modulus = " + 
		          m.toString() + ", \n\t\t\t\t\texponent = " + e.toString() + "\n");

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
	  
	  public static byte[] readSymKeyFromFile(String keyFileName) throws IOException {
		  byte[] retBytes = null;
		  
		  try{
			  BufferedInputStream bs = new BufferedInputStream(new FileInputStream(keyFileName));
			  retBytes = bs.readAllBytes();
			  bs.close();
		  }catch(Exception e) {
			  System.out.println("Symmetric key file read exception");
		  }
		  
		  return retBytes;
	  }
	  
	  public static byte[] readSymmetricKeyFromFile(String keyFileName) 
		      throws IOException {
		  byte[] key = null;
		  try {BufferedInputStream bs = new BufferedInputStream(new FileInputStream(keyFileName));
		  		key = bs.readAllBytes();
		  		bs.close();
		  }catch(Exception e) {
					  
		  }
		  return key;
	  }
	  
	  public static void writeKeyToFile(String fileName, String wriStr) throws Exception{
		  	FileWriter myWrite = new FileWriter(fileName, true);
		  	PrintWriter myPrint = new PrintWriter(myWrite);
		  
		  	System.out.println("Write to " + fileName + " " + wriStr);
		  	try {
		  		myPrint.println(wriStr);
		  	}catch(Exception e) {
		  		System.out.println("Write key to file exception");
		  }finally {
			  	myWrite.close();
		  }
	  }
	  
	  public static byte[] ReadAllBytes(String filename) throws IOException {
	        File file = new File(filename);
	        byte[] fileBytes = Files.readAllBytes(file.toPath());
	        return fileBytes;
	    }
	  
	  public byte[] readBytesFromFile(String fileName) throws Exception{
		  byte [] retByte = null;
		  File myFile = new File(fileName);
		  retByte = ReadAllBytes(fileName);
		  return retByte;
	  }
	  
	  private static void byteWriter(byte[] bytes, String fileName) {
	        try (FileOutputStream os = new FileOutputStream(fileName)) {
	            os.write(bytes);
	        } catch (IOException e) {
	            e.printStackTrace();
	        }
	    }
	  
	  private static void byteAppender(byte[] byteFile, String fileDest) {
	        try (FileOutputStream os = new FileOutputStream(fileDest, true)) {
	            os.write(byteFile);
	        } catch (IOException e) {
	            e.printStackTrace();
	        }
	    }
	  
	  public static String readStringFromFile(String fileName) throws IOException{
		  String retString = "";
		  BufferedReader br = new BufferedReader(new FileReader(fileName));
		  retString = br.readLine();
		  return retString;
	  }
	  
	 /* public static void appendKeyToFile(String fileName, String wriStr) throws Exception{
		  	FileWriter myWrite = new FileWriter(fileName, true);
		  	PrintWriter myPrint = new PrintWriter(myWrite);
		  
		  	System.out.println("Write to " + fileName + " " + wriStr);
		  	try {
		  		myPrint.print(wriStr);
		  	}catch(Exception e) {
		  		System.out.println("Write key to file exception");
		  }finally {
			  	myWrite.close();
		  }
	  }
	  */
	  
	  
	  // use this for RSA type encryption
	  @SuppressWarnings("deprecation")
	public static byte[] rsaEncrypt(PublicKey pubKey, byte[] input) throws Exception {
		    SecureRandom random = new SecureRandom();
		  	//byte [] input = "012340123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".getBytes();
		    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		    
		    /* first, encryption & decryption via the paired keys */
		    cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

		    byte[] cipherText = cipher.doFinal(input);

		    System.out.println("cipherText: block size = " + cipher.getBlockSize());
		    for (int i=0, j=0; i<cipherText.length; i++, j++) {
		      System.out.format("%2X ", Byte.valueOf(cipherText[i])) ;
		      if (j >= 15) {
		        System.out.println("");
		        j=-1;
		      }
		    }
		    System.out.println("");
		    return cipherText;
		  
	  }
	  
	  // not sure if i need this one here or in receiver.java
	  public void rsaDecrypt() {
		  
	  }

	
	

}

