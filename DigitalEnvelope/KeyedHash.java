//package receiver;

/*KeyedHash.java
 * 
 * Author: Justin Singleton, Anthony Walker
 * Course: CS 3750
 * 
 * Purpose:we are using digital envelope and a keyed hash mac
 * for encryption / decryption
 * 
 * The program is split into three parts key generation, sender and receiver
 * this is the key generator, which has been miss-named KeyedHash 
 * 
 * */


import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Scanner;
import java.math.BigInteger;

import javax.crypto.Cipher;

public class KeyedHash {
	
	
	//SHA256 mySHA = new SHA256();
	//AES AES1 = new AES();
	//RSAConfidentiality myRSAC = new RSAConfidentiality();
	KeyPair xKeys, yKeys;
	//File xFilePub = new File("xPublic.key");
	//File xFilePri = new File("xPrivate.key");
	//File yFilePub = new File("yPublic.key");
	//File yFilePri = new File("yPrivate.key");
	//File sKeyFile = new File("Symmetric.key");
	Key pub, priv;
	
	public static void main(String[] args) {
		
		//Greet User
		System.out.println("Welcome to key generator");		
		
		// create instance of keyedHash object
		KeyedHash myHash = new KeyedHash();
		System.out.println("Starting RSA keypair creation");
		try {
			
			//  assign random x and y keyPairs
			myHash.xKeys = myHash.makeRSAKeyPair();
			myHash.yKeys = myHash.makeRSAKeyPair();
		}catch (Exception e) {
			System.out.println("Keygen exception");
		}
		
		// Save generated keys to files
		myHash.pub = myHash.xKeys.getPublic();
		Key pubKey = myHash.xKeys.getPublic();
		Key privKey = myHash.xKeys.getPrivate();
		// we need the specs of the generated keys to save to the files
		try {
		KeyFactory factory = KeyFactory.getInstance("RSA");
	    RSAPublicKeySpec pubKSpec = factory.getKeySpec(pubKey, 
	        RSAPublicKeySpec.class);
	    RSAPrivateKeySpec privKSpec = factory.getKeySpec(privKey, 
	        RSAPrivateKeySpec.class);
	  //save the parameters of the keys to the files
	    KeyedHash.saveToFile("xPublic.key", pubKSpec.getModulus(), 
	        pubKSpec.getPublicExponent());
	    KeyedHash.saveToFile("xPrivate.key", privKSpec.getModulus(), 
	        privKSpec.getPrivateExponent());
	    
	    }catch(Exception e) {
	    	System.out.println("Save to file exception");
	    }
		
		// repeat that code for the yKeys
		//myHash.pub = myHash.yKeys.getPublic();
		pubKey = myHash.yKeys.getPublic();
		privKey = myHash.yKeys.getPrivate();
		// we need the specs of the generated keys to save to the files
		try {
		KeyFactory factory = KeyFactory.getInstance("RSA");
	    RSAPublicKeySpec pubKSpec = factory.getKeySpec(pubKey, 
	        RSAPublicKeySpec.class);
	    RSAPrivateKeySpec privKSpec = factory.getKeySpec(privKey, 
	        RSAPrivateKeySpec.class);
	  //save the parameters of the keys to the files
	    KeyedHash.saveToFile("yPublic.key", pubKSpec.getModulus(), 
	        pubKSpec.getPublicExponent());
	    KeyedHash.saveToFile("yPrivate.key", privKSpec.getModulus(), 
	        privKSpec.getPrivateExponent());
	    
	    }catch(Exception e) {
	    	System.out.println("Save to file exception");
	    }
		try {
		//PublicKey pubTestKey = KeyedHash.readPubKeyFromFile("yPublic.key");
		PrivateKey priTestKey = KeyedHash.readPrivKeyFromFile("yPrivate.key");
		}catch(Exception e) {
			System.out.println("Read Key Exception");
		}
		
		//next we need a 16 character key for the AES piece
		//of the encryption
		Scanner sc = new Scanner(System.in);
		System.out.println("Choose a 16 character symmetric key");
		String strSKey = sc.nextLine();
		
		//test string for 16 characters
		int keyLen = strSKey.length();
		byte[] symKeyByte = null;
		boolean goodKey = false;
		while(!goodKey) {
			if(keyLen == 16) {
				goodKey = true;
			}
			else {
				System.out.println("key not 16 characters!");
				System.out.println("Enter new key of 16 characters!");
				strSKey = sc.nextLine();
				keyLen = strSKey.length();
			}
			symKeyByte = strSKey.getBytes();
		}
		
		//save the valid key to a file
		
		try {
			OutputStream out1 = new FileOutputStream("Symmetric.key");
			out1.write(symKeyByte);
			out1.close();
		}catch(Exception e) {
			System.out.println("Save symmetric key exception");
		}
		
	}
	
	public KeyPair makeRSAKeyPair() throws Exception {
		
		//Generate a pair of keys
	    SecureRandom random = new SecureRandom();
	    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	    generator.initialize(1024, random);  //1024: key size in bits
	    KeyPair pair = generator.generateKeyPair();
	   
	    return pair;
	}
	
	//save the parameters of the public and private keys to file
	public static void saveToFile(String fileName,
	        BigInteger mod, BigInteger exp) throws IOException {

	    System.out.println("Write to " + fileName + ": modulus = " + 
	        mod.toString() + ", \n\t\t\texponent = " + exp.toString() + "\n");

	    ObjectOutputStream oout = new ObjectOutputStream(
	      new BufferedOutputStream(new FileOutputStream(fileName)));

	    try {
	      oout.writeObject(mod);
	      oout.writeObject(exp);
	    } catch (Exception e) {
	      throw new IOException("Unexpected error", e);
	    } finally {
	      oout.close();
	    }
	  }
	  
	  //overloaded method for saving non-RSA stuff to a file
	  public static void saveToFile(String fileName,
		        String keyStr) throws IOException {

		    System.out.println("Write to " + fileName + " " + keyStr);

		    ObjectOutputStream oout = new ObjectOutputStream(
		      new BufferedOutputStream(new FileOutputStream(fileName)));

		    try {
		      oout.writeObject(keyStr);
		      //oout.writeObject(exp);
		    } catch (Exception e) {
		    	throw new IOException("Unexpected error", e);
		    } finally {
		    	oout.close();
		    }
	  }
	  
	  //The saveToFile method was saving trash to the beginning of the Symmetric key
	  //this method cleans that up
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
	  
	  public static PublicKey readPubKeyFromFile(String keyFileName) 
		      throws IOException {

		    InputStream in = KeyedHash.class.getResourceAsStream(keyFileName);
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
	  
		 public static PrivateKey readPrivKeyFromFile(String keyFileName) 
			      throws IOException {

			    InputStream in = 
			       KeyedHash.class.getResourceAsStream(keyFileName);
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
	
	
	
	
}

