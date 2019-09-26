/*Homework2Decryption.java
 *Author: Justin Singleton
 *
 *
 * Purpose: This program is to teach us about
 * Symmetric encryption methods.  
 */

//package homework2decryption;
import java.util.Scanner;

public class Homework2Decryption {
	
	//Class variables
	int delta1 = 0x11111111;
	int delta2 = 0x22222222;
	int [] l = new int[4];
	int [] r = new int[4];
	int [] k = new int[4];
	
	// default constructor
	public Homework2Decryption() {
				
	}
	
	public static void main(String[] args) {
		// set up program objects
		Homework2Decryption hd = new Homework2Decryption();
		Scanner sc = new Scanner(System.in);
		
		//Greet user and begin key inputs
		System.out.println("Welcome to symeteric decryption!");
		System.out.println("Let's initialize our key values!");
		//User inputs key values
		System.out.println("Enter a key value in hex.");
		String kStr = sc.nextLine();
		hd.k[0] = Integer.parseUnsignedInt(kStr, 16);
		
		System.out.println("Enter a key value in hex.");
		kStr = sc.nextLine();
		hd.k[1] = Integer.parseUnsignedInt(kStr, 16);
		
		System.out.println("Enter a key value in hex.");
		kStr = sc.nextLine();
		hd.k[2] = Integer.parseUnsignedInt(kStr, 16);
		
		System.out.println("Enter a key value in hex.");
		kStr = sc.nextLine();
		hd.k[3] = Integer.parseUnsignedInt(kStr, 16);
		
		//get user to input an L2 and R2, L0 and R0
		System.out.println("Enter a value for L2 in hex.");
		kStr = sc.nextLine();
		hd.l[2] = Integer.parseUnsignedInt(kStr, 16);
		
		System.out.println("Enter a value for R2 in hex.");
		kStr = sc.nextLine();
		hd.r[2] = Integer.parseUnsignedInt(kStr, 16);
		
		System.out.println("Enter a value for L0 in hex.");
		kStr = sc.nextLine();
		hd.l[0] = Integer.parseUnsignedInt(kStr, 16);
		
		System.out.println("Enter a value for R2 in hex.");
		kStr = sc.nextLine();
		hd.r[0] = Integer.parseUnsignedInt(kStr, 16);
		
		// Here is the decryption portion of the program
		hd.decrypt();
		
		System.out.println("After one round of decryption ");
		String prStr = Integer.toHexString(hd.l[0]);
		System.out.println("L1 after decryption = " + prStr);
		
		prStr = Integer.toHexString(hd.r[0]);
		System.out.println("R1 after decryption = " + prStr);
		
		// Round2
		hd.decrypt();
		
		System.out.println("After two rounds of decryption ");
		prStr = Integer.toHexString(hd.l[0]);
		System.out.println("L0 after decryption = " + prStr);
		
		prStr = Integer.toHexString(hd.r[0]);
		System.out.println("R0 after decryption = " + prStr);
		
	}
	
	//  Decryption algorithm R0 and L0
    //  referred to in this method are the
    //  R0 and L0 in the assignment description
    public void decrypt(){
       int[] outInt = new int[3];
       int temp1 = 0x0, temp2 = 0x0, temp3 = 0x0;
       
       //R0 calculation 
       //Starting with shift
       temp1 = l[2] << 4;
       
       temp1 = temp1 + k[2];
       
       temp2 = temp2 + delta2;
       
       temp3 = l[2] >> 5;
       temp3 = temp3 + k[3];
       
       //XOR portion of calculation
       //updates array so proper value
       //is passed out
       outInt[0] = XOR(temp1, temp2);
       outInt[0] = XOR(outInt[0], temp3);
       
       //Final subtraction 
       outInt[0] = r[2] - outInt[0];
       
       //L0 calculation
       temp1 = r[0] << 4;
       temp1 = temp1 + k[2];
       
       temp2 = r[0] + delta2;
       
       temp3 = r[0] >> 5;
       temp3 = temp3 + k[1];
       
       outInt[1] = XOR(temp1, temp2);
       outInt[1] = XOR(outInt[1], temp3);
       
       //Final subtraction
       outInt[1] = l[2] - outInt[1];
      
       //change object level vars
       r[0] = outInt[0];
       l[0] = outInt[1];
       
    }
    
    //takes 2 integers and does a bitwise XOR 
    //operation and returns the result
    public int XOR(int a, int b){
        int result = 0;
        result = a ^ b;
        return result;
    }

}
