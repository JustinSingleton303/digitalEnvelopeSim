/*
*  Author: Justin Singleton
*  Course: CS 3750 A
*  Title : Symetric key encryption example
*/
//package homework2encryption;
import java.io.*;
import java.math.*;
import java.util.Scanner;


/**
 *
 * @author Justin Singleton
 */
public class Homework2Encryption {

    /**
     * @param args the command line arguments
     */
    
    //Global Variables
    int key = 0;
    int delta1 = 0x11111111;
    int delta2 = 0x22222222;
    //integer array decleration
    int [] k = new int[4];
    int [] l = new int[4];
    int [] r = new int[4];
    
    
    //empty constructor
    public Homework2Encryption(){
        
    }
    
    //The main method and main control loop
    
    public static void main(String[] args) {
        
        
        
        Homework2Encryption he = new Homework2Encryption();
        Scanner sc = new Scanner(System.in);
        System.out.println("welcome to Symetric Encryption");
        System.out.println("Enter an intial key value in Hex");
        String kStr = sc.nextLine();
        
        int k = Integer.parseUnsignedInt(kStr, 16);
        he.k[0] = k;
        
        System.out.println("Enter the next key value in Hex");
        kStr = sc.nextLine();
        
        k = Integer.parseUnsignedInt(kStr, 16);
        
        he.k[1] = k;
        System.out.println("Enter the next key Value in Hex");
        kStr = sc.nextLine();
        
        k = Integer.parseUnsignedInt(kStr, 16);
        he.k[2] = k;
        System.out.println("Enter the next key Value in Hex");
        kStr = sc.nextLine();
        
        k = Integer.parseUnsignedInt(kStr, 16);
        he.k[3] = k;
        
        
        //Encryption round 1
        
        //getting inital user inputs for arrays l[] and r[]
        System.out.println("Input a value for L0 in hex");
        String inStr = sc.nextLine();
        
        he.l[0] = Integer.parseUnsignedInt(inStr, 16);
        
        System.out.println("Input a value for R0 in hex");
        inStr = sc.nextLine();
        
        he.r[0] = Integer.parseUnsignedInt(inStr, 16);
        he.l[1]= he.r[0];
        
        // function F implementation as well as modular addition
        int fOut1 = he.F(he.delta1, he.r[0], he.k[0], he.k[1]);
        he.l[0] = he.l[0] + fOut1;
        he.r[1] = he.l[0];
        
        // print r[1] and l[1] to the screen
        String rStr = Integer.toHexString(he.r[1]);
        System.out.println("The encryption output r[1] is " + rStr);
        String lStr = Integer.toHexString(he.l[1]);
        System.out.println("and l[1] is" );
        
        //encryption round 2
        int fOut2 = he.F(he.delta2, he.r[1], he.k[2], he.k[3]);
        //passing r and l values in from the last r0
        he.l[2] = he.r[1];
        he.l[1] = he.l[1] + fOut2;
        he.r[2] = he.l[1];
        rStr = Integer.toHexString(he.r[2]);
        System.out.println("The encryption output is r[2]" + rStr);
       
        
    }
    
    //takes 2 integers and does a bitwise XOR 
    //operation and returns the result
    public int XOR(int a, int b){
        int result = 0;
        result = a ^ b;
        return result;
    }
    
    //the big function of encryption
    //does the F portion
    public int F(int delta, int x, int km, int kn){
        int result = 0;
        int x1 = x, x2 = x, x3 = x;
        
        // do the math stuff here
        //Doing the respective shift operations
        x1 = (x1<<4);
        x2 = (x2>>5);
        
        //here we have all of the modular operations
        //we assign them all to our x's to then XOR
        x1 = x1 + km;
        x2 = x2 + kn;
        x3 = x3 + delta;
        
        // XOR from left to right
        result = XOR(x1, x3);
        result = XOR(result, x2);
        return result;
    }
    
    //  Decryption algorithm R0 and L0
    //  referred to in this method are the
    //  R0 and L0 in the assignment description
    public int[] decrypt(){
       int[] outInt = new int[3];
       int temp1 = 0, temp2 = 0, temp3 = 0;
       
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
       
       return outInt;
    }
    
}



