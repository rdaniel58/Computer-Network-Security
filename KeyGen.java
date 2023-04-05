/**
 *  Name: Ryan Baertlein
 *  Date: 10/1/2022
 *  Assignment: Project 1
 *  Class: CS 3750.001
 */

/**
 * In the key generation program (required for EACH of Options 1, 2, and 3) in the directory “KeyGen”,
 * 1. Create a pair of RSA public and private keys for X, Kx+ and Kx–
 * 2. Create a pair of RSA public and private keys for Y, Ky+ and Ky–
 * 3. Get the modulus and exponent of each RSA public or private key and save them into files named “XPublic.key”,
 *    “XPrivate.key”, “YPublic.key”, and “YPrivate.key”, respectively;
 * 4. Take a 16-character user input from the keyboard and save this 16-character string to a file named “symmetric.key”.
 *    This string’s 128-bit UTF-8 encoding will be used as the 128-bit AES symmetric key, Kxy, in your application.
 */

import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;
import java.io.*;

public class KeyGen {

    static Key pubKeyX, privKeyX, pubKeyY, privKeyY;
    static byte[] symKey;

    // Create a pair of RSA public and private keys for X, Kx+, Kx–
    public static void createXPair() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);  //1024: key size in bits
        //when key size of RSA is 1024 bits, the RSA Plaintext block
        //size needs to be <= 117 bytes; and the RSA Ciphertext
        //block is always 128 Bytes (1024 bits) long.
        KeyPair pair = generator.generateKeyPair();
        pubKeyX = pair.getPublic();
        privKeyX = pair.getPrivate();
    }

    // Create a pair of RSA public and private keys for Y, Ky+ and Ky–
    public static void createYPair() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);  //1024: key size in bits
        //when key size of RSA is 1024 bits, the RSA Plaintext block
        //size needs to be <= 117 bytes; and the RSA Ciphertext
        //block is always 128 Bytes (1024 bits) long.
        KeyPair pair = generator.generateKeyPair();
        pubKeyY = pair.getPublic();
        privKeyY = pair.getPrivate();
    }

    // Get the modulus and exponent of each RSA public or private key and save them into files named “XPublic.key”,
    // “XPrivate.key”, “YPublic.key”, and “YPrivate.key”, respectively;
    public static void getModExponent() throws Exception {
        //get the parameters of the X-keys: modulus and exponent
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKSpecX = factory.getKeySpec(pubKeyX,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKSpecX = factory.getKeySpec(privKeyX,
                RSAPrivateKeySpec.class);
        //save the parameters of the X-keys to the files
        saveToFile("XPublic.key", pubKSpecX.getModulus(),
                pubKSpecX.getPublicExponent());
        saveToFile("XPrivate.key", privKSpecX.getModulus(),
                privKSpecX.getPrivateExponent());
        //get the parameters of the Y-keys: modulus and exponent
        factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKSpecY = factory.getKeySpec(pubKeyY,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKSpecY = factory.getKeySpec(privKeyY,
                RSAPrivateKeySpec.class);
        //save the parameters of the Y-keys to the files
        saveToFile("YPublic.key", pubKSpecY.getModulus(),
                pubKSpecY.getPublicExponent());
        saveToFile("YPrivate.key", privKSpecY.getModulus(),
                privKSpecY.getPrivateExponent());
    }


    // Take a 16-character user input from the keyboard and save this 16-character string to a file named “symmetric.key”.
    public static void createSymKey() throws Exception {
        // Take a 16-character user input from the keyboard
        BufferedOutputStream symKeyFile = new BufferedOutputStream(
                new FileOutputStream("symmetric.key"));
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Enter a 16-character string: ");
        // Save this 16-character string to a file named “symmetric.key”
        try {
            // Assign string to variable input
            String input = br.readLine();
            symKey = input.getBytes("UTF-8");
            symKeyFile.write(symKey, 0, symKey.length);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            symKeyFile.close();
        }
    }

    // Save the parameters of the public and private keys to file
    public static void saveToFile(String fileName,
                                  BigInteger mod, BigInteger exp) throws IOException {
        System.out.println("Write to " + fileName + ": modulus = " +
                mod.toString() + ", exponent = " + exp.toString() + "\n");
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

    // Main method
    public static void main(String[] args) throws Exception {
        // Create a pair of RSA public and private keys for X, Kx+ and Kx–;
        createXPair();
        // Create a pair of RSA public and private keys for Y, Ky+ and Ky–;
        createYPair();
        // Get the modulus and exponent of each RSA public or private key and save them into files named “XPublic.key”, ”XPrivate.key”, “YPublic.key”, and “YPrivate.key”, respectively;
        getModExponent();
        // Take a 16-character user input from the keyboard and save this 16-character string to a file named “symmetric.key”.
        createSymKey();
    }
}
