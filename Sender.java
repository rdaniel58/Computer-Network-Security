/**
 *  Name: Ryan Baertlein
 *  Date: 10/1/2022
 *  Assignment: Project 1
 *  Class: CS 3750.001
 */

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;

/**
 * In the sender’s program in the directory “Sender”, calculate SHA256 (Kxy || M || Kxy),
 * AES-En Kxy (M), and RSA-En Ky+ (Kxy)
 */

public class Sender {

    public static final int BLOCK_SIZE = 32 * 1024;
    static Key pubKeyY;
    static byte[] symKey;
    static int numBytesRead;
    static String fileName;

    // Read key parameters from a file and generate the public key
    public static PublicKey readPubKeyFromFile(String keyFileName)
            throws IOException {
        // Read in the message from the file
        InputStream in = new FileInputStream(keyFileName);
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

    // Read key parameters from a file and generate the symmetric key
    public static byte[] readSymKeyFromFile(String keyFileName)
            throws IOException {
        // Read in the message from the file
        BufferedInputStream symKeyFile = new BufferedInputStream(
                new FileInputStream("symmetric.key"));
        byte[] symKey;
        try {
            symKey = symKeyFile.readAllBytes();
            BigInteger no = new BigInteger(1, symKey);
            // Convert message digest into hex value
            String symHex = no.toString(16);
            // Add preceding 0s to make it 32 bit
            while (symHex.length() < 32) {
                symHex = "0" + symHex;
            }
            System.out.println("Read from " + keyFileName + ": " + symHex);
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
        return symKey;
    }

    // Read in the message file and save (Kxy||M||Kxy) to a file
    public static void readMessage()
            throws IOException {
        // Read in the message from the file
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Input the name of the message file: ");
        fileName = br.readLine();
        BufferedInputStream msgFile = new BufferedInputStream(new FileInputStream(fileName));
        // Create a byte array whose size is BLOCK_SIZE
        byte[] plaintext = new byte[BLOCK_SIZE];
        numBytesRead = msgFile.read(plaintext, 0, plaintext.length);
        //Read in the message from the file piece by piece
        try {
            while (msgFile.read(plaintext, 0, plaintext.length) != -1) {
                numBytesRead = msgFile.read(plaintext, 0, plaintext.length);
            }
        } catch (Exception e) {
            throw new RuntimeException("Error reading message. ", e);
        }
        byte[] message = new byte[2 * symKey.length + numBytesRead];
        for (int i = 0; i < symKey.length; i++) {
            message[i] = symKey[i];
        }
        for (int i = 0; i < numBytesRead; i++) {
            message[symKey.length + i] = plaintext[i];
        }
        for (int i = 0; i < symKey.length; i++) {
            message[symKey.length + numBytesRead + i] = symKey[i];
        }
        // Save (Kxy||M||Kxy) to a file
        saveToFile("message.kmk", message);
    }

    // Read in the message file and save the SHA256 (Kxy||M||Kxy) hash value to a file
    public static void hashMessage()
            throws IOException, NoSuchAlgorithmException {
        // Read in the message from the file
        BufferedInputStream bin = new BufferedInputStream(new FileInputStream("message.kmk"));
        // Create a byte array whose size is BLOCK_SIZE
        byte[] message = new byte[numBytesRead + 2 * symKey.length];
        try {
            //Read in the message from the file piece by piece
            while (bin.read(message, 0, message.length) != -1) {
                bin.read(message, 0, message.length);
            }
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            bin.close();
        }
        byte[] hash = getKeyedHashMac(message);
        // Save the message to a file named “message.kmk”
        saveToFile("message.khmac", hash);
    }

    // Read in the message file, encrypt the message using AES, and save the ciphertext to a file
    public static void encryptMessage()
            throws IOException {
        // Read in the message from the file
        BufferedInputStream msgFile = new BufferedInputStream(new FileInputStream(fileName));
        // Create a byte array whose size is BLOCK_SIZE
        byte[] plaintext = new byte[BLOCK_SIZE];
        //Read in the message from the file piece by piece
        byte[] cipherAES = new byte[0];
        while ((numBytesRead = msgFile.read(plaintext, 0, plaintext.length)) != -1) {
            if (numBytesRead < BLOCK_SIZE) {
                byte[] temp = new byte[numBytesRead];
                for (int i = 0; i < numBytesRead; i++) {
                    temp[i] = plaintext[i];
                }
                plaintext = temp;
            }
            cipherAES = new byte[numBytesRead]; // The encrypted message
            try {
                Cipher cipher = Cipher.getInstance("AES");
                SecretKey secretKey = new SecretKeySpec(symKey, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                cipherAES = cipher.doFinal(plaintext);
            } catch (Exception e) {
                System.out.println("Error while encrypting: " + e.toString());
            }
        }
        // Save the message to a file named “message.kmk”
        saveToFile("message.aescipher", cipherAES);
    }

    // Read in the symmetric key, encrypt the key using RSA, and save the ciphertext to a file
    public static void encryptSymKey()
            throws IOException {
        // Initialize symmetric cipher
        byte[] cipherRSA = new byte[256]; // The encrypted message
        byte[] symmetric = new byte[symKey.length];
        for (int i = 0; i < symKey.length; i++) {
            symmetric[i] = symKey[i];
        }
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKeyY);
            cipherRSA = cipher.doFinal(symmetric);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        // Save the message to a file named “message.kmk”
        saveToFile("kxy.rsacipher", cipherRSA);
    }

    // Invert the first byte in the byte array holding SHA256(M)
    public static byte[] invertFirstByte(byte[] msg)
            throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Do you want to invert the 1st byte in SHA256(Kxy||M||Kxy)? (Y/n): ");
        try {
            // Assign string to variable input
            String input = br.readLine();
            if (input.equals("Y") && msg.length > 0) {
                msg[0] = (byte) ~msg[0];
            }
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        }
        return msg;
    }

    public static byte[] getKeyedHashMac(byte[] message)
            throws NoSuchAlgorithmException {
        // Get the SHA256 hash value of (Kxy||M||Kxy)
        byte[] hash;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try {
            hash = md.digest(message);
            // Ask to invert the first byte in hash
            hash = invertFirstByte(hash);
            // Convert message digest into hex value
            // Add preceding 0s to make it 32 bit
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for(byte b: hash) {
                sb.append(String.format("%02X", b));
            }
            String hashtext = sb.toString();
            // Print the hash value
            System.out.println("The hash value of the message SHA256(Kxy||M||Kxy) is: " + hashtext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return hash;
    }

    public static void saveToFile(String fileName, byte[] b)
            throws IOException {
        System.out.println("Write to " + fileName + "\n");
        BufferedOutputStream bout = new BufferedOutputStream(
                new FileOutputStream(fileName));
        try {
            bout.write(b, 0, b.length);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            bout.close();
        }
    }

    // Main method
    public static void main(String[] args)
            throws Exception {
        // Read the information on the keys to be used in this program from the key files and generate Ky+ and Kxy
        pubKeyY = readPubKeyFromFile("YPublic.key");
        symKey = readSymKeyFromFile("symmetric.key");
        // Read in the message file and save (Kxy||M||Kxy) to a file
        readMessage();
        // Read in the message file and save the SHA256 (Kxy||M||Kxy) hash value to a file
        hashMessage();
        // Read in the message file, encrypt the message using AES, and save the ciphertext to a file
        encryptMessage();
        // Read in the symmetric key, encrypt the key using RSA, and save the ciphertext to a file
        encryptSymKey();
    }
}
