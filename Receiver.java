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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;

/**
 *  In the receiver’s program in the directory “Receiver”, use RSA Decryption to get Kxy, use AES Decryption
 *  to get M, compare SHA256(Kxy || M || Kxy) with the locally calculated SHA256 hash of (Kxy || M || Kxy),
 *  and report hashing error if any.
*/

 public class Receiver {

    public static final int BLOCK_SIZE = 32 * 1024;
    static Key privKeyY;
    public static byte[] decryptedMessage, symKey, localHash;
    static String message;

    // Read key parameters from a file and generate the private key
    public static PrivateKey readPrivKeyFromFile(String keyFileName)
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
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey privKey = fact.generatePrivate(keySpec);
            return privKey;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            in.close();
            oin.close();
        }
    }

    // Get symmetric key using RSA decryption
    public static void getSymKey()
            throws Exception {
        // Read in the encrypted symKey from the file
        Path path = Paths.get("kxy.rsacipher");
        byte[] encryptedSymKey;
        try {
            encryptedSymKey = Files.readAllBytes(path);
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
        // Read key parameters from a file and generate the private key
        privKeyY = readPrivKeyFromFile("YPrivate.key");
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privKeyY);
            symKey = cipher.doFinal(encryptedSymKey);
            BigInteger no = new BigInteger(1, symKey);
            // Convert message digest into hex value
            String symHex = no.toString(16);
            // Add preceding 0s to make it 32 bit
            while (symHex.length() < 32) {
                symHex = "0" + symHex;
            }
            System.out.println("Symmetric key: " + symHex);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
    }

    // Decrypt the message using AES decryption
    public static void decryptMessage()
            throws Exception {
        // Read in the message from the file
        BufferedInputStream msgFile = new BufferedInputStream(new FileInputStream("message.aescipher"));
        // Create a byte array whose size is BLOCK_SIZE
        byte[] ciphertext = new byte[BLOCK_SIZE];
        //Read in the message from the file piece by piece
        int numBytesRead;
        while ((numBytesRead = msgFile.read(ciphertext, 0, ciphertext.length)) != -1) {
            if (numBytesRead < BLOCK_SIZE) {
                byte[] temp = new byte[numBytesRead];
                for (int i = 0; i < numBytesRead; i++) {
                    temp[i] = ciphertext[i];
                }
                ciphertext = temp;
            }
            decryptedMessage = new byte[numBytesRead]; // The encrypted message
            try {
                Cipher cipher = Cipher.getInstance("AES");
                SecretKey secretKey = new SecretKeySpec(symKey, "AES");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                decryptedMessage = cipher.doFinal(ciphertext);
            } catch (Exception e) {
                System.out.println("Error while encrypting: " + e.toString());
            }
        }
        message = new String(decryptedMessage);
        System.out.println("Decrypted message: " + message);
        saveToFile(decryptedMessage);
    }

    public static void hashLocalMessage()
            throws Exception {
        localHash = getKeyedHashMac(decryptedMessage);
    }

    public static byte[] getKeyedHashMac(byte[] message)
            throws NoSuchAlgorithmException {
        // Get the SHA256 hash value of (Kxy||M||Kxy)
        byte[] hshMsg = new byte[2 * symKey.length + decryptedMessage.length];
        for (int i = 0; i < symKey.length; i++) {
            hshMsg[i] = symKey[i];
        }
        for (int i = 0; i < decryptedMessage.length; i++) {
            hshMsg[symKey.length + i] = decryptedMessage[i];
        }
        for (int i = 0; i < symKey.length; i++) {
            hshMsg[symKey.length + decryptedMessage.length + i] = symKey[i];
        }
        byte[] hash;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try {
            hash = md.digest(hshMsg);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for(byte b: hash) {
                sb.append(String.format("%02x", b));
            }
            String hashtext = sb.toString();
            // Print the hash value
            System.out.println("The local hash value of the message SHA256(Kxy||M||Kxy) is: " + hashtext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return hash;
    }

    public static boolean compareHashes()
            throws IOException, NoSuchAlgorithmException {
        // Read in the message from the file
        Path path = Paths.get("message.khmac");
        byte[] remoteHash;
        try {
            remoteHash = Files.readAllBytes(path);
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
        // Compare the two hash values
        if (Arrays.equals(remoteHash, localHash)) {
            System.out.println("The hash values match.");
            return true;
        } else {
            System.out.println("The hash values do not match.");
            return false;
        }
    }

    public static void saveToFile(byte[] b)
            throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Input the file destination to save the message: ");
        String fileName;
        try {
            fileName = br.readLine();
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            br.close();
        }
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
        getSymKey();
        decryptMessage();
        hashLocalMessage();
        compareHashes();
    }
}
