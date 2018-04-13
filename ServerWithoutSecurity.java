import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.EOFException;
import java.net.ServerSocket;
import java.net.Socket;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerWithoutSecurity {
    static SecretKey aesSymmetricKey;
    static String protocol;
    static Cipher rsaEncryptCipher;
    static Cipher decryptCipher;

    public static void main(String[] args){
        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Enter protocol(RSA/AES):");

        try {
            protocol = stdIn.readLine();
            if (!protocol.equals("RSA") && !protocol.equals("AES")) {
                throw new IllegalArgumentException();
            }
        } catch (IOException | IllegalArgumentException ex) {
            ex.printStackTrace();
        }

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;
        while(true) {
            try {
                welcomeSocket = new ServerSocket(1234);
                connectionSocket = welcomeSocket.accept();
                fromClient = new DataInputStream(connectionSocket.getInputStream());
                toClient = new DataOutputStream(connectionSocket.getOutputStream());

                // Send certificate to client
                int clientSignal = fromClient.readInt();

                // Time to start.
                if(clientSignal == 1) {
                    // Start the h a n d s h a k e
                    // Read nonce
                    int nonceSize = fromClient.readInt();
                    byte[] nonce = new byte[nonceSize];
                    fromClient.read(nonce);
                    System.out.println("Received nonce from client.");

                    try {
                        rsaEncryptCipher = initialiseCipher("RSA-E");
                        System.out.println("Encrypting nonce...");
                        byte[] encryptedNonce = encryptBytes(nonce);
                        // String nonceStr = String.valueOf(nonce);
                        // byte[] encryptedMsg = encryptString(nonceStr);
                        toClient.writeInt(encryptedNonce.length); // Write length of message in bytes
                        toClient.write(encryptedNonce);

                        Path path = Paths.get("jyCert/server.crt");
                        byte[] data = Files.readAllBytes(path);
                        System.out.println("Sending certificate...");
                        toClient.writeInt(data.length); // Write length of certificate in bytes
                        toClient.write(data);

                        //Initialise cipher based on protocol
                        if (protocol.equals("RSA")) {
                            System.out.println("Using RSA protocol");
                            decryptCipher = initialiseCipher("RSA-D");

                        } else if (protocol.equals("AES")){
                            System.out.println("Using AES protocol");
                            decryptCipher = initialiseCipher("AES-D");
                            System.out.println("Encrypting session key...");
                            byte[] encryptedSymmetricKey = encryptBytes(aesSymmetricKey.getEncoded());
                            toClient.writeInt(encryptedSymmetricKey.length);
                            toClient.write(encryptedSymmetricKey);
                        }
                    }
                    catch(EOFException ex) {
                        ex.printStackTrace();
                    }
                    catch(IOException ex) {
                        ex.printStackTrace();
                    }
                }

                while (!connectionSocket.isClosed()) {
                    int packetType = fromClient.readInt();

                    // If the packet is for transferring the filename
                    if (packetType == 0) {
                        System.out.println(packetType);
                        System.out.println("Receiving filename...");

                        int numBytes = fromClient.readInt();
                        byte [] encryptedfilename = null;
                        if (protocol.equals("RSA")) {
                            encryptedfilename = new byte[128];
                            System.out.println("Block size: " + decryptCipher.getBlockSize());
                        } else if(protocol.equals("AES")){
                            encryptedfilename = new byte[decryptCipher.getBlockSize()];
                            System.out.println("Block size: " + decryptCipher.getBlockSize());
                        }
                        fromClient.read(encryptedfilename);
                        System.out.println("number of Bytes expected: " + numBytes);
                        byte[] filename = decryptCipher.doFinal(encryptedfilename);
                        System.out.println("Filename is " + new String(filename));
                        fileOutputStream = new FileOutputStream("recv/"+new String(filename, 0, numBytes));
                        bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                    } else if (packetType == 1) {
                        // System.out.println("Receiving file...");
                        int numBytes = fromClient.readInt();
                        byte[] encryptedBlock = new byte[128];
                        fromClient.read(encryptedBlock);
                        byte[] decryptedBlock = decryptCipher.doFinal(encryptedBlock);

                        if (numBytes > 0)
                            bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);
                    }

                    if (packetType == 2) {
                        System.out.println("Closing connection...");

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        toClient.writeInt(3);
                        fromClient.close();
                        toClient.close();
                        connectionSocket.close();
                        welcomeSocket.close();
                    }

                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }

    public static byte[] encryptString(String s) throws Exception {
        // Read private key from privateServer.pem
        // encrypt digest message
        byte[] encryptedBytes = rsaEncryptCipher.doFinal(s.getBytes());
        return encryptedBytes;
    }

    public static byte[] encryptBytes(byte[] b) throws Exception {
        // Read private key from privateServer.pem
        // encrypt digest message
        byte[] encryptedBytes = rsaEncryptCipher.doFinal(b);
        return encryptedBytes;
    }

    public static Cipher initialiseCipher(String type) throws Exception{
        Cipher cipher;
        Key privateKey;
        switch(type) {
            case "RSA-E":
                privateKey = getPrivateKey();
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                return cipher;
            case "RSA-D":
                privateKey = getPrivateKey();
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                return cipher;
            case "AES-D":
                aesSymmetricKey = KeyGenerator.getInstance("AES").generateKey();
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, aesSymmetricKey);
                return cipher;
            default:
                throw new IllegalArgumentException();
        }
    }

    public static Key getPrivateKey() throws Exception {
        // Load private key from .der file
        Path privateKeyPath = Paths.get("jyCert/privateServer.der");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        return privateKey;
    }

}
