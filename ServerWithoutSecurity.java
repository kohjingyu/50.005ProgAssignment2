import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
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
    static final String PROTOCOL = "cp2";
    static Cipher rsaEncryptCipher;
    static Cipher rsaDecryptCipher;
    static Cipher aesDecryptCipher;

    public static void main(String[] args){
        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

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
                    initialiseCipher();
                    System.out.println("Encrypting nonce...");
                    byte[] encryptedNonce = encryptBytes(nonce);
                    // String nonceStr = String.valueOf(nonce);
                    // byte[] encryptedMsg = encryptString(nonceStr);
                    toClient.writeInt(encryptedNonce.length); // Write length of message in bytes
                    toClient.write(encryptedNonce);

                    Path path = Paths.get("jyCert/server.crt");
                    byte[] data = Files.readAllBytes(path);
                    toClient.writeInt(data.length); // Write length of certificate in bytes
                    toClient.write(data);

                    System.out.println("Encrypting session key...");
                    byte[] encryptedSymmetricKey = encryptBytes(aesSymmetricKey.getEncoded());
                    toClient.writeInt(encryptedSymmetricKey.length);
                    toClient.write(encryptedSymmetricKey);
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
                    byte [] encryptedfilename = new byte[aesDecryptCipher.getBlockSize()];
                    fromClient.read(encryptedfilename);
                    System.out.println("number of Bytes expected: " + numBytes);
                    byte[] filename = decryptBytes(encryptedfilename,PROTOCOL);
                    System.out.println("Filename is " + new String(filename));
                    fileOutputStream = new FileOutputStream("recv/"+new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {
                    // System.out.println("Receiving file...");
                    int numBytes = fromClient.readInt();
                    byte[] encryptedBlock = new byte[128];
                    fromClient.read(encryptedBlock);
                    byte[] decryptedBlock = decryptBytes(encryptedBlock,PROTOCOL);

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
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
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

    public static void initialiseCipher() throws Exception{
        Key privateKey = getPrivateKey();
        rsaEncryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaEncryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        rsaDecryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaDecryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        aesSymmetricKey = KeyGenerator.getInstance("AES").generateKey();
        aesDecryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesDecryptCipher.init(Cipher.DECRYPT_MODE, aesSymmetricKey);
    }

    public static byte[] decryptBytes(byte[] encryptedByte, String protocol) throws Exception {
        if (protocol.equals("cp1")) {
            byte[] decryptedBytes = rsaDecryptCipher.doFinal(encryptedByte);
            return decryptedBytes;
        } else if (protocol.equals("cp2")) {
            byte[] decryptedBytes = aesDecryptCipher.doFinal(encryptedByte);
            return decryptedBytes;
        } else {
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
