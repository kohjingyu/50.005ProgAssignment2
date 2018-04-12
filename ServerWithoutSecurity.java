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
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerWithoutSecurity {
    Key privateKey;
    static Cipher encryptCipher;
    static Cipher decryptCipher;


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

            // Start the h a n d s h a k e
            try {
                initialiseCipher();
                byte[] encryptedMsg = encryptString("Helllo this is SecStore!");
                toClient.writeInt(encryptedMsg.length); // Write length of message in bytes
                toClient.write(encryptedMsg);

                Path path = Paths.get("jyCert/server.crt");
                byte[] data = Files.readAllBytes(path);
                toClient.writeInt(data.length); // Write length of certificate in bytes
                toClient.write(data);
            }
            catch(EOFException ex) {
                ex.printStackTrace();
            }
            catch(IOException ex) {
                ex.printStackTrace();
            }

            while (!connectionSocket.isClosed()) {
                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {
                    System.out.println(packetType);
                    System.out.println("Receiving filename...");

                    int numBytes = fromClient.readInt();
                    byte [] encryptedfilename = new byte[128];
                    fromClient.read(encryptedfilename);
                    System.out.println("number of Bytes expected: " + numBytes);
                    byte[] filename = decryptBytes(encryptedfilename);
                    System.out.println("Filename is " + new String(filename));
                    fileOutputStream = new FileOutputStream("recv/"+new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {
                    // System.out.println("Receiving file...");
                    int numBytes = fromClient.readInt();
                    byte[] encryptedBlock = new byte[128];
                    fromClient.read(encryptedBlock);
                    byte[] decryptedBlock = decryptBytes(encryptedBlock);

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

    byte[] encryptedBytes = encryptCipher.doFinal(s.getBytes());
    return encryptedBytes;
    }

    public static byte[] decryptBytes(byte[] encryptedByte) throws Exception {
        byte[] decryptedBytes = decryptCipher.doFinal(encryptedByte);
        return decryptedBytes;
    }


    public static void initialiseCipher() throws Exception{
        Key privateKey = getPrivateKey();
        encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    public static Key getPrivateKey() throws Exception {
        Path privateKeyPath = Paths.get("jyCert/privateServer8.pem");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
        String privateKeyString = new String(privateKeyBytes, "UTF-8");

        // Strip header, footer
        privateKeyString = privateKeyString.replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");

        byte[] privateKeyRepresentation = Base64.getDecoder().decode(privateKeyString.getBytes("UTF-8"));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyRepresentation));

        return privateKey;
    }

}
