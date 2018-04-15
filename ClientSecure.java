import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;

import java.util.Arrays;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.PublicKey;
import java.security.Key;
import java.security.SecureRandom;
import javax.security.auth.x500.X500Principal;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public class ClientSecure {
    static Cipher rsaEncryptCipher;
    static Cipher rsaDecryptCipher;
    static Cipher decryptCipher;
    static Cipher encryptCipher;
    static Key aesSymmetricKey;

    public static void main(String[] args) {
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        String filename = "";
        String protocol = "";
        try {
            System.out.println("Enter protocol(RSA/AES):");
            protocol = stdIn.readLine();
            System.out.println("Enter name of file to be sent:");
            filename = stdIn.readLine();
        } catch (IOException ioEx) {
            ioEx.printStackTrace();
        }

        PublicKey serverPublicKey;

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        boolean identityVerified = false;
        long timeStarted = System.nanoTime();

        try {
            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            // String server = "10.12.182.147" (laptop)
            // (desktop)
            // String server = "10.12.150.191";
            String server = "localhost";
            clientSocket = new Socket(server, 1234);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            // Tell server to receive nonce
            toServer.writeInt(1);
            // Send nonce
            int nonceSize = 64;
            SecureRandom random = new SecureRandom();
            byte nonce[] = new byte[nonceSize];
            random.nextBytes(nonce);
            toServer.writeInt(nonceSize);
            toServer.write(nonce);

            byte [] encryptedMsg;
            // Transferring message (nonce)
            System.out.println("Receiving encrypted nonce...");
            int msgBytes = fromServer.readInt();
            encryptedMsg = new byte[msgBytes];
            fromServer.read(encryptedMsg);


            try {
                // Transferring certificate
                System.out.println("Receiving certificate...");
                int certBytes = fromServer.readInt();
                byte [] data = new byte[certBytes];
                fromServer.read(data);

                System.out.println("Verifying certificate...");

                InputStream certIn = new ByteArrayInputStream(data);

                // Receive certificate from server
                // InputStream serverFis = new FileInputStream("cert/server.crt");
                CertificateFactory serverCf = CertificateFactory.getInstance("X.509");
                X509Certificate serverCert =(X509Certificate)serverCf.generateCertificate(certIn);

                serverPublicKey = getServerPublicKey(serverCert);

                //Initialise RSA Cipher
                rsaDecryptCipher = initialiseCipher("RSA-D",serverPublicKey);
                rsaEncryptCipher = initialiseCipher("RSA-E",serverPublicKey);



                // Decrypt message from SecStore

                byte[] decryptedNonce = rsaDecryptCipher.doFinal(encryptedMsg);
                if(!Arrays.equals(decryptedNonce, nonce)) {
                    System.out.println("Nonce was not equal!");
                    throw new Exception("Nonce was not equal!");
                }
                System.out.println("Nonce is valid. SecStore identity verified.");
                identityVerified = true; // Allow for file transfer
            }
            catch(Exception e) {
                e.printStackTrace();
                System.out.println("Oh no, you were not verified. Bye!");
            }

            // If check succeeded, send file
            if(identityVerified) {
                if (protocol.equals("AES")) {
                    System.out.println("Receiving session key...");
                    int encryptedSessionKeyLength = fromServer.readInt();
                    byte[] encryptedSessionKey = new byte[encryptedSessionKeyLength];
                    fromServer.read(encryptedSessionKey);
                    byte[] decryptedSessionKey = rsaDecryptCipher.doFinal(encryptedSessionKey);
                    aesSymmetricKey = new SecretKeySpec(decryptedSessionKey,"AES");
                    encryptCipher = initialiseCipher("AES-E", aesSymmetricKey);
                } else if (protocol.equals("RSA")){
                    encryptCipher = rsaEncryptCipher;
                }

                // EncodedKeySpec eks = new X509EncodedKeySpec(decryptedSessionKey);
                // SecretKeySpec sks = new SecretKeySpec()

                //Initialising AES Cipher

                byte[] fileNameBytes = filename.getBytes();
                int byteArrayLength = fileNameBytes.length;
                System.out.println("Length of filename bytes is: " + byteArrayLength);
                fileNameBytes = encryptCipher.doFinal(fileNameBytes);

                System.out.println("Sending file...");

                // Send the filename
                toServer.writeInt(0);
                toServer.writeInt(byteArrayLength);
                toServer.write(fileNameBytes);
                toServer.flush();

                // Open the file
                fileInputStream = new FileInputStream(filename);
                bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                byte [] fromFileBuffer = new byte[117];


                // Send the file
                for (boolean fileEnded = false; !fileEnded;) {
                // Reading from the inputstream into the fromFileBuffer
                    numBytes = bufferedFileInputStream.read(fromFileBuffer);
                    fileEnded = numBytes < fromFileBuffer.length;

                    byte[] encryptedFile = encryptCipher.doFinal(fromFileBuffer);

                    toServer.writeInt(1);
                    toServer.writeInt(numBytes);
                    toServer.write(encryptedFile);
                    toServer.flush();
                }

                bufferedFileInputStream.close();
                fileInputStream.close();
            }

            System.out.println("Closing connection, waiting for Server...");
            toServer.writeInt(2);
            toServer.flush();
            int signal = fromServer.readInt();
            if (signal == 3) {

            }
        } catch (Exception e) {
            // Not valid!
            // Some error occured, or server is not verified
            e.printStackTrace();

            try {
                System.out.println("Some error occurred. Bye!");
        toServer.writeInt(2);
        toServer.flush();
            }
            catch(IOException ex) {
                ex.printStackTrace();
            }
        }
        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }

    public static PublicKey getServerPublicKey(X509Certificate serverCert) throws Exception {
        System.out.println("Checking server certificate...");

        // Load CA's public key
        InputStream CAFis = new FileInputStream("jyCert/CA.crt");
        CertificateFactory CACf = CertificateFactory.getInstance("X.509");
        X509Certificate CAcert =(X509Certificate)CACf.generateCertificate(CAFis);

        PublicKey CAKey = CAcert.getPublicKey();

        serverCert.checkValidity(); // Throws a CertificateExpiredException or CertificateNotYetValidException if invalid
        serverCert.verify(CAKey);
        System.out.println("Server certificate is signed by CA!");

        System.out.println("Checking owner of certificate...");

        X500Principal CAPrincipal = serverCert.getSubjectX500Principal();
        String name = CAPrincipal.getName();

        // Check that the name is equal to the expected signer
        String expectedName = "1.2.840.113549.1.9.1=#161d6a696e6779755f6b6f68406d796d61696c2e737574642e6564752e7367,CN=SUTD,OU=ISTD,O=SUTD,L=Singapore,ST=Singapore,C=SG";
        if(!name.equals(expectedName)) {
            System.out.println("Certificate is not owned by SecStore!");
            throw new Exception("Certificate is not owned by SecStore!");
        }

        // Get K_S^+
        PublicKey serverPublicKey = serverCert.getPublicKey();
        return serverPublicKey;
    }

    public static Cipher initialiseCipher(String type, Key key) throws Exception{
        Cipher cipher;
        switch(type) {
            case "RSA-E":
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                return cipher;
            case "RSA-D":
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, key);
                return cipher;
            case "AES-D":
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, key);
                return cipher;
            case "AES-E":
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                return cipher;
            default:
                throw new IllegalArgumentException();
        }
    }
}
