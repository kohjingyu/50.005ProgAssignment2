import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class ClientWithoutSecurity {

	public static void main(String[] args) {
    	String filename = "rr.txt";

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();
		boolean identityVerified = false;

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket("localhost", 4321);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			byte [] encryptedMsg;
			// Transferring message
			System.out.println("Receiving encrypted message...");
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

				PublicKey serverPublicKey = getServerPublicKey(serverCert);

				// Decrypt message from SecStore
	            Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	            decryptCipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
	            byte[] decryptedBytes = decryptCipher.doFinal(encryptedMsg);
	            String decryptedMsg = new String(decryptedBytes, "UTF-8");

	            // TODO: How to make message consistent between client and server?
	            assert(decryptedMsg.equals("Helllo this is SecStore!"));
	            System.out.println("SecStore identity verified.");

				identityVerified = true; // Allow for file transfer
			}
			catch(Exception e) {
				// e.printStackTrace();
				System.out.println("Oh no, you were not verified. Bye!");
			}

			// TODO: YAY! Verification done! Now Vincent will do the rest.

			// If check succeeded, send file
			if(identityVerified) {
				System.out.println("Sending file...");

				// Send the filename
				toServer.writeInt(0);
				toServer.writeInt(filename.getBytes().length);
				toServer.write(filename.getBytes());
				toServer.flush();

				// Open the file
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);

		        byte [] fromFileBuffer = new byte[117];

		        // Send the file
		        for (boolean fileEnded = false; !fileEnded;) {
					numBytes = bufferedFileInputStream.read(fromFileBuffer);
					fileEnded = numBytes < fromFileBuffer.length;

					toServer.writeInt(1);
					toServer.writeInt(numBytes);
					toServer.write(fromFileBuffer);
					toServer.flush();
				}

		        bufferedFileInputStream.close();
		        fileInputStream.close();
			}

			System.out.println("Closing connection...");
	        toServer.writeInt(2);
	        toServer.flush();
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
		// Load CA's public key
		InputStream CAFis = new FileInputStream("jyCert/CA.crt");
		CertificateFactory CACf = CertificateFactory.getInstance("X.509");
		X509Certificate CAcert =(X509Certificate)CACf.generateCertificate(CAFis);

		PublicKey CAKey = CAcert.getPublicKey();

		serverCert.checkValidity(); // Throws a CertificateExpiredException or CertificateNotYetValidException if invalid
		serverCert.verify(CAKey);

		System.out.println("Server certificate is signed by CA!");

		// Get K_S^+
		PublicKey serverPublicKey = serverCert.getPublicKey();
		return serverPublicKey;
	}
}
