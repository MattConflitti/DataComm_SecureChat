import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;
import java.util.*;

/**
Project 4 Matt Conflitti
*/


class client {
	public static void main(String args[]) {
    cryptotest c = new cryptotest();
		//use same public key
    c.setPublicKey("RSApub.der");
		Console cons = System.console();
		try {
			SocketChannel sc = SocketChannel.open();
			//hard coded address because typing is a hassle
			sc.connect(new InetSocketAddress("127.0.0.1", Integer.parseInt("5000")));

			//generateAESKey, encrypt with pubRSA and send
      SecretKey s = c.generateAESKey();
      byte encryptedsecret[] = c.RSAEncrypt(s.getEncoded());
      ByteBuffer keyBuf = ByteBuffer.allocate(256);
      keyBuf.put(encryptedsecret);
      keyBuf.flip();
      sc.write(keyBuf);

			//start prompting and receiving
		  TcpRecvThread t = new TcpRecvThread(sc,c,s);
			t.start();
			TcpPromptThread p = new TcpPromptThread(sc,c,s);
			p.start();
		} catch (IOException e) {
			System.out.println("Server disconnected");
		}
	}
}

class TcpRecvThread extends Thread {

    SocketChannel sc;
    cryptotest c;
    SecretKey s;
    TcpRecvThread(SocketChannel channel, cryptotest crypto, SecretKey secret) {
        sc = channel;
        c = crypto;
        s = secret;
    }

    public void run() {
        try {
            while(true) {
                ByteBuffer buf = ByteBuffer.allocate(4096);
                sc.read(buf);

								//get iv from buffer
                byte[] ivBytes = Arrays.copyOfRange(buf.array(),0,16);
								IvParameterSpec iv = new IvParameterSpec(ivBytes);

								//get msg length from buffer
								byte[] rawLength = Arrays.copyOfRange(buf.array(),16,20);
								int length = getLengthFromBytes(rawLength);

								//get msg form buffer
								byte[] tmp = Arrays.copyOfRange(buf.array(), 20, 20+length);

								//decrypt and display
              	byte decryptedplaintext[] = c.decrypt(tmp,s,iv);
	              String m = new String(decryptedplaintext).trim();

	            if(m.equalsIgnoreCase("quit")) {
	                System.out.println("Server disconnected or you were kicked...press enter to exit");
	                break;
	            }
	            System.out.println(m);
            }
            sc.close();
        } catch(IOException e) {
            System.out.println("Goodbye. Closing chat...");
        }


    }

		public static int getLengthFromBytes(byte[] rawLength) {
			return ((rawLength[0] & 0xFF) << 24) | ((rawLength[1] & 0xFF) << 16)
			| ((rawLength[2] & 0xFF) << 8) | (rawLength[3] & 0xFF);
		}
}

class TcpPromptThread extends Thread {

    SocketChannel sc;
    cryptotest c;
    SecretKey s;
    TcpPromptThread(SocketChannel channel, cryptotest crypto, SecretKey secret) {
        sc = channel;
        c = crypto;
        s = secret;
    }

    public void run() {
        try {
            Console cons = System.console();
            String m = "";

	          while(!m.trim().equalsIgnoreCase("quit")) {
              m = cons.readLine("Message: ");
							ByteBuffer buf = ByteBuffer.allocate(4096);

							//create IV, encrypt msg and send it
              SecureRandom r = new SecureRandom();
            	byte ivbytes[] = new byte[16];
            	r.nextBytes(ivbytes);
							//System.out.println(new String(ivbytes));
            	IvParameterSpec iv = new IvParameterSpec(ivbytes);
              byte ciphertext[] = c.encrypt(m.trim().getBytes(),s,iv);
							//System.out.printf("CipherText: %s%n",DatatypeConverter.printHexBinary(ciphertext));
              buf.put(iv.getIV());
							buf.putInt((int)ciphertext.length);
              buf.put(ciphertext);
              buf.flip();
		          sc.write(buf);
	          }
	          // buf = ByteBuffer.wrap(m.getBytes());
			      // sc.write(buf);
	          System.out.println("Server disconnected or you were kicked...press enter to exit");
	          sc.close();
        } catch(IOException e) {
            System.out.println("Goodbye. Closing chat...");
        }
    }
}
