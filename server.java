import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;


/**
Project 4 Matt Conflitti
*/

class server {
	public static void main(String args[]) {
    cryptotest crypt = new cryptotest();
		try {
			ServerSocketChannel c = ServerSocketChannel.open();
			Selector s = Selector.open();
			c.configureBlocking(false);

			//hard code the port for ease of use
			c.bind(new InetSocketAddress(Integer.parseInt("5000")));
      c.register(s,SelectionKey.OP_ACCEPT);
			System.out.println("Listening on Port 5000...");

			//set up maps to store the data
      HashMap<Integer,SocketChannel> openSockets = new HashMap<Integer,SocketChannel>();
      HashMap<SocketChannel,SecretKey> keyPairs = new HashMap<SocketChannel,SecretKey>();
      int uuid = 1;
      String outgoingMsg = "";
      String incomingMsg = "";
      int incomingUser = 0;
      String cmd = "";

      /**
      Set up RSA keys and such
      */
      crypt.setPrivateKey("RSApriv.der");
    	crypt.setPublicKey("RSApub.der");

			while(true) {
			    int n = s.select(5000);
			    if(n == 0) {
			        continue;
			    }
			    Iterator i = s.selectedKeys().iterator();
			    while(i.hasNext()) {
            SelectionKey selKey = (SelectionKey) i.next();
            i.remove();
            int currentUser = 0;

						//code to run when connection is accepted, like adding socket to map
            if (selKey.isAcceptable()) {
                SocketChannel sc = ((ServerSocketChannel) selKey.channel()).accept();
                sc.configureBlocking(false);

                if(!openSockets.containsValue(sc)) {
                  openSockets.put(uuid, sc);
                  currentUser = uuid++;
                } else {
                  currentUser = getKeyByValue(openSockets, sc);
                }

                System.out.println("User connected: UUID" + currentUser);

                // prepare for read,
                sc.register(s, SelectionKey.OP_READ);

            } else if (selKey.isReadable()) {
                // read
                SocketChannel client = (SocketChannel) selKey.channel();

								//check if secret key exists for current user; happens on first transmission
                if(!keyPairs.containsKey(client)) {
                  ByteBuffer inBuf = ByteBuffer.allocate(256);
                  client.read(inBuf);
                  keyPairs.put(client,new SecretKeySpec(crypt.RSADecrypt(inBuf.array()),"AES"));
									System.out.println("AES Secret Key Received. Ready for encrypted transmission...");
                } else {
									//otherwise get command, decrypt it, and save it for later
                  ByteBuffer inBuf = ByteBuffer.allocate(4096);
                  client.read(inBuf);
                  incomingUser = getKeyByValue(openSockets, client);
                  System.out.println("-------- Inbound Encrypted Cmd From UUID" + incomingUser + " --------");

                  incomingMsg = receiveAndDecrypt(inBuf,crypt, keyPairs, client);
                  System.out.println("Decrypted Command: " + incomingMsg);
                  cmd = incomingMsg.split(" ")[0];

                  // prepare for write,
                  client.register(s, SelectionKey.OP_WRITE);
                }
            } else if (selKey.isWritable()) {
              SocketChannel cmdClient = (SocketChannel) selKey.channel();

							//read the command and act accordingly
              if(cmd.equals("BCAST")) {
                //BCAST message
                outgoingMsg = "BCAST FROM " + incomingUser + ": " + incomingMsg.split(" ",2)[1].trim();
                List<Integer> list = new ArrayList<Integer>(openSockets.keySet());
                for(Integer user : list) {
                  if(user == incomingUser) {
                    continue;
                  }
                  SocketChannel tmp = openSockets.get(user);
                  encryptAndSend(outgoingMsg, crypt, keyPairs, tmp);
                }
              } else if(cmd.equals("GET_USERS")) {
                //GET_USERS
                String userList = "\nConnected Users:\n";
                List<Integer> list = new ArrayList<Integer>(openSockets.keySet());
                for(Integer user : list) {
                  userList += ((user != incomingUser) ? user : user + " (you)") + "\n";
                }
                outgoingMsg = userList;
                encryptAndSend(outgoingMsg, crypt, keyPairs, cmdClient);
              } else if(cmd.equals("SENDTO")) {
                //SENDTO user message
                int sendToUser = Integer.parseInt(incomingMsg.split(" ")[1].trim());
                String sendMsg = "MSG FROM " + incomingUser + ": " + incomingMsg.split(" ",3)[2].trim();

                SocketChannel sendTo = openSockets.get(sendToUser);
								if(sendTo != null) {
									encryptAndSend(sendMsg, crypt, keyPairs, sendTo);
								} else {
									encryptAndSend("User doesn't exist", crypt, keyPairs, cmdClient);
								}
              } else if(cmd.equals("KICK")) {
                //KICK user
                int user = Integer.parseInt(incomingMsg.split(" ")[1].trim());
                SocketChannel kicked = openSockets.remove(user);
                if(kicked == null) {
                  outgoingMsg = "No user existed.";
                } else {
                  //ByteBuffer tmpBuf = ByteBuffer.wrap(quitMsg.getBytes());
                  encryptAndSend("quit", crypt, keyPairs, kicked);
									keyPairs.remove(kicked);
                  kicked.close();
                  outgoingMsg = "UUID" + user + " kicked.";
                }
                //ByteBuffer buffer = ByteBuffer.wrap(outgoingMsg.getBytes());
                encryptAndSend(outgoingMsg, crypt, keyPairs, cmdClient);
              } else {
                outgoingMsg = "Bad command. Try again.";
                //ByteBuffer buffer = ByteBuffer.wrap(outgoingMsg.getBytes());
                encryptAndSend(outgoingMsg, crypt, keyPairs, cmdClient);
              }
							System.out.println("-------- Command Successfully Processed --------\n");
              // switch to read, and disable write,
              cmdClient.register(s, SelectionKey.OP_READ);
            }
			    }
			}
		} catch (IOException e) {
			System.out.println("IOEXCEPTION");
      //e.printStackTrace();
		}
	}

	/**
	Helper method to get a key from map based on the value.
	*/
  public static <T, E> T getKeyByValue(Map<T, E> map, E value) {
      for (Map.Entry<T, E> entry : map.entrySet()) {
          if (Objects.equals(value, entry.getValue())) {
              return entry.getKey();
          }
      }
      return null;
  }

	/**
	Get integer from byte array
	*/
	public static int getLengthFromBytes(byte[] rawLength) {
		return ((rawLength[0] & 0xFF) << 24) | ((rawLength[1] & 0xFF) << 16)
		| ((rawLength[2] & 0xFF) << 8) | (rawLength[3] & 0xFF);
	}

	/**
	Process a buffer to extract message and decrypt it
	*/
	public static String receiveAndDecrypt(ByteBuffer inBuf, cryptotest crypt, HashMap<SocketChannel,SecretKey> keyPairs, SocketChannel client) {
		byte[] ivBytes = Arrays.copyOfRange(inBuf.array(),0,16);
		IvParameterSpec iv = new IvParameterSpec(ivBytes);

		byte[] rawLength = Arrays.copyOfRange(inBuf.array(),16,20);
		int length = getLengthFromBytes(rawLength);

		byte[] tmp = Arrays.copyOfRange(inBuf.array(), 20, 20+length);
		System.out.printf("Encrypted Command: %s%n",DatatypeConverter.printHexBinary(tmp));
		return new String(crypt.decrypt(tmp, keyPairs.get(client), iv)).trim();
	}

	/**
	Encrypt the message and send it on given socketchannel
	*/
	public static void encryptAndSend(String ob, cryptotest c, HashMap<SocketChannel,SecretKey> keyPairs, SocketChannel client)
	throws IOException {
		SecureRandom r = new SecureRandom();
		byte ivbytes[] = new byte[16];
		r.nextBytes(ivbytes);
		IvParameterSpec iv = new IvParameterSpec(ivbytes);
		System.out.printf("Outbound message:\t%s%n",new String(ob));
		byte ciphertext[] = c.encrypt(ob.getBytes(),keyPairs.get(client),iv);
		System.out.printf("Encrypted Outbound message: %s%n",DatatypeConverter.printHexBinary(ciphertext));
		ByteBuffer buf = ByteBuffer.allocate(4096);
		buf.put(iv.getIV());
		buf.putInt((int)ciphertext.length);
		buf.put(ciphertext);
		buf.flip();
		client.write(buf);
	}
}
