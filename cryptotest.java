import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;

class cryptotest{
    private PrivateKey privKey;
    private PublicKey pubKey;

    public cryptotest(){
    	privKey=null;
    	pubKey=null;
    }
    public byte[] encrypt(byte[] plaintext, SecretKey secKey, IvParameterSpec iv){
    	try{
    	    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	    c.init(Cipher.ENCRYPT_MODE,secKey,iv);
    	    byte[] ciphertext = c.doFinal(plaintext);
    	    return ciphertext;
    	}catch(Exception e){
    	    System.out.println("AES Encrypt Exception");
          e.printStackTrace();
    	    System.exit(1);
    	    return null;
    	}
    }
    public byte[] decrypt(byte[] ciphertext, SecretKey secKey, IvParameterSpec iv){
    	try{
    	    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	    c.init(Cipher.DECRYPT_MODE,secKey,iv);
    	    byte[] plaintext = c.doFinal(ciphertext);
    	    return plaintext;
    	}catch(Exception e){
    	    System.out.println("AES Decrypt Exception");
          e.printStackTrace();
    	    System.exit(1);
    	    return null;
    	}
    }
    public byte[] RSADecrypt(byte[] ciphertext){
    	try{
    	    Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
    	    c.init(Cipher.DECRYPT_MODE,privKey);
    	    byte[] plaintext=c.doFinal(ciphertext);
    	    return plaintext;
    	}catch(Exception e){
    	    System.out.println("RSA Decrypt Exception");
          e.printStackTrace();
    	    System.exit(1);
    	    return null;
    	}
    }
    public byte[] RSAEncrypt(byte[] plaintext){
    	try{
    	    Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
    	    c.init(Cipher.ENCRYPT_MODE,pubKey);
    	    byte[] ciphertext=c.doFinal(plaintext);
    	    return ciphertext;
    	}catch(Exception e){
    	    System.out.println("RSA Encrypt Exception");
          e.printStackTrace();
    	    System.exit(1);
    	    return null;
    	}
    }
    public SecretKey generateAESKey(){
    	try{
    	    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    	    keyGen.init(128);
    	    SecretKey secKey = keyGen.generateKey();
    	    return secKey;
    	}catch(Exception e){
    	    System.out.println("Key Generation Exception");
          e.printStackTrace();
    	    System.exit(1);
    	    return null;
    	}
    }
    public void setPrivateKey(String filename){
    	try{
    	    File f = new File(filename);
    	    FileInputStream fs = new FileInputStream(f);
    	    byte[] keybytes = new byte[(int)f.length()];
    	    fs.read(keybytes);
    	    fs.close();
    	    PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(keybytes);
    	    KeyFactory rsafactory = KeyFactory.getInstance("RSA");
    	    privKey = rsafactory.generatePrivate(keyspec);
    	}catch(Exception e){
    	    System.out.println("Private Key Exception");
    	    e.printStackTrace(System.out);
    	    System.exit(1);
    	}
    }
    public void setPublicKey(String filename){
    	try{
    	    File f = new File(filename);
    	    FileInputStream fs = new FileInputStream(f);
    	    byte[] keybytes = new byte[(int)f.length()];
    	    fs.read(keybytes);
    	    fs.close();
    	    X509EncodedKeySpec keyspec = new X509EncodedKeySpec(keybytes);
    	    KeyFactory rsafactory = KeyFactory.getInstance("RSA");
    	    pubKey = rsafactory.generatePublic(keyspec);
    	}catch(Exception e){
    	    System.out.println("Public Key Exception");
    	    System.exit(1);
    	}
    }

    public static void main(String args[]){
    	cryptotest c = new cryptotest();
    	c.setPrivateKey("RSApriv.der");
    	c.setPublicKey("RSApub.der");
    	SecretKey s = c.generateAESKey();
    	byte encryptedsecret[] = c.RSAEncrypt(s.getEncoded());
    	SecureRandom r = new SecureRandom();
    	byte ivbytes[] = new byte[16];
    	r.nextBytes(ivbytes);
    	IvParameterSpec iv = new IvParameterSpec(ivbytes);
    	String plaintext = "This is a test string to encrypt";
    	byte ciphertext[] = c.encrypt(plaintext.getBytes(),s,iv);
    	System.out.printf("CipherText: %s%n",DatatypeConverter.printHexBinary(ciphertext));
    	byte decryptedsecret[] = c.RSADecrypt(encryptedsecret);
    	SecretKey ds = new SecretKeySpec(decryptedsecret,"AES");
    	byte decryptedplaintext[] = c.decrypt(ciphertext,ds,iv);
    	String dpt = new String(decryptedplaintext);
    	System.out.printf("PlainText: %s%n",dpt);
    }
}
