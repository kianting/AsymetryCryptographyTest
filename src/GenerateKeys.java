import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.io.StringWriter;
import java.util.Base64;
import java.util.Base64.Encoder;


public class GenerateKeys {

    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Encoder enc;
    
    public GenerateKeys(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.keyGen = KeyPairGenerator.getInstance("RSA");
        this.keyGen.initialize(keylength);
    }

    public void createKeys() {
    	this.enc = Base64.getEncoder();
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public String getPublicKeyBase64() throws Exception {
        StringWriter sw = new StringWriter();
      	 sw.write((new String(enc.encode(getPublicKey().getEncoded()))));
      	 return sw.toString();
    }
    
    public String getPrivateKeyBase64() throws Exception {
     StringWriter sw = new StringWriter();
   	 sw.write((new String(enc.encode(getPrivateKey().getEncoded()))));
   	 return sw.toString();
   }
    
    public String getPublicKeyPEM() throws Exception {
        StringWriter sw = new StringWriter();
      	 sw.write(ConstantConfig.BEGIN_PUBLIC_KEY + "\n");
      	 sw.write((new String(enc.encode(getPublicKey().getEncoded()))).replaceAll("(.{64})", "$1\n"));
      	 sw.write(ConstantConfig.END_PUBLIC_KEY + "\n");
      	 return sw.toString();
    }
    
    public String getPrivateKeyPEM() throws Exception {
     StringWriter sw = new StringWriter();
   	 sw.write(ConstantConfig.BEGIN_PRIVATE_KEY + "\n");
   	 sw.write((new String(enc.encode(getPrivateKey().getEncoded()))).replaceAll("(.{64})", "$1\n"));
   	 sw.write(ConstantConfig.END_PRIVATE_KEY + "\n");
   	 return sw.toString();
   }
    
    public static void main(String[] args) {
        GenerateKeys gk;
        try {
            gk = new GenerateKeys(1024);
            gk.createKeys();
            System.out.println("Private Key PEM:\n" + gk.getPublicKeyPEM());
            System.out.println("Public Key PEM:\n" + gk.getPrivateKeyPEM()); 
            System.out.println("Private Key BASE64:\n" + gk.getPublicKeyBase64());
            System.out.println("Public Key BASE64:\n" + gk.getPrivateKeyBase64());             
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.err.println(e.getMessage());
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

    }

}