package com.javatutoriales;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {

    private static Cipher cipher;

    public static void main(String[] args) throws GeneralSecurityException, IOException, OperatorCreationException, PKCSException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        System.out.println("Hello world!");

        cipher = Cipher.getInstance("RSA/None/OAEPWITHSHA-256ANDMGF1PADDING", BouncyCastleProvider.PROVIDER_NAME);



//        https://stackoverflow.com/questions/49932334/how-read-a-pkcs8-encrypted-private-key-which-is-also-encoded-in-der-with-bouncyc
//        https://stackoverflow.com/questions/11787571/how-to-read-pem-file-to-get-private-and-public-key
        String privateKeyPEM = getKey("demo.pkcs8");
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replace("-----END ENCRYPTED PRIVATE KEY-----", "");

        System.out.println("Private key");
        System.out.println(privateKeyPEM);


        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPEM);
        ASN1Sequence ASN1 = ASN1Sequence.getInstance(privateKeyBytes);
        PKCS8EncryptedPrivateKeyInfo encobj = new PKCS8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo.getInstance(ASN1));
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        InputDecryptorProvider decryptionProv = new JceOpenSSLPKCS8DecryptorProviderBuilder().build("asdf".toCharArray());
        PrivateKeyInfo privateKeyInfo = encobj.decryptPrivateKeyInfo(decryptionProv);
        RSAPrivateKey privateKey = (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
        System.out.println (privateKey.getAlgorithm());


        String cypheredText = encryptText("Hola mundo", privateKey);

        System.out.println(cypheredText);




        String publicKeyPEM = getKey("demo.pub");
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");


        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        System.out.println(pubKey.getAlgorithm());
        System.out.println("Public key");

        System.out.println(publicKeyPEM);

        System.out.println(decryptText(cypheredText, pubKey));

    }


    //https://www.baeldung.com/java-read-pem-file-keys
    public static PrivateKey readPrivateKeySecondApproach(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {

            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());

            return converter.getPrivateKey(privateKeyInfo);
        }
    }

//https://stackoverflow.com/questions/11787571/how-to-read-pem-file-to-get-private-and-public-key
    private static String getKey(String filename) throws IOException {
        // Read key from file
        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line.trim() + "";
        }
        br.close();
        return strKeyPEM;
    }

    public static RSAPrivateKey getPrivateKey(String filename) throws IOException, GeneralSecurityException {
        String privateKeyPEM = getKey(filename);
        return getPrivateKeyFromString(privateKeyPEM);
    }

    public static RSAPrivateKey getPrivateKeyFromString(String key) throws IOException, GeneralSecurityException {
        String privateKeyPEM = key;
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
        byte[] encoded = Base64.getEncoder().encode(privateKeyPEM.getBytes());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
        return privKey;
    }

    //https://mkyong.com/java/java-asymmetric-cryptography-example/
    public static String encryptText(String msg, PrivateKey key) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
    }


    public static String decryptText(String msg, PublicKey key) throws InvalidKeyException, UnsupportedEncodingException,  IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(msg)), StandardCharsets.UTF_8);
    }
}